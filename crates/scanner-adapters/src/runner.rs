use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

#[cfg(test)]
use std::ffi::OsString;
use tempfile::{NamedTempFile, TempDir, tempdir_in};

use crate::{
    commands::{ScanRequest, build_arguments, validate_request},
    install::ScannerAdapters,
    normalize::{normalize_osv_scanner, normalize_semgrep, normalize_trivy},
    process::run_process,
    types::{
        EngineDetection, EngineKind, EngineStatus, ScanDiagnostic, ScanDiagnosticKind,
        ScanExecution, ScannerError,
    },
    version::{
        detect_in_paths, executable_search_paths, managed_executable_path, pinned_tool,
        platform_key,
    },
};

impl ScannerAdapters {
    pub async fn detect_engine(&self, engine: EngineKind) -> EngineDetection {
        let managed = self
            .managed_path(engine)
            .and_then(|managed_path| managed_path.parent().map(|parent| parent.to_path_buf()));
        let managed = match managed {
            Some(directory) => Some(detect_in_paths(engine, [directory]).await),
            None => None,
        };
        if let Some(detection) = managed
            .as_ref()
            .filter(|detection| detection.status == EngineStatus::Available)
        {
            return detection.clone();
        }
        let system = detect_in_paths(engine, executable_search_paths()).await;
        select_detection(engine, system, managed)
    }

    pub async fn scan(&self, request: ScanRequest) -> Result<ScanExecution, ScannerError> {
        let validated = validate_request(&request)?;
        if request.engine == EngineKind::Semgrep && contains_semgrepignore(&validated.project_root)?
        {
            return Err(ScannerError::RepositoryConfigurationRequiresApproval);
        }
        let detection = self.detect_engine(request.engine).await;
        if detection.status != EngineStatus::Available {
            return Ok(ScanExecution {
                detection,
                mode: request.mode,
                result: None,
            });
        }
        let executable = detection
            .executable
            .as_ref()
            .ok_or(ScannerError::VersionUnverified)?;
        let app_data = canonical_app_data(&self.app_data_dir)?;
        let cache_directory = create_private_directory(&app_data, "cache/scanners")?;
        let working_directory = create_working_directory(&app_data)?;
        let trusted_config = if request.engine == EngineKind::OsvScanner {
            Some(
                NamedTempFile::new_in(&app_data)
                    .map_err(ScannerError::Io)?
                    .into_temp_path(),
            )
        } else {
            None
        };
        let osv_cache_directory = if request.engine == EngineKind::OsvScanner {
            Some(create_private_directory(&app_data, "osv/scanner-db")?)
        } else {
            None
        };
        let arguments = build_arguments(
            &request,
            &validated,
            &cache_directory,
            trusted_config.as_ref().map(|path| path.as_ref()),
        )?;
        let process = run_process(
            executable,
            &arguments,
            working_directory.path(),
            osv_cache_directory.as_deref(),
        )
        .await?;
        let result = match request.engine {
            EngineKind::OsvScanner => {
                normalize_osv_scanner(&process.stdout, &validated.project_root)
            }
            EngineKind::Trivy => normalize_trivy(
                &process.stdout,
                (request.mode != crate::commands::ScanMode::ImageArchive)
                    .then_some(validated.project_root.as_path()),
            ),
            EngineKind::Semgrep => normalize_semgrep(&process.stdout, &validated.project_root),
        };
        let mut result = match result {
            Ok(result) => result,
            Err(_) if !process.success => return Err(ScannerError::ProcessFailed),
            Err(error) => return Err(error),
        };
        if !process.success {
            result.complete = false;
            result.diagnostics.push(ScanDiagnostic {
                kind: ScanDiagnosticKind::ScannerReportedError,
                path: None,
            });
        }
        Ok(ScanExecution {
            detection,
            mode: request.mode,
            result: Some(result),
        })
    }

    fn managed_path(&self, engine: EngineKind) -> Option<PathBuf> {
        let app_root = self.app_data_dir.canonicalize().ok()?;
        let path = managed_executable_path(&app_root, engine).ok()??;
        let canonical = path.canonicalize().ok()?;
        canonical.starts_with(&app_root).then_some(canonical)
    }
}

pub(crate) fn select_detection(
    engine: EngineKind,
    system: EngineDetection,
    managed: Option<EngineDetection>,
) -> EngineDetection {
    if let Some(detection) = managed
        .as_ref()
        .filter(|detection| detection.status == EngineStatus::Available)
    {
        return detection.clone();
    }
    if system.status != EngineStatus::Missing {
        return system;
    }
    unsupported_or_system(engine, managed.unwrap_or(system))
}

pub(crate) fn contains_semgrepignore(root: &Path) -> Result<bool, ScannerError> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).map_err(ScannerError::Io)? {
            let entry = entry.map_err(ScannerError::Io)?;
            let file_name = entry.file_name();
            if file_name == OsStr::new(".semgrepignore") {
                return Ok(true);
            }
            let file_type = entry.file_type().map_err(ScannerError::Io)?;
            if file_type.is_dir() && file_name != OsStr::new(".git") {
                pending.push(entry.path());
            }
        }
    }
    Ok(false)
}

fn unsupported_or_system(engine: EngineKind, mut detection: EngineDetection) -> EngineDetection {
    if detection.status != EngineStatus::Missing {
        return detection;
    }
    let supported = platform_key().is_some_and(|platform| {
        pinned_tool(engine)
            .ok()
            .flatten()
            .is_some_and(|tool| tool.downloads.contains_key(&platform))
    });
    if matches!(engine, EngineKind::OsvScanner | EngineKind::Trivy) && !supported {
        detection.status = EngineStatus::UnsupportedPlatform;
    }
    detection
}

fn canonical_app_data(path: &Path) -> Result<PathBuf, ScannerError> {
    fs::create_dir_all(path).map_err(ScannerError::Io)?;
    path.canonicalize().map_err(ScannerError::Io)
}

fn create_private_directory(root: &Path, relative: &str) -> Result<PathBuf, ScannerError> {
    let target = root.join(relative);
    fs::create_dir_all(&target).map_err(ScannerError::Io)?;
    let canonical = target.canonicalize().map_err(ScannerError::Io)?;
    if canonical.starts_with(root) {
        Ok(canonical)
    } else {
        Err(ScannerError::UnsafePath)
    }
}

fn create_working_directory(root: &Path) -> Result<TempDir, ScannerError> {
    let working_directory = tempdir_in(root).map_err(ScannerError::Io)?;
    let canonical = working_directory
        .path()
        .canonicalize()
        .map_err(ScannerError::Io)?;
    if canonical.starts_with(root) {
        Ok(working_directory)
    } else {
        Err(ScannerError::UnsafePath)
    }
}

#[cfg(test)]
pub(crate) fn args_for_test(
    request: &ScanRequest,
    target: &Path,
    cache_directory: &Path,
    rules_file: Option<&Path>,
) -> Result<Vec<OsString>, ScannerError> {
    let validated = crate::commands::ValidatedRequest {
        target: target.to_path_buf(),
        rules_file: rules_file.map(Path::to_path_buf),
        project_root: target.to_path_buf(),
    };
    build_arguments(request, &validated, cache_directory, rules_file)
}
