use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

use crate::types::{EngineKind, ScannerError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanMode {
    Dependencies,
    Filesystem,
    Misconfiguration,
    ImageArchive,
    Code,
}

impl ScanMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dependencies => "dependencies",
            Self::Filesystem => "filesystem",
            Self::Misconfiguration => "misconfiguration",
            Self::ImageArchive => "image_archive",
            Self::Code => "code",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRequest {
    pub engine: EngineKind,
    pub mode: ScanMode,
    pub target: PathBuf,
    pub rules_file: Option<PathBuf>,
}

impl ScanRequest {
    pub fn new(engine: EngineKind, mode: ScanMode, target: impl Into<PathBuf>) -> Self {
        Self {
            engine,
            mode,
            target: target.into(),
            rules_file: None,
        }
    }

    pub fn with_local_rules(mut self, rules_file: impl Into<PathBuf>) -> Self {
        self.rules_file = Some(rules_file.into());
        self
    }
}

pub(crate) struct ValidatedRequest {
    pub target: PathBuf,
    pub rules_file: Option<PathBuf>,
    pub project_root: PathBuf,
}

pub(crate) fn validate_request(request: &ScanRequest) -> Result<ValidatedRequest, ScannerError> {
    match (request.engine, request.mode) {
        (EngineKind::OsvScanner, ScanMode::Dependencies)
        | (EngineKind::Trivy, ScanMode::Dependencies | ScanMode::Filesystem)
        | (EngineKind::Trivy, ScanMode::Misconfiguration)
        | (EngineKind::Trivy, ScanMode::ImageArchive)
        | (EngineKind::Semgrep, ScanMode::Code) => {}
        _ => return Err(ScannerError::InvalidConfiguration),
    }

    match request.mode {
        ScanMode::ImageArchive => {
            let target = request.target.canonicalize().map_err(ScannerError::Io)?;
            if !target.is_file() {
                return Err(ScannerError::InvalidTarget);
            }
            let parent = target.parent().ok_or(ScannerError::InvalidTarget)?;
            let project_root = parent.canonicalize().map_err(ScannerError::Io)?;
            if !target.starts_with(&project_root) {
                return Err(ScannerError::UnsafePath);
            }
            Ok(ValidatedRequest {
                target,
                rules_file: None,
                project_root,
            })
        }
        ScanMode::Dependencies
        | ScanMode::Filesystem
        | ScanMode::Misconfiguration
        | ScanMode::Code => {
            let project_root = request.target.canonicalize().map_err(ScannerError::Io)?;
            if !project_root.is_dir() {
                return Err(ScannerError::InvalidTarget);
            }
            let rules_file = if request.mode == ScanMode::Code {
                let path = request
                    .rules_file
                    .as_ref()
                    .ok_or(ScannerError::InvalidConfiguration)?
                    .canonicalize()
                    .map_err(ScannerError::Io)?;
                if !path.is_file() || !path.starts_with(&project_root) {
                    return Err(ScannerError::UnsafePath);
                }
                Some(path)
            } else {
                if request.rules_file.is_some() {
                    return Err(ScannerError::InvalidConfiguration);
                }
                None
            };
            Ok(ValidatedRequest {
                target: project_root.clone(),
                rules_file,
                project_root,
            })
        }
    }
}

pub(crate) fn build_arguments(
    request: &ScanRequest,
    validated: &ValidatedRequest,
    cache_directory: &Path,
    trusted_config: Option<&Path>,
) -> Result<Vec<OsString>, ScannerError> {
    let mut args = Vec::new();
    match (request.engine, request.mode) {
        (EngineKind::OsvScanner, ScanMode::Dependencies) => {
            args.extend(["scan", "source", "--format=json", "--config"].map(OsString::from));
            let trusted_config = trusted_config.ok_or(ScannerError::InvalidConfiguration)?;
            args.push(trusted_config.as_os_str().to_owned());
            args.extend(
                ["--offline", "--offline-vulnerabilities", "--recursive"].map(OsString::from),
            );
            args.push(validated.target.as_os_str().to_owned());
        }
        (EngineKind::Trivy, ScanMode::Dependencies | ScanMode::Filesystem) => {
            args.extend(
                [
                    "--cache-dir",
                    "--skip-version-check",
                    "--disable-telemetry",
                    "fs",
                    "--format",
                    "json",
                    "--scanners",
                    "vuln,secret",
                    "--skip-db-update",
                    "--skip-java-db-update",
                    "--skip-check-update",
                    "--offline-scan",
                    "--config=",
                    "--ignorefile=",
                    "--secret-config=",
                ]
                .map(OsString::from),
            );
            args.insert(1, cache_directory.as_os_str().to_owned());
            args.push(validated.target.as_os_str().to_owned());
        }
        (EngineKind::Trivy, ScanMode::Misconfiguration) => {
            args.extend(
                [
                    "--cache-dir",
                    "--skip-version-check",
                    "--disable-telemetry",
                    "config",
                    "--format",
                    "json",
                    "--skip-check-update",
                    "--include-non-failures",
                    "--config=",
                    "--ignorefile=",
                ]
                .map(OsString::from),
            );
            args.insert(1, cache_directory.as_os_str().to_owned());
            args.push(validated.target.as_os_str().to_owned());
        }
        (EngineKind::Trivy, ScanMode::ImageArchive) => {
            args.extend(
                [
                    "--cache-dir",
                    "--skip-version-check",
                    "--disable-telemetry",
                    "image",
                    "--input",
                    "--format",
                    "json",
                    "--scanners",
                    "vuln,secret,misconfig",
                    "--skip-db-update",
                    "--skip-java-db-update",
                    "--skip-check-update",
                    "--offline-scan",
                    "--config=",
                    "--ignorefile=",
                    "--secret-config=",
                ]
                .map(OsString::from),
            );
            args.insert(1, cache_directory.as_os_str().to_owned());
            args.insert(6, validated.target.as_os_str().to_owned());
        }
        (EngineKind::Semgrep, ScanMode::Code) => {
            let rules_file = validated
                .rules_file
                .as_ref()
                .ok_or(ScannerError::InvalidConfiguration)?;
            args.extend(
                [
                    "scan",
                    "--json",
                    "--metrics=off",
                    "--disable-version-check",
                    "--disable-nosem",
                    "--no-git-ignore",
                    "--config",
                ]
                .map(OsString::from),
            );
            args.push(rules_file.as_os_str().to_owned());
            args.push(validated.target.as_os_str().to_owned());
        }
        _ => return Err(ScannerError::InvalidConfiguration),
    }
    Ok(args)
}
