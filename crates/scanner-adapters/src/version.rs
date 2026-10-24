use std::{
    collections::BTreeMap,
    env,
    path::{Path, PathBuf},
};

use semver::Version;
use serde::Deserialize;

use crate::{
    process::run_process,
    types::{EngineDetection, EngineKind, EngineStatus, ScannerError},
};

const VERSIONS_TOML: &str = include_str!("../versions.toml");

#[derive(Debug, Deserialize)]
pub(crate) struct Versions {
    pub osv_scanner: PinnedTool,
    pub trivy: PinnedTool,
    pub semgrep: SemgrepTool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PinnedTool {
    pub version: String,
    pub minimum_version: String,
    pub max_download_bytes: u64,
    pub downloads: BTreeMap<String, DownloadArtifact>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SemgrepTool {
    pub minimum_version: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DownloadArtifact {
    pub url: String,
    pub sha256: String,
    pub format: String,
    pub binary: String,
}

pub(crate) fn versions() -> Result<Versions, ScannerError> {
    toml::from_str(VERSIONS_TOML).map_err(|_| ScannerError::VersionConfiguration)
}

pub(crate) fn pinned_tool(engine: EngineKind) -> Result<Option<PinnedTool>, ScannerError> {
    let versions = versions()?;
    Ok(match engine {
        EngineKind::OsvScanner => Some(versions.osv_scanner),
        EngineKind::Trivy => Some(versions.trivy),
        EngineKind::Semgrep => None,
    })
}

fn minimum_string(engine: EngineKind) -> Result<String, ScannerError> {
    let versions = versions()?;
    Ok(match engine {
        EngineKind::OsvScanner => versions.osv_scanner.minimum_version,
        EngineKind::Trivy => versions.trivy.minimum_version,
        EngineKind::Semgrep => versions.semgrep.minimum_version,
    })
}

pub fn minimum_supported_version(engine: EngineKind) -> Result<Version, ScannerError> {
    Version::parse(&minimum_string(engine)?).map_err(|_| ScannerError::VersionConfiguration)
}

pub(crate) fn platform_key() -> Option<String> {
    let os = match env::consts::OS {
        "windows" => "windows",
        "linux" => "linux",
        "macos" => "macos",
        _ => return None,
    };
    let architecture = match env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        _ => return None,
    };
    Some(format!("{os}_{architecture}"))
}

pub(crate) async fn detect_in_paths(
    engine: EngineKind,
    paths: impl IntoIterator<Item = PathBuf>,
) -> EngineDetection {
    let Some(executable) = find_executable(engine, paths) else {
        return EngineDetection {
            engine,
            status: EngineStatus::Missing,
            version: None,
            executable: None,
        };
    };
    let Some(version) = probe_version(&executable).await else {
        return EngineDetection {
            engine,
            status: EngineStatus::Unverified,
            version: None,
            executable: Some(executable),
        };
    };
    let minimum = match minimum_supported_version(engine) {
        Ok(version) => version,
        Err(_) => {
            return EngineDetection {
                engine,
                status: EngineStatus::Unverified,
                version: Some(version.to_string()),
                executable: Some(executable),
            };
        }
    };
    EngineDetection {
        engine,
        status: if version < minimum {
            EngineStatus::Outdated
        } else {
            EngineStatus::Available
        },
        version: Some(version.to_string()),
        executable: Some(executable),
    }
}

pub(crate) fn find_executable(
    engine: EngineKind,
    paths: impl IntoIterator<Item = PathBuf>,
) -> Option<PathBuf> {
    let name = engine.executable_name();
    paths.into_iter().find_map(|directory| {
        let candidate = directory.join(name);
        let canonical = candidate.canonicalize().ok()?;
        let metadata = canonical.metadata().ok()?;
        metadata.is_file().then_some(canonical)
    })
}

async fn probe_version(executable: &Path) -> Option<Version> {
    let args = [std::ffi::OsString::from("--version")];
    let current_directory = env::temp_dir();
    let output = run_process(executable, &args, &current_directory, None)
        .await
        .ok()?;
    if !output.success {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_version_from_text(&text).or_else(|| {
        let text = String::from_utf8_lossy(&output.stderr);
        parse_version_from_text(&text)
    })
}

fn parse_version_from_text(text: &str) -> Option<Version> {
    text.split(|character: char| {
        !(character.is_ascii_alphanumeric() || matches!(character, '.' | '+' | '-'))
    })
    .filter_map(|token| {
        let token = token.trim_start_matches('v');
        token
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_digit)
            .then_some(token)
    })
    .find_map(|token| Version::parse(token).ok())
}

pub(crate) fn managed_executable_path(
    root: &Path,
    engine: EngineKind,
) -> Result<Option<PathBuf>, ScannerError> {
    let Some(platform) = platform_key() else {
        return Ok(None);
    };
    let Some(tool) = pinned_tool(engine)? else {
        return Ok(None);
    };
    if !tool.downloads.contains_key(&platform) {
        return Ok(None);
    }
    Ok(Some(
        root.join("scanners")
            .join(engine.as_str())
            .join(tool.version)
            .join(engine.executable_name()),
    ))
}

pub(crate) fn executable_search_paths() -> Vec<PathBuf> {
    env::var_os("PATH")
        .map(|path| env::split_paths(&path).collect())
        .unwrap_or_default()
}

#[cfg(test)]
pub(crate) fn parse_version_for_test(text: &str) -> Option<Version> {
    parse_version_from_text(text)
}
