use std::{
    fs::{self, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
};

#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;

use serde::Deserialize;
use thiserror::Error;

const CONFIG_PATH: &str = "/etc/secmon/agent.toml";
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_ALLOWLISTED_PATHS: usize = 64;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    #[serde(default)]
    pub allowed_paths: Vec<PathBuf>,
    #[serde(default)]
    pub docker_cli_approved: bool,
    #[serde(default = "default_process_limit")]
    pub max_processes: usize,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            allowed_paths: Vec::new(),
            docker_cli_approved: false,
            max_processes: default_process_limit(),
        }
    }
}

fn default_process_limit() -> usize {
    4096
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("agent configuration is missing")]
    Missing,
    #[error("agent configuration is not a regular file")]
    InvalidFile,
    #[error("agent configuration exceeds the size limit")]
    TooLarge,
    #[error("agent configuration is invalid")]
    InvalidFormat,
    #[error("an allowlisted path is invalid")]
    PathInvalid,
}

#[derive(Debug)]
pub struct LoadedConfig {
    pub config: AgentConfig,
    pub diagnostic: Option<ConfigDiagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigDiagnostic {
    Missing,
    Invalid,
    PathInvalid,
}

impl AgentConfig {
    pub fn load_default() -> LoadedConfig {
        match Self::load_from(Path::new(CONFIG_PATH)) {
            Ok(config) => LoadedConfig {
                config,
                diagnostic: None,
            },
            Err(ConfigError::Missing) => LoadedConfig {
                config: Self::default(),
                diagnostic: Some(ConfigDiagnostic::Missing),
            },
            Err(ConfigError::PathInvalid) => LoadedConfig {
                config: Self::default(),
                diagnostic: Some(ConfigDiagnostic::PathInvalid),
            },
            Err(ConfigError::InvalidFile | ConfigError::TooLarge | ConfigError::InvalidFormat) => {
                LoadedConfig {
                    config: Self::default(),
                    diagnostic: Some(ConfigDiagnostic::Invalid),
                }
            }
        }
    }

    pub fn load_from(path: &Path) -> Result<Self, ConfigError> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ConfigError::Missing);
            }
            Err(_) => return Err(ConfigError::InvalidFile),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ConfigError::InvalidFile);
        }
        if metadata.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge);
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(target_os = "linux")]
        options.custom_flags(libc::O_NOFOLLOW);
        let file = options.open(path).map_err(|_| ConfigError::InvalidFile)?;
        let metadata = file.metadata().map_err(|_| ConfigError::InvalidFile)?;
        if !metadata.is_file() {
            return Err(ConfigError::InvalidFile);
        }
        if metadata.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge);
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ConfigError::InvalidFile)?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge);
        }
        let text = String::from_utf8(bytes).map_err(|_| ConfigError::InvalidFile)?;
        let mut config: Self = toml::from_str(&text).map_err(|_| ConfigError::InvalidFormat)?;
        if config.allowed_paths.len() > MAX_ALLOWLISTED_PATHS
            || !(1..=8192).contains(&config.max_processes)
        {
            return Err(ConfigError::InvalidFormat);
        }
        let mut canonical_paths = Vec::with_capacity(config.allowed_paths.len());
        for path in &config.allowed_paths {
            let canonical = path.canonicalize().map_err(|_| ConfigError::PathInvalid)?;
            if !canonical.is_dir() || canonical_paths.contains(&canonical) {
                return Err(ConfigError::PathInvalid);
            }
            canonical_paths.push(canonical);
        }
        config.allowed_paths = canonical_paths;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::{AgentConfig, ConfigDiagnostic};

    static NEXT_TEMP_PATH: AtomicUsize = AtomicUsize::new(0);

    fn temp_path(label: &str) -> PathBuf {
        let safe_label = label
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>();
        let sequence = NEXT_TEMP_PATH.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "secmon-agent-{safe_label}-{}-{sequence}",
            std::process::id()
        ))
    }

    #[test]
    fn missing_config_is_partial_default_and_docker_stays_disabled() {
        let loaded = AgentConfig::load_default();
        assert!(!loaded.config.docker_cli_approved);
        assert_eq!(loaded.config.max_processes, 4096);
        assert_eq!(loaded.diagnostic, Some(ConfigDiagnostic::Missing));
    }

    #[test]
    fn configured_paths_are_canonicalized_and_duplicate_paths_rejected() {
        let root = temp_path("config-paths");
        fs::create_dir_all(&root).expect("temp dir");
        let file = root.join("agent.toml");
        let escaped_root = root.to_string_lossy().replace('\\', "\\\\");
        let config_text =
            format!("allowed_paths = [\"{escaped_root}\"]\ndocker_cli_approved = false\n");
        fs::write(&file, &config_text).expect("config write");
        let loaded = AgentConfig::load_from(&file).expect("valid config");
        assert_eq!(
            loaded.allowed_paths,
            vec![root.canonicalize().expect("canonical")]
        );
        fs::write(
            &file,
            format!("allowed_paths = [\"{escaped_root}\", \"{escaped_root}\"]\n"),
        )
        .expect("config write");
        assert!(AgentConfig::load_from(&file).is_err());
        fs::remove_dir_all(root).expect("cleanup");
    }
}
