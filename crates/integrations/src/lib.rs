use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Component as PathComponent, Path, PathBuf},
};

use security_monitor_agent_transport::CredentialStore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Agent {
    ClaudeCode,
    Codex,
    Opencode,
}

impl Agent {
    pub fn display_name(self) -> Result<String, IntegrationError> {
        Ok(common::agent_spec(self)?.display_name)
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "claude-code" => Some(Self::ClaudeCode),
            "codex" => Some(Self::Codex),
            "opencode" => Some(Self::Opencode),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::Opencode => "opencode",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    User,
    Project,
}

impl Scope {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "project" => Some(Self::Project),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Project => "project",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedChange {
    pub relative_path: PathBuf,
    pub before: Option<Vec<u8>>,
    pub after: Vec<u8>,
    pub description: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IntegrationPlan {
    pub changes: Vec<PlannedChange>,
}

impl IntegrationPlan {
    pub fn diff(&self, agent: Agent) -> String {
        if self.changes.is_empty() {
            return format!(
                "{} is already integrated; no files would change.\n",
                agent.as_str()
            );
        }
        let mut output = String::new();
        for change in &self.changes {
            output.push_str(&format!(
                "--- a/{}\n+++ b/{}\n@@\n# {}\n",
                change.relative_path.display(),
                change.relative_path.display(),
                change.description
            ));
            if let Some(before) = change.before.as_deref() {
                for line in String::from_utf8_lossy(before).lines() {
                    output.push('-');
                    output.push_str(&redact_diff_line(line));
                    output.push('\n');
                }
            }
            for line in String::from_utf8_lossy(&change.after).lines() {
                output.push('+');
                output.push_str(&redact_diff_line(line));
                output.push('\n');
            }
        }
        output
    }
}

fn redact_diff_line(line: &str) -> String {
    let Some((key, _)) = line.split_once(['=', ':']) else {
        return line.to_owned();
    };
    let key = key
        .trim()
        .trim_matches(['"', '\'', '[', ']', '{', '}', ' '])
        .to_ascii_lowercase();
    if [
        "key",
        "api_key",
        "token",
        "secret",
        "password",
        "client_secret",
    ]
    .iter()
    .any(|marker| key.contains(marker))
    {
        format!("{key} = \"[REDACTED]\"")
    } else {
        line.to_owned()
    }
}

#[derive(Debug, Error)]
pub enum IntegrationError {
    #[error("integration configuration is invalid")]
    InvalidConfiguration,
    #[error("agent or scope is not supported")]
    Unsupported,
    #[error("project scope requires an existing project directory")]
    ProjectRequired,
    #[error("configuration file is invalid or conflicts with a different secmon entry")]
    Conflict,
    #[error("integration is already installed")]
    AlreadyInstalled,
    #[error("integration is not installed")]
    NotInstalled,
    #[error(
        "integration files changed after installation; remove them manually or restore the recorded version"
    )]
    ModifiedAfterInstall,
    #[error("integration state could not be read or written")]
    StateUnavailable,
    #[error("OS credential store could not preserve the original configuration")]
    BackupUnavailable,
    #[error("filesystem operation failed")]
    Io(#[source] std::io::Error),
    #[error("integration state serialization failed")]
    Serialization(#[source] serde_json::Error),
}

mod claude;
mod codex;
mod common;
mod opencode;
mod service;
#[cfg(test)]
mod tests;
mod uninstall;

pub(crate) use common::*;
#[cfg(test)]
pub(crate) use opencode::OPENCODE_PLUGIN;
pub use service::IntegrationService;
