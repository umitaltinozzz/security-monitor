use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use chrono::{DateTime, Utc};
pub use security_monitor_core::AgentCliProduct;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};
use ts_rs::TS;
use uuid::Uuid;

const DEFAULT_PROCESS_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const MAX_AGENT_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_TEST_OUTPUT_BYTES: usize = 256 * 1024;
const WORKTREE_BRANCH_PREFIX: &str = "secmon/remediation-";
const DOCKER: &str = "docker";
const PODMAN: &str = "podman";
const MAX_MCP_REQUEST_BYTES: u64 = 8 * 1024;
const MAX_MCP_REQUESTS: usize = 200;
const MAX_WORKTREE_ENTRIES: usize = 250_000;
const AGENT_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "CODEX_HOME",
    "CLAUDE_CONFIG_DIR",
    "LANG",
    "LC_ALL",
    "TERM",
];
const UNSAFE_AGENT_CONFIG_NAMES: &[&str] = &[
    ".claude",
    ".mcp.json",
    ".codex",
    ".agents",
    "claude.md",
    "agents.md",
    "agents.override.md",
    "opencode.json",
    "opencode.jsonc",
    ".opencode",
];
pub(crate) const OPENCODE_POLICY: &str = r#"{
  "$schema": "https://opencode.ai/config.json",
  "permission": {
    "*": "deny",
    "read": "allow",
    "edit": "allow",
    "glob": "allow",
    "grep": "allow",
    "list": "allow",
    "external_directory": "deny",
    "bash": "deny",
    "task": "deny",
    "todowrite": "deny",
    "todoread": "deny",
    "webfetch": "deny",
    "websearch": "deny",
    "question": "deny",
    "lsp": "deny",
    "skill": "deny",
    "doom_loop": "deny"
  },
  "agent": {
    "secmon-remediation": {
      "mode": "primary",
      "permission": {
        "*": "deny",
        "read": "allow",
        "edit": "allow",
        "glob": "allow",
        "grep": "allow",
        "list": "allow",
        "external_directory": "deny"
      }
    }
  }
}"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum SandboxEngine {
    Docker,
    Podman,
}

impl SandboxEngine {
    fn executable(self) -> &'static str {
        match self {
            Self::Docker => DOCKER,
            Self::Podman => PODMAN,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeTestCommand {
    pub executable: String,
    pub args: Vec<String>,
    /// A local, already-present OCI image pinned by digest. Pulling is disabled.
    pub image: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessResult {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub output_truncated: bool,
    pub output: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedWorktree {
    pub id: String,
    pub repository_root: PathBuf,
    pub worktree_path: PathBuf,
    pub branch: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorktreeDiff {
    pub sha256: String,
    pub has_changes: bool,
}

#[derive(Debug, Error)]
pub enum RemediationError {
    #[error("repository path is invalid")]
    InvalidRepository,
    #[error("repository has uncommitted changes")]
    RepositoryNotClean,
    #[error("worktree path is outside the remediation directory")]
    WorktreePathInvalid,
    #[error("agent source transfer approval is required")]
    SourceTransferApprovalRequired,
    #[error("agent network access approval is required")]
    NetworkApprovalRequired,
    #[error("agent remediation requires an operating system sandbox")]
    AgentSandboxUnavailable,
    #[error("project agent configuration must be reviewed before launching an agent")]
    AgentProjectConfigPresent,
    #[error("repository Git filters cannot run in remediation worktrees")]
    GitFiltersNotAllowed,
    #[error("test execution approval is required")]
    ExecuteApprovalRequired,
    #[error("sandbox engine is unavailable")]
    SandboxUnavailable,
    #[error("test image must be pinned by digest and already available locally")]
    InvalidImage,
    #[error("test command cannot launch a command interpreter")]
    ShellNotAllowed,
    #[error("test command is invalid")]
    InvalidTestCommand,
    #[error("process operation failed")]
    ProcessFailed,
    #[error("worktree operation failed")]
    WorktreeFailed,
    #[error("process exceeded its time limit")]
    TimedOut,
    #[error("filesystem operation failed")]
    FilesystemFailed,
}

impl std::fmt::Debug for ProcessResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProcessResult")
            .field("exit_code", &self.exit_code)
            .field("timed_out", &self.timed_out)
            .field("output_truncated", &self.output_truncated)
            .finish()
    }
}

pub fn parse_agent_cli_product(value: &str) -> Option<AgentCliProduct> {
    match value {
        "claude_code" => Some(AgentCliProduct::ClaudeCode),
        "codex" => Some(AgentCliProduct::Codex),
        "opencode" => Some(AgentCliProduct::OpenCode),
        _ => None,
    }
}

pub fn validate_safe_test(command: &SafeTestCommand) -> Result<(), RemediationError> {
    let executable = command.executable.to_ascii_lowercase();
    if matches!(
        executable.as_str(),
        "sh" | "bash"
            | "dash"
            | "zsh"
            | "fish"
            | "cmd"
            | "cmd.exe"
            | "powershell"
            | "powershell.exe"
            | "pwsh"
            | "pwsh.exe"
    ) {
        return Err(RemediationError::ShellNotAllowed);
    }
    if !matches!(
        executable.as_str(),
        "cargo"
            | "go"
            | "pytest"
            | "python"
            | "python3"
            | "phpunit"
            | "dotnet"
            | "gradle"
            | "mvn"
            | "npm"
            | "pnpm"
            | "yarn"
            | "bun"
            | "composer"
            | "make"
    ) || command.executable.trim().is_empty()
        || command.executable.len() > 128
        || command.args.len() > 64
        || command.args.iter().any(|arg| arg.len() > 4096)
        || command.image.len() > 255
        || command.image.chars().any(char::is_whitespace)
    {
        return Err(RemediationError::InvalidTestCommand);
    }
    if !valid_pinned_image(&command.image) {
        return Err(RemediationError::InvalidImage);
    }
    Ok(())
}

fn valid_pinned_image(image: &str) -> bool {
    let valid_digest =
        |value: &str| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    if let Some(digest) = image.strip_prefix("sha256:") {
        return valid_digest(digest);
    }
    let Some((name, digest)) = image.split_once("@sha256:") else {
        return false;
    };
    !name.is_empty()
        && !name.starts_with('-')
        && !name.ends_with('/')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
        && valid_digest(digest)
}

mod agent;
mod git_safety;
mod mcp;
mod process;
mod sandbox;
#[cfg(test)]
mod tests;
mod workspace_tools;
mod worktree;

#[cfg(test)]
pub(crate) use agent::ScopedOpenCodePolicy;
pub use agent::{agent_cli_executable, agent_sandbox_available, run_agent_cli};
pub(crate) use git_safety::contains_symlink;
pub use git_safety::{GitCommandSafety, validate_worktree_under};
pub use mcp::{
    ApprovalRequest, McpRemediationAction, McpRemediationRequest, list_mcp_remediation_requests,
    remove_mcp_remediation_request, write_mcp_remediation_request,
};
pub(crate) use process::{capture_child, path_arg, run_command, run_git_command};
#[cfg(all(test, target_os = "linux"))]
pub(crate) use sandbox::remove_sandbox_temp;
pub use sandbox::{
    available_engine, build_test_args, engine_available, run_sandbox_test, sandbox_executable,
};
pub use workspace_tools::{RemediationWorkspaceExecutor, remediation_workspace_tools};
pub(crate) use worktree::canonical_worktrees_directory;
pub use worktree::{
    create_worktree, create_worktree_with_id, remove_worktree, worktree_diff, worktrees_directory,
};
