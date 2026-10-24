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
    time::timeout,
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
const OPENCODE_POLICY: &str = r#"{
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

fn agent_executable(product: AgentCliProduct) -> &'static str {
    match product {
        AgentCliProduct::ClaudeCode => "claude",
        AgentCliProduct::Codex => "codex",
        AgentCliProduct::OpenCode => "opencode",
    }
}

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
    #[error("OpenCode project configuration must be reviewed before launching its agent")]
    OpenCodeProjectConfigPresent,
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
    let digest = command
        .image
        .strip_prefix("sha256:")
        .or_else(|| command.image.split_once("@sha256:").map(|(_, value)| value));
    if !digest.is_some_and(|value| {
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) {
        return Err(RemediationError::InvalidImage);
    }
    Ok(())
}

pub fn build_test_args(
    engine: SandboxEngine,
    worktree_path: &Path,
    container_name: &str,
    command: &SafeTestCommand,
) -> Result<Vec<OsString>, RemediationError> {
    validate_safe_test(command)?;
    if container_name.is_empty()
        || container_name.len() > 80
        || !container_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(RemediationError::InvalidTestCommand);
    }
    let worktree =
        fs::canonicalize(worktree_path).map_err(|_| RemediationError::WorktreePathInvalid)?;
    if !worktree.is_dir() || worktree.to_string_lossy().contains(',') {
        return Err(RemediationError::WorktreePathInvalid);
    }
    let mut args = vec![
        OsString::from("run"),
        OsString::from("--rm"),
        OsString::from("--pull=never"),
        OsString::from("--network=none"),
        OsString::from("--read-only"),
        OsString::from("--cpus=1"),
        OsString::from("--memory=1g"),
        OsString::from("--pids-limit=128"),
        OsString::from("--cap-drop=ALL"),
        OsString::from("--security-opt=no-new-privileges"),
        OsString::from(format!("--name={container_name}")),
        OsString::from("--mount"),
        OsString::from(format!(
            "type=bind,src={},dst=/workspace,rw",
            path_arg(&worktree)?
        )),
        OsString::from("--workdir=/workspace"),
        OsString::from("--env=TMPDIR=/workspace/.secmon-tmp"),
        OsString::from(command.image.as_str()),
        OsString::from(command.executable.as_str()),
    ];
    args.extend(command.args.iter().map(OsString::from));
    let _ = engine;
    Ok(args)
}

pub fn sandbox_executable(engine: SandboxEngine) -> &'static str {
    engine.executable()
}

pub fn worktrees_directory(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("worktrees")
}

pub async fn create_worktree(
    repository_path: &Path,
    app_data_dir: &Path,
) -> Result<PreparedWorktree, RemediationError> {
    create_worktree_with_id(repository_path, app_data_dir, &Uuid::new_v4().to_string()).await
}

pub async fn create_worktree_with_id(
    repository_path: &Path,
    app_data_dir: &Path,
    id: &str,
) -> Result<PreparedWorktree, RemediationError> {
    Uuid::parse_str(id).map_err(|_| RemediationError::WorktreePathInvalid)?;
    let repository =
        fs::canonicalize(repository_path).map_err(|_| RemediationError::InvalidRepository)?;
    if !repository.is_dir() {
        return Err(RemediationError::InvalidRepository);
    }
    let top_level = run_git_command(
        &["-C", path_arg(&repository)?, "rev-parse", "--show-toplevel"],
        Duration::from_secs(15),
        MAX_TEST_OUTPUT_BYTES,
    )
    .await?;
    let root = PathBuf::from(String::from_utf8_lossy(&top_level.0).trim());
    let root = fs::canonicalize(root).map_err(|_| RemediationError::InvalidRepository)?;
    if contains_symlink(&root)? {
        return Err(RemediationError::WorktreePathInvalid);
    }
    let git_dir_output = run_git_command(
        &["-C", path_arg(&root)?, "rev-parse", "--absolute-git-dir"],
        Duration::from_secs(15),
        MAX_TEST_OUTPUT_BYTES,
    )
    .await?;
    let git_dir = fs::canonicalize(String::from_utf8_lossy(&git_dir_output.0).trim())
        .map_err(|_| RemediationError::InvalidRepository)?;
    if has_git_filter_attributes(&root, &git_dir)? {
        return Err(RemediationError::GitFiltersNotAllowed);
    }
    let status = run_git_command(
        &[
            "-C",
            path_arg(&root)?,
            "status",
            "--porcelain",
            "--untracked-files=all",
        ],
        Duration::from_secs(15),
        MAX_TEST_OUTPUT_BYTES,
    )
    .await?;
    if !status.0.is_empty() {
        return Err(RemediationError::RepositoryNotClean);
    }

    let canonical_directory = canonical_worktrees_directory(app_data_dir)?;
    let branch = format!("{WORKTREE_BRANCH_PREFIX}{id}");
    let path = canonical_directory.join(id);
    if !path.starts_with(&canonical_directory) {
        return Err(RemediationError::WorktreePathInvalid);
    }
    run_git_command(
        &[
            "-C",
            path_arg(&root)?,
            "worktree",
            "add",
            "-b",
            &branch,
            path_arg(&path)?,
            "HEAD",
        ],
        Duration::from_secs(60),
        MAX_TEST_OUTPUT_BYTES,
    )
    .await?;
    let canonical_worktree =
        fs::canonicalize(&path).map_err(|_| RemediationError::WorktreeFailed)?;
    if !canonical_worktree.starts_with(&canonical_directory)
        || contains_symlink(&canonical_worktree)?
    {
        let _ = remove_worktree(&root, &canonical_worktree).await;
        return Err(RemediationError::WorktreePathInvalid);
    }
    Ok(PreparedWorktree {
        id: id.to_owned(),
        repository_root: root,
        worktree_path: canonical_worktree,
        branch,
    })
}

pub async fn remove_worktree(
    repository_root: &Path,
    worktree_path: &Path,
) -> Result<(), RemediationError> {
    let root =
        fs::canonicalize(repository_root).map_err(|_| RemediationError::InvalidRepository)?;
    let worktree =
        fs::canonicalize(worktree_path).map_err(|_| RemediationError::WorktreePathInvalid)?;
    run_git_command(
        &[
            "-C",
            path_arg(&root)?,
            "worktree",
            "remove",
            "--force",
            path_arg(&worktree)?,
        ],
        Duration::from_secs(60),
        MAX_TEST_OUTPUT_BYTES,
    )
    .await?;
    Ok(())
}

pub async fn worktree_diff(worktree_path: &Path) -> Result<WorktreeDiff, RemediationError> {
    let worktree =
        fs::canonicalize(worktree_path).map_err(|_| RemediationError::WorktreePathInvalid)?;
    if !worktree.is_dir() || contains_symlink(&worktree)? {
        return Err(RemediationError::WorktreePathInvalid);
    }
    let git_dir_output = run_git_command(
        &[
            "-C",
            path_arg(&worktree)?,
            "rev-parse",
            "--absolute-git-dir",
        ],
        Duration::from_secs(15),
        MAX_TEST_OUTPUT_BYTES,
    )
    .await?;
    let git_dir = fs::canonicalize(String::from_utf8_lossy(&git_dir_output.0).trim())
        .map_err(|_| RemediationError::WorktreePathInvalid)?;
    if has_git_filter_attributes(&worktree, &git_dir)? {
        return Err(RemediationError::GitFiltersNotAllowed);
    }
    let diff = run_git_command(
        &[
            "-C",
            path_arg(&worktree)?,
            "diff",
            "--binary",
            "--no-ext-diff",
            "--no-textconv",
            "HEAD",
        ],
        Duration::from_secs(30),
        MAX_AGENT_OUTPUT_BYTES,
    )
    .await?;
    if diff.1 {
        return Err(RemediationError::WorktreePathInvalid);
    }
    let untracked = run_git_command(
        &["-C", path_arg(&worktree)?, "ls-files", "--others", "-z"],
        Duration::from_secs(30),
        MAX_AGENT_OUTPUT_BYTES,
    )
    .await?;
    if untracked.1 {
        return Err(RemediationError::WorktreePathInvalid);
    }
    let mut hash = Sha256::new();
    hash.update(&diff.0);
    let mut untracked_count = 0usize;
    let mut untracked_bytes = 0usize;
    for path_bytes in untracked
        .0
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let relative = path_from_git_bytes(path_bytes)?;
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(RemediationError::WorktreePathInvalid);
        }
        let file_path = worktree.join(&relative);
        let metadata =
            fs::symlink_metadata(&file_path).map_err(|_| RemediationError::FilesystemFailed)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(RemediationError::WorktreePathInvalid);
        }
        let canonical =
            fs::canonicalize(&file_path).map_err(|_| RemediationError::WorktreePathInvalid)?;
        if !canonical.starts_with(&worktree) {
            return Err(RemediationError::WorktreePathInvalid);
        }
        untracked_bytes = untracked_bytes.saturating_add(metadata.len() as usize);
        if untracked_bytes > MAX_AGENT_OUTPUT_BYTES {
            return Err(RemediationError::WorktreePathInvalid);
        }
        let contents = fs::read(&canonical).map_err(|_| RemediationError::FilesystemFailed)?;
        hash.update((path_bytes.len() as u64).to_le_bytes());
        hash.update(path_bytes);
        hash.update((contents.len() as u64).to_le_bytes());
        hash.update(contents);
        untracked_count = untracked_count.saturating_add(1);
        if untracked_count > MAX_WORKTREE_ENTRIES {
            return Err(RemediationError::WorktreePathInvalid);
        }
    }
    Ok(WorktreeDiff {
        sha256: format!("{:x}", hash.finalize()),
        has_changes: !diff.0.is_empty() || untracked_count > 0,
    })
}

fn path_from_git_bytes(bytes: &[u8]) -> Result<PathBuf, RemediationError> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
    }
    #[cfg(windows)]
    {
        let path = std::str::from_utf8(bytes).map_err(|_| RemediationError::WorktreePathInvalid)?;
        Ok(PathBuf::from(path))
    }
}

fn has_git_filter_attributes(root: &Path, git_dir: &Path) -> Result<bool, RemediationError> {
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).map_err(|_| RemediationError::FilesystemFailed)? {
            visited = visited.saturating_add(1);
            if visited > MAX_WORKTREE_ENTRIES {
                return Err(RemediationError::WorktreePathInvalid);
            }
            let entry = entry.map_err(|_| RemediationError::FilesystemFailed)?;
            let file_type = entry
                .file_type()
                .map_err(|_| RemediationError::FilesystemFailed)?;
            if file_type.is_symlink() {
                return Err(RemediationError::WorktreePathInvalid);
            }
            if file_type.is_dir() {
                if entry.file_name() != ".git" {
                    pending.push(entry.path());
                }
            } else if entry.file_name() == ".gitattributes"
                && file_has_filter_attribute(&entry.path())?
            {
                return Ok(true);
            }
        }
    }
    let info_attributes = git_dir.join("info").join("attributes");
    if info_attributes.exists() && file_has_filter_attribute(&info_attributes)? {
        return Ok(true);
    }
    Ok(false)
}

fn file_has_filter_attribute(path: &Path) -> Result<bool, RemediationError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RemediationError::FilesystemFailed)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 1024 * 1024 {
        return Err(RemediationError::GitFiltersNotAllowed);
    }
    let contents = fs::read(path).map_err(|_| RemediationError::FilesystemFailed)?;
    for line in contents.split(|byte| *byte == b'\n') {
        let line = line.trim_ascii();
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        let mut fields = line
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty());
        let _pattern = fields.next();
        if fields.any(|field| {
            let field = field
                .strip_prefix(b"!")
                .or_else(|| field.strip_prefix(b"-"))
                .unwrap_or(field);
            field.split(|byte| *byte == b'=').next() == Some(b"filter".as_slice())
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub async fn run_agent_cli(
    product: AgentCliProduct,
    worktree_path: &Path,
    prompt: &str,
    source_transfer_approved: bool,
) -> Result<ProcessResult, RemediationError> {
    if !source_transfer_approved {
        return Err(RemediationError::SourceTransferApprovalRequired);
    }
    let worktree =
        fs::canonicalize(worktree_path).map_err(|_| RemediationError::WorktreePathInvalid)?;
    if !worktree.is_dir()
        || contains_symlink(&worktree)?
        || prompt.trim().is_empty()
        || prompt.len() > 32_768
    {
        return Err(RemediationError::InvalidTestCommand);
    }
    let mut command = Command::new(agent_executable(product));
    command.current_dir(&worktree).kill_on_drop(true);
    let _opencode_policy = if product == AgentCliProduct::OpenCode {
        Some(ScopedOpenCodePolicy::create(&worktree)?)
    } else {
        None
    };
    match product {
        AgentCliProduct::ClaudeCode => {
            command.args([
                "--print",
                "--restricted",
                "--safe-mode",
                "--permission-mode",
                "acceptEdits",
                "--tools",
                "Read,Edit,Write,Glob,Grep",
                "--disallowedTools",
                "mcp__*",
                "--max-turns",
                "3",
            ]);
            command.arg(prompt);
        }
        AgentCliProduct::Codex => {
            command.args([
                "exec",
                "--sandbox",
                "workspace-write",
                "--ask-for-approval",
                "on-request",
                "-",
            ]);
            command.stdin(Stdio::piped());
        }
        AgentCliProduct::OpenCode => {
            let policy = _opencode_policy
                .as_ref()
                .ok_or(RemediationError::ProcessFailed)?;
            command.env("OPENCODE_CONFIG", &policy.path).args([
                "run",
                "--agent",
                "secmon-remediation",
            ]);
            command.arg(prompt);
        }
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|_| RemediationError::ProcessFailed)?;
    if product == AgentCliProduct::Codex {
        let mut stdin = child.stdin.take().ok_or(RemediationError::ProcessFailed)?;
        stdin
            .write_all(prompt.as_bytes())
            .await
            .map_err(|_| RemediationError::ProcessFailed)?;
    }
    let output = capture_child(child, DEFAULT_PROCESS_TIMEOUT, MAX_AGENT_OUTPUT_BYTES).await?;
    Ok(ProcessResult {
        exit_code: output.exit_code,
        timed_out: false,
        output_truncated: output.output_truncated,
    })
}

pub async fn run_sandbox_test(
    engine: SandboxEngine,
    worktree_path: &Path,
    command: &SafeTestCommand,
    execute_approved: bool,
) -> Result<ProcessResult, RemediationError> {
    if !execute_approved {
        return Err(RemediationError::ExecuteApprovalRequired);
    }
    validate_safe_test(command)?;
    let worktree =
        fs::canonicalize(worktree_path).map_err(|_| RemediationError::WorktreePathInvalid)?;
    if contains_symlink(&worktree)? {
        return Err(RemediationError::WorktreePathInvalid);
    }
    if !engine_available(engine).await {
        return Err(RemediationError::SandboxUnavailable);
    }
    let container_name = format!("secmon-test-{}", Uuid::new_v4().simple());
    let args = build_test_args(engine, &worktree, &container_name, command)?;
    fs::create_dir(worktree.join(".secmon-tmp")).map_err(|_| RemediationError::FilesystemFailed)?;
    let command_args = args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let mut process = Command::new(engine.executable());
    process.args(&command_args).kill_on_drop(true);
    process.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = match process.spawn() {
        Ok(child) => child,
        Err(_) => {
            remove_sandbox_temp(&worktree)?;
            return Err(RemediationError::ProcessFailed);
        }
    };
    let result = match capture_child(child, DEFAULT_PROCESS_TIMEOUT, MAX_TEST_OUTPUT_BYTES).await {
        Ok(output) => Ok(ProcessResult {
            exit_code: output.exit_code,
            timed_out: false,
            output_truncated: output.output_truncated,
        }),
        Err(RemediationError::TimedOut) => {
            let _ = run_command(
                engine.executable(),
                &["stop", "--time", "1", &container_name],
                None,
                Duration::from_secs(5),
                1024,
            )
            .await;
            let _ = run_command(
                engine.executable(),
                &["rm", "--force", &container_name],
                None,
                Duration::from_secs(5),
                1024,
            )
            .await;
            Ok(ProcessResult {
                exit_code: None,
                timed_out: true,
                output_truncated: false,
            })
        }
        Err(error) => Err(error),
    };
    remove_sandbox_temp(&worktree)?;
    result
}

pub async fn engine_available(engine: SandboxEngine) -> bool {
    run_command(
        engine.executable(),
        &["version", "--format", "{{.Server.Version}}"],
        None,
        Duration::from_secs(5),
        1024,
    )
    .await
    .is_ok()
}

pub async fn available_engine() -> Option<SandboxEngine> {
    if engine_available(SandboxEngine::Docker).await {
        Some(SandboxEngine::Docker)
    } else if engine_available(SandboxEngine::Podman).await {
        Some(SandboxEngine::Podman)
    } else {
        None
    }
}

async fn run_command(
    executable: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    limit: Duration,
    max_output: usize,
) -> Result<(Vec<u8>, bool), RemediationError> {
    run_command_with_git_safety(executable, args, stdin, limit, max_output, None).await
}

async fn run_git_command(
    args: &[&str],
    limit: Duration,
    max_output: usize,
) -> Result<(Vec<u8>, bool), RemediationError> {
    let safety = GitCommandSafety::create()?;
    run_command_with_git_safety("git", args, None, limit, max_output, Some(&safety)).await
}

async fn run_command_with_git_safety(
    executable: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    limit: Duration,
    max_output: usize,
    git_safety: Option<&GitCommandSafety>,
) -> Result<(Vec<u8>, bool), RemediationError> {
    let mut command = Command::new(executable);
    command.args(args).kill_on_drop(true);
    if let Some(safety) = git_safety {
        safety.configure(&mut command);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command
        .spawn()
        .map_err(|_| RemediationError::ProcessFailed)?;
    if let Some(input) = stdin {
        let mut writer = child.stdin.take().ok_or(RemediationError::ProcessFailed)?;
        writer
            .write_all(input)
            .await
            .map_err(|_| RemediationError::ProcessFailed)?;
    }
    let output = capture_child(child, limit, max_output).await?;
    if output.exit_code != Some(0) {
        return Err(RemediationError::WorktreeFailed);
    }
    Ok((output.stdout, output.output_truncated))
}

struct GitCommandSafety {
    directory: PathBuf,
    hooks_directory: PathBuf,
    empty_file: PathBuf,
}

impl GitCommandSafety {
    fn create() -> Result<Self, RemediationError> {
        let directory =
            std::env::temp_dir().join(format!("secmon-git-safe-{}", Uuid::new_v4().simple()));
        fs::create_dir(&directory).map_err(|_| RemediationError::FilesystemFailed)?;
        let hooks_directory = directory.join("hooks");
        let empty_file = directory.join("empty");
        if fs::create_dir(&hooks_directory).is_err()
            || OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&empty_file)
                .is_err()
        {
            let _ = fs::remove_dir_all(&directory);
            return Err(RemediationError::FilesystemFailed);
        }
        Ok(Self {
            directory,
            hooks_directory,
            empty_file,
        })
    }

    fn configure(&self, command: &mut Command) {
        command
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", &self.empty_file)
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_CONFIG_COUNT", "3")
            .env("GIT_CONFIG_KEY_0", "core.hooksPath")
            .env("GIT_CONFIG_VALUE_0", &self.hooks_directory)
            .env("GIT_CONFIG_KEY_1", "core.fsmonitor")
            .env("GIT_CONFIG_VALUE_1", "false")
            .env("GIT_CONFIG_KEY_2", "core.attributesFile")
            .env("GIT_CONFIG_VALUE_2", &self.empty_file)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env_remove("GIT_CONFIG_PARAMETERS")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_COMMON_DIR")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_OBJECT_DIRECTORY")
            .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
            .env_remove("GIT_PREFIX")
            .env_remove("GIT_EXTERNAL_DIFF");
    }
}

impl Drop for GitCommandSafety {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

struct CapturedProcess {
    stdout: Vec<u8>,
    exit_code: Option<i32>,
    output_truncated: bool,
}

async fn capture_child(
    mut child: tokio::process::Child,
    limit: Duration,
    max_output: usize,
) -> Result<CapturedProcess, RemediationError> {
    let stdout = child.stdout.take().ok_or(RemediationError::ProcessFailed)?;
    let stderr = child.stderr.take().ok_or(RemediationError::ProcessFailed)?;
    let capture = async {
        let stdout_reader = async {
            let mut bytes = Vec::new();
            stdout
                .take(max_output.saturating_add(1) as u64)
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| RemediationError::ProcessFailed)?;
            Ok::<_, RemediationError>(bytes)
        };
        let stderr_reader = async {
            let mut bytes = Vec::new();
            stderr
                .take(max_output.saturating_add(1) as u64)
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| RemediationError::ProcessFailed)?;
            Ok::<_, RemediationError>(bytes)
        };
        let status_wait = async {
            child
                .wait()
                .await
                .map_err(|_| RemediationError::ProcessFailed)
        };
        let (mut stdout, stderr, status) =
            tokio::try_join!(stdout_reader, stderr_reader, status_wait)
                .map_err(|_| RemediationError::ProcessFailed)?;
        let truncated = stdout.len().saturating_add(stderr.len()) > max_output;
        stdout.truncate(max_output);
        Ok::<_, RemediationError>((stdout, status.code(), truncated))
    };
    match timeout(limit, capture).await {
        Ok(result) => {
            let (stdout, exit_code, output_truncated) = result?;
            Ok(CapturedProcess {
                stdout,
                exit_code,
                output_truncated,
            })
        }
        Err(_) => Err(RemediationError::TimedOut),
    }
}

fn path_arg(path: &Path) -> Result<&str, RemediationError> {
    let value = path.to_str().ok_or(RemediationError::WorktreePathInvalid)?;
    if value.starts_with("\\\\?\\UNC\\") {
        return Err(RemediationError::WorktreePathInvalid);
    }
    Ok(value.strip_prefix("\\\\?\\").unwrap_or(value))
}

pub fn validate_worktree_under(
    app_data_dir: &Path,
    worktree_path: &Path,
) -> Result<PathBuf, RemediationError> {
    let canonical_root = canonical_worktrees_directory(app_data_dir)?;
    let canonical_worktree =
        fs::canonicalize(worktree_path).map_err(|_| RemediationError::WorktreePathInvalid)?;
    if !canonical_worktree.starts_with(&canonical_root)
        || !canonical_worktree.is_dir()
        || contains_symlink(&canonical_worktree)?
    {
        return Err(RemediationError::WorktreePathInvalid);
    }
    Ok(canonical_worktree)
}

fn contains_symlink(root: &Path) -> Result<bool, RemediationError> {
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0usize;
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(directory).map_err(|_| RemediationError::FilesystemFailed)?;
        for entry in entries {
            visited = visited.saturating_add(1);
            if visited > MAX_WORKTREE_ENTRIES {
                return Err(RemediationError::WorktreePathInvalid);
            }
            let entry = entry.map_err(|_| RemediationError::FilesystemFailed)?;
            let file_type = entry
                .file_type()
                .map_err(|_| RemediationError::FilesystemFailed)?;
            if file_type.is_symlink() {
                return Ok(true);
            }
            if file_type.is_dir() && entry.file_name() != ".git" {
                pending.push(entry.path());
            }
        }
    }
    Ok(false)
}

struct ScopedOpenCodePolicy {
    path: PathBuf,
}

impl ScopedOpenCodePolicy {
    fn create(worktree: &Path) -> Result<Self, RemediationError> {
        for relative in ["opencode.json", "opencode.jsonc", ".opencode"] {
            match fs::symlink_metadata(worktree.join(relative)) {
                Ok(_) => return Err(RemediationError::OpenCodeProjectConfigPresent),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(RemediationError::FilesystemFailed),
            }
        }
        let path = std::env::temp_dir().join(format!(
            "secmon-opencode-policy-{}.json",
            Uuid::new_v4().simple()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| RemediationError::FilesystemFailed)?;
        if file.write_all(OPENCODE_POLICY.as_bytes()).is_err() {
            let _ = fs::remove_file(&path);
            return Err(RemediationError::FilesystemFailed);
        }
        Ok(Self { path })
    }
}

impl Drop for ScopedOpenCodePolicy {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn remove_sandbox_temp(worktree: &Path) -> Result<(), RemediationError> {
    let temporary = worktree.join(".secmon-tmp");
    match fs::symlink_metadata(&temporary) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            fs::remove_file(temporary).map_err(|_| RemediationError::FilesystemFailed)
        }
        Ok(metadata) if metadata.is_dir() => {
            fs::remove_dir_all(temporary).map_err(|_| RemediationError::FilesystemFailed)
        }
        Ok(_) => fs::remove_file(temporary).map_err(|_| RemediationError::FilesystemFailed),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(RemediationError::FilesystemFailed),
    }
}

fn canonical_worktrees_directory(app_data_dir: &Path) -> Result<PathBuf, RemediationError> {
    fs::create_dir_all(app_data_dir).map_err(|_| RemediationError::FilesystemFailed)?;
    let canonical_data =
        fs::canonicalize(app_data_dir).map_err(|_| RemediationError::FilesystemFailed)?;
    let directory = canonical_data.join("worktrees");
    fs::create_dir_all(&directory).map_err(|_| RemediationError::FilesystemFailed)?;
    let canonical_directory =
        fs::canonicalize(directory).map_err(|_| RemediationError::FilesystemFailed)?;
    if !canonical_directory.starts_with(&canonical_data) {
        return Err(RemediationError::WorktreePathInvalid);
    }
    Ok(canonical_directory)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: String,
    pub finding_id: String,
    pub provider_id: String,
    pub requested_action: String,
    pub approval_state: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum McpRemediationAction {
    PreparePatch,
    RunSafeTests,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct McpRemediationRequest {
    pub id: String,
    pub action: McpRemediationAction,
    pub finding_id: String,
    pub provider_id: Option<String>,
    pub remediation_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

pub fn write_mcp_remediation_request(
    app_data_dir: &Path,
    request: &McpRemediationRequest,
) -> Result<(), RemediationError> {
    validate_mcp_request(request)?;
    let queue = canonical_mcp_queue_directory(app_data_dir)?;
    let path = queue.join(format!("{}.json", request.id));
    let bytes = serde_json::to_vec(request).map_err(|_| RemediationError::FilesystemFailed)?;
    if bytes.len() as u64 > MAX_MCP_REQUEST_BYTES {
        return Err(RemediationError::InvalidTestCommand);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| RemediationError::FilesystemFailed)?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| RemediationError::FilesystemFailed)
}

pub fn list_mcp_remediation_requests(
    app_data_dir: &Path,
) -> Result<Vec<McpRemediationRequest>, RemediationError> {
    let queue = canonical_mcp_queue_directory(app_data_dir)?;
    let mut requests = Vec::new();
    for entry in fs::read_dir(&queue).map_err(|_| RemediationError::FilesystemFailed)? {
        let entry = entry.map_err(|_| RemediationError::FilesystemFailed)?;
        let file_type = entry
            .file_type()
            .map_err(|_| RemediationError::FilesystemFailed)?;
        if !file_type.is_file()
            || entry.path().extension().and_then(|ext| ext.to_str()) != Some("json")
        {
            continue;
        }
        let metadata = entry
            .metadata()
            .map_err(|_| RemediationError::FilesystemFailed)?;
        if metadata.len() > MAX_MCP_REQUEST_BYTES || requests.len() >= MAX_MCP_REQUESTS {
            return Err(RemediationError::InvalidTestCommand);
        }
        let bytes = fs::read(entry.path()).map_err(|_| RemediationError::FilesystemFailed)?;
        let request: McpRemediationRequest =
            serde_json::from_slice(&bytes).map_err(|_| RemediationError::InvalidTestCommand)?;
        validate_mcp_request(&request)?;
        if entry.file_name().to_string_lossy() != format!("{}.json", request.id) {
            return Err(RemediationError::InvalidTestCommand);
        }
        requests.push(request);
    }
    requests.sort_by_key(|request| request.created_at);
    Ok(requests)
}

pub fn remove_mcp_remediation_request(
    app_data_dir: &Path,
    request_id: &str,
) -> Result<(), RemediationError> {
    Uuid::parse_str(request_id).map_err(|_| RemediationError::InvalidTestCommand)?;
    let queue = canonical_mcp_queue_directory(app_data_dir)?;
    let path = queue.join(format!("{request_id}.json"));
    let metadata = fs::symlink_metadata(&path).map_err(|_| RemediationError::FilesystemFailed)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(RemediationError::InvalidTestCommand);
    }
    fs::remove_file(path).map_err(|_| RemediationError::FilesystemFailed)
}

fn validate_mcp_request(request: &McpRemediationRequest) -> Result<(), RemediationError> {
    Uuid::parse_str(&request.id).map_err(|_| RemediationError::InvalidTestCommand)?;
    for value in [
        &request.finding_id,
        request.provider_id.as_deref().unwrap_or(""),
        request.remediation_id.as_deref().unwrap_or(""),
    ] {
        if value.len() > 128 || value.chars().any(char::is_control) {
            return Err(RemediationError::InvalidTestCommand);
        }
    }
    match request.action {
        McpRemediationAction::PreparePatch
            if request.finding_id.is_empty()
                || request.provider_id.as_deref().is_none_or(str::is_empty)
                || request.remediation_id.is_some() =>
        {
            Err(RemediationError::InvalidTestCommand)
        }
        McpRemediationAction::RunSafeTests
            if request.finding_id.is_empty()
                || request.remediation_id.as_deref().is_none_or(str::is_empty)
                || request.provider_id.is_some() =>
        {
            Err(RemediationError::InvalidTestCommand)
        }
        _ => Ok(()),
    }
}

fn canonical_mcp_queue_directory(app_data_dir: &Path) -> Result<PathBuf, RemediationError> {
    fs::create_dir_all(app_data_dir).map_err(|_| RemediationError::FilesystemFailed)?;
    let canonical_data =
        fs::canonicalize(app_data_dir).map_err(|_| RemediationError::FilesystemFailed)?;
    let directory = canonical_data.join("mcp-remediation-queue");
    fs::create_dir_all(&directory).map_err(|_| RemediationError::FilesystemFailed)?;
    let canonical_directory =
        fs::canonicalize(directory).map_err(|_| RemediationError::FilesystemFailed)?;
    if !canonical_directory.starts_with(&canonical_data) {
        return Err(RemediationError::WorktreePathInvalid);
    }
    Ok(canonical_directory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, process::Command as StdCommand};
    use tempfile::TempDir;

    fn fixture_repository() -> (TempDir, PathBuf) {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("repo");
        fs::create_dir_all(root.join("src")).unwrap();
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/remediation/repo");
        copy_tree(&fixture, &root);
        let init = StdCommand::new("git")
            .args(["init", "--quiet"])
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(init.success());
        let added = StdCommand::new("git")
            .args(["add", "."])
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(added.success());
        let committed = StdCommand::new("git")
            .args([
                "-c",
                "user.name=Secmon Test",
                "-c",
                "user.email=secmon@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ])
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(committed.success());
        (temp, root)
    }

    fn copy_tree(from: &Path, to: &Path) {
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let dest = to.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                fs::create_dir_all(&dest).unwrap();
                copy_tree(&entry.path(), &dest);
            } else {
                fs::copy(entry.path(), dest).unwrap();
            }
        }
    }

    async fn git(root: &Path, args: &[&str]) -> String {
        let output = StdCommand::new("git")
            .args(["-C", root.to_str().unwrap()])
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    #[tokio::test]
    async fn patch_worktree_is_isolated_from_the_original_branch_and_files() {
        let (temp, repository) = fixture_repository();
        let original_branch = git(&repository, &["branch", "--show-current"]).await;
        let original_head = git(&repository, &["rev-parse", "HEAD"]).await;
        let original_source = fs::read_to_string(repository.join("src/lib.rs")).unwrap();
        let prepared = create_worktree(&repository, temp.path()).await.unwrap();
        fs::write(
            prepared.worktree_path.join("src/lib.rs"),
            "pub fn value() -> u8 { 2 }\n",
        )
        .unwrap();
        let diff = worktree_diff(&prepared.worktree_path).await.unwrap();
        assert!(diff.has_changes);
        assert_eq!(diff.sha256.len(), 64);
        fs::write(prepared.worktree_path.join("new.txt"), "new patch file\n").unwrap();
        let first_untracked_diff = worktree_diff(&prepared.worktree_path).await.unwrap();
        fs::write(
            prepared.worktree_path.join("new.txt"),
            "changed patch file\n",
        )
        .unwrap();
        let second_untracked_diff = worktree_diff(&prepared.worktree_path).await.unwrap();
        assert_ne!(first_untracked_diff.sha256, second_untracked_diff.sha256);
        fs::write(
            prepared.worktree_path.join(".gitattributes"),
            "*.bin filter=untrusted\n",
        )
        .unwrap();
        assert!(matches!(
            worktree_diff(&prepared.worktree_path).await,
            Err(RemediationError::GitFiltersNotAllowed)
        ));
        fs::remove_file(prepared.worktree_path.join(".gitattributes")).unwrap();
        assert_eq!(
            git(&repository, &["branch", "--show-current"]).await,
            original_branch
        );
        assert_eq!(
            git(&repository, &["rev-parse", "HEAD"]).await,
            original_head
        );
        assert_eq!(
            fs::read_to_string(repository.join("src/lib.rs")).unwrap(),
            original_source
        );
        remove_worktree(&repository, &prepared.worktree_path)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn repositories_with_git_filters_are_refused_before_checkout() {
        let (temp, repository) = fixture_repository();
        fs::write(
            repository.join(".gitattributes"),
            "*.bin filter=untrusted\n",
        )
        .unwrap();
        let add = StdCommand::new("git")
            .args(["add", ".gitattributes"])
            .current_dir(&repository)
            .status()
            .unwrap();
        assert!(add.success());
        let commit = StdCommand::new("git")
            .args([
                "-c",
                "user.name=Secmon Test",
                "-c",
                "user.email=secmon@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "add filter attribute",
            ])
            .current_dir(&repository)
            .status()
            .unwrap();
        assert!(commit.success());

        assert!(matches!(
            create_worktree(&repository, temp.path()).await,
            Err(RemediationError::GitFiltersNotAllowed)
        ));
    }

    #[test]
    fn test_command_builder_disables_network_and_limits_the_container() {
        let temp = TempDir::new().unwrap();
        let command = SafeTestCommand {
            executable: "cargo".into(),
            args: vec!["test".into(), "--locked".into(), "--offline".into()],
            image: format!("registry.invalid/secmon/rust@sha256:{}", "a".repeat(64)),
        };
        let args = build_test_args(
            SandboxEngine::Podman,
            temp.path(),
            "secmon-test-1",
            &command,
        )
        .unwrap();
        let values = args
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>();
        for required in [
            "--pull=never",
            "--network=none",
            "--read-only",
            "--cpus=1",
            "--memory=1g",
            "--pids-limit=128",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
        ] {
            assert!(
                values.iter().any(|arg| arg == required),
                "missing {required}"
            );
        }
        assert!(values.iter().any(|arg| arg.starts_with("type=bind,src=") && arg.ends_with(",dst=/workspace,rw")));
        assert!(!values.iter().any(|arg| arg.contains("--network=host")));
    }

    #[test]
    fn safe_tests_reject_shells_and_unpinned_images() {
        let mut command = SafeTestCommand {
            executable: "powershell.exe".into(),
            args: vec!["-Command".into(), "Write-Host nope".into()],
            image: format!("rust@sha256:{}", "a".repeat(64)),
        };
        assert!(matches!(
            validate_safe_test(&command),
            Err(RemediationError::ShellNotAllowed)
        ));
        command.executable = "cargo".into();
        command.image = "rust:latest".into();
        assert!(matches!(
            validate_safe_test(&command),
            Err(RemediationError::InvalidTestCommand | RemediationError::InvalidImage)
        ));
    }

    #[test]
    fn opencode_policy_denies_commands_and_refuses_project_overrides() {
        let temp = TempDir::new().unwrap();
        let policy = ScopedOpenCodePolicy::create(temp.path()).unwrap();
        let policy_path = policy.path.clone();
        let config: serde_json::Value = serde_json::from_str(OPENCODE_POLICY).unwrap();
        assert_eq!(config["permission"]["*"], "deny");
        assert_eq!(config["permission"]["edit"], "allow");
        assert_eq!(config["permission"]["bash"], "deny");
        assert_eq!(config["permission"]["external_directory"], "deny");
        assert_eq!(config["permission"]["task"], "deny");
        drop(policy);
        assert!(!policy_path.exists());

        fs::write(temp.path().join("opencode.json"), "{}").unwrap();
        assert!(matches!(
            ScopedOpenCodePolicy::create(temp.path()),
            Err(RemediationError::OpenCodeProjectConfigPresent)
        ));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn sandbox_runs_fixture_code_without_network_or_host_writes() {
        let (temp, repository) = fixture_repository();
        let prepared = create_worktree(&repository, temp.path()).await.unwrap();
        fs::write(
            prepared.worktree_path.join("src/lib.rs"),
            "pub fn value() -> u8 { 2 }\n",
        )
        .unwrap();

        let context = temp.path().join("sandbox-image");
        fs::create_dir_all(&context).unwrap();
        let executable = context.join("cargo");
        let fixture_program = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/remediation/sandbox_probe.c");
        let compile = StdCommand::new("cc")
            .args(["-static", "-O2", "-o"])
            .arg(&executable)
            .arg(fixture_program)
            .status()
            .unwrap();
        assert!(compile.success());
        fs::write(
            context.join("Dockerfile"),
            "FROM scratch\nCOPY cargo /cargo\nENV PATH=/\n",
        )
        .unwrap();

        let engine = available_engine()
            .await
            .expect("Linux CI must provide Docker or Podman");
        let image_tag = format!("secmon-remediation-fixture:{}", Uuid::new_v4().simple());
        let build = StdCommand::new(sandbox_executable(engine))
            .args(["build", "--network=none", "--tag"])
            .arg(&image_tag)
            .arg(&context)
            .status()
            .unwrap();
        assert!(build.success());
        let inspect = StdCommand::new(sandbox_executable(engine))
            .args(["image", "inspect", "--format={{.Id}}"])
            .arg(&image_tag)
            .output()
            .unwrap();
        assert!(inspect.status.success());
        let image_id = String::from_utf8(inspect.stdout).unwrap().trim().to_owned();
        let test = SafeTestCommand {
            executable: "cargo".into(),
            args: vec!["test".into(), "--locked".into(), "--offline".into()],
            image: image_id,
        };
        let result = run_sandbox_test(engine, &prepared.worktree_path, &test, true)
            .await
            .unwrap();
        if result.exit_code != Some(0) || result.timed_out {
            let diagnostic_name = format!("secmon-diagnostic-{}", Uuid::new_v4().simple());
            let diagnostic_args =
                build_test_args(engine, &prepared.worktree_path, &diagnostic_name, &test).unwrap();
            fs::create_dir(prepared.worktree_path.join(".secmon-tmp")).unwrap();
            let diagnostic = StdCommand::new(sandbox_executable(engine))
                .args(diagnostic_args)
                .output()
                .unwrap();
            let _ = remove_sandbox_temp(&prepared.worktree_path);
            panic!(
                "sandbox failed with {:?}; retry exit={} stderr={}",
                result.exit_code,
                diagnostic.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&diagnostic.stderr)
            );
        }
        assert_eq!(result.exit_code, Some(0));
        assert!(!result.timed_out);
        assert_eq!(
            fs::read_to_string(repository.join("src/lib.rs")).unwrap(),
            "pub fn value() -> u8 { 1 }\n"
        );
        let _ = StdCommand::new(sandbox_executable(engine))
            .args(["image", "rm", "--force"])
            .arg(image_tag)
            .status();
        remove_worktree(&repository, &prepared.worktree_path)
            .await
            .unwrap();
    }

    #[test]
    fn product_selection_is_closed_over_the_supported_cli_set() {
        assert_eq!(
            parse_agent_cli_product("codex"),
            Some(AgentCliProduct::Codex)
        );
        assert_eq!(parse_agent_cli_product("../../some-command"), None);
    }

    #[test]
    fn mcp_requests_are_local_atomic_and_reject_path_traversal() {
        let temp = TempDir::new().unwrap();
        let request = McpRemediationRequest {
            id: Uuid::new_v4().to_string(),
            action: McpRemediationAction::PreparePatch,
            finding_id: "finding-1".into(),
            provider_id: Some("provider-1".into()),
            remediation_id: None,
            created_at: Utc::now(),
        };
        write_mcp_remediation_request(temp.path(), &request).unwrap();
        assert_eq!(
            list_mcp_remediation_requests(temp.path()).unwrap(),
            vec![request.clone()]
        );
        remove_mcp_remediation_request(temp.path(), &request.id).unwrap();
        assert!(
            list_mcp_remediation_requests(temp.path())
                .unwrap()
                .is_empty()
        );
        assert!(remove_mcp_remediation_request(temp.path(), "../escape").is_err());
    }
}
