use super::*;

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

pub(crate) struct ScopedOpenCodePolicy {
    pub(crate) path: PathBuf,
}

impl ScopedOpenCodePolicy {
    pub(crate) fn create(worktree: &Path) -> Result<Self, RemediationError> {
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
