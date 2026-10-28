use super::*;

/// No provider currently has a tested operating-system sandbox in this crate.
/// Keep agent execution disabled until a platform backend and its negative probes exist.
pub fn agent_sandbox_available() -> bool {
    false
}

pub fn agent_cli_executable(product: AgentCliProduct) -> &'static str {
    #[cfg(windows)]
    {
        match product {
            AgentCliProduct::ClaudeCode => "claude.exe",
            AgentCliProduct::Codex => "codex.exe",
            AgentCliProduct::OpenCode => "opencode.exe",
        }
    }
    #[cfg(not(windows))]
    {
        match product {
            AgentCliProduct::ClaudeCode => "claude",
            AgentCliProduct::Codex => "codex",
            AgentCliProduct::OpenCode => "opencode",
        }
    }
}

pub async fn run_agent_cli(
    product: AgentCliProduct,
    worktree_path: &Path,
    prompt: &str,
    source_transfer_approved: bool,
    network_access_approved: bool,
) -> Result<ProcessResult, RemediationError> {
    if !source_transfer_approved {
        return Err(RemediationError::SourceTransferApprovalRequired);
    }
    if !network_access_approved {
        return Err(RemediationError::NetworkApprovalRequired);
    }
    if !agent_sandbox_available() {
        return Err(RemediationError::AgentSandboxUnavailable);
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
    reject_agent_project_configuration(&worktree)?;
    let mut command = Command::new(agent_cli_executable(product));
    process::configure_process_group(&mut command);
    configure_agent_environment(&mut command, &worktree);
    let _opencode_policy = if product == AgentCliProduct::OpenCode {
        Some(ScopedOpenCodePolicy::create(&worktree)?)
    } else {
        None
    };
    match product {
        AgentCliProduct::ClaudeCode => {
            command.args([
                "--print",
                "--setting-sources",
                "user",
                "--strict-mcp-config",
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
                "--ephemeral",
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
        output: process::captured_output(&output.stdout, &output.stderr),
    })
}

fn configure_agent_environment(command: &mut Command, worktree: &Path) {
    command.env_clear();
    for name in AGENT_ENV_ALLOWLIST {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.current_dir(worktree).kill_on_drop(true);
}

fn reject_agent_project_configuration(worktree: &Path) -> Result<(), RemediationError> {
    let mut pending = vec![worktree.to_path_buf()];
    let mut visited = 0usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).map_err(|_| RemediationError::FilesystemFailed)? {
            visited = visited.saturating_add(1);
            if visited > MAX_WORKTREE_ENTRIES {
                return Err(RemediationError::WorktreePathInvalid);
            }
            let entry = entry.map_err(|_| RemediationError::FilesystemFailed)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_agent_config_name(&name) {
                return Err(RemediationError::AgentProjectConfigPresent);
            }
            if name == ".git" {
                continue;
            }
            let file_type = entry
                .file_type()
                .map_err(|_| RemediationError::FilesystemFailed)?;
            if file_type.is_symlink() {
                return Err(RemediationError::WorktreePathInvalid);
            }
            if file_type.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    Ok(())
}

fn is_agent_config_name(name: &str) -> bool {
    UNSAFE_AGENT_CONFIG_NAMES
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

pub(crate) struct ScopedOpenCodePolicy {
    pub(crate) path: PathBuf,
}

impl ScopedOpenCodePolicy {
    pub(crate) fn create(worktree: &Path) -> Result<Self, RemediationError> {
        for relative in ["opencode.json", "opencode.jsonc", ".opencode"] {
            match fs::symlink_metadata(worktree.join(relative)) {
                Ok(_) => return Err(RemediationError::AgentProjectConfigPresent),
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

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::{agent_cli_executable, is_agent_config_name, reject_agent_project_configuration};
    use crate::{
        AGENT_ENV_ALLOWLIST, AgentCliProduct, RemediationError, UNSAFE_AGENT_CONFIG_NAMES,
    };

    #[test]
    fn agent_cli_uses_native_windows_executables_without_command_shims() {
        #[cfg(windows)]
        let expected = ["claude.exe", "codex.exe", "opencode.exe"];
        #[cfg(not(windows))]
        let expected = ["claude", "codex", "opencode"];

        let actual = [
            agent_cli_executable(AgentCliProduct::ClaudeCode),
            agent_cli_executable(AgentCliProduct::Codex),
            agent_cli_executable(AgentCliProduct::OpenCode),
        ];
        assert_eq!(actual, expected);
    }

    #[test]
    fn project_agent_configuration_is_rejected_at_any_depth() {
        for name in UNSAFE_AGENT_CONFIG_NAMES {
            let temp = TempDir::new().unwrap();
            let nested = temp.path().join("nested");
            std::fs::create_dir(&nested).unwrap();
            let config = nested.join(name);
            if name.starts_with('.') && !name.ends_with(".json") {
                std::fs::create_dir(&config).unwrap();
            } else {
                std::fs::write(config, "untrusted project configuration").unwrap();
            }
            assert!(matches!(
                reject_agent_project_configuration(temp.path()),
                Err(RemediationError::AgentProjectConfigPresent)
            ));
        }
    }

    #[test]
    fn agent_environment_allowlist_keeps_runtime_paths_and_excludes_secrets_and_hooks() {
        assert!(AGENT_ENV_ALLOWLIST.contains(&"PATH"));
        assert!(AGENT_ENV_ALLOWLIST.contains(&"HOME"));
        for forbidden in [
            "ANTHROPIC_API_KEY",
            "CLAUDE_CODE_OAUTH_TOKEN",
            "OPENAI_API_KEY",
            "AWS_SECRET_ACCESS_KEY",
            "NODE_OPTIONS",
            "BASH_ENV",
            "LD_PRELOAD",
        ] {
            assert!(!AGENT_ENV_ALLOWLIST.contains(&forbidden));
        }
        assert!(is_agent_config_name("AGENTS.md"));
        assert!(is_agent_config_name("AGENTS.override.md"));
        assert!(is_agent_config_name(".CLAUDE"));
    }

    #[tokio::test]
    async fn agent_cli_refuses_to_start_without_explicit_network_approval() {
        let temp = TempDir::new().unwrap();
        let result = super::run_agent_cli(
            AgentCliProduct::Codex,
            temp.path(),
            "review this patch",
            true,
            false,
        )
        .await;

        assert!(matches!(
            result,
            Err(RemediationError::NetworkApprovalRequired)
        ));
    }

    #[tokio::test]
    async fn agent_cli_fails_closed_without_a_tested_os_sandbox() {
        let temp = TempDir::new().unwrap();
        let result = super::run_agent_cli(
            AgentCliProduct::Codex,
            temp.path(),
            "review this patch",
            true,
            true,
        )
        .await;

        assert!(matches!(
            result,
            Err(RemediationError::AgentSandboxUnavailable)
        ));
    }
}
