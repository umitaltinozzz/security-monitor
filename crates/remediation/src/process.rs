use super::*;

pub(super) async fn run_command(
    executable: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    limit: Duration,
    max_output: usize,
) -> Result<(Vec<u8>, bool), RemediationError> {
    run_command_with_git_safety(executable, args, stdin, limit, max_output, None).await
}

pub(super) async fn run_git_command(
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

pub(super) struct CapturedProcess {
    pub(super) stdout: Vec<u8>,
    pub(super) exit_code: Option<i32>,
    pub(super) output_truncated: bool,
}

pub(super) async fn capture_child(
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

pub(super) fn path_arg(path: &Path) -> Result<&str, RemediationError> {
    let value = path.to_str().ok_or(RemediationError::WorktreePathInvalid)?;
    if value.starts_with("\\\\?\\UNC\\") {
        return Err(RemediationError::WorktreePathInvalid);
    }
    Ok(value.strip_prefix("\\\\?\\").unwrap_or(value))
}
