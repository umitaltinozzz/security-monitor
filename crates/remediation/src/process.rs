use super::*;
#[cfg(unix)]
use std::io;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

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
    configure_process_group(&mut command);
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
    pub(super) stderr: Vec<u8>,
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
    let total_bytes = Arc::new(AtomicUsize::new(0));
    let truncated = Arc::new(AtomicBool::new(false));
    let (limit_sender, mut limit_receiver) = tokio::sync::mpsc::unbounded_channel();
    let stdout_reader = read_output_stream(
        stdout,
        max_output,
        total_bytes.clone(),
        truncated.clone(),
        limit_sender.clone(),
    );
    let stderr_reader = read_output_stream(
        stderr,
        max_output,
        total_bytes,
        truncated.clone(),
        limit_sender,
    );
    let output_capture = tokio::spawn(async move {
        tokio::try_join!(stdout_reader, stderr_reader).map_err(|_| RemediationError::ProcessFailed)
    });
    let status = match timeout(limit, async {
        tokio::select! {
            status = child.wait() => status.map_err(|_| RemediationError::ProcessFailed),
            signal = limit_receiver.recv() => {
                if signal.is_some() {
                    terminate_process_group(&mut child)?;
                }
                child.wait().await.map_err(|_| RemediationError::ProcessFailed)
            }
        }
    })
    .await
    {
        Ok(result) => result?,
        Err(_) => {
            terminate_process_group(&mut child)?;
            let _ = child.wait().await;
            return Err(RemediationError::TimedOut);
        }
    };
    let (stdout, stderr) = output_capture
        .await
        .map_err(|_| RemediationError::ProcessFailed)??;
    Ok(CapturedProcess {
        stdout,
        stderr,
        exit_code: status.code(),
        output_truncated: truncated.load(Ordering::Relaxed),
    })
}

async fn read_output_stream<R>(
    mut reader: R,
    max_output: usize,
    total_bytes: Arc<AtomicUsize>,
    truncated: Arc<AtomicBool>,
    limit_sender: tokio::sync::mpsc::UnboundedSender<()>,
) -> Result<Vec<u8>, RemediationError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut output = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let count = reader
            .read(&mut chunk)
            .await
            .map_err(|_| RemediationError::ProcessFailed)?;
        if count == 0 {
            break;
        }
        let previous = reserve_output_bytes(&total_bytes, count);
        let allowed = max_output.saturating_sub(previous).min(count);
        output.extend_from_slice(&chunk[..allowed]);
        if allowed < count && !truncated.swap(true, Ordering::Relaxed) {
            let _ = limit_sender.send(());
        }
    }
    Ok(output)
}

fn reserve_output_bytes(total_bytes: &AtomicUsize, count: usize) -> usize {
    let mut total = total_bytes.load(Ordering::Relaxed);
    loop {
        match total_bytes.compare_exchange_weak(
            total,
            total.saturating_add(count),
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(previous) => return previous,
            Err(updated) => total = updated,
        }
    }
}

pub(super) fn configure_process_group(command: &mut Command) {
    #[cfg(unix)]
    {
        command.process_group(0);
    }
    #[cfg(not(unix))]
    {
        let _ = command;
    }
}

fn terminate_process_group(child: &mut tokio::process::Child) -> Result<(), RemediationError> {
    #[cfg(unix)]
    {
        let Some(process_id) = child.id() else {
            return Ok(());
        };
        let result = unsafe { libc::kill(-(process_id as i32), libc::SIGKILL) };
        if result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(RemediationError::ProcessFailed)
        }
    }
    #[cfg(not(unix))]
    {
        child
            .start_kill()
            .map_err(|_| RemediationError::ProcessFailed)
    }
}

pub(super) fn captured_output(stdout: &[u8], stderr: &[u8]) -> String {
    let mut output = String::new();
    if !stdout.is_empty() {
        output.push_str("stdout:\n");
        output.push_str(&String::from_utf8_lossy(stdout));
    }
    if !stderr.is_empty() {
        if !output.is_empty() && !output.ends_with('\n') {
            output.push('\n');
        }
        output.push_str("stderr:\n");
        output.push_str(&String::from_utf8_lossy(stderr));
    }
    output
}

pub(super) fn path_arg(path: &Path) -> Result<&str, RemediationError> {
    let value = path.to_str().ok_or(RemediationError::WorktreePathInvalid)?;
    if value.starts_with("\\\\?\\UNC\\") {
        return Err(RemediationError::WorktreePathInvalid);
    }
    Ok(value.strip_prefix("\\\\?\\").unwrap_or(value))
}
