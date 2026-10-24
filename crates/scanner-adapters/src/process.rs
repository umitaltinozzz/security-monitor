use std::{ffi::OsString, path::Path, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    time::timeout,
};

use crate::types::ScannerError;

const MAX_STDOUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 2 * 1024 * 1024;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(600);

pub(crate) struct ProcessOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub(crate) async fn run_process(
    executable: &Path,
    args: &[OsString],
    working_directory: &Path,
    osv_cache_directory: Option<&Path>,
) -> Result<ProcessOutput, ScannerError> {
    timeout(
        PROCESS_TIMEOUT,
        run_process_inner(executable, args, working_directory, osv_cache_directory),
    )
    .await
    .map_err(|_| ScannerError::ProcessTimedOut)?
}

async fn run_process_inner(
    executable: &Path,
    args: &[OsString],
    working_directory: &Path,
    osv_cache_directory: Option<&Path>,
) -> Result<ProcessOutput, ScannerError> {
    let mut command = Command::new(executable);
    command
        .args(args)
        .current_dir(working_directory)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    command.env_clear();
    for key in [
        "PATH",
        "HOME",
        "USERPROFILE",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command.env("HOME", working_directory);
    command.env("USERPROFILE", working_directory);
    if let Some(cache_directory) = osv_cache_directory {
        command.env("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", cache_directory);
    }

    let mut child = command.spawn().map_err(|_| ScannerError::Invocation)?;
    let stdout = child.stdout.take().ok_or(ScannerError::Invocation)?;
    let stderr = child.stderr.take().ok_or(ScannerError::Invocation)?;
    let (stdout, stderr) = match tokio::try_join!(
        read_limited(stdout, MAX_STDOUT_BYTES),
        read_limited(stderr, MAX_STDERR_BYTES)
    ) {
        Ok(output) => output,
        Err(error) => {
            let _ = child.kill().await;
            return Err(error);
        }
    };
    let status = child.wait().await.map_err(|_| ScannerError::Invocation)?;

    Ok(ProcessOutput {
        success: status.success(),
        stdout,
        stderr,
    })
}

async fn read_limited<R>(mut reader: R, limit: usize) -> Result<Vec<u8>, ScannerError>
where
    R: AsyncRead + Unpin,
{
    let mut output = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .map_err(|_| ScannerError::Invocation)?;
        if read == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(read) > limit {
            return Err(ScannerError::OutputTooLarge);
        }
        output.extend_from_slice(&buffer[..read]);
    }
}
