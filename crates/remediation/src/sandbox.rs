use super::*;

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
        OsString::from(format!("--user={}", sandbox_user(&worktree)?)),
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
            "type=bind,src={},dst=/workspace",
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

fn sandbox_user(worktree: &Path) -> Result<String, RemediationError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let metadata = fs::metadata(worktree).map_err(|_| RemediationError::FilesystemFailed)?;
        Ok(format!("{}:{}", metadata.uid(), metadata.gid()))
    }
    #[cfg(windows)]
    {
        let _ = worktree;
        // Docker Desktop mounts Windows directories into its Linux VM; use an unprivileged
        // Linux container identity because Windows metadata has no UID/GID pair.
        Ok("1000:1000".to_owned())
    }
}

pub fn sandbox_executable(engine: SandboxEngine) -> &'static str {
    engine.executable()
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
    process::configure_process_group(&mut process);
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
        Ok(output) => {
            if output.output_truncated {
                stop_sandbox_container(engine, &container_name).await;
            }
            Ok(ProcessResult {
                exit_code: output.exit_code,
                timed_out: false,
                output_truncated: output.output_truncated,
                output: process::captured_output(&output.stdout, &output.stderr),
            })
        }
        Err(RemediationError::TimedOut) => {
            stop_sandbox_container(engine, &container_name).await;
            Ok(ProcessResult {
                exit_code: None,
                timed_out: true,
                output_truncated: false,
                output: String::new(),
            })
        }
        Err(error) => Err(error),
    };
    remove_sandbox_temp(&worktree)?;
    result
}

async fn stop_sandbox_container(engine: SandboxEngine, container_name: &str) {
    let _ = run_command(
        engine.executable(),
        &["kill", container_name],
        None,
        Duration::from_secs(5),
        1024,
    )
    .await;
    let _ = run_command(
        engine.executable(),
        &["rm", "--force", container_name],
        None,
        Duration::from_secs(5),
        1024,
    )
    .await;
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

pub(crate) fn remove_sandbox_temp(worktree: &Path) -> Result<(), RemediationError> {
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
