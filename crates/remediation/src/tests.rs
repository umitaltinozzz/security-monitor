use super::*;
use std::{collections::BTreeMap, fs, process::Command as StdCommand};
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

#[test]
fn git_command_safety_blocks_ssh_and_promisor_fetches() {
    let safety = GitCommandSafety::create().unwrap();
    let mut command = StdCommand::new("git");
    command
        .env("GIT_CONFIG_PARAMETERS", "'core.sshCommand=untrusted'")
        .env("GIT_NO_LAZY_FETCH", "0")
        .env("GIT_ALLOW_PROTOCOL", "ssh:file");
    safety.configure_std(&mut command);

    let environment = command
        .get_envs()
        .map(|(key, value)| {
            (
                key.to_string_lossy().into_owned(),
                value.map(|value| value.to_string_lossy().into_owned()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        environment.get("GIT_NO_LAZY_FETCH"),
        Some(&Some("1".into()))
    );
    assert_eq!(
        environment.get("GIT_ALLOW_PROTOCOL"),
        Some(&Some(String::new()))
    );
    assert_eq!(environment.get("GIT_CONFIG_COUNT"), Some(&Some("4".into())));
    assert_eq!(
        environment.get("GIT_CONFIG_KEY_3"),
        Some(&Some("core.sshCommand".into()))
    );
    assert_eq!(
        environment.get("GIT_CONFIG_VALUE_3"),
        Some(&Some(String::new()))
    );
    assert_eq!(environment.get("GIT_CONFIG_PARAMETERS"), Some(&None));
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
        prepared.worktree_path.join(".gitignore"),
        "target/\nnode_modules/\n__pycache__/\n",
    )
    .unwrap();
    let baseline = worktree_diff(&prepared.worktree_path).await.unwrap();
    for ignored in [
        "target/build.log",
        "node_modules/cache",
        "__pycache__/cache",
    ] {
        let path = prepared.worktree_path.join(ignored);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "generated data").unwrap();
    }
    assert_eq!(
        baseline.sha256,
        worktree_diff(&prepared.worktree_path).await.unwrap().sha256
    );
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
    remove_worktree(
        &repository,
        temp.path(),
        &prepared.worktree_path,
        &prepared.branch,
    )
    .await
    .unwrap();
    assert!(
        git(&repository, &["branch", "--list", &prepared.branch])
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn removing_a_missing_worktree_also_removes_its_managed_branch() {
    let (temp, repository) = fixture_repository();
    let prepared = create_worktree(&repository, temp.path()).await.unwrap();
    fs::remove_dir_all(&prepared.worktree_path).unwrap();

    remove_worktree(
        &repository,
        temp.path(),
        &prepared.worktree_path,
        &prepared.branch,
    )
    .await
    .unwrap();

    assert!(
        git(&repository, &["branch", "--list", &prepared.branch])
            .await
            .is_empty()
    );
    assert!(
        !git(&repository, &["worktree", "list", "--porcelain"])
            .await
            .contains(prepared.worktree_path.to_str().unwrap())
    );
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
    assert!(
        values
            .iter()
            .any(|arg| arg.starts_with("type=bind,src=") && arg.ends_with(",dst=/workspace"))
    );
    let user = values
        .iter()
        .find_map(|arg| arg.strip_prefix("--user="))
        .expect("sandbox user is configured");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let metadata = fs::metadata(temp.path()).unwrap();
        assert_eq!(user, format!("{}:{}", metadata.uid(), metadata.gid()));
    }
    #[cfg(windows)]
    assert_eq!(user, "1000:1000");
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
        Err(RemediationError::AgentProjectConfigPresent)
    ));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn sandbox_runs_fixture_code_without_network_or_host_writes() {
    let (temp, repository) = fixture_repository();
    let original_source = fs::read_to_string(repository.join("src/lib.rs")).unwrap();
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
        original_source
    );
    let _ = StdCommand::new(sandbox_executable(engine))
        .args(["image", "rm", "--force"])
        .arg(image_tag)
        .status();
    remove_worktree(
        &repository,
        temp.path(),
        &prepared.worktree_path,
        &prepared.branch,
    )
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
