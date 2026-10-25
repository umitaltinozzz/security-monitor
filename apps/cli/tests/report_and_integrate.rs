use std::{
    env,
    ffi::OsString,
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
    time::Instant,
};

use chrono::Utc;
use security_monitor_advisory_providers::OsvUpdateStatus;
use security_monitor_database::Database;
use serde_json::Value;

fn secmon() -> Command {
    Command::new(env!("CARGO_BIN_EXE_secmon"))
}

struct HookTestEnvironment {
    data_home: tempfile::TempDir,
    home: tempfile::TempDir,
    binary_directory: &'static Path,
}

impl HookTestEnvironment {
    fn new() -> Self {
        Self {
            data_home: tempfile::tempdir().unwrap(),
            home: tempfile::tempdir().unwrap(),
            binary_directory: Path::new(env!("CARGO_BIN_EXE_secmon")).parent().unwrap(),
        }
    }

    fn configure(&self, command: &mut Command) {
        let mut path = vec![self.binary_directory.to_owned()];
        path.extend(env::split_paths(&env::var_os("PATH").unwrap_or_default()));
        command
            .env("HOME", self.home.path())
            .env("USERPROFILE", self.home.path())
            .env("APPDATA", self.data_home.path())
            .env("XDG_DATA_HOME", self.data_home.path())
            .env("PATH", env::join_paths(path).unwrap());
    }

    fn app_data(&self) -> std::path::PathBuf {
        if cfg!(target_os = "macos") {
            self.home
                .path()
                .join("Library/Application Support/org.securitymonitor.desktop")
        } else {
            self.data_home.path().join("org.securitymonitor.desktop")
        }
    }
}

fn git_command(repository: &Path, args: &[OsString], environment: &HookTestEnvironment) -> Output {
    let mut command = Command::new("git");
    command.args(args).current_dir(repository);
    environment.configure(&mut command);
    command.output().unwrap()
}

fn assert_git_success(repository: &Path, args: &[OsString], environment: &HookTestEnvironment) {
    let output = git_command(repository, args, environment);
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn initialize_git_fixture(repository: &Path, remote: &Path, environment: &HookTestEnvironment) {
    std::fs::create_dir_all(repository).unwrap();
    let remote_path = remote.to_str().unwrap();
    assert_git_success(repository, &args(&["init", "--quiet"]), environment);
    assert_git_success(
        repository,
        &args(&["config", "user.name", "Fixture User"]),
        environment,
    );
    assert_git_success(
        repository,
        &args(&["config", "user.email", "fixture@example.invalid"]),
        environment,
    );
    assert_git_success(
        repository,
        &[
            OsString::from("remote"),
            OsString::from("add"),
            OsString::from("origin"),
            OsString::from(remote_path),
        ],
        environment,
    );
}

fn install_hook(repository: &Path, kind: &str, mode: &str, environment: &HookTestEnvironment) {
    let mut command = secmon();
    command
        .args(["hook", "install", kind, "--mode", mode, "--fail-on", "high"])
        .current_dir(repository);
    environment.configure(&mut command);
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "hook install failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn seed_hook_data(environment: &HookTestEnvironment) {
    let app_data = environment.app_data();
    let database_path = app_data.join("security-monitor.sqlite3");
    std::fs::create_dir_all(&app_data).unwrap();
    Database::open(database_path).await.unwrap().close().await;
    std::fs::write(
        app_data.join("settings.json"),
        br#"{"public_downloads_enabled":false,"ecosystems":["npm"]}"#,
    )
    .unwrap();
    let osv_cache = app_data.join("advisories/osv/npm");
    std::fs::create_dir_all(&osv_cache).unwrap();
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/advisory-db/npm/GHSA-abcd-efgh-ijkl.json"),
        osv_cache.join("GHSA-abcd-efgh-ijkl.json"),
    )
    .unwrap();
    std::fs::write(
        osv_cache.join(".secmon-cache.json"),
        serde_json::to_vec(&OsvUpdateStatus {
            ecosystem: "npm".into(),
            updated_at: Some(Utc::now()),
            stale: false,
            error: None,
            ..OsvUpdateStatus::default()
        })
        .unwrap(),
    )
    .unwrap();
}

fn package_lock(version: &str) -> String {
    format!(
        r#"{{"name":"hook-fixture","lockfileVersion":3,"packages":{{"":{{"name":"hook-fixture","version":"1.0.0"}},"node_modules/fixture-package":{{"version":"{version}"}}}}}}"#
    )
}

#[tokio::test]
async fn report_validates_each_supported_format_before_printing() {
    let temp = tempfile::tempdir().unwrap();
    let database_path = temp.path().join("security-monitor.sqlite3");
    Database::open(&database_path).await.unwrap().close().await;

    for (format, path, expected) in [
        ("json", "/format", "security-monitor-json"),
        ("sarif", "/version", "2.1.0"),
        ("cyclonedx", "/bomFormat", "CycloneDX"),
        ("openvex", "/@context", "https://openvex.dev/ns/v0.2.0"),
    ] {
        let output = secmon()
            .args(["report", "--format", format, "--database"])
            .arg(&database_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        if format == "openvex" {
            assert!(!output.status.success());
            assert!(output.stdout.is_empty());
            assert_eq!(
                String::from_utf8(output.stderr).unwrap().trim(),
                "report_schema_validation_failed"
            );
            continue;
        }
        assert!(output.status.success(), "{format}: {:?}", output.stderr);
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report.pointer(path).and_then(Value::as_str), Some(expected));
        match format {
            "json" => assert_eq!(
                report.pointer("/verification").and_then(Value::as_str),
                Some("needs_review")
            ),
            "sarif" => assert_eq!(
                report
                    .pointer("/runs/0/properties/verification")
                    .and_then(Value::as_str),
                Some("needs_review")
            ),
            "cyclonedx" => assert!(
                report
                    .pointer("/metadata/properties")
                    .and_then(Value::as_array)
                    .is_some_and(|properties| properties.iter().any(|property| {
                        property.get("name").and_then(Value::as_str)
                            == Some("security-monitor:verification")
                            && property.get("value").and_then(Value::as_str) == Some("needs_review")
                    }))
            ),
            "openvex" => unreachable!(),
            _ => unreachable!(),
        }
    }
}

#[test]
fn integrate_dry_run_shows_changes_without_writing_agent_files() {
    for (agent, config_snippet) in [
        ("claude-code", "mcpServers"),
        ("codex", "mcp_servers"),
        ("opencode", "local Security Monitor MCP"),
    ] {
        let home = tempfile::tempdir().unwrap();
        let mut command = secmon();
        command
            .args(["integrate", agent, "--scope", "user", "--dry-run"])
            .env("USERPROFILE", home.path())
            .env("HOME", home.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = command.output().unwrap();
        assert!(output.status.success(), "{agent}: {:?}", output.stderr);
        let diff = String::from_utf8(output.stdout).unwrap();
        assert!(diff.contains(config_snippet), "{agent}: {diff}");
        assert!(diff.contains("Security Monitor skill"));
        assert!(diff.contains("pre-tool Git hook"));
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    }
}

#[test]
fn hook_install_and_uninstall_preserve_existing_hook_bytes() {
    let repo = tempfile::tempdir().unwrap();
    let init = Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(repo.path())
        .output()
        .unwrap();
    assert!(init.status.success());
    let configured_hooks = Command::new("git")
        .args(["config", "core.hooksPath", ".githooks"])
        .current_dir(repo.path())
        .output()
        .unwrap();
    assert!(configured_hooks.status.success());
    let hooks = repo.path().join(".githooks");
    std::fs::create_dir(&hooks).unwrap();
    let original = b"#!/bin/sh\n# existing hook bytes\nexit 0\n";
    let target = hooks.join("pre-push");
    std::fs::write(&target, original).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let install = secmon()
        .args([
            "hook",
            "install",
            "--pre-push",
            "--mode",
            "warn",
            "--fail-on",
            "high",
        ])
        .current_dir(repo.path())
        .output()
        .unwrap();
    assert!(install.status.success(), "{:?}", install.stderr);
    assert_eq!(
        std::fs::read(hooks.join("pre-push.secmon-original")).unwrap(),
        original
    );
    assert!(
        std::fs::read(&target)
            .unwrap()
            .starts_with(b"#!/bin/sh\n# secmon-managed-hook-v1\n")
    );

    let uninstall = secmon()
        .args(["hook", "uninstall", "--pre-push"])
        .current_dir(repo.path())
        .output()
        .unwrap();
    assert!(uninstall.status.success(), "{:?}", uninstall.stderr);
    assert_eq!(std::fs::read(&target).unwrap(), original);
    assert!(!hooks.join("pre-push.secmon-state.json").exists());
}

#[test]
fn hook_install_rejects_an_external_configured_hooks_path() {
    let repository = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let init = Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(repository.path())
        .output()
        .unwrap();
    assert!(init.status.success());
    let configured_hooks = Command::new("git")
        .args([
            "config",
            "core.hooksPath",
            external.path().to_str().unwrap(),
        ])
        .current_dir(repository.path())
        .output()
        .unwrap();
    assert!(configured_hooks.status.success());
    let install = secmon()
        .args(["hook", "install", "--pre-push"])
        .current_dir(repository.path())
        .output()
        .unwrap();
    assert!(!install.status.success());
    assert!(String::from_utf8_lossy(&install.stderr).contains("repository_metadata_unsafe"));
    assert_eq!(std::fs::read_dir(external.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn pre_push_hook_warns_or_blocks_fixture_vulnerability_under_three_seconds() {
    let environment = HookTestEnvironment::new();
    seed_hook_data(&environment).await;
    let root = tempfile::tempdir().unwrap();
    let remote = root.path().join("remote.git");
    let repository = root.path().join("working");
    std::fs::create_dir(&repository).unwrap();
    assert_git_success(
        &repository,
        &[
            OsString::from("init"),
            OsString::from("--bare"),
            OsString::from("--quiet"),
            remote.as_os_str().to_owned(),
        ],
        &environment,
    );
    initialize_git_fixture(&repository, &remote, &environment);
    std::fs::write(repository.join("package-lock.json"), package_lock("1.0.0")).unwrap();
    assert_git_success(
        &repository,
        &args(&["add", "--", "package-lock.json"]),
        &environment,
    );
    assert_git_success(
        &repository,
        &args(&["commit", "--quiet", "-m", "add vulnerable dependency"]),
        &environment,
    );

    let hooks = repository.join(".git/hooks");
    std::fs::write(
        hooks.join("pre-push"),
        b"#!/bin/sh\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" > existing-hook-ran\ndone\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            hooks.join("pre-push"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    install_hook(&repository, "--pre-push", "warn", &environment);
    let started = Instant::now();
    let warn_push = git_command(
        &repository,
        &args(&["push", "origin", "HEAD:refs/heads/main"]),
        &environment,
    );
    let warn_elapsed = started.elapsed();
    assert!(
        warn_push.status.success(),
        "warn push failed: {}",
        String::from_utf8_lossy(&warn_push.stderr)
    );
    assert!(
        warn_elapsed.as_secs_f64() < 3.0,
        "warn hook took {warn_elapsed:?}"
    );
    assert!(String::from_utf8_lossy(&warn_push.stderr).contains("warning"));
    assert!(String::from_utf8_lossy(&warn_push.stdout).contains("1 finding(s)"));
    assert!(repository.join("existing-hook-ran").is_file());

    let remote_revision = git_command(
        &repository,
        &[
            OsString::from(format!("--git-dir={}", remote.to_string_lossy())),
            OsString::from("rev-parse"),
            OsString::from("refs/heads/main"),
        ],
        &environment,
    );
    assert!(remote_revision.status.success());
    let remote_revision = String::from_utf8(remote_revision.stdout)
        .unwrap()
        .trim()
        .to_owned();

    std::fs::write(repository.join("package-lock.json"), package_lock("1.0.1")).unwrap();
    assert_git_success(
        &repository,
        &args(&["add", "--", "package-lock.json"]),
        &environment,
    );
    assert_git_success(
        &repository,
        &args(&["commit", "--quiet", "-m", "update vulnerable dependency"]),
        &environment,
    );
    let mut uninstall = secmon();
    uninstall
        .args(["hook", "uninstall", "--pre-push"])
        .current_dir(&repository);
    environment.configure(&mut uninstall);
    assert!(uninstall.output().unwrap().status.success());
    install_hook(&repository, "--pre-push", "block", &environment);

    let started = Instant::now();
    let blocked_push = git_command(
        &repository,
        &args(&["push", "origin", "HEAD:refs/heads/main"]),
        &environment,
    );
    let block_elapsed = started.elapsed();
    assert!(!blocked_push.status.success());
    assert!(
        block_elapsed.as_secs_f64() < 3.0,
        "block hook took {block_elapsed:?}"
    );
    assert!(String::from_utf8_lossy(&blocked_push.stderr).contains("blocked"));
    assert!(String::from_utf8_lossy(&blocked_push.stdout).contains("1 finding(s)"));
    let still_remote_revision = git_command(
        &repository,
        &[
            OsString::from(format!("--git-dir={}", remote.to_string_lossy())),
            OsString::from("rev-parse"),
            OsString::from("refs/heads/main"),
        ],
        &environment,
    );
    assert_eq!(
        String::from_utf8(still_remote_revision.stdout)
            .unwrap()
            .trim(),
        remote_revision
    );
}

#[tokio::test]
async fn pre_commit_hook_checks_the_staged_lockfile_snapshot() {
    let environment = HookTestEnvironment::new();
    seed_hook_data(&environment).await;
    let root = tempfile::tempdir().unwrap();
    let repository = root.path().join("working");
    std::fs::create_dir(&repository).unwrap();
    assert_git_success(&repository, &args(&["init", "--quiet"]), &environment);
    assert_git_success(
        &repository,
        &args(&["config", "user.name", "Fixture User"]),
        &environment,
    );
    assert_git_success(
        &repository,
        &args(&["config", "user.email", "fixture@example.invalid"]),
        &environment,
    );
    std::fs::write(repository.join("README.txt"), "fixture\n").unwrap();
    assert_git_success(
        &repository,
        &args(&["add", "--", "README.txt"]),
        &environment,
    );
    assert_git_success(
        &repository,
        &args(&["commit", "--quiet", "-m", "initial"]),
        &environment,
    );

    install_hook(&repository, "--pre-commit", "block", &environment);
    std::fs::write(repository.join("package-lock.json"), package_lock("1.0.0")).unwrap();
    assert_git_success(
        &repository,
        &args(&["add", "--", "package-lock.json"]),
        &environment,
    );
    std::fs::write(repository.join("package-lock.json"), package_lock("1.1.0")).unwrap();
    let started = Instant::now();
    let commit = git_command(
        &repository,
        &args(&["commit", "--quiet", "-m", "stage vulnerable dependency"]),
        &environment,
    );
    let elapsed = started.elapsed();
    assert!(!commit.status.success());
    assert!(
        elapsed.as_secs_f64() < 3.0,
        "pre-commit hook took {elapsed:?}"
    );
    let commit_output = format!(
        "{}{}",
        String::from_utf8_lossy(&commit.stdout),
        String::from_utf8_lossy(&commit.stderr)
    );
    assert!(commit_output.contains("blocked"));
    assert!(commit_output.contains("1 finding(s)"));
}

#[test]
fn block_hook_allows_manifest_only_changes_without_a_verified_threshold_breach() {
    let environment = HookTestEnvironment::new();
    let root = tempfile::tempdir().unwrap();
    let repository = root.path().join("working");
    std::fs::create_dir(&repository).unwrap();
    assert_git_success(&repository, &args(&["init", "--quiet"]), &environment);
    assert_git_success(
        &repository,
        &args(&["config", "user.name", "Fixture User"]),
        &environment,
    );
    assert_git_success(
        &repository,
        &args(&["config", "user.email", "fixture@example.invalid"]),
        &environment,
    );
    std::fs::write(repository.join("README.txt"), "fixture\n").unwrap();
    assert_git_success(
        &repository,
        &args(&["add", "--", "README.txt"]),
        &environment,
    );
    assert_git_success(
        &repository,
        &args(&["commit", "--quiet", "-m", "initial"]),
        &environment,
    );

    install_hook(&repository, "--pre-commit", "block", &environment);
    std::fs::write(
        repository.join("package.json"),
        br#"{"name":"manifest-only","dependencies":{"fixture-package":"^1.0.0"}}"#,
    )
    .unwrap();
    assert_git_success(
        &repository,
        &args(&["add", "--", "package.json"]),
        &environment,
    );
    let commit = git_command(
        &repository,
        &args(&["commit", "--quiet", "-m", "change dependency manifest"]),
        &environment,
    );
    assert!(
        commit.status.success(),
        "manifest-only change was blocked: {}",
        String::from_utf8_lossy(&commit.stderr)
    );
    assert!(String::from_utf8_lossy(&commit.stderr).contains("incomplete"));
}

#[test]
fn hook_modes_continue_when_the_check_itself_cannot_run() {
    // A plain directory has no Git history, so the pre-push check cannot read pushed commits.
    let directory = tempfile::tempdir().unwrap();
    let environment = HookTestEnvironment::new();
    let pushed = "refs/heads/main 1111111111111111111111111111111111111111 \
                  refs/heads/main 0000000000000000000000000000000000000000\n";
    let run = |mode: &str| {
        let mut command = secmon();
        command
            .args([
                "hook",
                "run",
                "--pre-push",
                "--mode",
                mode,
                "--fail-on",
                "high",
            ])
            .current_dir(directory.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        environment.configure(&mut command);
        let mut child = command.spawn().unwrap();
        std::io::Write::write_all(&mut child.stdin.take().unwrap(), pushed.as_bytes()).unwrap();
        child.wait_with_output().unwrap()
    };

    let warn = run("warn");
    assert!(
        warn.status.success(),
        "{}",
        String::from_utf8_lossy(&warn.stderr)
    );
    let block = run("block");
    assert!(block.status.success());
    assert!(String::from_utf8_lossy(&block.stderr).contains("no threshold was confirmed"));
}

#[test]
fn agent_hook_ignores_non_git_commands_without_opening_the_database() {
    let project = tempfile::tempdir().unwrap();
    let home = HookTestEnvironment::new();
    let database = home.data_home.path().join("must-not-be-created.sqlite");
    let mut command = secmon();
    command
        .args([
            "--database",
            database.to_str().unwrap(),
            "hook",
            "run",
            "--mode",
            "block",
            "--agent-event",
        ])
        .current_dir(project.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    home.configure(&mut command);
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status"}}"#,
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "agent hook failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!database.exists());
}
