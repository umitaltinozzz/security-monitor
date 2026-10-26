use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    io::{self, Read},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration as StdDuration, Instant},
};

use chrono::{Duration, Utc};
use security_monitor_advisory_providers::{
    AdvisoryFinding, AdvisoryMerger, FindingReason, OsvDatabase, ecosystem_slug, evaluate_inventory,
};
use security_monitor_core::{Advisory, FindingStatus, Severity};
use security_monitor_database::Database;
use security_monitor_inventory::{Inventory, is_dependency_file, scan_repository};
use security_monitor_reporting::FailOn;

const MAX_HOOK_INPUT_BYTES: usize = 256 * 1024;
const MAX_GIT_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_CHANGED_FILES: usize = 1024;
const MAX_CHANGED_FILE_BYTES: usize = 32 * 1024 * 1024;
const MAX_CHANGED_BYTES: usize = 128 * 1024 * 1024;
const GIT_PROCESS_TIMEOUT: StdDuration = StdDuration::from_secs(30);
const OSV_FRESHNESS: Duration = Duration::hours(24);
pub(super) const THRESHOLD_BREACH_EXIT: i32 = 2;
pub(super) const VERIFICATION_INCOMPLETE_EXIT: i32 = 3;

struct SnapshotChanges {
    revision: String,
    files: BTreeMap<PathBuf, bool>,
}

pub async fn scan_changed_inputs(
    repository: &Path,
    database_path: &Path,
    app_data: &Path,
    pre_push: bool,
    fail_on: FailOn,
) -> Result<i32, &'static str> {
    let repository = repository
        .canonicalize()
        .map_err(|_| "repository_unavailable")?;
    let snapshots = if pre_push {
        pre_push_snapshots(&repository)?
    } else {
        pre_commit_snapshot(&repository)?
            .into_iter()
            .collect::<Vec<_>>()
    };
    let snapshots = snapshots
        .into_iter()
        .filter(|snapshot| !snapshot.files.is_empty())
        .collect::<Vec<_>>();
    if snapshots.is_empty() {
        println!("hook: no changed dependency inputs");
        return Ok(0);
    }

    let mut finding_count = 0;
    let mut needs_review = false;
    let mut changed_input_count = 0;
    let mut total_bytes = 0_usize;
    for snapshot in snapshots {
        let temporary = tempfile::tempdir().map_err(|_| "hook_scan_unavailable")?;
        let mut has_supported_input = false;
        let mut has_unparsed_input = false;
        for (relative, deleted) in &snapshot.files {
            changed_input_count += 1;
            if *deleted {
                needs_review = true;
                continue;
            }
            has_supported_input |= is_scannable_input(relative);
            has_unparsed_input |= !is_scannable_input(relative);
            if changed_input_count > MAX_CHANGED_FILES {
                return Err("hook_scan_limits_exceeded");
            }
            let specification = if snapshot.revision == "index" {
                format!(":{}", relative.to_string_lossy().replace('\\', "/"))
            } else {
                format!(
                    "{}:{}",
                    snapshot.revision,
                    relative.to_string_lossy().replace('\\', "/")
                )
            };
            let bytes = match git_output(
                &repository,
                ["show", "--no-ext-diff", "--no-textconv"]
                    .into_iter()
                    .map(OsString::from)
                    .chain([OsString::from(specification)])
                    .collect::<Vec<_>>(),
                MAX_CHANGED_FILE_BYTES,
            ) {
                Ok(bytes) => bytes,
                Err(_) => {
                    needs_review = true;
                    continue;
                }
            };
            total_bytes = total_bytes
                .checked_add(bytes.len())
                .filter(|total| *total <= MAX_CHANGED_BYTES)
                .ok_or("hook_scan_limits_exceeded")?;
            let target = temporary.path().join(relative);
            let parent = target.parent().ok_or("hook_scan_unavailable")?;
            fs::create_dir_all(parent).map_err(|_| "hook_scan_unavailable")?;
            fs::write(target, bytes).map_err(|_| "hook_scan_unavailable")?;
        }
        if !has_supported_input || has_unparsed_input {
            needs_review = true;
        }
        let inventory = scan_repository(temporary.path()).map_err(|_| "hook_scan_unavailable")?;
        if !inventory.complete {
            needs_review = true;
        }
        let (count, cache_needs_review, threshold_exceeded) =
            offline_findings(&inventory, database_path, app_data, fail_on).await;
        finding_count += count;
        needs_review |= cache_needs_review;
        if threshold_exceeded {
            println!(
                "hook: {changed_input_count} changed dependency input(s); {finding_count} finding(s)"
            );
            return Ok(THRESHOLD_BREACH_EXIT);
        }
    }

    println!(
        "hook: {changed_input_count} changed dependency input(s); {finding_count} finding(s); verification: {}",
        if needs_review {
            "needs_review"
        } else {
            "verified"
        }
    );
    Ok(if needs_review { 3 } else { 0 })
}

fn pre_commit_snapshot(repository: &Path) -> Result<Option<SnapshotChanges>, &'static str> {
    let args = [
        "diff",
        "--cached",
        "--no-ext-diff",
        "--no-textconv",
        "--name-status",
        "-z",
        "--no-renames",
        "--diff-filter=ACMTD",
        "--",
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    let output = git_output(repository, args, MAX_GIT_OUTPUT_BYTES)?;
    let files = parse_changed_paths(&output)?;
    Ok((!files.is_empty()).then_some(SnapshotChanges {
        revision: "index".to_owned(),
        files,
    }))
}

fn pre_push_snapshots(repository: &Path) -> Result<Vec<SnapshotChanges>, &'static str> {
    let mut input = Vec::new();
    io::stdin()
        .take((MAX_HOOK_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| "hook_input_unavailable")?;
    if input.len() > MAX_HOOK_INPUT_BYTES {
        return Err("hook_input_too_large");
    }
    let input = std::str::from_utf8(&input).map_err(|_| "hook_input_invalid")?;
    pre_push_snapshots_from_input(repository, input)
}

fn pre_push_snapshots_from_input(
    repository: &Path,
    input: &str,
) -> Result<Vec<SnapshotChanges>, &'static str> {
    let mut updates = BTreeSet::<(String, String)>::new();
    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 4 {
            return Err("hook_input_invalid");
        }
        let local = fields[1];
        let remote = fields[3];
        validate_object_id(local)?;
        validate_object_id(remote)?;
        if is_zero_object_id(local) {
            continue;
        }
        let base = if is_zero_object_id(remote) {
            empty_tree_id(repository)?
        } else {
            remote.to_owned()
        };
        updates.insert((local.to_owned(), base));
    }

    let mut snapshots = Vec::new();
    for (local, base) in updates {
        let args = [
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--name-status",
            "-z",
            "--no-renames",
            "--diff-filter=ACMTD",
        ]
        .into_iter()
        .map(OsString::from)
        .chain([OsString::from(base), OsString::from(local.clone())])
        .chain([OsString::from("--")])
        .collect::<Vec<_>>();
        let output = git_output(repository, args, MAX_GIT_OUTPUT_BYTES)?;
        let files = parse_changed_paths(&output)?;
        if !files.is_empty() {
            snapshots.push(SnapshotChanges {
                revision: local,
                files,
            });
        }
    }
    Ok(snapshots)
}

fn parse_changed_paths(output: &[u8]) -> Result<BTreeMap<PathBuf, bool>, &'static str> {
    let fields = output
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    let (pairs, remainder) = fields.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err("hook_git_output_invalid");
    }
    let mut paths = BTreeMap::new();
    for [status_field, path_field] in pairs {
        let status = std::str::from_utf8(status_field).map_err(|_| "hook_git_output_invalid")?;
        if status.len() != 1 {
            return Err("hook_git_output_invalid");
        }
        let path_text = std::str::from_utf8(path_field).map_err(|_| "hook_path_invalid")?;
        let path = PathBuf::from(path_text);
        if !safe_relative_path(&path) {
            return Err("hook_path_invalid");
        }
        if !is_dependency_file(&path) {
            continue;
        }
        paths.insert(path, status == "D");
    }
    Ok(paths)
}

fn safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn is_scannable_input(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    matches!(
        name,
        "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "bun.lock"
            | "poetry.lock"
            | "uv.lock"
            | "Pipfile.lock"
            | "composer.lock"
            | "go.sum"
            | "go.mod"
            | "Cargo.lock"
    ) || (name.starts_with("requirements")
        && Path::new(name)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("txt")))
}

async fn offline_findings(
    inventory: &Inventory,
    database_path: &Path,
    app_data: &Path,
    fail_on: FailOn,
) -> (usize, bool, bool) {
    let mut needs_review = false;
    let mut advisories = Vec::<Advisory>::new();
    if database_path.is_file() {
        match Database::open_read_only(database_path).await {
            Ok(database) => {
                match database.repository::<Advisory>().list().await {
                    Ok(records) => advisories.extend(records),
                    Err(_) => needs_review = true,
                }
                database.close().await;
            }
            Err(_) => needs_review = true,
        }
    }

    let cache_root = app_data.join("advisories").join("osv");
    let mut osv_databases = BTreeMap::<String, Option<OsvDatabase>>::new();
    let now = Utc::now();
    for component in &inventory.components {
        let Some(slug) = ecosystem_slug(&component.ecosystem) else {
            needs_review = true;
            continue;
        };
        if !osv_databases.contains_key(slug) {
            let opened = match OsvDatabase::open(cache_root.join(slug)) {
                Ok(cache) => {
                    let status = cache.status();
                    if status.stale
                        || !status.updated_at.is_some_and(|updated| {
                            updated <= now && now.signed_duration_since(updated) < OSV_FRESHNESS
                        })
                    {
                        needs_review = true;
                    }
                    Some(cache)
                }
                Err(_) => {
                    needs_review = true;
                    None
                }
            };
            osv_databases.insert(slug.to_owned(), opened);
        }
        if let Some(cache) = osv_databases.get(slug).and_then(Option::as_ref) {
            advisories.extend(cache.query(&component.ecosystem, &component.name));
        } else {
            // A single failed ecosystem load invalidates every component check in that ecosystem.
            needs_review = true;
        }
    }

    let advisories = AdvisoryMerger::new(advisories).into_records();
    let findings = evaluate_inventory(&advisories, inventory);
    needs_review |= findings_require_review(&findings);
    let threshold = match fail_on {
        FailOn::Critical => 4,
        FailOn::High => 3,
        FailOn::Medium => 2,
        FailOn::Low => 1,
    };
    let severities = advisories
        .iter()
        .map(|advisory| {
            (
                advisory.canonical_id.as_str(),
                advisory_severity_rank(advisory),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let threshold_exceeded = findings.iter().any(|finding| {
        severities
            .get(finding.advisory_id.as_str())
            .is_some_and(|rank| finding_exceeds_threshold(finding.reason, *rank, threshold))
    });
    (findings.len(), needs_review, threshold_exceeded)
}

fn findings_require_review(findings: &[AdvisoryFinding]) -> bool {
    findings
        .iter()
        .any(|finding| finding.status == FindingStatus::NeedsReview)
}

fn finding_exceeds_threshold(reason: FindingReason, severity_rank: u8, threshold: u8) -> bool {
    reason == FindingReason::AffectedVersion && severity_rank >= threshold && severity_rank > 0
}

fn advisory_severity_rank(advisory: &Advisory) -> u8 {
    match advisory.severity.as_ref() {
        Some(Severity::Critical) => 4,
        Some(Severity::High) => 3,
        Some(Severity::Medium) => 2,
        Some(Severity::Low) => 1,
        Some(Severity::Unknown) | None => advisory.cvss.map_or(0, |score| {
            if score >= 9.0 {
                4
            } else if score >= 7.0 {
                3
            } else if score >= 4.0 {
                2
            } else if score > 0.0 {
                1
            } else {
                0
            }
        }),
    }
}

fn validate_object_id(value: &str) -> Result<(), &'static str> {
    if matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("hook_input_invalid")
    }
}

fn is_zero_object_id(value: &str) -> bool {
    value.bytes().all(|byte| byte == b'0')
}

fn empty_tree_id(repository: &Path) -> Result<String, &'static str> {
    let output = git_output(
        repository,
        ["hash-object", "-t", "tree", "--stdin"]
            .into_iter()
            .map(OsString::from)
            .collect(),
        128,
    )?;
    let value = std::str::from_utf8(&output)
        .map_err(|_| "hook_git_output_invalid")?
        .trim();
    validate_object_id(value)?;
    Ok(value.to_owned())
}

fn git_output(
    repository: &Path,
    args: Vec<OsString>,
    max_bytes: usize,
) -> Result<Vec<u8>, &'static str> {
    let mut command = Command::new("git");
    command
        .args(args)
        .current_dir(repository)
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_TERMINAL_PROMPT", "0");
    git_output_with_timeout(command, max_bytes, GIT_PROCESS_TIMEOUT)
}

fn git_output_with_timeout(
    mut command: Command,
    max_bytes: usize,
    timeout: StdDuration,
) -> Result<Vec<u8>, &'static str> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "hook_git_unavailable")?;
    let mut stdout = child.stdout.take().ok_or("hook_git_operation_failed")?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let mut output = Vec::new();
        let result = stdout
            .by_ref()
            .take(max_bytes.saturating_add(1) as u64)
            .read_to_end(&mut output)
            .map(|_| output);
        let _ = sender.send(result);
    });
    let deadline = Instant::now() + timeout;
    let mut output = None;
    loop {
        if output.is_none() {
            match receiver.try_recv() {
                Ok(Ok(bytes)) => {
                    if bytes.len() > max_bytes {
                        terminate_git_process(&mut child);
                        let _ = reader.join();
                        return Err("hook_scan_limits_exceeded");
                    }
                    output = Some(bytes);
                }
                Ok(Err(_)) => {
                    terminate_git_process(&mut child);
                    let _ = reader.join();
                    return Err("hook_git_operation_failed");
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    terminate_git_process(&mut child);
                    let _ = reader.join();
                    return Err("hook_git_operation_failed");
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(_) => {
                terminate_git_process(&mut child);
                let _ = reader.join();
                return Err("hook_git_operation_failed");
            }
        };
        if let Some(status) = status {
            if !status.success() {
                terminate_git_process(&mut child);
                let _ = reader.join();
                return Err("hook_git_operation_failed");
            }
            if let Some(output) = output {
                let _ = reader.join();
                return Ok(output);
            }
        }
        if Instant::now() >= deadline {
            terminate_git_process(&mut child);
            let _ = reader.join();
            return Err("hook_git_timeout");
        }
        thread::sleep(StdDuration::from_millis(10));
    }
}

fn terminate_git_process(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let _ = unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use security_monitor_advisory_providers::{FindingReason, evaluate_inventory};
    use security_monitor_core::{Advisory, AffectedRange, FindingStatus, RangeEvent, Severity};
    use security_monitor_inventory::{Inventory, InventoryComponent};
    use std::{
        ffi::OsStr,
        path::{Path, PathBuf},
        process::Command,
        time::{Duration as StdDuration, Instant},
    };

    use super::{
        AdvisoryMerger, OSV_FRESHNESS, finding_exceeds_threshold, findings_require_review,
        git_output_with_timeout, is_scannable_input, parse_changed_paths,
        pre_push_snapshots_from_input, safe_relative_path,
    };

    #[test]
    fn git_timeout_child_fixture() {
        if std::env::var_os("SECMON_GIT_TIMEOUT_FIXTURE").is_some() {
            std::thread::sleep(StdDuration::from_secs(5));
        }
    }

    #[test]
    fn git_subprocess_timeout_kills_the_child() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "hooks::tests::git_timeout_child_fixture",
                "--nocapture",
            ])
            .env("SECMON_GIT_TIMEOUT_FIXTURE", "1");
        let started = Instant::now();
        let result = git_output_with_timeout(command, 1024, StdDuration::from_millis(100));
        assert_eq!(result, Err("hook_git_timeout"));
        assert!(started.elapsed() < StdDuration::from_secs(3));
    }

    fn git(repository: &Path, args: &[&OsStr]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(repository)
            .output()
            .expect("git is available for the hook integration test");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("git output is UTF-8")
            .trim()
            .to_owned()
    }

    #[test]
    fn changed_file_parser_only_accepts_safe_dependency_inputs() {
        let changed = b"M\0package-lock.json\0A\0src/main.rs\0D\0Cargo.lock\0";
        let paths = parse_changed_paths(changed).unwrap();
        assert_eq!(paths.get(Path::new("package-lock.json")), Some(&false));
        assert_eq!(paths.get(Path::new("Cargo.lock")), Some(&true));
        assert!(!paths.contains_key(Path::new("src/main.rs")));
        assert!(safe_relative_path(Path::new("project/package-lock.json")));
        assert!(!safe_relative_path(Path::new("../package-lock.json")));
        assert!(is_scannable_input(Path::new("requirements.txt")));
        assert!(!is_scannable_input(Path::new("package.json")));
    }

    #[test]
    fn block_threshold_requires_a_verified_affected_version() {
        assert!(finding_exceeds_threshold(
            FindingReason::AffectedVersion,
            3,
            3
        ));
        for reason in [
            FindingReason::VersionDataPending,
            FindingReason::SourceDisagreement,
            FindingReason::VersionRangeUnverified,
        ] {
            assert!(!finding_exceeds_threshold(reason, 4, 3));
        }
        assert!(!finding_exceeds_threshold(
            FindingReason::AffectedVersion,
            2,
            3
        ));
    }

    #[test]
    fn osv_cache_freshness_window_is_24_hours() {
        assert_eq!(OSV_FRESHNESS, Duration::hours(24));
    }

    fn advisory(fixed: &str, source: &str) -> Advisory {
        let now = Utc::now();
        Advisory {
            canonical_id: "CVE-2026-7001".to_owned(),
            title: "Fixture advisory".to_owned(),
            summary: None,
            summary_model: None,
            description: None,
            source_attributions: Vec::new(),
            aliases: Vec::new(),
            affected_ranges: vec![AffectedRange {
                ecosystem: "npm".to_owned(),
                package: Some("fixture-package".to_owned()),
                source: Some(source.to_owned()),
                range_type: Some("SEMVER".to_owned()),
                events: vec![RangeEvent {
                    introduced: Some("1.0.0".to_owned()),
                    fixed: Some(fixed.to_owned()),
                    last_affected: None,
                    limit: None,
                }],
            }],
            fixed_versions: vec![fixed.to_owned()],
            cvss: Some(8.0),
            severity: Some(Severity::High),
            kev: false,
            epss: None,
            epss_date: None,
            source_urls: Vec::new(),
            source_updated_at: Some(now),
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn newer_osv_ranges_are_merged_and_conflicts_require_review() {
        let advisories = AdvisoryMerger::new([
            advisory("2.0.0", "local database"),
            advisory("3.0.0", "OSV"),
        ])
        .into_records();
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].affected_ranges.len(), 2);

        let inventory = Inventory {
            components: vec![InventoryComponent {
                purl: "pkg:npm/fixture-package@2.5.0".to_owned(),
                ecosystem: "npm".to_owned(),
                name: "fixture-package".to_owned(),
                version: Some("2.5.0".to_owned()),
                source_type: "lockfile".to_owned(),
                evidence_paths: vec!["package-lock.json".to_owned()],
            }],
            project_roots: Vec::new(),
            detected_files: Vec::new(),
            diagnostics: Vec::new(),
            complete: true,
        };
        let findings = evaluate_inventory(&advisories, &inventory);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].reason, FindingReason::SourceDisagreement);
        assert_eq!(findings[0].status, FindingStatus::NeedsReview);
        assert!(findings_require_review(&findings));
    }

    #[test]
    fn pre_push_keeps_distinct_ref_updates_for_the_same_local_commit() {
        let temp = tempfile::tempdir().unwrap();
        let repository = temp.path();
        git(repository, &[OsStr::new("init"), OsStr::new("--quiet")]);
        git(
            repository,
            &[
                OsStr::new("config"),
                OsStr::new("user.name"),
                OsStr::new("Fixture"),
            ],
        );
        git(
            repository,
            &[
                OsStr::new("config"),
                OsStr::new("user.email"),
                OsStr::new("fixture@example.invalid"),
            ],
        );
        std::fs::write(repository.join("README.md"), "base\n").unwrap();
        git(
            repository,
            &[OsStr::new("add"), OsStr::new("--"), OsStr::new("README.md")],
        );
        git(
            repository,
            &[
                OsStr::new("commit"),
                OsStr::new("--quiet"),
                OsStr::new("-m"),
                OsStr::new("base"),
            ],
        );
        let first_base = git(repository, &[OsStr::new("rev-parse"), OsStr::new("HEAD")]);

        std::fs::write(repository.join("package-lock.json"), "fixture lock\n").unwrap();
        git(
            repository,
            &[
                OsStr::new("add"),
                OsStr::new("--"),
                OsStr::new("package-lock.json"),
            ],
        );
        git(
            repository,
            &[
                OsStr::new("commit"),
                OsStr::new("--quiet"),
                OsStr::new("-m"),
                OsStr::new("dependency input"),
            ],
        );
        let second_base = git(repository, &[OsStr::new("rev-parse"), OsStr::new("HEAD")]);

        std::fs::write(repository.join("README.md"), "updated\n").unwrap();
        git(
            repository,
            &[OsStr::new("add"), OsStr::new("--"), OsStr::new("README.md")],
        );
        git(
            repository,
            &[
                OsStr::new("commit"),
                OsStr::new("--quiet"),
                OsStr::new("-m"),
                OsStr::new("same target"),
            ],
        );
        let local = git(repository, &[OsStr::new("rev-parse"), OsStr::new("HEAD")]);
        let updates = format!(
            "refs/heads/one {local} refs/remotes/origin/one {first_base}\nrefs/heads/two {local} refs/remotes/origin/two {second_base}\n"
        );

        let snapshots = pre_push_snapshots_from_input(repository, &updates).unwrap();
        assert_eq!(snapshots.len(), 1);
        assert!(snapshots.iter().any(|snapshot| {
            snapshot
                .files
                .contains_key(&PathBuf::from("package-lock.json"))
        }));
    }
}
