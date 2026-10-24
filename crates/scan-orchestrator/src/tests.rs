use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use security_monitor_advisory_providers::HttpPolicy;
use security_monitor_core::{
    Advisory, AffectedRange, ComponentInstance, Finding, Project, ProjectScanCheckpoint,
    RangeEvent, ScanOutcome, ScanRun, Severity,
};
use security_monitor_database::Database;
use tokio_util::sync::CancellationToken;

use crate::{
    DebouncedChanges, FileChangeKind, LocalProjectScanner, LocalScanSettings, QueueWaitError,
    ScanError, ScanExecutor, ScanLimits, ScanProfile, ScanQueue, ScanReason, ScanRequest,
    ScanSummary, ScheduleAction, SchedulePlan, Scheduler, discover_projects,
    hash_dependency_inputs,
};

const FIXTURE_LOCKFILE: &str =
    include_str!("../../../tests/fixtures/orchestration/package-lock.json");

fn fixture_project(base: &Path, id: &str) -> Project {
    let root = base.join(id);
    fs::create_dir_all(&root).expect("create fixture project");
    fs::write(root.join("package-lock.json"), FIXTURE_LOCKFILE).expect("write fixture lockfile");
    let now = Utc.with_ymd_and_hms(2026, 10, 24, 12, 0, 0).unwrap();
    Project {
        id: id.to_owned(),
        name: id.to_owned(),
        root_path: root.to_string_lossy().into_owned(),
        git_remote: None,
        reference_branch: None,
        allowed_ai_providers: Vec::new(),
        last_scan_at: None,
        created_at: now,
        updated_at: now,
    }
}

fn scanner(database: Database, app_data: &Path) -> Arc<LocalProjectScanner> {
    Arc::new(
        LocalProjectScanner::new(
            database,
            app_data,
            HttpPolicy {
                public_downloads_enabled: false,
            },
            LocalScanSettings::default(),
        )
        .expect("construct scanner"),
    )
}

fn limits(max_parallel_scans: usize, queue_capacity: usize) -> ScanLimits {
    ScanLimits {
        max_parallel_scans,
        queue_capacity,
        max_scan_duration: Duration::from_secs(120),
    }
}

#[test]
fn debounce_resets_three_second_window_and_full_profile_wins() {
    let start = tokio::time::Instant::now();
    let mut changes = DebouncedChanges::new(Duration::from_secs(3));
    changes.push(
        PathBuf::from("package-lock.json"),
        FileChangeKind::DependencyInput,
        start,
    );
    changes.push(
        PathBuf::from("src/main.rs"),
        FileChangeKind::SourceOrConfiguration,
        start + Duration::from_secs(2),
    );

    assert!(
        changes
            .take_if_ready(start + Duration::from_secs(4))
            .is_none()
    );
    let batch = changes
        .take_if_ready(start + Duration::from_secs(5))
        .expect("debounced batch");
    assert_eq!(batch.profile, ScanProfile::Full);
    assert_eq!(
        batch.paths,
        vec![
            PathBuf::from("package-lock.json"),
            PathBuf::from("src/main.rs")
        ]
    );
}

#[test]
fn input_hash_changes_with_lockfile_and_unknown_or_over_limit_inputs_are_incomplete() {
    let temp = tempfile::tempdir().unwrap();
    let project = fixture_project(temp.path(), "hash-project");
    let root = Path::new(&project.root_path);
    let first = hash_dependency_inputs(root, Default::default());
    assert!(first.complete);
    assert!(first.sha256.is_some());

    fs::write(
        root.join("package-lock.json"),
        FIXTURE_LOCKFILE.replace("2.4.1", "2.4.2"),
    )
    .unwrap();
    let changed = hash_dependency_inputs(root, Default::default());
    assert!(changed.complete);
    assert_ne!(first.sha256, changed.sha256);

    let limited = hash_dependency_inputs(
        root,
        crate::InputHashLimits {
            max_files: 1,
            max_bytes: 1,
        },
    );
    assert!(!limited.complete);
    assert!(limited.sha256.is_none());

    let empty = temp.path().join("empty-project");
    fs::create_dir(&empty).unwrap();
    assert!(!hash_dependency_inputs(&empty, Default::default()).complete);
}

#[test]
fn discovery_returns_nested_gitless_fixture_projects_for_review() {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/inventory/monorepo");
    let discovered = discover_projects(fixture).expect("discover fixture projects");
    let relative = discovered
        .candidates
        .iter()
        .map(|candidate| {
            candidate
                .root_path
                .strip_prefix(&discovered.parent)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect::<Vec<_>>();
    assert!(discovered.complete);
    assert!(relative.iter().any(String::is_empty));
    assert!(relative.iter().any(|path| path == "apps/api"));
}

#[tokio::test]
async fn startup_scans_only_changed_projects_and_reports_unverified_roots() {
    let temp = tempfile::tempdir().unwrap();
    let database = Database::in_memory().await.unwrap();
    let projects = vec![
        fixture_project(temp.path(), "project-a"),
        fixture_project(temp.path(), "project-b"),
    ];
    for project in &projects {
        database
            .repository::<Project>()
            .create(project)
            .await
            .unwrap();
    }
    let invalid = Project {
        root_path: temp
            .path()
            .join("missing-project")
            .to_string_lossy()
            .into_owned(),
        id: "unverified-project".to_owned(),
        name: "unverified-project".to_owned(),
        git_remote: None,
        reference_branch: None,
        allowed_ai_providers: Vec::new(),
        last_scan_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let scanner = scanner(database.clone(), temp.path().join("app-data").as_path());
    let queue = scanner.queue(limits(2, 8)).unwrap();

    let first = scanner.startup_check(&projects, &queue).await.unwrap();
    assert_eq!(first.scanned_project_ids, vec!["project-a", "project-b"]);
    assert!(first.unchanged_project_ids.is_empty());
    assert_eq!(
        database
            .repository::<ProjectScanCheckpoint>()
            .list()
            .await
            .unwrap()
            .len(),
        2
    );

    let second = scanner.startup_check(&projects, &queue).await.unwrap();
    assert!(second.scanned_project_ids.is_empty());
    assert_eq!(second.unchanged_project_ids, vec!["project-a", "project-b"]);

    let changed_lockfile = Path::new(&projects[0].root_path).join("package-lock.json");
    fs::write(
        &changed_lockfile,
        FIXTURE_LOCKFILE.replace("2.4.1", "2.4.2"),
    )
    .unwrap();
    let third = scanner
        .startup_check(&[projects[0].clone(), projects[1].clone(), invalid], &queue)
        .await
        .unwrap();
    assert_eq!(third.scanned_project_ids, vec!["project-a"]);
    assert_eq!(third.unchanged_project_ids, vec!["project-b"]);
    assert_eq!(third.unverified_project_ids, vec!["unverified-project"]);
}

fn left_pad_advisory() -> Advisory {
    let now = Utc.with_ymd_and_hms(2026, 10, 24, 12, 0, 0).unwrap();
    Advisory {
        canonical_id: "CVE-2099-0001".to_owned(),
        title: "Fixture advisory".to_owned(),
        summary: None,
        summary_model: None,
        description: None,
        source_attributions: Vec::new(),
        aliases: Vec::new(),
        affected_ranges: vec![AffectedRange {
            ecosystem: "npm".to_owned(),
            package: Some("left-pad".to_owned()),
            source: Some("OSV".to_owned()),
            range_type: Some("SEMVER".to_owned()),
            events: vec![RangeEvent {
                introduced: Some("1.0.0".to_owned()),
                fixed: Some("1.3.1".to_owned()),
                last_affected: None,
                limit: None,
            }],
        }],
        fixed_versions: vec!["1.3.1".to_owned()],
        cvss: Some(9.8),
        severity: Some(Severity::Critical),
        kev: false,
        epss: None,
        epss_date: None,
        source_urls: Vec::new(),
        source_updated_at: Some(now),
        created_at: now,
        updated_at: now,
    }
}

#[tokio::test]
async fn new_advisory_recorrelates_cached_inventory_without_another_scan() {
    let temp = tempfile::tempdir().unwrap();
    let database = Database::in_memory().await.unwrap();
    let project = fixture_project(temp.path(), "advisory-project");
    database
        .repository::<Project>()
        .create(&project)
        .await
        .unwrap();
    let scanner = scanner(database.clone(), temp.path().join("app-data").as_path());
    let queue = scanner.queue(limits(1, 4)).unwrap();
    let handle = queue
        .enqueue(ScanRequest {
            project_id: project.id.clone(),
            root: PathBuf::from(&project.root_path),
            profile: ScanProfile::Quick,
            reason: ScanReason::Manual,
        })
        .await
        .unwrap();
    let scan = handle.wait().await.unwrap();
    assert_eq!(scan.outcome, ScanOutcome::Partial);
    assert!(scan.inventory_complete);
    assert_eq!(
        database.repository::<ScanRun>().list().await.unwrap().len(),
        1
    );

    database
        .repository::<security_monitor_core::Advisory>()
        .create(&left_pad_advisory())
        .await
        .unwrap();
    let updated_findings =
        tokio::time::timeout(Duration::from_secs(15), queue.refresh_advisories())
            .await
            .expect("advisory re-correlation must not deadlock")
            .unwrap();

    assert!(updated_findings > 0);
    assert!(
        !database
            .repository::<Finding>()
            .list()
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        database.repository::<ScanRun>().list().await.unwrap().len(),
        1
    );
    let instances = database
        .repository::<ComponentInstance>()
        .list()
        .await
        .unwrap();
    assert!(
        instances
            .iter()
            .any(|instance| instance.project_id.as_deref() == Some("advisory-project"))
    );
}

#[tokio::test]
async fn fifty_gitless_fixture_projects_complete_quick_scans_within_two_minutes() {
    let temp = tempfile::tempdir().unwrap();
    let database = Database::in_memory().await.unwrap();
    let scanner = scanner(database.clone(), temp.path().join("app-data").as_path());
    let queue = scanner.queue(limits(2, 64)).unwrap();
    let mut handles = Vec::new();
    for index in 0..50 {
        let id = format!("fixture-project-{index:02}");
        let project = fixture_project(temp.path(), &id);
        database
            .repository::<Project>()
            .create(&project)
            .await
            .unwrap();
        handles.push(
            queue
                .enqueue(ScanRequest {
                    project_id: project.id,
                    root: PathBuf::from(project.root_path),
                    profile: ScanProfile::Quick,
                    reason: ScanReason::Manual,
                })
                .await
                .unwrap(),
        );
    }

    let started = Instant::now();
    tokio::time::timeout(Duration::from_secs(120), async {
        for handle in handles {
            let summary = handle.wait().await.unwrap();
            assert!(summary.inventory_complete);
            assert_eq!(summary.outcome, ScanOutcome::Partial);
        }
    })
    .await
    .expect("50-project quick scan exceeded two minutes");
    assert!(started.elapsed() < Duration::from_secs(120));
    assert_eq!(
        database
            .repository::<ProjectScanCheckpoint>()
            .list()
            .await
            .unwrap()
            .len(),
        50
    );
}

struct ConcurrencyExecutor {
    active: Arc<AtomicUsize>,
    maximum: Arc<AtomicUsize>,
}

#[async_trait]
impl ScanExecutor for ConcurrencyExecutor {
    async fn scan(
        &self,
        _request: ScanRequest,
        cancellation: CancellationToken,
    ) -> Result<ScanSummary, ScanError> {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.maximum.fetch_max(active, Ordering::SeqCst);
        tokio::select! {
            _ = cancellation.cancelled() => {
                self.active.fetch_sub(1, Ordering::SeqCst);
                return Err(ScanError::Cancelled);
            }
            _ = tokio::time::sleep(Duration::from_millis(15)) => {}
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
        Ok(ScanSummary {
            scan_id: "fixture-scan".to_owned(),
            outcome: ScanOutcome::Succeeded,
            input_hash: Some("fixture-hash".to_owned()),
            inventory_complete: true,
            component_count: 0,
            correlated_finding_count: 0,
            scanner_findings: 0,
            diagnostics: Vec::new(),
            executions: Vec::new(),
        })
    }

    async fn refresh_advisories(
        &self,
        _cancellation: CancellationToken,
    ) -> Result<usize, ScanError> {
        Ok(0)
    }
}

#[tokio::test]
async fn queue_enforces_parallel_limit_and_supports_cancellation() {
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let executor = Arc::new(ConcurrencyExecutor {
        active: active.clone(),
        maximum: maximum.clone(),
    });
    let queue = ScanQueue::new(executor, limits(2, 8)).unwrap();
    let mut handles = Vec::new();
    for index in 0..6 {
        handles.push(
            queue
                .enqueue(ScanRequest {
                    project_id: format!("project-{index}"),
                    root: PathBuf::from("fixture"),
                    profile: ScanProfile::Quick,
                    reason: ScanReason::Manual,
                })
                .await
                .unwrap(),
        );
    }
    for handle in handles {
        assert_eq!(handle.wait().await.unwrap().outcome, ScanOutcome::Succeeded);
    }
    assert!(maximum.load(Ordering::SeqCst) <= 2);

    let handle = queue
        .enqueue(ScanRequest {
            project_id: "cancelled-project".to_owned(),
            root: PathBuf::from("fixture"),
            profile: ScanProfile::Quick,
            reason: ScanReason::Manual,
        })
        .await
        .unwrap();
    handle.cancel();
    assert!(matches!(
        handle.wait().await,
        Err(QueueWaitError::Scan(ScanError::Cancelled))
    ));
}

#[test]
fn scheduler_reports_each_due_action_without_catching_up_missed_ticks() {
    let start = tokio::time::Instant::now();
    let plan = SchedulePlan {
        inventory_check_interval: Duration::from_secs(15),
        advisory_refresh_interval: Duration::from_secs(10),
        full_scan_interval: Duration::from_secs(30),
    };
    let mut scheduler = Scheduler::new(plan, start).unwrap();

    assert_eq!(
        scheduler.due_actions(start + Duration::from_secs(10)),
        vec![ScheduleAction::RefreshAdvisories]
    );
    assert_eq!(
        scheduler.due_actions(start + Duration::from_secs(31)),
        vec![
            ScheduleAction::CheckProjects,
            ScheduleAction::RefreshAdvisories,
            ScheduleAction::FullScanProjects,
        ]
    );
    assert!(
        scheduler
            .due_actions(start + Duration::from_secs(32))
            .is_empty()
    );
}
