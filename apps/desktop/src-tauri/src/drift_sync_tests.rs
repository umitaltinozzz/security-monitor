use std::{collections::HashSet, path::Path, process::Command};

use chrono::{DateTime, Duration, Utc};
use security_monitor_agent_protocol::AgentInventory;
use security_monitor_core::{
    Advisory, Component, ComponentInstance, Finding, FindingDisposition, FindingDispositionReason,
    FindingStatus, ProductionStatus, Project, RepoStatus, Severity,
};
use security_monitor_database::Database;
use security_monitor_drift::WorkingTreeStatus;
use security_monitor_inventory::Inventory;

use super::{
    GitReference, apply_drift, dependency_tree_status, normalize_remote, read_git_reference,
    select_deployment,
};

const ADVISORY: &str = include_str!("../../../../tests/fixtures/drift/advisory.json");
const REFERENCE_FIXED: &str = include_str!("../../../../tests/fixtures/drift/reference-fixed.json");
const PRODUCTION_AFFECTED: &str =
    include_str!("../../../../tests/fixtures/drift/production-affected.json");
const PRODUCTION_FIXED: &str =
    include_str!("../../../../tests/fixtures/drift/production-fixed.json");

fn now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-10-24T12:00:00Z")
        .expect("fixed timestamp is valid")
        .with_timezone(&Utc)
}

fn parse<T: serde::de::DeserializeOwned>(value: &str) -> T {
    serde_json::from_str(value).expect("fixture JSON is valid")
}

fn verified_main() -> GitReference {
    GitReference {
        branch: "main".to_owned(),
        commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        head_verified: true,
        working_tree: WorkingTreeStatus::Clean,
    }
}

async fn seeded(status: FindingStatus) -> (Database, Project) {
    let database = Database::in_memory()
        .await
        .expect("in-memory database opens");
    let project = Project {
        id: "project-web".to_owned(),
        name: "web".to_owned(),
        root_path: "C:/fixture/web".to_owned(),
        git_remote: Some("git@github.com:acme/web.git".to_owned()),
        reference_branch: Some("main".to_owned()),
        allowed_ai_providers: Vec::new(),
        last_scan_at: None,
        created_at: now(),
        updated_at: now(),
    };
    database
        .repository::<Project>()
        .create(&project)
        .await
        .expect("project stored");
    let advisory: Advisory = parse(ADVISORY);
    database
        .repository::<Advisory>()
        .create(&advisory)
        .await
        .expect("advisory stored");
    let component = Component {
        id: "component-lodash".to_owned(),
        purl: "pkg:npm/lodash@4.17.20".to_owned(),
        ecosystem: "npm".to_owned(),
        name: "lodash".to_owned(),
        version: "4.17.20".to_owned(),
        source_type: "lockfile".to_owned(),
        created_at: now(),
    };
    database
        .repository::<Component>()
        .create(&component)
        .await
        .expect("component stored");
    let instance = ComponentInstance {
        id: "instance-lodash".to_owned(),
        component_id: component.id.clone(),
        project_id: Some(project.id.clone()),
        asset_id: None,
        service_id: None,
        deployment_id: None,
        evidence: Vec::new(),
        created_at: now(),
    };
    database
        .repository::<ComponentInstance>()
        .create(&instance)
        .await
        .expect("instance stored");
    let needs_disposition = status == FindingStatus::NotReachable;
    let finding = Finding {
        id: "finding-lodash".to_owned(),
        advisory_id: advisory.canonical_id.clone(),
        component_instance_id: instance.id.clone(),
        status,
        severity: Severity::High,
        priority_score: 80,
        priority_reasons: vec!["severity_base_high".to_owned()],
        fingerprint: "sha256:fixture".to_owned(),
        repo_status: RepoStatus::Unknown,
        production_status: ProductionStatus::Unknown,
        disposition: needs_disposition.then(|| FindingDisposition {
            reason: FindingDispositionReason::NoAffectedCodePath,
            scope: "finding".to_owned(),
            scope_id: "finding-lodash".to_owned(),
            set_at: now(),
            expires_at: None,
        }),
        risk_expires_at: None,
        fix_version: Some("4.17.21".to_owned()),
        created_at: now(),
        updated_at: now(),
    };
    database
        .repository::<Finding>()
        .create(&finding)
        .await
        .expect("finding stored");
    (database, project)
}

async fn stored_finding(database: &Database) -> Finding {
    database
        .repository::<Finding>()
        .get("finding-lodash")
        .await
        .expect("finding readable")
        .expect("finding exists")
}

#[tokio::test]
async fn fixed_in_repo_but_still_running_in_production_is_recorded() {
    let (database, project) = seeded(FindingStatus::ConfirmedAffected).await;
    let reference: Inventory = parse(REFERENCE_FIXED);
    let production: AgentInventory = parse(PRODUCTION_AFFECTED);

    let summary = apply_drift(
        &database,
        &project,
        Some(&verified_main()),
        Some(&reference),
        true,
        std::slice::from_ref(&production),
        now(),
    )
    .await
    .expect("drift applies");

    let finding = stored_finding(&database).await;
    assert_eq!(finding.repo_status, RepoStatus::FixedInRepo);
    assert_eq!(finding.production_status, ProductionStatus::StillAffected);
    assert_eq!(finding.status, FindingStatus::FixedInRepo);
    assert_eq!(summary.status_changes, 1);
}

#[tokio::test]
async fn production_fix_on_every_linked_server_marks_the_finding_fixed() {
    let (database, project) = seeded(FindingStatus::FixedInRepo).await;
    let reference: Inventory = parse(REFERENCE_FIXED);
    let production: AgentInventory = parse(PRODUCTION_FIXED);

    apply_drift(
        &database,
        &project,
        Some(&verified_main()),
        Some(&reference),
        true,
        &[production.clone(), production],
        now(),
    )
    .await
    .expect("drift applies");

    let finding = stored_finding(&database).await;
    assert_eq!(
        finding.production_status,
        ProductionStatus::FixedInProduction
    );
    assert_eq!(finding.status, FindingStatus::FixedInProduction);
}

#[tokio::test]
async fn one_unfixed_server_keeps_production_affected() {
    let (database, project) = seeded(FindingStatus::ConfirmedAffected).await;
    let reference: Inventory = parse(REFERENCE_FIXED);
    let fixed: AgentInventory = parse(PRODUCTION_FIXED);
    let affected: AgentInventory = parse(PRODUCTION_AFFECTED);

    apply_drift(
        &database,
        &project,
        Some(&verified_main()),
        Some(&reference),
        true,
        &[fixed, affected],
        now(),
    )
    .await
    .expect("drift applies");

    assert_eq!(
        stored_finding(&database).await.production_status,
        ProductionStatus::StillAffected
    );
}

#[tokio::test]
async fn without_linked_servers_production_stays_unknown_and_status_is_kept() {
    let (database, project) = seeded(FindingStatus::ConfirmedAffected).await;
    let reference: Inventory = parse(REFERENCE_FIXED);

    apply_drift(
        &database,
        &project,
        Some(&verified_main()),
        Some(&reference),
        false,
        &[],
        now(),
    )
    .await
    .expect("drift applies");

    let finding = stored_finding(&database).await;
    assert_eq!(finding.repo_status, RepoStatus::FixedInRepo);
    assert_eq!(finding.production_status, ProductionStatus::Unknown);
    assert_eq!(finding.status, FindingStatus::ConfirmedAffected);
}

#[tokio::test]
async fn stale_server_inventory_withdraws_a_production_fix() {
    let (database, project) = seeded(FindingStatus::FixedInProduction).await;
    let reference: Inventory = parse(REFERENCE_FIXED);
    let production: AgentInventory = parse(PRODUCTION_FIXED);

    apply_drift(
        &database,
        &project,
        Some(&verified_main()),
        Some(&reference),
        true,
        &[production],
        now() + Duration::days(3),
    )
    .await
    .expect("drift applies");

    let finding = stored_finding(&database).await;
    assert_eq!(finding.production_status, ProductionStatus::Unknown);
    assert_eq!(finding.status, FindingStatus::NeedsReview);
}

#[tokio::test]
async fn unverified_reference_head_leaves_repo_status_unknown() {
    let (database, project) = seeded(FindingStatus::ConfirmedAffected).await;
    let reference: Inventory = parse(REFERENCE_FIXED);
    let mut git = verified_main();
    git.head_verified = false;
    git.working_tree = WorkingTreeStatus::HasUncommittedChanges;

    apply_drift(
        &database,
        &project,
        Some(&git),
        Some(&reference),
        false,
        &[],
        now(),
    )
    .await
    .expect("drift applies");

    assert_eq!(
        stored_finding(&database).await.repo_status,
        RepoStatus::Unknown
    );
}

#[tokio::test]
async fn user_dispositions_are_never_overwritten() {
    let (database, project) = seeded(FindingStatus::NotReachable).await;
    let reference: Inventory = parse(REFERENCE_FIXED);
    let production: AgentInventory = parse(PRODUCTION_AFFECTED);

    apply_drift(
        &database,
        &project,
        Some(&verified_main()),
        Some(&reference),
        true,
        &[production],
        now(),
    )
    .await
    .expect("drift applies");

    let finding = stored_finding(&database).await;
    assert_eq!(finding.status, FindingStatus::NotReachable);
    assert_eq!(finding.production_status, ProductionStatus::StillAffected);
}

#[test]
fn deployment_selection_prefers_the_project_remote_and_rejects_ambiguity() {
    let mut inventory: AgentInventory = parse(PRODUCTION_AFFECTED);
    assert!(select_deployment(&inventory, Some("git@github.com:acme/web.git")).is_some());
    assert!(select_deployment(&inventory, None).is_some());

    let mut other = inventory.deployments[0].clone();
    other.repository = Some("https://github.com/acme/api".to_owned());
    other.commit_sha = Some("1111111111111111111111111111111111111111".to_owned());
    inventory.deployments.push(other);
    let selected = select_deployment(&inventory, Some("https://github.com/acme/web"))
        .expect("the matching repository decides");
    assert_eq!(
        selected.repository.as_deref(),
        Some("https://github.com/acme/web")
    );
    assert!(select_deployment(&inventory, None).is_none());
}

#[test]
fn remotes_normalize_across_ssh_and_https_forms() {
    assert_eq!(
        normalize_remote("git@github.com:Acme/Web.git"),
        normalize_remote("https://github.com/acme/web")
    );
    assert_eq!(
        normalize_remote("ssh://git@github.com/acme/web.git").as_deref(),
        Some("github.com/acme/web")
    );
    assert!(normalize_remote("  ").is_none());
}

#[test]
fn dependency_files_must_match_the_committed_blob_and_be_tracked() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    std::fs::write(root.join("package-lock.json"), "{\r\n}\r\n").expect("lockfile written");
    let tracked = HashSet::from(["package-lock.json".to_owned(), "src/index.ts".to_owned()]);
    let committed = |_: &str| Some(b"{\n}\n".to_vec());

    assert_eq!(
        dependency_tree_status(root, &tracked, &["package-lock.json".to_owned()], committed),
        WorkingTreeStatus::Clean
    );
    assert_eq!(
        dependency_tree_status(
            root,
            &tracked,
            &["web/package-lock.json".to_owned()],
            committed
        ),
        WorkingTreeStatus::HasUncommittedChanges
    );
    assert_eq!(
        dependency_tree_status(root, &tracked, &[], |_: &str| Some(b"{}".to_vec())),
        WorkingTreeStatus::HasUncommittedChanges
    );
    assert_eq!(
        dependency_tree_status(root, &tracked, &[], |_: &str| None),
        WorkingTreeStatus::Unknown
    );
}

fn run_git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_AUTHOR_NAME", "Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .status()
        .expect("git runs");
    assert!(status.success(), "git {args:?} failed");
}

#[test]
fn reference_is_verified_only_on_a_clean_reference_branch_tip() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    run_git(root, &["init", "--quiet", "--initial-branch=main"]);
    run_git(root, &["config", "commit.gpgsign", "false"]);
    std::fs::write(root.join("package-lock.json"), "{}\n").expect("lockfile written");
    run_git(root, &["add", "package-lock.json"]);
    run_git(root, &["commit", "--quiet", "-m", "initial"]);
    let lockfile = ["package-lock.json".to_owned()];
    // A repository-local fsmonitor must never run while the reference is read.
    let marker = root.join("fsmonitor-ran");
    run_git(
        root,
        &[
            "config",
            "core.fsmonitor",
            &format!("echo ran > \"{}\"", marker.display()),
        ],
    );

    let clean = read_git_reference(root, Some("main"), &lockfile).expect("git reference read");
    assert!(clean.head_verified);
    assert_eq!(clean.working_tree, WorkingTreeStatus::Clean);
    assert_eq!(clean.commit.len(), 40);

    std::fs::write(root.join("package-lock.json"), "{\"changed\":true}\n")
        .expect("lockfile changed");
    let dirty = read_git_reference(root, Some("main"), &lockfile).expect("git reference read");
    assert!(!dirty.head_verified);
    assert_eq!(dirty.working_tree, WorkingTreeStatus::HasUncommittedChanges);

    assert!(read_git_reference(root, Some("--upload-pack=x"), &lockfile).is_none());
    assert!(
        read_git_reference(root, Some("missing-branch"), &lockfile)
            .is_some_and(|reference| !reference.head_verified)
    );
    assert!(!marker.exists(), "repository fsmonitor must not execute");
}
