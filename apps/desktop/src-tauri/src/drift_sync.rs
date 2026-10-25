//! Connects the conservative drift assessment to stored findings. Repository state is verified
//! only when the working tree sits on the reference branch tip without uncommitted dependency
//! changes; production state is read only from servers the user linked to the project.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    process::Command,
};

use chrono::{DateTime, Duration, Utc};
use security_monitor_agent_protocol::{AgentInventory, DeploymentIdentity};
use security_monitor_bounded_reader::read_bounded_text;
use security_monitor_core::{
    Advisory, Component, ComponentInstance, Finding, FindingStatus, ProductionStatus, Project,
    ProjectServerLink, RepoStatus,
};
use security_monitor_correlation::{
    StatusActor, StatusEvidence, StatusTransition, apply_transition,
};
use security_monitor_database::Database;
use security_monitor_drift::{
    DriftTarget, InventoryFreshness, ProductionSnapshot, ReferenceSnapshot, WorkingTreeStatus,
    assess_drift,
};
use security_monitor_inventory::{Inventory, is_dependency_file, scan_repository};
use security_monitor_remediation::GitCommandSafety;

/// Server inventory older than this no longer counts as current production evidence.
const PRODUCTION_SNAPSHOT_MAX_AGE_HOURS: i64 = 24;
/// Large enough for real lockfiles; anything bigger is treated as unverifiable, not read.
const MAX_DEPENDENCY_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DriftSyncSummary {
    pub assessed: usize,
    pub updated: usize,
    pub status_changes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitReference {
    pub branch: String,
    pub commit: String,
    pub head_verified: bool,
    pub working_tree: WorkingTreeStatus,
}

pub async fn refresh_project_drift(
    database: &Database,
    app_data_dir: &Path,
    project_id: &str,
    now: DateTime<Utc>,
) -> Result<DriftSyncSummary, String> {
    let project = database
        .repository::<Project>()
        .get(project_id)
        .await
        .map_err(|_| "storage_unavailable".to_owned())?
        .ok_or_else(|| "project_not_found".to_owned())?;
    let root = PathBuf::from(&project.root_path)
        .canonicalize()
        .map_err(|_| "invalid_project_path".to_owned())?;

    let reference_branch = project.reference_branch.clone();
    let scan_root = root.clone();
    let (git, inventory) = tokio::task::spawn_blocking(move || {
        let inventory = scan_repository(&scan_root).ok();
        let dependency_paths = inventory
            .as_ref()
            .map(|inventory| {
                inventory
                    .components
                    .iter()
                    .flat_map(|component| component.evidence_paths.iter().cloned())
                    .chain(
                        inventory
                            .detected_files
                            .iter()
                            .filter(|file| is_dependency_file(Path::new(&file.path)))
                            .map(|file| file.path.clone()),
                    )
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let git = read_git_reference(&scan_root, reference_branch.as_deref(), &dependency_paths);
        (git, inventory)
    })
    .await
    .map_err(|_| "scan_failed".to_owned())?;

    let links = database
        .repository::<ProjectServerLink>()
        .list()
        .await
        .map_err(|_| "storage_unavailable".to_owned())?
        .into_iter()
        .filter(|link| link.project_id == project.id)
        .collect::<Vec<_>>();
    let mut snapshots = Vec::new();
    for link in &links {
        if let Some(snapshot) = crate::ipc::load_server_snapshot(app_data_dir, &link.asset_id)? {
            snapshots.push(snapshot);
        }
    }

    apply_drift(
        database,
        &project,
        git.as_ref(),
        inventory.as_ref(),
        !links.is_empty(),
        &snapshots,
        now,
    )
    .await
}

/// Assesses and stores drift for one project. Kept separate from Git and file access so the
/// decision logic can be tested with fixed inputs.
pub async fn apply_drift(
    database: &Database,
    project: &Project,
    git: Option<&GitReference>,
    working_tree_inventory: Option<&Inventory>,
    has_linked_servers: bool,
    snapshots: &[AgentInventory],
    now: DateTime<Utc>,
) -> Result<DriftSyncSummary, String> {
    let instances = database
        .repository::<ComponentInstance>()
        .list()
        .await
        .map_err(|_| "storage_unavailable".to_owned())?
        .into_iter()
        .filter(|instance| instance.project_id.as_deref() == Some(project.id.as_str()))
        .map(|instance| (instance.id.clone(), instance))
        .collect::<HashMap<_, _>>();
    if instances.is_empty() {
        return Ok(DriftSyncSummary::default());
    }
    let components = database
        .repository::<Component>()
        .list()
        .await
        .map_err(|_| "storage_unavailable".to_owned())?
        .into_iter()
        .map(|component| (component.id.clone(), component))
        .collect::<HashMap<_, _>>();
    let advisories = database
        .repository::<Advisory>()
        .list()
        .await
        .map_err(|_| "storage_unavailable".to_owned())?
        .into_iter()
        .map(|advisory| (advisory.canonical_id.clone(), advisory))
        .collect::<HashMap<_, _>>();
    let findings = database
        .repository::<Finding>()
        .list()
        .await
        .map_err(|_| "storage_unavailable".to_owned())?
        .into_iter()
        .filter(|finding| instances.contains_key(&finding.component_instance_id))
        .collect::<Vec<_>>();

    let mut targets = Vec::new();
    for finding in &findings {
        let Some(component) = instances
            .get(&finding.component_instance_id)
            .and_then(|instance| components.get(&instance.component_id))
        else {
            continue;
        };
        let Some(advisory) = advisories.get(&finding.advisory_id) else {
            continue;
        };
        targets.push(DriftTarget {
            finding,
            advisory,
            component_purl: &component.purl,
        });
    }
    if targets.is_empty() {
        return Ok(DriftSyncSummary::default());
    }

    let reference = match (git, working_tree_inventory) {
        (Some(git), Some(inventory)) => Some(ReferenceSnapshot {
            branch: &git.branch,
            commit_sha: &git.commit,
            inventory,
            reference_head_verified: git.head_verified,
        }),
        _ => None,
    };
    let working_tree = git.map_or(WorkingTreeStatus::GitUnavailable, |git| git.working_tree);

    // Each linked server is assessed on its own; a finding counts as fixed in production only
    // when every linked server shows the fix.
    let mut production_by_finding: HashMap<String, Vec<ProductionStatus>> = HashMap::new();
    let mut repo_by_finding: HashMap<String, RepoStatus> = HashMap::new();
    let production_runs: Vec<Option<ProductionSnapshot<'_>>> = if snapshots.is_empty() {
        vec![None]
    } else {
        snapshots
            .iter()
            .map(|inventory| {
                Some(ProductionSnapshot {
                    inventory,
                    deployment: select_deployment(inventory, project.git_remote.as_deref()),
                    project_association_confirmed: true,
                    freshness: snapshot_freshness(inventory.captured_at, now),
                })
            })
            .collect()
    };
    for production in production_runs {
        let reference = reference.as_ref().map(|value| ReferenceSnapshot {
            branch: value.branch,
            commit_sha: value.commit_sha,
            inventory: value.inventory,
            reference_head_verified: value.reference_head_verified,
        });
        let assessments = assess_drift(
            &targets,
            reference,
            working_tree_inventory,
            production,
            working_tree,
            now,
        )
        .map_err(|_| "drift_failed".to_owned())?;
        for assessment in assessments {
            repo_by_finding.insert(assessment.finding_id.clone(), assessment.repo_status);
            production_by_finding
                .entry(assessment.finding_id)
                .or_default()
                .push(assessment.production_status);
        }
    }

    let mut summary = DriftSyncSummary {
        assessed: targets.len(),
        ..DriftSyncSummary::default()
    };
    for finding in &findings {
        let Some(repo_status) = repo_by_finding.get(&finding.id).cloned() else {
            continue;
        };
        let production_status = if has_linked_servers {
            merge_production(production_by_finding.get(&finding.id))
        } else {
            ProductionStatus::Unknown
        };
        let mut updated = finding.clone();
        updated.repo_status = repo_status;
        updated.production_status = production_status;
        let status_changed = match system_transition(&updated, now) {
            Some(transition) => apply_transition(&mut updated, &transition).is_ok(),
            None => false,
        };
        if updated.repo_status == finding.repo_status
            && updated.production_status == finding.production_status
            && !status_changed
        {
            continue;
        }
        updated.updated_at = now;
        database
            .repository::<Finding>()
            .update(&updated)
            .await
            .map_err(|_| "storage_unavailable".to_owned())?;
        summary.updated += 1;
        if status_changed {
            summary.status_changes += 1;
        }
    }
    Ok(summary)
}

fn merge_production(statuses: Option<&Vec<ProductionStatus>>) -> ProductionStatus {
    let Some(statuses) = statuses.filter(|values| !values.is_empty()) else {
        return ProductionStatus::Unknown;
    };
    if statuses.contains(&ProductionStatus::StillAffected) {
        ProductionStatus::StillAffected
    } else if statuses
        .iter()
        .all(|status| *status == ProductionStatus::FixedInProduction)
    {
        ProductionStatus::FixedInProduction
    } else {
        ProductionStatus::Unknown
    }
}

/// Only statuses the system owns are moved; user dispositions (not reachable, accepted risk,
/// false positive) and mitigations are never overwritten by drift evidence.
fn system_transition(finding: &Finding, now: DateTime<Utc>) -> Option<StatusTransition> {
    if !matches!(
        finding.status,
        FindingStatus::New
            | FindingStatus::NeedsReview
            | FindingStatus::ConfirmedAffected
            | FindingStatus::FixProposed
            | FindingStatus::FixedInRepo
            | FindingStatus::FixedInProduction
    ) {
        return None;
    }
    let (to, evidence) = match (&finding.repo_status, &finding.production_status) {
        (_, ProductionStatus::FixedInProduction) => (
            FindingStatus::FixedInProduction,
            StatusEvidence::ProductionFixVerified,
        ),
        (RepoStatus::FixedInRepo, ProductionStatus::StillAffected) => (
            FindingStatus::FixedInRepo,
            StatusEvidence::ReferenceBranchFixVerified,
        ),
        (_, ProductionStatus::StillAffected) => (
            FindingStatus::ConfirmedAffected,
            StatusEvidence::AffectedVersionVerified,
        ),
        // Evidence that once supported a production fix is no longer current.
        (_, ProductionStatus::Unknown) if finding.status == FindingStatus::FixedInProduction => (
            FindingStatus::NeedsReview,
            StatusEvidence::CurrentDataIncomplete,
        ),
        _ => return None,
    };
    if finding.status == to {
        return None;
    }
    Some(StatusTransition {
        from: finding.status.clone(),
        to,
        actor: StatusActor::System,
        evidence,
        disposition: None,
        current_risk_expires_at: finding.risk_expires_at,
        at: now,
    })
}

fn snapshot_freshness(captured_at: DateTime<Utc>, now: DateTime<Utc>) -> InventoryFreshness {
    if captured_at > now {
        InventoryFreshness::Unknown
    } else if now - captured_at <= Duration::hours(PRODUCTION_SNAPSHOT_MAX_AGE_HOURS) {
        InventoryFreshness::Current
    } else {
        InventoryFreshness::Stale
    }
}

/// Picks the deployment identity that belongs to the project. With several candidates, only a
/// repository that matches the project's Git remote decides; anything ambiguous yields none.
pub fn select_deployment<'a>(
    inventory: &'a AgentInventory,
    git_remote: Option<&str>,
) -> Option<&'a DeploymentIdentity> {
    let mut candidates: Vec<&DeploymentIdentity> = Vec::new();
    for identity in inventory.deployments.iter().chain(
        inventory
            .services
            .iter()
            .filter_map(|service| service.deploy_identity.as_ref()),
    ) {
        if !candidates.contains(&identity) {
            candidates.push(identity);
        }
    }
    if let Some(remote) = git_remote.and_then(normalize_remote) {
        let matching = candidates
            .iter()
            .copied()
            .filter(|identity| {
                identity.repository.as_deref().and_then(normalize_remote) == Some(remote.clone())
            })
            .collect::<Vec<_>>();
        if !matching.is_empty() {
            return (matching.len() == 1).then(|| matching[0]);
        }
    }
    (candidates.len() == 1).then(|| candidates[0])
}

fn normalize_remote(value: &str) -> Option<String> {
    let mut value = value.trim().to_ascii_lowercase();
    if value.is_empty() {
        return None;
    }
    if let Some(rest) = value.strip_prefix("git@") {
        value = rest.replacen(':', "/", 1);
    }
    for prefix in ["https://", "http://", "ssh://", "git://"] {
        if let Some(rest) = value.strip_prefix(prefix) {
            value = rest.to_owned();
        }
    }
    if let Some((_, host_path)) = value.split_once('@') {
        value = host_path.to_owned();
    }
    let value = value.trim_end_matches('/').trim_end_matches(".git");
    (!value.is_empty()).then(|| value.to_owned())
}

/// Reads the reference branch state with fixed Git argument vectors and without shell use.
/// Repository content is untrusted: hooks, fsmonitor and global config are neutralized, and only
/// commands that never run repository-defined filters (`rev-parse`, `ls-files`, `cat-file`) are
/// used. Dependency files are compared byte-for-byte (ignoring CR) with the committed blob.
pub fn read_git_reference(
    root: &Path,
    configured_branch: Option<&str>,
    dependency_paths: &[String],
) -> Option<GitReference> {
    let safety = GitCommandSafety::create().ok()?;
    let git = |args: &[&str]| run_git(&safety, root, args);
    let head = text(git(&["rev-parse", "--verify", "HEAD^{commit}"])?)?;
    let branch = match configured_branch {
        Some(branch) => branch.to_owned(),
        None => git(&[
            "symbolic-ref",
            "--quiet",
            "--short",
            "refs/remotes/origin/HEAD",
        ])
        .and_then(text)
        .and_then(|value| value.strip_prefix("origin/").map(str::to_owned))
        .or_else(|| git(&["symbolic-ref", "--quiet", "--short", "HEAD"]).and_then(text))?,
    };
    if !safe_branch_name(&branch) {
        return None;
    }
    let tip = git(&[
        "rev-parse",
        "--verify",
        &format!("refs/heads/{branch}^{{commit}}"),
    ])
    .and_then(text);
    let working_tree = match git(&["ls-files", "-z"]) {
        Some(listing) => {
            let tracked = listing
                .split(|byte| *byte == 0)
                .filter(|entry| !entry.is_empty())
                .filter_map(|entry| std::str::from_utf8(entry).ok())
                .map(str::to_owned)
                .collect::<HashSet<_>>();
            dependency_tree_status(root, &tracked, dependency_paths, |path| {
                let object = format!("HEAD:{path}");
                let size = git(&["cat-file", "-s", &object])
                    .and_then(text)
                    .and_then(|value| value.parse::<u64>().ok())?;
                if size > MAX_DEPENDENCY_FILE_BYTES {
                    return None;
                }
                git(&["cat-file", "blob", &object])
            })
        }
        None => WorkingTreeStatus::Unknown,
    };
    let head_verified =
        tip.as_deref() == Some(head.as_str()) && working_tree == WorkingTreeStatus::Clean;
    Some(GitReference {
        branch,
        commit: head,
        head_verified,
        working_tree,
    })
}

/// Tracked dependency files must match the committed blob; a dependency file found by the
/// inventory but not tracked counts as an uncommitted change.
fn dependency_tree_status(
    root: &Path,
    tracked: &HashSet<String>,
    dependency_paths: &[String],
    committed_blob: impl Fn(&str) -> Option<Vec<u8>>,
) -> WorkingTreeStatus {
    if dependency_paths.iter().any(|path| !tracked.contains(path)) {
        return WorkingTreeStatus::HasUncommittedChanges;
    }
    for path in tracked
        .iter()
        .filter(|path| is_dependency_file(Path::new(path.as_str())))
    {
        let current = match read_dependency_file(root, path) {
            DependencyFile::Read(bytes) => bytes,
            DependencyFile::Missing => return WorkingTreeStatus::HasUncommittedChanges,
            DependencyFile::Unverifiable => return WorkingTreeStatus::Unknown,
        };
        let Some(committed) = committed_blob(path) else {
            return WorkingTreeStatus::Unknown;
        };
        if without_carriage_returns(&current) != without_carriage_returns(&committed) {
            return WorkingTreeStatus::HasUncommittedChanges;
        }
    }
    WorkingTreeStatus::Clean
}

enum DependencyFile {
    Read(Vec<u8>),
    Missing,
    Unverifiable,
}

/// Repository paths are untrusted: symlinks, non-regular files, paths that resolve outside the
/// project root, and oversized files are never read.
fn read_dependency_file(root: &Path, relative: &str) -> DependencyFile {
    let path = root.join(relative);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return DependencyFile::Missing;
        }
        Err(_) => return DependencyFile::Unverifiable,
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_DEPENDENCY_FILE_BYTES {
        return DependencyFile::Unverifiable;
    }
    let (Ok(canonical_root), Ok(canonical_path)) = (root.canonicalize(), path.canonicalize())
    else {
        return DependencyFile::Unverifiable;
    };
    if !canonical_path.starts_with(&canonical_root) {
        return DependencyFile::Unverifiable;
    }
    match read_bounded_text(&canonical_path, MAX_DEPENDENCY_FILE_BYTES) {
        Ok(contents) => DependencyFile::Read(contents.into_bytes()),
        Err(_) => DependencyFile::Unverifiable,
    }
}

fn without_carriage_returns(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .copied()
        .filter(|byte| *byte != b'\r')
        .collect()
}

fn safe_branch_name(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
}

fn text(bytes: Vec<u8>) -> Option<String> {
    String::from_utf8(bytes)
        .ok()
        .map(|value| value.trim_end().to_owned())
}

fn run_git(safety: &GitCommandSafety, root: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(root)
        .arg("--no-optional-locks")
        .args(args);
    safety.configure_std(&mut command);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let output = command.output().ok()?;
    output.status.success().then_some(output.stdout)
}

#[cfg(test)]
#[path = "drift_sync_tests.rs"]
mod tests;
