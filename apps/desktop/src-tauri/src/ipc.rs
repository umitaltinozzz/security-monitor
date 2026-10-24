use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use chrono::Utc;
use security_monitor_advisory_providers::{HttpPolicy, OsvDatabaseUpdater, PublicDataHttp};
use security_monitor_agent_protocol::AgentInventory;
use security_monitor_agent_transport::{
    CredentialStore, InventoryCollectionApproval, OsCredentialStore, SshIdentity, SshTarget,
    collect_agent, create_pairing_instructions, inspect_host_key, load_user_ssh_hosts,
};
use security_monitor_core::{
    Advisory, Asset, AssetType, AuditEvent, AuditResult, AuditScope, Component, ComponentInstance,
    Finding, FindingDispositionReason, FindingEvidence, FindingStatus, Project, ScanOutcome,
    ScanRun,
};
use security_monitor_correlation::{
    DispositionScope, StatusActor, StatusEvidence, StatusTransition, UserDisposition,
    apply_transition,
};
use security_monitor_database::Database;
use security_monitor_scan_orchestrator::{
    ScanProfile, ScanReason, ScanRequest, ScanSummary, discover_projects,
};
use security_monitor_scanner_adapters::{EngineKind, EngineStatus, ScannerAdapters};
use serde::{Deserialize, Serialize};
use tauri::State;
use ts_rs::TS;
use uuid::Uuid;

use crate::{app_state::AppState, ipc_types::*};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AdvisoryUpdateStatus {
    pub ecosystem: String,
    pub stale: bool,
    pub updated_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct StoredSshTarget {
    target: SshTargetInput,
    private_key_ref: String,
}

#[tauri::command]
pub async fn get_app_settings(state: State<'_, AppState>) -> Result<AppSettings, String> {
    Ok(state.settings.read().await.clone())
}

#[tauri::command]
pub async fn save_app_settings(
    state: State<'_, AppState>,
    settings: AppSettings,
) -> Result<(), String> {
    state.save_settings(settings).await
}

#[tauri::command]
pub async fn list_projects(state: State<'_, AppState>) -> Result<Vec<Project>, String> {
    state
        .database
        .repository::<Project>()
        .list()
        .await
        .map_err(|_| "storage_unavailable".to_owned())
}

#[tauri::command]
pub async fn add_project(state: State<'_, AppState>, path: String) -> Result<Project, String> {
    let canonical = PathBuf::from(path)
        .canonicalize()
        .map_err(|_| "invalid_project_path".to_owned())?;
    if !canonical.is_dir() {
        return Err("invalid_project_path".to_owned());
    }
    let root_path = canonical
        .to_str()
        .ok_or_else(|| "invalid_project_path".to_owned())?
        .to_owned();
    let projects = state
        .database
        .repository::<Project>()
        .list()
        .await
        .map_err(|_| "storage_unavailable".to_owned())?;
    if projects
        .iter()
        .any(|project| project.root_path == root_path)
    {
        return Err("project_exists".to_owned());
    }
    let now = Utc::now();
    let name = canonical
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("project")
        .to_owned();
    let project = Project {
        id: Uuid::new_v4().to_string(),
        name,
        root_path,
        git_remote: None,
        reference_branch: None,
        allowed_ai_providers: Vec::new(),
        last_scan_at: None,
        created_at: now,
        updated_at: now,
    };
    state
        .database
        .repository::<Project>()
        .create(&project)
        .await
        .map_err(|_| "storage_unavailable".to_owned())?;
    write_audit_event(
        &state.database,
        "project_added",
        "project",
        Some(project.id.clone()),
        now,
        AuditResult::Succeeded,
    )
    .await?;
    Ok(project)
}

#[tauri::command]
pub async fn discover_local_projects(path: String) -> Result<ProjectDiscoveryView, String> {
    let result = discover_projects(path).map_err(|_| "invalid_project_path".to_owned())?;
    let candidates = result
        .candidates
        .into_iter()
        .map(|candidate| {
            let root_path = candidate
                .root_path
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| "invalid_project_path".to_owned())?;
            Ok(ProjectCandidateView {
                name: candidate.name,
                root_path,
                component_count: candidate.component_count,
                inventory_complete: candidate.inventory_complete,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(ProjectDiscoveryView {
        candidates,
        diagnostics: result.diagnostics,
        complete: result.complete,
    })
}

#[tauri::command]
pub async fn start_project_scan(
    state: State<'_, AppState>,
    project_id: String,
    profile: String,
) -> Result<String, String> {
    let profile = match profile.as_str() {
        "quick" => ScanProfile::Quick,
        "full" => ScanProfile::Full,
        _ => return Err("invalid_input".to_owned()),
    };
    let project = state
        .database
        .repository::<Project>()
        .get(&project_id)
        .await
        .map_err(|_| "storage_unavailable".to_owned())?
        .ok_or_else(|| "project_not_found".to_owned())?;
    let root = PathBuf::from(&project.root_path)
        .canonicalize()
        .map_err(|_| "invalid_project_path".to_owned())?;
    if !root.is_dir() {
        return Err("invalid_project_path".to_owned());
    }
    let queue = state.scans.read().await.queue.clone();
    let handle = queue
        .enqueue(ScanRequest {
            project_id,
            root,
            profile,
            reason: ScanReason::Manual,
        })
        .await
        .map_err(|_| "scan_failed".to_owned())?;
    let scan_id = handle.id.clone();
    let returned_id = scan_id.clone();
    let result_store = Arc::clone(&state.scan_results);
    tauri::async_runtime::spawn(async move {
        let result = match handle.wait().await {
            Ok(summary) => ScanResult::from_summary(summary),
            Err(_) => ScanResult {
                scan_id: scan_id.clone(),
                outcome: ScanOutcome::Failed,
                inventory_complete: false,
                component_count: 0,
                finding_count: 0,
                scanner_finding_count: 0,
                diagnostics: vec!["scan_failed".to_owned()],
            },
        };
        result_store.lock().await.insert(scan_id, result);
    });
    Ok(returned_id)
}

impl ScanResult {
    fn from_summary(summary: ScanSummary) -> Self {
        Self {
            scan_id: summary.scan_id,
            outcome: summary.outcome,
            inventory_complete: summary.inventory_complete,
            component_count: summary.component_count,
            finding_count: summary.correlated_finding_count,
            scanner_finding_count: summary.scanner_findings,
            diagnostics: summary.diagnostics,
        }
    }
}

#[tauri::command]
pub async fn cancel_project_scan(
    state: State<'_, AppState>,
    scan_id: String,
) -> Result<bool, String> {
    let queue = state.scans.read().await.queue.clone();
    Ok(queue.cancel(&scan_id).await)
}

#[tauri::command]
pub async fn get_scan_result(
    state: State<'_, AppState>,
    scan_id: String,
) -> Result<Option<ScanResult>, String> {
    Ok(state.scan_results.lock().await.get(&scan_id).cloned())
}

#[tauri::command]
pub async fn list_findings(state: State<'_, AppState>) -> Result<Vec<Finding>, String> {
    state
        .database
        .repository::<Finding>()
        .list()
        .await
        .map_err(|_| "storage_unavailable".to_owned())
}

#[tauri::command]
pub async fn list_advisories(state: State<'_, AppState>) -> Result<Vec<Advisory>, String> {
    state
        .database
        .repository::<Advisory>()
        .list()
        .await
        .map_err(|_| "storage_unavailable".to_owned())
}

#[tauri::command]
pub async fn list_components(state: State<'_, AppState>) -> Result<Vec<Component>, String> {
    state
        .database
        .repository::<Component>()
        .list()
        .await
        .map_err(|_| "storage_unavailable".to_owned())
}

#[tauri::command]
pub async fn list_component_instances(
    state: State<'_, AppState>,
) -> Result<Vec<ComponentInstance>, String> {
    state
        .database
        .repository::<ComponentInstance>()
        .list()
        .await
        .map_err(|_| "storage_unavailable".to_owned())
}

#[tauri::command]
pub async fn list_finding_evidence(
    state: State<'_, AppState>,
) -> Result<Vec<FindingEvidence>, String> {
    state
        .database
        .repository::<FindingEvidence>()
        .list()
        .await
        .map_err(|_| "storage_unavailable".to_owned())
}

#[tauri::command]
pub async fn list_scan_runs(state: State<'_, AppState>) -> Result<Vec<ScanRun>, String> {
    state
        .database
        .repository::<ScanRun>()
        .list()
        .await
        .map_err(|_| "storage_unavailable".to_owned())
}

#[tauri::command]
pub async fn list_audit_events(state: State<'_, AppState>) -> Result<Vec<AuditEvent>, String> {
    state
        .database
        .repository::<AuditEvent>()
        .list()
        .await
        .map_err(|_| "storage_unavailable".to_owned())
}

#[tauri::command]
pub async fn set_finding_status(
    state: State<'_, AppState>,
    change: FindingStatusChange,
) -> Result<Finding, String> {
    let repository = state.database.repository::<Finding>();
    let mut finding = repository
        .get(&change.finding_id)
        .await
        .map_err(|_| "storage_unavailable".to_owned())?
        .ok_or_else(|| "finding_not_found".to_owned())?;
    let scope = match change.scope.as_str() {
        "finding" => DispositionScope::Finding,
        "project" => DispositionScope::Project,
        "asset" => DispositionScope::Asset,
        "deployment" => DispositionScope::Deployment,
        _ => return Err("invalid_input".to_owned()),
    };
    let transition = StatusTransition {
        from: finding.status.clone(),
        to: change.status.clone(),
        actor: StatusActor::User,
        evidence: StatusEvidence::UserAction,
        disposition: Some(UserDisposition {
            reason: change.reason,
            scope,
            scope_id: change.scope_id,
            expires_at: change.expires_at,
        }),
        current_risk_expires_at: finding.risk_expires_at,
        at: Utc::now(),
    };
    apply_transition(&mut finding, &transition).map_err(|_| "status_rejected".to_owned())?;
    repository
        .update(&finding)
        .await
        .map_err(|_| "storage_unavailable".to_owned())?;
    let action = format!(
        "finding_status_changed:{}:{}",
        status_key(&finding.status),
        reason_key(change.reason)
    );
    write_audit_event(
        &state.database,
        &action,
        "finding",
        Some(finding.id.clone()),
        transition.at,
        AuditResult::Succeeded,
    )
    .await?;
    Ok(finding)
}

#[tauri::command]
pub async fn list_server_assets(state: State<'_, AppState>) -> Result<Vec<Asset>, String> {
    state
        .database
        .repository::<Asset>()
        .list()
        .await
        .map_err(|_| "storage_unavailable".to_owned())
}

#[tauri::command]
pub async fn detect_scanners(
    state: State<'_, AppState>,
) -> Result<Vec<ScannerAvailability>, String> {
    let settings = state.settings.read().await.clone();
    let http = PublicDataHttp::new(HttpPolicy {
        public_downloads_enabled: settings.public_downloads_enabled,
    })
    .map_err(|_| "storage_unavailable".to_owned())?;
    let adapters = ScannerAdapters::new(http, state.app_data_dir.clone());
    let mut results = Vec::new();
    for engine in [
        EngineKind::OsvScanner,
        EngineKind::Trivy,
        EngineKind::Semgrep,
    ] {
        let detected = adapters.detect_engine(engine).await;
        results.push(ScannerAvailability {
            engine: engine.as_str().to_owned(),
            status: match detected.status {
                EngineStatus::Available => "available",
                EngineStatus::Missing => "missing",
                EngineStatus::Outdated => "outdated",
                EngineStatus::UnsupportedPlatform => "unsupported_platform",
                EngineStatus::Unverified => "unverified",
            }
            .to_owned(),
            version: detected.version,
        });
    }
    for runtime in ["docker", "podman"] {
        let available = Command::new(runtime)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success());
        results.push(ScannerAvailability {
            engine: runtime.to_owned(),
            status: if available { "available" } else { "missing" }.to_owned(),
            version: None,
        });
    }
    Ok(results)
}

#[tauri::command]
pub async fn install_scanner(
    state: State<'_, AppState>,
    engine: String,
    user_approved_download: bool,
) -> Result<(), String> {
    if !user_approved_download || !state.settings.read().await.public_downloads_enabled {
        return Err("permission_denied".to_owned());
    }
    let engine_kind = match engine.as_str() {
        "osv-scanner" => EngineKind::OsvScanner,
        "trivy" => EngineKind::Trivy,
        "semgrep" => EngineKind::Semgrep,
        _ => return Err("invalid_input".to_owned()),
    };
    let http = PublicDataHttp::new(HttpPolicy {
        public_downloads_enabled: true,
    })
    .map_err(|_| "unknown".to_owned())?;
    let adapters = ScannerAdapters::new(http, state.app_data_dir.clone());
    adapters
        .install_pinned(engine_kind, true)
        .await
        .map_err(|_| "unknown".to_owned())?;
    write_audit_event(
        &state.database,
        "scanner_installed",
        "scanner",
        Some(engine),
        Utc::now(),
        AuditResult::Succeeded,
    )
    .await
}

#[tauri::command]
pub async fn update_advisory_data(
    state: State<'_, AppState>,
) -> Result<Vec<AdvisoryUpdateStatus>, String> {
    let settings = state.settings.read().await.clone();
    if !settings.public_downloads_enabled {
        return Err("permission_denied".to_owned());
    }
    let http = PublicDataHttp::new(HttpPolicy {
        public_downloads_enabled: true,
    })
    .map_err(|_| "unknown".to_owned())?;
    let updater = OsvDatabaseUpdater::new(http);
    let statuses = updater
        .update_ecosystems(state.app_data_dir.join("advisory-db"), settings.ecosystems)
        .await
        .map_err(|_| "unknown".to_owned())?;
    Ok(statuses
        .into_iter()
        .map(|status| AdvisoryUpdateStatus {
            ecosystem: status.ecosystem,
            stale: status.stale,
            updated_at: status.updated_at,
        })
        .collect())
}

#[tauri::command]
pub async fn list_ssh_config_hosts() -> Result<Vec<SshHostSummary>, String> {
    let Ok((hosts, _warnings)) = load_user_ssh_hosts() else {
        return Ok(Vec::new());
    };
    Ok(hosts
        .into_iter()
        .map(|host| SshHostSummary {
            alias: host.alias,
            hostname: host.hostname,
            username: host.username,
            port: host.port,
            has_proxy_jump: host.proxy_jump.is_some(),
        })
        .collect())
}

#[tauri::command]
pub async fn inspect_server_host_key(input: SshTargetInput) -> Result<String, String> {
    let target = to_ssh_target(input)?;
    let candidate = inspect_host_key(&target)
        .await
        .map_err(|_| "host_key_failed".to_owned())?;
    Ok(candidate.fingerprint)
}

#[tauri::command]
pub async fn pair_server(
    state: State<'_, AppState>,
    input: SshTargetInput,
    confirmed_fingerprint: String,
    fingerprint_confirmed: bool,
    device_label: String,
) -> Result<PairingInstructionsView, String> {
    if !fingerprint_confirmed {
        return Err("permission_denied".to_owned());
    }
    let target = to_ssh_target(input.clone())?;
    let candidate = inspect_host_key(&target)
        .await
        .map_err(|_| "host_key_failed".to_owned())?;
    if candidate.fingerprint != confirmed_fingerprint {
        return Err("host_key_changed".to_owned());
    }
    let store = OsCredentialStore;
    let instructions = create_pairing_instructions(&store, &device_label)
        .map_err(|_| "pairing_failed".to_owned())?;
    let credential = StoredSshTarget {
        target: input.clone(),
        private_key_ref: instructions.private_key_ref.clone(),
    };
    let credential_bytes =
        serde_json::to_vec(&credential).map_err(|_| "pairing_failed".to_owned())?;
    let target_ref = match store.put(&credential_bytes) {
        Ok(reference) => reference,
        Err(_) => {
            let _ = store.delete(&instructions.private_key_ref);
            return Err("pairing_failed".to_owned());
        }
    };
    let now = Utc::now();
    let asset = Asset {
        id: Uuid::new_v4().to_string(),
        asset_type: AssetType::Server,
        hostname_alias: input.alias,
        environment: input.environment,
        ssh_target_ref: Some(target_ref.clone()),
        host_key_fingerprint: Some(confirmed_fingerprint.clone()),
        last_seen_at: Some(now),
        last_success_at: None,
        created_at: now,
        updated_at: now,
    };
    if state
        .database
        .repository::<Asset>()
        .create(&asset)
        .await
        .is_err()
    {
        let _ = store.delete(&target_ref);
        let _ = store.delete(&instructions.private_key_ref);
        return Err("storage_unavailable".to_owned());
    }
    write_audit_event(
        &state.database,
        "server_paired",
        "asset",
        Some(asset.id.clone()),
        now,
        AuditResult::Succeeded,
    )
    .await?;
    Ok(PairingInstructionsView {
        asset,
        fingerprint: confirmed_fingerprint,
        authorized_keys_line: instructions.authorized_keys_line,
    })
}

#[tauri::command]
pub async fn collect_server_inventory(
    state: State<'_, AppState>,
    asset_id: String,
    transfer_approved: bool,
) -> Result<CollectionSummary, String> {
    if !transfer_approved {
        return Err("permission_denied".to_owned());
    }
    let asset = state
        .database
        .repository::<Asset>()
        .get(&asset_id)
        .await
        .map_err(|_| "storage_unavailable".to_owned())?
        .ok_or_else(|| "server_not_found".to_owned())?;
    let target_ref = asset
        .ssh_target_ref
        .as_deref()
        .ok_or_else(|| "collection_failed".to_owned())?;
    let fingerprint = asset
        .host_key_fingerprint
        .as_deref()
        .ok_or_else(|| "collection_failed".to_owned())?;
    let store = OsCredentialStore;
    let target_bytes = store
        .get(target_ref)
        .map_err(|_| "collection_failed".to_owned())?;
    let stored: StoredSshTarget =
        serde_json::from_slice(&target_bytes).map_err(|_| "collection_failed".to_owned())?;
    let target = to_ssh_target(stored.target)?;
    let approved_at = Utc::now();
    let collection = collect_agent(
        &target,
        fingerprint,
        &SshIdentity::PrivateKeyRef(stored.private_key_ref),
        &store,
        InventoryCollectionApproval::after_explicit_user_confirmation(approved_at),
    )
    .await
    .map_err(|_| "collection_failed".to_owned())?;
    collection
        .inventory
        .validate()
        .map_err(|_| "collection_failed".to_owned())?;
    persist_server_snapshot(&state.app_data_dir, &asset.id, &collection.inventory)?;
    let mut updated_asset = asset.clone();
    updated_asset.last_seen_at = Some(collection.inventory.captured_at);
    if collection.inventory.complete {
        updated_asset.last_success_at = Some(collection.inventory.captured_at);
    }
    updated_asset.updated_at = Utc::now();
    state
        .database
        .repository::<Asset>()
        .update(&updated_asset)
        .await
        .map_err(|_| "storage_unavailable".to_owned())?;
    write_audit_event(
        &state.database,
        "server_inventory_collection_approved",
        "asset",
        Some(asset.id.clone()),
        collection.approval.approved_at(),
        AuditResult::Succeeded,
    )
    .await?;
    Ok(CollectionSummary {
        asset_id: asset.id,
        complete: collection.inventory.complete,
        package_count: collection.inventory.packages.len(),
        service_count: collection.inventory.services.len(),
        container_count: collection.inventory.containers.len(),
        deployment_count: collection.inventory.deployments.len(),
        approved_at: collection.approval.approved_at(),
    })
}

#[tauri::command]
pub async fn get_server_inventory_summary(
    state: State<'_, AppState>,
    asset_id: String,
) -> Result<Option<CollectionSummary>, String> {
    let asset = state
        .database
        .repository::<Asset>()
        .get(&asset_id)
        .await
        .map_err(|_| "storage_unavailable".to_owned())?;
    let Some(asset) = asset else {
        return Ok(None);
    };
    let Some(inventory) = load_server_snapshot(&state.app_data_dir, &asset.id)? else {
        return Ok(None);
    };
    let audit = state
        .database
        .repository::<AuditEvent>()
        .list()
        .await
        .map_err(|_| "storage_unavailable".to_owned())?
        .into_iter()
        .filter(|event| {
            event.action == "server_inventory_collection_approved"
                && event.scope.resource_id.as_deref() == Some(asset.id.as_str())
                && event.result == AuditResult::Succeeded
        })
        .max_by_key(|event| event.timestamp);
    let approved_at = audit
        .map(|event| event.timestamp)
        .ok_or_else(|| "collection_failed".to_owned())?;
    Ok(Some(CollectionSummary {
        asset_id: asset.id,
        complete: inventory.complete,
        package_count: inventory.packages.len(),
        service_count: inventory.services.len(),
        container_count: inventory.containers.len(),
        deployment_count: inventory.deployments.len(),
        approved_at,
    }))
}

fn to_ssh_target(input: SshTargetInput) -> Result<SshTarget, String> {
    SshTarget::new(
        input.alias,
        input.hostname,
        input.username,
        input.port,
        None,
    )
    .map_err(|_| "invalid_input".to_owned())
}

fn persist_server_snapshot(
    app_data_dir: &Path,
    asset_id: &str,
    inventory: &AgentInventory,
) -> Result<(), String> {
    if Uuid::parse_str(asset_id).is_err() {
        return Err("collection_failed".to_owned());
    }
    let directory = app_data_dir.join("server-inventory");
    fs::create_dir_all(&directory).map_err(|_| "storage_unavailable".to_owned())?;
    let destination = directory.join(format!("{asset_id}.json"));
    let temporary = directory.join(format!(".{asset_id}-{}.tmp", Uuid::new_v4()));
    let bytes = serde_json::to_vec(inventory).map_err(|_| "collection_failed".to_owned())?;
    fs::write(&temporary, bytes).map_err(|_| "storage_unavailable".to_owned())?;
    fs::rename(&temporary, &destination).map_err(|_| {
        let _ = fs::remove_file(&temporary);
        "storage_unavailable".to_owned()
    })
}

fn load_server_snapshot(
    app_data_dir: &Path,
    asset_id: &str,
) -> Result<Option<AgentInventory>, String> {
    if Uuid::parse_str(asset_id).is_err() {
        return Err("invalid_input".to_owned());
    }
    let path = app_data_dir
        .join("server-inventory")
        .join(format!("{asset_id}.json"));
    match fs::read(path) {
        Ok(bytes) => {
            let inventory: AgentInventory =
                serde_json::from_slice(&bytes).map_err(|_| "collection_failed".to_owned())?;
            inventory
                .validate()
                .map_err(|_| "collection_failed".to_owned())?;
            Ok(Some(inventory))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("storage_unavailable".to_owned()),
    }
}

async fn write_audit_event(
    database: &Database,
    action: &str,
    resource_type: &str,
    resource_id: Option<String>,
    timestamp: chrono::DateTime<Utc>,
    result: AuditResult,
) -> Result<(), String> {
    database
        .repository::<AuditEvent>()
        .create(&AuditEvent {
            id: Uuid::new_v4().to_string(),
            timestamp,
            actor: "user".to_owned(),
            action: action.to_owned(),
            scope: AuditScope {
                resource_type: resource_type.to_owned(),
                resource_id,
            },
            result,
        })
        .await
        .map_err(|_| "storage_unavailable".to_owned())
}

fn status_key(status: &FindingStatus) -> &'static str {
    match status {
        FindingStatus::New => "new",
        FindingStatus::NeedsReview => "needs_review",
        FindingStatus::ConfirmedAffected => "confirmed_affected",
        FindingStatus::NotReachable => "not_reachable",
        FindingStatus::Mitigated => "mitigated",
        FindingStatus::FixProposed => "fix_proposed",
        FindingStatus::FixedInRepo => "fixed_in_repo",
        FindingStatus::FixedInProduction => "fixed_in_production",
        FindingStatus::AcceptedRisk => "accepted_risk",
        FindingStatus::FalsePositive => "false_positive",
    }
}

fn reason_key(reason: FindingDispositionReason) -> &'static str {
    match reason {
        FindingDispositionReason::BusinessAccepted => "business_accepted",
        FindingDispositionReason::CompensatingControl => "compensating_control",
        FindingDispositionReason::TemporaryException => "temporary_exception",
        FindingDispositionReason::FixPlanned => "fix_planned",
        FindingDispositionReason::DuplicateFinding => "duplicate_finding",
        FindingDispositionReason::IncorrectPackage => "incorrect_package",
        FindingDispositionReason::UnaffectedVersion => "unaffected_version",
        FindingDispositionReason::NoAffectedCodePath => "no_affected_code_path",
        FindingDispositionReason::ConfigurationPreventsReachability => {
            "configuration_prevents_reachability"
        }
        FindingDispositionReason::OtherReviewed => "other_reviewed",
    }
}
