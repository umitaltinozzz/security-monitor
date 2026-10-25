pub(super) use chrono::Utc;
pub(super) use security_monitor_advisory_providers::{
    HttpPolicy, NewsSignalService, NewsSyncReport, OsvDatabaseUpdater, ProviderError,
    PublicDataHttp, authorize_updater_destination, configure_updater_client,
};
pub(super) use security_monitor_agent_protocol::AgentInventory;
pub(super) use security_monitor_agent_transport::{
    CredentialStore, InventoryCollectionApproval, OsCredentialStore, SshIdentity, SshTarget,
    collect_agent, create_pairing_instructions, inspect_host_key, load_user_ssh_hosts,
};
pub(super) use security_monitor_ai::{
    AiRequest, AiSettings, DataCategory, HttpAiTransport, MAX_OUTPUT_TOKENS_PER_CALL,
    TransferApprovalInput, create_transfer_approval, enforce_budget, estimate_cost,
    maximum_run_token_bounds, redact_text_with_host_aliases, run_tool_loop,
    validate_provider_config,
};
pub(super) use security_monitor_core::{
    Advisory, AgentCliProduct, AiDataTransferApproval, AiProvider, AiProviderKind, AiRun, AiTier,
    ApprovalState, Asset, AssetType, AuditEvent, AuditResult, AuditScope, Component,
    ComponentInstance, Finding, FindingDispositionReason, FindingEvidence, FindingStatus, Memory,
    MemoryArchive, MemoryArchiveEntry, MemoryKind, MemoryScope, NewsSignal, Project,
    ProjectServerLink, Remediation, RemediationTest, ScanOutcome, ScanRun, is_source_code_like,
};
pub(super) use security_monitor_correlation::{
    DispositionScope, StatusActor, StatusEvidence, StatusTransition, UserDisposition,
    apply_transition,
};
pub(super) use security_monitor_database::Database;
pub(super) use security_monitor_mcp_server::{WorkspaceTools, supported_tools};
pub(super) use security_monitor_remediation::{
    SafeTestCommand, SandboxEngine, available_engine, create_worktree_with_id,
    list_mcp_remediation_requests as read_mcp_remediation_requests, remove_mcp_remediation_request,
    run_agent_cli, run_sandbox_test, validate_worktree_under, worktree_diff, worktrees_directory,
};
pub(super) use security_monitor_scan_orchestrator::{
    ScanProfile, ScanReason, ScanRequest, ScanSummary, discover_projects,
};
pub(super) use security_monitor_scanner_adapters::{EngineKind, EngineStatus, ScannerAdapters};
pub(super) use serde::{Deserialize, Serialize};
pub(super) use sha2::{Digest, Sha256};
pub(super) use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};
pub(super) use tauri::{AppHandle, State};
pub(super) use tauri_plugin_updater::UpdaterExt;
pub(super) use ts_rs::TS;
pub(super) use url::Url;
pub(super) use uuid::Uuid;

pub(super) use crate::{app_state::AppState, ipc_types::*};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct StoredSshTarget {
    pub(super) target: SshTargetInput,
    pub(super) private_key_ref: String,
}

pub(super) fn to_ssh_target(input: SshTargetInput) -> Result<SshTarget, String> {
    SshTarget::new(
        input.alias,
        input.hostname,
        input.username,
        input.port,
        None,
    )
    .map_err(|_| "invalid_input".to_owned())
}

pub(super) fn persist_server_snapshot(
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

pub(crate) fn load_server_snapshot(
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

pub(crate) async fn write_audit_event(
    database: &Database,
    action: &str,
    resource_type: &str,
    resource_id: Option<String>,
    timestamp: chrono::DateTime<Utc>,
    result: AuditResult,
) -> Result<(), String> {
    write_audit_event_as(
        database,
        "user",
        action,
        resource_type,
        resource_id,
        timestamp,
        result,
    )
    .await
}

pub(super) async fn write_audit_event_as(
    database: &Database,
    actor: &str,
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
            actor: actor.to_owned(),
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

pub(super) fn status_key(status: &FindingStatus) -> &'static str {
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

pub(super) fn reason_key(reason: FindingDispositionReason) -> &'static str {
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
