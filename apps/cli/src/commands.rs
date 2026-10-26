use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use chrono::Utc;
use security_monitor_advisory_providers::{
    HttpPolicy, OsvDatabaseUpdater, PublicDataHttp, ecosystem_slug,
};
use security_monitor_agent_transport::{
    CredentialStore, InventoryCollectionApproval, OsCredentialStore, SshIdentity, SshTarget,
    collect_agent,
};
use security_monitor_app_services::{
    ServerSnapshotError, database_locations, persist_server_snapshot,
};
use security_monitor_core::{
    Asset, AuditEvent, AuditResult, AuditScope, Project, ScanOutcome, ScanRun,
};
use security_monitor_database::Database;
use security_monitor_integrations::{Agent, IntegrationService, Scope};
use security_monitor_reporting::{FailOn, ReportFormat, assess, load_snapshot, render, validate};
use security_monitor_scan_orchestrator::{
    LocalProjectScanner, LocalScanSettings, ScanLimits, ScanProfile, ScanReason, ScanRequest,
};
use security_monitor_scanner_adapters::{EngineKind, ScannerAdapters};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{HookMode, IntegrationScope};

const HOOK_MARKER: &str = "#!/bin/sh\n# secmon-managed-hook-v1\n";

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct LocalSettings {
    public_downloads_enabled: bool,
    ecosystems: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct StoredSshTarget {
    target: StoredSshTargetInput,
    private_key_ref: String,
}

#[derive(Debug, Deserialize)]
struct StoredSshTargetInput {
    alias: String,
    hostname: String,
    username: String,
    port: u16,
    #[serde(default)]
    proxy_jump: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct HookState {
    version: u8,
    installed_sha256: String,
    backup_exists: bool,
}

pub async fn run_scan(
    path: PathBuf,
    database_path: Option<PathBuf>,
    format: &str,
    fail_on: Option<&str>,
    offline: bool,
) -> Result<i32, &'static str> {
    let format = match format {
        "table" => None,
        "json" => Some(ReportFormat::Json),
        "sarif" => Some(ReportFormat::Sarif),
        _ => return Err("invalid_report_format"),
    };
    let fail_on = match fail_on {
        Some(value) => Some(FailOn::parse(value).ok_or("invalid_fail_on")?),
        None => None,
    };
    let root = path.canonicalize().map_err(|_| "project_path_invalid")?;
    if !root.is_dir() {
        return Err("project_path_invalid");
    }
    let (database_path, app_data) =
        database_locations(database_path).map_err(|_| "app_data_directory_unavailable")?;
    fs::create_dir_all(&app_data).map_err(|_| "storage_unavailable")?;
    let database = Database::open(&database_path)
        .await
        .map_err(|_| "storage_unavailable")?;
    let project = ensure_project(&database, &root).await?;
    let settings = load_settings(&app_data);
    let scanner = std::sync::Arc::new(
        LocalProjectScanner::new(
            database.clone(),
            &app_data,
            HttpPolicy {
                public_downloads_enabled: !offline && settings.public_downloads_enabled,
            },
            LocalScanSettings::default(),
        )
        .map_err(|_| "scan_unavailable")?,
    );
    let queue = scanner
        .queue(ScanLimits::default())
        .map_err(|_| "scan_unavailable")?;
    let handle = queue
        .enqueue(ScanRequest {
            project_id: project.id.clone(),
            root,
            profile: ScanProfile::Quick,
            reason: ScanReason::Manual,
        })
        .await
        .map_err(|_| "scan_unavailable")?;
    let summary = handle.wait().await.map_err(|_| "scan_failed")?;
    let snapshot = load_snapshot(&database, Some(&project.id), Utc::now())
        .await
        .map_err(|_| "report_failed")?;
    if let Some(format) = format {
        write_report(&snapshot, format)?;
    } else {
        print_scan_table(&project.name, &summary, snapshot.findings.len());
    }
    database.close().await;
    Ok(assess(&snapshot, fail_on).code())
}

pub async fn run_report(
    database_path: Option<PathBuf>,
    format: &str,
    project_id: Option<&str>,
) -> Result<i32, &'static str> {
    let format = ReportFormat::parse(format).ok_or("invalid_report_format")?;
    let (database_path, _) =
        database_locations(database_path).map_err(|_| "app_data_directory_unavailable")?;
    let database = Database::open_read_only(database_path)
        .await
        .map_err(|_| "database_unavailable")?;
    let snapshot = load_snapshot(&database, project_id, Utc::now())
        .await
        .map_err(|_| "report_failed")?;
    write_report(&snapshot, format)?;
    database.close().await;
    Ok(0)
}

pub async fn run_database_update(
    database_path: Option<PathBuf>,
    ecosystems: Vec<String>,
) -> Result<i32, &'static str> {
    let (_, app_data) =
        database_locations(database_path).map_err(|_| "app_data_directory_unavailable")?;
    let settings = load_settings(&app_data);
    if !settings.public_downloads_enabled {
        return Err("public_downloads_disabled");
    }
    let ecosystems = if ecosystems.is_empty() {
        settings.ecosystems
    } else {
        ecosystems
    };
    if ecosystems.is_empty() || ecosystems.iter().any(|name| ecosystem_slug(name).is_none()) {
        return Err("unsupported_or_empty_ecosystem_list");
    }
    let http = PublicDataHttp::new(HttpPolicy {
        public_downloads_enabled: true,
    })
    .map_err(|_| "provider_unavailable")?;
    let updater = OsvDatabaseUpdater::new(http);
    let results = updater
        .update_ecosystems(osv_database_directory(&app_data), ecosystems)
        .await
        .map_err(|_| "provider_unavailable")?;
    let mut has_stale = false;
    for result in results {
        let state = if result.stale {
            has_stale = true;
            "stale"
        } else {
            "updated"
        };
        println!("{}: {state}", result.ecosystem);
    }
    Ok(if has_stale { 3 } else { 0 })
}

pub async fn run_doctor(database_path: Option<PathBuf>) -> Result<i32, &'static str> {
    let (database_path, app_data) =
        database_locations(database_path).map_err(|_| "app_data_directory_unavailable")?;
    let mut needs_review = false;
    if !database_path.is_file() {
        println!("database: missing (needs_review)");
        needs_review = true;
    } else {
        let database = Database::open_read_only(&database_path)
            .await
            .map_err(|_| "database_unavailable")?;
        let projects = database
            .repository::<Project>()
            .list()
            .await
            .map_err(|_| "database_unavailable")?;
        let scans = database
            .repository::<ScanRun>()
            .list()
            .await
            .map_err(|_| "database_unavailable")?;
        let latest_scan = scans
            .iter()
            .max_by_key(|scan| scan.finished_at.unwrap_or(scan.started_at));
        println!("database: available; projects: {}", projects.len());
        match latest_scan {
            Some(scan)
                if scan.outcome == ScanOutcome::Succeeded
                    && scan.finished_at.is_some_and(|finished| {
                        Utc::now().signed_duration_since(finished).num_hours() < 24
                    }) =>
            {
                println!("last scan: current")
            }
            Some(_) => {
                println!("last scan: stale or incomplete (needs_review)");
                needs_review = true;
            }
            None => {
                println!("last scan: missing (needs_review)");
                needs_review = true;
            }
        }
        database.close().await;
    }

    let settings = load_settings(&app_data);
    match PublicDataHttp::new(HttpPolicy {
        public_downloads_enabled: settings.public_downloads_enabled,
    }) {
        Ok(http) => {
            let scanners = ScannerAdapters::new(http, &app_data);
            for engine in [
                EngineKind::OsvScanner,
                EngineKind::Trivy,
                EngineKind::Semgrep,
            ] {
                let detection = scanners.detect_engine(engine).await;
                let state = format!("{:?}", detection.status).to_ascii_lowercase();
                println!("{}: {state}", engine.as_str());
                if detection.status != security_monitor_scanner_adapters::EngineStatus::Available {
                    needs_review = true;
                }
            }
        }
        Err(_) => {
            println!("scanner status: unavailable (needs_review)");
            needs_review = true;
        }
    }
    let provider_status = app_data.join("advisories/provider-status.json");
    let fresh = fs::read(provider_status)
        .ok()
        .and_then(|bytes| {
            serde_json::from_slice::<Vec<security_monitor_advisory_providers::ProviderFreshness>>(
                &bytes,
            )
            .ok()
        })
        .is_some_and(|statuses| {
            !statuses.is_empty()
                && statuses.iter().all(|status| {
                    !status.stale
                        && status.updated_at.is_some_and(|at| {
                            at <= Utc::now()
                                && Utc::now().signed_duration_since(at).num_hours() < 24
                        })
                })
        });
    println!(
        "advisory data: {}",
        if fresh {
            "current"
        } else {
            "stale or missing (needs_review)"
        }
    );
    if !fresh {
        needs_review = true;
    }
    Ok(if needs_review { 3 } else { 0 })
}

pub async fn run_server_collect(
    database_path: Option<PathBuf>,
    asset_id: &str,
    transfer_approved: bool,
) -> Result<i32, &'static str> {
    if !transfer_approved {
        return Err("explicit_transfer_approval_required");
    }
    let (database_path, app_data) =
        database_locations(database_path).map_err(|_| "app_data_directory_unavailable")?;
    fs::create_dir_all(&app_data).map_err(|_| "storage_unavailable")?;
    let database = Database::open(&database_path)
        .await
        .map_err(|_| "storage_unavailable")?;
    let asset = database
        .repository::<Asset>()
        .get(asset_id)
        .await
        .map_err(|_| "server_unavailable")?
        .ok_or("server_unavailable")?;
    let target_ref = asset
        .ssh_target_ref
        .as_deref()
        .ok_or("server_unavailable")?;
    let fingerprint = asset
        .host_key_fingerprint
        .as_deref()
        .ok_or("server_unavailable")?;
    let store = OsCredentialStore;
    let target_bytes = store
        .get(target_ref)
        .map_err(|_| "credential_unavailable")?;
    let stored: StoredSshTarget =
        serde_json::from_slice(&target_bytes).map_err(|_| "credential_unavailable")?;
    let target = SshTarget::new(
        stored.target.alias,
        stored.target.hostname,
        stored.target.username,
        stored.target.port,
        stored.target.proxy_jump,
    )
    .map_err(|_| "server_unavailable")?;
    let approved_at = Utc::now();
    write_audit_event(
        &database,
        "server_inventory_transfer_approval_granted",
        "asset",
        asset_id,
        approved_at,
        AuditResult::Succeeded,
    )
    .await?;
    let collection = match collect_agent(
        &target,
        fingerprint,
        &SshIdentity::PrivateKeyRef(stored.private_key_ref),
        &store,
        InventoryCollectionApproval::after_explicit_user_confirmation(approved_at),
    )
    .await
    {
        Ok(collection) => collection,
        Err(_) => {
            let _ = write_audit_event(
                &database,
                "server_inventory_collection_failed",
                "asset",
                asset_id,
                Utc::now(),
                AuditResult::Failed,
            )
            .await;
            return Err("server_collection_failed");
        }
    };
    collection
        .inventory
        .validate()
        .map_err(|_| "server_collection_failed")?;
    persist_server_snapshot(&app_data, asset_id, &collection.inventory).map_err(
        |error| match error {
            ServerSnapshotError::InvalidAssetId => "server_unavailable",
            ServerSnapshotError::Serialization => "server_collection_failed",
            ServerSnapshotError::Storage => "storage_unavailable",
        },
    )?;
    let mut updated = asset.clone();
    updated.last_seen_at = Some(collection.inventory.captured_at);
    if collection.inventory.complete {
        updated.last_success_at = Some(collection.inventory.captured_at);
    }
    updated.updated_at = Utc::now();
    database
        .repository::<Asset>()
        .update(&updated)
        .await
        .map_err(|_| "storage_unavailable")?;
    write_audit_event(
        &database,
        "server_inventory_collection_succeeded",
        "asset",
        asset_id,
        Utc::now(),
        AuditResult::Succeeded,
    )
    .await?;
    println!(
        "server inventory collected: {} packages; {}",
        collection.inventory.packages.len(),
        if collection.inventory.complete {
            "complete"
        } else {
            "partial (needs_review)"
        }
    );
    database.close().await;
    Ok(if collection.inventory.complete { 0 } else { 3 })
}

pub fn run_integrate(
    parts: Vec<String>,
    scope_arg: IntegrationScope,
    project_path: Option<PathBuf>,
    dry_run: bool,
    yes: bool,
) -> Result<i32, &'static str> {
    let (remove, agent_name) = match parts.as_slice() {
        [agent] => (false, agent.as_str()),
        [verb, agent] if verb == "remove" => (true, agent.as_str()),
        _ => return Err("invalid_integration_command"),
    };
    let agent = Agent::parse(agent_name).ok_or("unsupported_agent")?;
    let home = home_directory().ok_or("home_directory_unavailable")?;
    let scope = match scope_arg {
        IntegrationScope::User => Scope::User,
        IntegrationScope::Project => Scope::Project,
    };
    let project = if scope == Scope::Project {
        let path =
            project_path.unwrap_or(std::env::current_dir().map_err(|_| "project_path_invalid")?);
        Some(path.canonicalize().map_err(|_| "project_path_invalid")?)
    } else {
        if project_path.is_some() {
            return Err("project_path_requires_project_scope");
        }
        None
    };
    let service = IntegrationService::new(OsCredentialStore);
    if remove {
        service
            .remove(agent, scope, &home, project.as_deref())
            .map_err(|_| "integration_remove_failed")?;
        println!("{} integration removed", agent.as_str());
        return Ok(0);
    }
    let plan = service
        .plan(agent, scope, &home, project.as_deref())
        .map_err(|_| "integration_plan_failed")?;
    if dry_run {
        print!("{}", plan.diff(agent));
        return Ok(0);
    }
    if !confirm_install(yes)? {
        return Err("installation_not_confirmed");
    }
    service
        .install(agent, scope, &home, project.as_deref())
        .map_err(|_| "integration_install_failed")?;
    println!("{} integration installed", agent.as_str());
    Ok(0)
}

pub fn run_hook_install(
    pre_push: bool,
    pre_commit: bool,
    mode: HookMode,
    fail_on: &str,
) -> Result<i32, &'static str> {
    let fail_on = FailOn::parse(fail_on).ok_or("invalid_fail_on")?;
    let hook_name = hook_name(pre_push, pre_commit)?;
    let root = std::env::current_dir().map_err(|_| "repository_unavailable")?;
    let hooks = repository_hooks_directory(&root)?;
    let hook_path = hooks.join(hook_name);
    let backup_path = hooks.join(format!("{hook_name}.secmon-original"));
    let state_path = hooks.join(format!("{hook_name}.secmon-state.json"));
    if state_path.exists() {
        return Err("hook_already_installed");
    }
    if fs::symlink_metadata(&hook_path)
        .is_ok_and(|metadata| metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err("hook_path_unsafe");
    }
    let backup_exists = hook_path.exists();
    if backup_exists && backup_path.exists() {
        return Err("hook_backup_conflict");
    }
    if backup_exists {
        fs::rename(&hook_path, &backup_path).map_err(|_| "hook_install_failed")?;
    }
    let mode_name = match mode {
        HookMode::Warn => "warn",
        HookMode::Block => "block",
    };
    let hook_argument = format!("--{hook_name}");
    let script = format!(
        "{HOOK_MARKER}umask 077\nhook_input=$(mktemp) || exit 1\ntrap 'rm -f \"$hook_input\"' EXIT HUP INT TERM\ncat > \"$hook_input\" || exit 1\nif [ -x \"${{0}}.secmon-original\" ]; then\n  \"${{0}}.secmon-original\" \"$@\" < \"$hook_input\"\n  original_status=$?\n  if [ \"$original_status\" -ne 0 ]; then exit \"$original_status\"; fi\nfi\nsecmon hook run --mode {mode_name} --fail-on {} {hook_argument} < \"$hook_input\"\nhook_status=$?\nexit \"$hook_status\"\n",
        fail_on_text(fail_on),
    );
    if write_hook_executable(&hook_path, script.as_bytes()).is_err() {
        if backup_exists {
            let _ = fs::rename(&backup_path, &hook_path);
        }
        return Err("hook_install_failed");
    }
    let state = HookState {
        version: 1,
        installed_sha256: sha256(script.as_bytes()),
        backup_exists,
    };
    if write_json(&state_path, &state).is_err() {
        let _ = fs::remove_file(&hook_path);
        if backup_exists {
            let _ = fs::rename(&backup_path, &hook_path);
        }
        return Err("hook_install_failed");
    }
    println!(
        "installed {hook_name} hook ({mode_name}, fail-on {})",
        fail_on_text(fail_on)
    );
    Ok(0)
}

pub fn run_hook_uninstall(pre_push: bool, pre_commit: bool) -> Result<i32, &'static str> {
    let hook_name = hook_name(pre_push, pre_commit)?;
    let root = std::env::current_dir().map_err(|_| "repository_unavailable")?;
    let hooks = repository_hooks_directory(&root)?;
    let hook_path = hooks.join(hook_name);
    let backup_path = hooks.join(format!("{hook_name}.secmon-original"));
    let state_path = hooks.join(format!("{hook_name}.secmon-state.json"));
    let state: HookState = fs::read(&state_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or("hook_not_installed")?;
    if state.version != 1 {
        return Err("hook_state_invalid");
    }
    let installed = fs::read(&hook_path).map_err(|_| "hook_modified_after_install")?;
    if sha256(&installed) != state.installed_sha256 {
        return Err("hook_modified_after_install");
    }
    fs::remove_file(&hook_path).map_err(|_| "hook_remove_failed")?;
    if state.backup_exists {
        fs::rename(&backup_path, &hook_path).map_err(|_| "hook_restore_failed")?;
    }
    fs::remove_file(state_path).map_err(|_| "hook_remove_failed")?;
    println!("removed {hook_name} hook");
    Ok(0)
}

pub async fn run_hook(
    database_path: Option<PathBuf>,
    mode: HookMode,
    fail_on: &str,
    pre_push: bool,
    pre_commit: bool,
    agent_event: bool,
) -> Result<i32, &'static str> {
    if (pre_push && pre_commit) || (agent_event && (pre_push || pre_commit)) {
        return Err("choose_one_hook");
    }
    let actions = if agent_event {
        match super::hook_events::actions_from_stdin() {
            Ok(actions) => actions,
            Err(error) if matches!(mode, HookMode::Warn) => {
                eprintln!("warning: security check could not run ({error}); continuing");
                return Ok(0);
            }
            Err(error) => {
                eprintln!("blocked: hook input could not be verified ({error})");
                return unverified_agent_event_result(mode);
            }
        }
    } else if !pre_push && !pre_commit {
        return Ok(0);
    } else {
        super::hook_events::GitHookActions {
            pre_commit,
            pre_push,
        }
    };
    if !actions.pre_commit && !actions.pre_push {
        return Ok(0);
    }
    let fail_on = FailOn::parse(fail_on).ok_or("invalid_fail_on")?;
    let mut code = 0;
    for (pre_push, selected) in [(false, actions.pre_commit), (true, actions.pre_push)] {
        if !selected {
            continue;
        }
        if let Some(result) = agent_push_missing_ref_result(agent_event, pre_push, mode) {
            eprintln!("blocked: an agent push event has no verified ref-update input");
            return result;
        }
        code = match hook_scan(database_path.clone(), fail_on, pre_push, !pre_push).await {
            Ok(next_code) => code.max(next_code),
            // Warn mode never stops a commit or push, not even when the check itself fails.
            Err(error) if matches!(mode, HookMode::Warn) => {
                eprintln!("warning: security check could not run ({error}); continuing");
                return Ok(0);
            }
            Err(error) => {
                eprintln!(
                    "blocked: security check could not run ({error}); verification is incomplete"
                );
                return Err(error);
            }
        };
    }
    if code == 0 {
        return Ok(0);
    }
    match mode {
        HookMode::Warn => {
            eprintln!("warning: scan threshold or verification check requires review; continuing");
            Ok(0)
        }
        HookMode::Block if should_block_hook(mode, code) => {
            eprintln!(
                "blocked: the security check found a threshold breach or incomplete verification"
            );
            Ok(code)
        }
        HookMode::Block => {
            eprintln!("warning: scan verification is incomplete; no threshold was confirmed");
            Ok(0)
        }
    }
}

fn should_block_hook(mode: HookMode, result_code: i32) -> bool {
    matches!(mode, HookMode::Block)
        && matches!(
            result_code,
            super::hooks::THRESHOLD_BREACH_EXIT | super::hooks::VERIFICATION_INCOMPLETE_EXIT
        )
}

fn unverified_agent_event_result(mode: HookMode) -> Result<i32, &'static str> {
    match mode {
        HookMode::Warn => Ok(0),
        HookMode::Block => Err("hook_input_unavailable"),
    }
}

fn agent_push_missing_ref_result(
    agent_event: bool,
    pre_push: bool,
    mode: HookMode,
) -> Option<Result<i32, &'static str>> {
    (agent_event && pre_push).then(|| unverified_agent_event_result(mode))
}

async fn hook_scan(
    database_path: Option<PathBuf>,
    fail_on: FailOn,
    pre_push: bool,
    pre_commit: bool,
) -> Result<i32, &'static str> {
    let root = std::env::current_dir().map_err(|_| "project_path_invalid")?;
    if pre_push || pre_commit {
        let (database_path, app_data) =
            database_locations(database_path).map_err(|_| "app_data_directory_unavailable")?;
        fs::create_dir_all(&app_data).map_err(|_| "storage_unavailable")?;
        super::hooks::scan_changed_inputs(&root, &database_path, &app_data, pre_push, fail_on).await
    } else {
        Ok(0)
    }
}

fn write_report(
    snapshot: &security_monitor_reporting::ReportSnapshot,
    format: ReportFormat,
) -> Result<(), &'static str> {
    let output = render(snapshot, format).map_err(|_| "report_failed")?;
    let document: Value = serde_json::from_str(&output).map_err(|_| "report_failed")?;
    validate(format, &document).map_err(|_| "report_schema_validation_failed")?;
    println!("{output}");
    Ok(())
}

fn print_scan_table(
    project_name: &str,
    summary: &security_monitor_scan_orchestrator::ScanSummary,
    findings: usize,
) {
    println!("project: {project_name}");
    println!(
        "scan: {:?}; inventory: {}",
        summary.outcome,
        if summary.inventory_complete {
            "complete"
        } else {
            "needs_review"
        }
    );
    println!(
        "components: {}; findings: {}",
        summary.component_count, findings
    );
    if !summary.diagnostics.is_empty() {
        println!("diagnostics: {}", summary.diagnostics.join(", "));
    }
}

async fn ensure_project(database: &Database, root: &Path) -> Result<Project, &'static str> {
    let projects = database
        .repository::<Project>()
        .list()
        .await
        .map_err(|_| "storage_unavailable")?;
    let project = projects.iter().find(|project| {
        Path::new(&project.root_path)
            .canonicalize()
            .is_ok_and(|existing| existing == root)
    });
    if let Some(project) = project {
        return Ok(project.clone());
    }
    let now = Utc::now();
    let project = Project {
        id: Uuid::new_v4().to_string(),
        name: root
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .unwrap_or("project")
            .to_owned(),
        root_path: root.to_string_lossy().into_owned(),
        git_remote: None,
        reference_branch: None,
        allowed_ai_providers: Vec::new(),
        last_scan_at: None,
        created_at: now,
        updated_at: now,
    };
    database
        .repository::<Project>()
        .create(&project)
        .await
        .map_err(|_| "storage_unavailable")?;
    Ok(project)
}

async fn write_audit_event(
    database: &Database,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    timestamp: chrono::DateTime<Utc>,
    result: AuditResult,
) -> Result<(), &'static str> {
    database
        .repository::<AuditEvent>()
        .create(&AuditEvent {
            id: Uuid::new_v4().to_string(),
            timestamp,
            actor: "user".to_owned(),
            action: action.to_owned(),
            scope: AuditScope {
                resource_type: resource_type.to_owned(),
                resource_id: Some(resource_id.to_owned()),
            },
            result,
        })
        .await
        .map_err(|_| "audit_storage_unavailable")
}

fn osv_database_directory(app_data: &Path) -> PathBuf {
    app_data.join("advisories").join("osv")
}

fn load_settings(app_data: &Path) -> LocalSettings {
    fs::read(app_data.join("settings.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn home_directory() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    let home = std::env::var_os("USERPROFILE").map(PathBuf::from);
    #[cfg(not(target_os = "windows"))]
    let home = std::env::var_os("HOME").map(PathBuf::from);
    home
}

fn confirm_install(yes: bool) -> Result<bool, &'static str> {
    if yes {
        return Ok(true);
    }
    print!("Install these Security Monitor integration changes? [y/N] ");
    io::stdout().flush().map_err(|_| "confirmation_failed")?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|_| "confirmation_failed")?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES"))
}

fn hook_name(pre_push: bool, pre_commit: bool) -> Result<&'static str, &'static str> {
    if pre_push && pre_commit {
        Err("choose_one_hook")
    } else if pre_commit {
        Ok("pre-commit")
    } else {
        Ok("pre-push")
    }
}

fn repository_hooks_directory(start: &Path) -> Result<PathBuf, &'static str> {
    let start = start.canonicalize().map_err(|_| "repository_unavailable")?;
    let mut found = None;
    for ancestor in start.ancestors() {
        let marker = ancestor.join(".git");
        let metadata = match fs::symlink_metadata(&marker) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.file_type().is_symlink() {
            return Err("repository_metadata_unsafe");
        }
        if metadata.is_dir() {
            found = Some(
                marker
                    .canonicalize()
                    .map_err(|_| "repository_unavailable")?,
            );
            break;
        }
        if metadata.is_file() {
            let bytes = fs::read(&marker).map_err(|_| "repository_unavailable")?;
            if bytes.len() > 4096 {
                return Err("repository_metadata_unsafe");
            }
            let text = std::str::from_utf8(&bytes).map_err(|_| "repository_metadata_unsafe")?;
            let value = text
                .trim()
                .strip_prefix("gitdir: ")
                .ok_or("repository_metadata_unsafe")?;
            let path = PathBuf::from(value);
            let resolved = if path.is_absolute() {
                path
            } else {
                ancestor.join(path)
            };
            found = Some(
                resolved
                    .canonicalize()
                    .map_err(|_| "repository_unavailable")?,
            );
            break;
        }
    }
    let git_dir = found.ok_or("not_a_git_repository")?;
    let common_dir = match fs::read_to_string(git_dir.join("commondir")) {
        Ok(value) if value.len() <= 4096 => {
            let path = PathBuf::from(value.trim());
            let resolved = if path.is_absolute() {
                path
            } else {
                git_dir.join(path)
            };
            resolved
                .canonicalize()
                .map_err(|_| "repository_unavailable")?
        }
        Ok(_) => return Err("repository_metadata_unsafe"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => git_dir,
        Err(_) => return Err("repository_unavailable"),
    };
    let configured = Command::new("git")
        .args(["config", "--path", "--get", "core.hooksPath"])
        .current_dir(&start)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| "repository_unavailable")?;
    let hooks = if configured.status.success() {
        if configured.stdout.len() > 4096 {
            return Err("repository_metadata_unsafe");
        }
        let configured_path = std::str::from_utf8(&configured.stdout)
            .map_err(|_| "repository_metadata_unsafe")?
            .trim();
        if configured_path.is_empty() {
            return Err("repository_metadata_unsafe");
        }
        let path = PathBuf::from(configured_path);
        if path.is_absolute() {
            path
        } else {
            start.join(path)
        }
    } else if configured.status.code() == Some(1) && configured.stdout.is_empty() {
        common_dir.join("hooks")
    } else {
        return Err("repository_unavailable");
    };
    let mut existing_ancestor = hooks.as_path();
    while !existing_ancestor.exists() {
        existing_ancestor = existing_ancestor
            .parent()
            .ok_or("repository_metadata_unsafe")?;
    }
    let canonical_ancestor = existing_ancestor
        .canonicalize()
        .map_err(|_| "repository_unavailable")?;
    if !canonical_ancestor.starts_with(&start) && !canonical_ancestor.starts_with(&common_dir) {
        return Err("repository_metadata_unsafe");
    }
    fs::create_dir_all(&hooks).map_err(|_| "repository_unavailable")?;
    let metadata = fs::symlink_metadata(&hooks).map_err(|_| "repository_unavailable")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("repository_metadata_unsafe");
    }
    let canonical = hooks.canonicalize().map_err(|_| "repository_unavailable")?;
    if !canonical.starts_with(&start) && !canonical.starts_with(&common_dir) {
        return Err("repository_metadata_unsafe");
    }
    Ok(canonical)
}

fn write_hook_executable(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<(), &'static str> {
    let bytes = serde_json::to_vec(value).map_err(|_| "hook_state_invalid")?;
    fs::write(path, bytes).map_err(|_| "hook_install_failed")
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn fail_on_text(fail_on: FailOn) -> &'static str {
    match fail_on {
        FailOn::Critical => "critical",
        FailOn::High => "high",
        FailOn::Medium => "medium",
        FailOn::Low => "low",
    }
}

#[cfg(test)]
mod hook_mode_tests {
    use super::{
        HookMode, agent_push_missing_ref_result, should_block_hook, unverified_agent_event_result,
    };

    #[test]
    fn block_mode_stops_only_on_a_threshold_breach() {
        assert!(should_block_hook(HookMode::Block, 2));
        assert!(should_block_hook(HookMode::Block, 3));
        assert!(!should_block_hook(HookMode::Warn, 2));
        assert!(!should_block_hook(HookMode::Block, 0));
        assert!(!should_block_hook(HookMode::Block, 4));
    }

    #[test]
    fn invalid_agent_hook_input_blocks_only_in_block_mode() {
        assert_eq!(unverified_agent_event_result(HookMode::Warn), Ok(0));
        assert_eq!(
            unverified_agent_event_result(HookMode::Block),
            Err("hook_input_unavailable")
        );
    }

    #[test]
    fn agent_push_without_ref_updates_is_unverified() {
        assert_eq!(
            agent_push_missing_ref_result(true, true, HookMode::Warn),
            Some(Ok(0))
        );
        assert_eq!(
            agent_push_missing_ref_result(true, true, HookMode::Block),
            Some(Err("hook_input_unavailable"))
        );
        assert_eq!(
            agent_push_missing_ref_result(false, true, HookMode::Block),
            None
        );
    }
}
