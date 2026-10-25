use super::update::AdvisoryUpdateStatus;
use super::*;

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
            project_id: project_id.clone(),
            root,
            profile,
            reason: ScanReason::Manual,
        })
        .await
        .map_err(|_| "scan_failed".to_owned())?;
    let scan_id = handle.id.clone();
    let returned_id = scan_id.clone();
    let result_store = Arc::clone(&state.scan_results);
    let database = state.database.clone();
    let app_data_dir = state.app_data_dir.clone();
    tauri::async_runtime::spawn(async move {
        let result = match handle.wait().await {
            Ok(summary) => {
                // Drift failures leave statuses unknown; they never fail the scan itself.
                if let Err(error) = crate::drift_sync::refresh_project_drift(
                    &database,
                    &app_data_dir,
                    &project_id,
                    Utc::now(),
                )
                .await
                {
                    tracing::warn!(%error, "drift assessment after scan failed");
                }
                ScanResult::from_summary(summary)
            }
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
    let mut ecosystems = settings.ecosystems;
    if let Ok(assets) = state.database.repository::<Asset>().list().await {
        for asset in assets {
            let Ok(Some(inventory)) = load_server_snapshot(&state.app_data_dir, &asset.id) else {
                continue;
            };
            if let Some(ecosystem) = inventory
                .operating_system
                .as_ref()
                .and_then(security_monitor_agent_protocol::osv_os_package_ecosystem)
            {
                ecosystems.push(ecosystem);
            }
        }
    }
    let statuses = updater
        .update_ecosystems(
            state.app_data_dir.join("advisories").join("osv"),
            ecosystems,
        )
        .await
        .map_err(|_| "unknown".to_owned())?;
    let queue = state.scans.read().await.queue.clone();
    queue
        .refresh_advisories()
        .await
        .map_err(|_| "scan_failed".to_owned())?;
    Ok(statuses
        .into_iter()
        .map(|status| AdvisoryUpdateStatus {
            ecosystem: status.ecosystem,
            stale: status.stale,
            updated_at: status.updated_at,
        })
        .collect())
}
