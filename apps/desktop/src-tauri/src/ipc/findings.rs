use super::*;

#[tauri::command]
pub async fn list_findings(state: State<'_, AppState>) -> Result<Vec<Finding>, String> {
    state
        .database
        .repository::<Finding>()
        .list()
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))
}

#[tauri::command]
pub async fn list_scanner_findings(
    state: State<'_, AppState>,
) -> Result<Vec<ScannerFinding>, String> {
    let mut findings = state
        .database
        .repository::<ScannerFinding>()
        .list()
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?;
    findings.sort_by_key(|finding| std::cmp::Reverse(finding.last_seen_at));
    Ok(findings)
}

#[tauri::command]
pub async fn list_findings_page(
    state: State<'_, AppState>,
    offset: u32,
    limit: u32,
    status: Option<FindingStatus>,
    severity: Option<Severity>,
    project_id: Option<String>,
    query: String,
) -> Result<FindingPageView, String> {
    let status = status
        .map(|value| serde_json::to_value(value).map_err(|error| opaque(error, "invalid_input")))
        .transpose()?
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "invalid_input".to_owned())
        })
        .transpose()?;
    let severity = severity
        .map(|value| serde_json::to_value(value).map_err(|error| opaque(error, "invalid_input")))
        .transpose()?
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "invalid_input".to_owned())
        })
        .transpose()?;
    let page = state
        .database
        .repository::<Finding>()
        .list_filtered_page(
            offset,
            limit,
            &security_monitor_database::FindingPageFilter {
                status: status.as_deref(),
                severity: severity.as_deref(),
                project_id: project_id.as_deref(),
                search: &query,
            },
        )
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?;
    Ok(FindingPageView {
        findings: page.items,
        total_count: page.total_count,
        offset: page.offset,
        limit: page.limit,
    })
}

#[tauri::command]
pub async fn list_advisories(state: State<'_, AppState>) -> Result<Vec<Advisory>, String> {
    state
        .database
        .repository::<Advisory>()
        .list()
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))
}

#[tauri::command]
pub async fn list_components(state: State<'_, AppState>) -> Result<Vec<Component>, String> {
    state
        .database
        .repository::<Component>()
        .list()
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))
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
        .map_err(|error| opaque(error, "storage_unavailable"))
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
        .map_err(|error| opaque(error, "storage_unavailable"))
}

#[tauri::command]
pub async fn list_scan_runs(state: State<'_, AppState>) -> Result<Vec<ScanRun>, String> {
    state
        .database
        .repository::<ScanRun>()
        .list()
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))
}

#[tauri::command]
pub async fn list_audit_events(
    state: State<'_, AppState>,
    offset: u32,
    limit: u32,
) -> Result<Vec<AuditEvent>, String> {
    state
        .database
        .repository::<AuditEvent>()
        .list_page(offset, limit)
        .await
        .map(|page| page.items)
        .map_err(|error| opaque(error, "storage_unavailable"))
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
        .map_err(|error| opaque(error, "storage_unavailable"))?
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
    apply_transition(&mut finding, &transition)
        .map_err(|error| opaque(error, "status_rejected"))?;
    repository
        .update(&finding)
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?;
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
