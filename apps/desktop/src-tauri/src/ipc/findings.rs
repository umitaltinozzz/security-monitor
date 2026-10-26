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
pub async fn set_scanner_finding_review(
    state: State<'_, AppState>,
    finding_id: String,
    status: ScannerFindingStatus,
    reason: Option<String>,
) -> Result<ScannerFinding, String> {
    let repository = state.database.repository::<ScannerFinding>();
    let mut finding = repository
        .get(&finding_id)
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?
        .ok_or_else(|| "scanner_finding_not_found".to_owned())?;
    (finding.review_reason, finding.reviewed_at) =
        normalized_scanner_review_fields(status, reason, Utc::now()).map_err(str::to_owned)?;
    finding.status = status;
    repository
        .update(&finding)
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?;
    let now = finding.reviewed_at.unwrap_or_else(Utc::now);
    write_audit_event(
        &state.database,
        &format!(
            "scanner_finding_review_changed:{}",
            scanner_status_key(status)
        ),
        "scanner_finding",
        Some(finding.id.clone()),
        now,
        AuditResult::Succeeded,
    )
    .await?;
    Ok(finding)
}

fn normalized_scanner_review_fields(
    status: ScannerFindingStatus,
    reason: Option<String>,
    reviewed_at: chrono::DateTime<Utc>,
) -> Result<(Option<String>, Option<chrono::DateTime<Utc>>), &'static str> {
    if status == ScannerFindingStatus::NeedsReview {
        if reason
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        {
            return Err("invalid_input");
        }
        return Ok((None, None));
    }
    let reason = reason
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty() && value.len() <= 1000)
        .ok_or("invalid_input")?;
    Ok((Some(reason), Some(reviewed_at)))
}

fn scanner_status_key(status: ScannerFindingStatus) -> &'static str {
    match status {
        ScannerFindingStatus::NeedsReview => "needs_review",
        ScannerFindingStatus::Confirmed => "confirmed",
        ScannerFindingStatus::AcceptedRisk => "accepted_risk",
        ScannerFindingStatus::FalsePositive => "false_positive",
        ScannerFindingStatus::Resolved => "resolved",
    }
}

#[cfg(test)]
mod scanner_review_tests {
    use chrono::{TimeZone, Utc};

    use super::{ScannerFindingStatus, normalized_scanner_review_fields};

    #[test]
    fn reviewed_scanner_status_requires_a_bounded_reason() {
        let at = Utc.with_ymd_and_hms(2026, 10, 26, 12, 0, 0).unwrap();
        assert_eq!(
            normalized_scanner_review_fields(
                ScannerFindingStatus::FalsePositive,
                Some("  reviewed source  ".to_owned()),
                at,
            )
            .unwrap(),
            (Some("reviewed source".to_owned()), Some(at))
        );
        assert!(
            normalized_scanner_review_fields(
                ScannerFindingStatus::AcceptedRisk,
                Some("  ".to_owned()),
                at,
            )
            .is_err()
        );
        assert!(
            normalized_scanner_review_fields(
                ScannerFindingStatus::Resolved,
                Some("x".repeat(1001)),
                at,
            )
            .is_err()
        );
    }

    #[test]
    fn returning_to_needs_review_clears_user_review_metadata() {
        let at = Utc.with_ymd_and_hms(2026, 10, 26, 12, 0, 0).unwrap();
        assert_eq!(
            normalized_scanner_review_fields(ScannerFindingStatus::NeedsReview, None, at,).unwrap(),
            (None, None)
        );
        assert!(
            normalized_scanner_review_fields(
                ScannerFindingStatus::NeedsReview,
                Some("unexpected note".to_owned()),
                at,
            )
            .is_err()
        );
    }
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
