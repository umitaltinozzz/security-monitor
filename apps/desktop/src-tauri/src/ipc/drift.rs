use super::*;

#[tauri::command]
pub async fn list_project_server_links(
    state: State<'_, AppState>,
) -> Result<Vec<ProjectServerLink>, String> {
    state
        .database
        .repository::<ProjectServerLink>()
        .list()
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))
}

/// Links a server to a project only after the user confirms it runs that project's deployments;
/// production drift is never inferred from an unconfirmed association.
#[tauri::command]
pub async fn link_project_server(
    state: State<'_, AppState>,
    project_id: String,
    asset_id: String,
    confirmed: bool,
) -> Result<ProjectServerLink, String> {
    if !confirmed {
        return Err("permission_denied".to_owned());
    }
    let projects = state.database.repository::<Project>();
    if projects
        .get(&project_id)
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?
        .is_none()
    {
        return Err("project_not_found".to_owned());
    }
    let asset = state
        .database
        .repository::<Asset>()
        .get(&asset_id)
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?
        .ok_or_else(|| "server_not_found".to_owned())?;
    if asset.removed_at.is_some() {
        return Err("server_not_found".to_owned());
    }
    let links = state.database.repository::<ProjectServerLink>();
    if let Some(existing) = links
        .list()
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?
        .into_iter()
        .find(|link| link.project_id == project_id && link.asset_id == asset_id)
    {
        return Ok(existing);
    }
    let now = Utc::now();
    let link = ProjectServerLink {
        id: Uuid::new_v4().to_string(),
        project_id: project_id.clone(),
        asset_id,
        confirmed_at: now,
    };
    links
        .create(&link)
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?;
    write_audit_event(
        &state.database,
        "project_server_link_confirmed",
        "project",
        Some(project_id.clone()),
        now,
        AuditResult::Succeeded,
    )
    .await?;
    crate::drift_sync::refresh_project_drift(
        &state.database,
        &state.app_data_dir,
        &project_id,
        now,
    )
    .await?;
    Ok(link)
}

#[tauri::command]
pub async fn unlink_project_server(
    state: State<'_, AppState>,
    link_id: String,
) -> Result<bool, String> {
    let links = state.database.repository::<ProjectServerLink>();
    let Some(link) = links
        .get(&link_id)
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?
    else {
        return Ok(false);
    };
    links
        .delete(&link.id)
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?;
    let now = Utc::now();
    write_audit_event(
        &state.database,
        "project_server_link_removed",
        "project",
        Some(link.project_id.clone()),
        now,
        AuditResult::Succeeded,
    )
    .await?;
    crate::drift_sync::refresh_project_drift(
        &state.database,
        &state.app_data_dir,
        &link.project_id,
        now,
    )
    .await?;
    Ok(true)
}

pub(super) async fn refresh_linked_projects(
    state: &AppState,
    asset_id: &str,
) -> Result<(), String> {
    let project_ids = state
        .database
        .repository::<ProjectServerLink>()
        .list()
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?
        .into_iter()
        .filter(|link| link.asset_id == asset_id)
        .map(|link| link.project_id)
        .collect::<Vec<_>>();
    for project_id in project_ids {
        crate::drift_sync::refresh_project_drift(
            &state.database,
            &state.app_data_dir,
            &project_id,
            Utc::now(),
        )
        .await?;
    }
    Ok(())
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
        .map_err(|error| opaque(error, "storage_unavailable"))?;
    let Some(asset) = asset else {
        return Ok(None);
    };
    let Some(inventory) = load_server_snapshot(&state.app_data_dir, &asset.id)? else {
        return Ok(None);
    };
    let audit = state
        .database
        .latest_successful_audit_event("server_inventory_collection_approved", &asset.id)
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?;
    let approved_at = audit
        .map(|event| event.timestamp)
        .ok_or_else(|| "collection_failed".to_owned())?;
    let evaluation = super::servers::evaluate_server_os_packages(
        state.app_data_dir.join("advisories").join("osv"),
        inventory.clone(),
    )
    .await?;
    Ok(Some(collection_summary(
        asset.id,
        &inventory,
        approved_at,
        evaluation,
    )))
}

pub(super) fn collection_summary(
    asset_id: String,
    inventory: &AgentInventory,
    approved_at: chrono::DateTime<Utc>,
    os_package_evaluation: super::os_packages::OsPackageEvaluation,
) -> CollectionSummary {
    let mut services_needing_restart = inventory
        .processes
        .iter()
        .filter(|process| !process.deleted_shared_libraries.is_empty())
        .filter_map(|process| {
            process
                .service_unit
                .as_deref()
                .and_then(|unit| unit.strip_suffix(".service"))
                .or_else(|| {
                    process
                        .executable_path
                        .as_deref()
                        .and_then(|path| Path::new(path).file_name())
                        .and_then(|name| name.to_str())
                })
        })
        .map(str::to_owned)
        .collect::<Vec<_>>();
    services_needing_restart.sort();
    services_needing_restart.dedup();
    let operating_system = inventory.operating_system.as_ref();
    CollectionSummary {
        asset_id,
        complete: inventory.complete,
        package_count: inventory.packages.len(),
        service_count: inventory.services.len(),
        container_count: inventory.containers.len(),
        deployment_count: inventory.deployments.len(),
        running_kernel_release: operating_system.and_then(|os| os.kernel_release.clone()),
        installed_kernel_release: operating_system
            .and_then(|os| os.installed_kernel_release.clone()),
        kernel_restart_required: operating_system.and_then(|os| os.kernel_restart_required),
        services_needing_restart,
        deleted_shared_library_count: inventory
            .processes
            .iter()
            .map(|process| process.deleted_shared_libraries.len())
            .sum(),
        maps_unverified_process_count: inventory
            .processes
            .iter()
            .filter(|process| {
                matches!(
                    process.maps_status,
                    security_monitor_agent_protocol::MapsStatus::Unavailable
                        | security_monitor_agent_protocol::MapsStatus::Unknown
                )
            })
            .count(),
        os_package_evaluation_status: os_package_evaluation.status,
        os_package_findings: os_package_evaluation.findings,
        approved_at,
    }
}

#[cfg(test)]
mod collection_summary_tests {
    use chrono::Utc;
    use security_monitor_agent_protocol::{MapsStatus, decode_inventory};

    use super::collection_summary;
    use crate::{ipc::os_packages::OsPackageEvaluation, ipc_types::OsPackageEvaluationStatus};

    #[test]
    fn collection_summary_counts_unknown_and_unavailable_maps_per_process() {
        let mut inventory = decode_inventory(include_bytes!(
            "../../../../../tests/fixtures/agent/realistic-complete.json"
        ))
        .expect("complete server inventory fixture should decode");
        let mut unavailable = inventory.processes[0].clone();
        unavailable.maps_status = MapsStatus::Unavailable;
        let mut not_applicable = inventory.processes[0].clone();
        not_applicable.maps_status = MapsStatus::NotApplicable;
        let mut unknown = inventory.processes[0].clone();
        unknown.maps_status = MapsStatus::Unknown;
        inventory.processes = vec![unavailable, not_applicable, unknown];

        let summary = collection_summary(
            "asset-1".to_owned(),
            &inventory,
            Utc::now(),
            OsPackageEvaluation {
                status: OsPackageEvaluationStatus::NotEvaluated,
                findings: Vec::new(),
            },
        );

        assert_eq!(summary.maps_unverified_process_count, 2);
    }
}
