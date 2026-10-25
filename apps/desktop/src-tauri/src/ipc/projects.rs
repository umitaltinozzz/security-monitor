use super::*;

#[tauri::command]
pub async fn list_projects(state: State<'_, AppState>) -> Result<Vec<Project>, String> {
    state
        .database
        .repository::<Project>()
        .list()
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))
}

#[tauri::command]
pub async fn add_project(state: State<'_, AppState>, path: String) -> Result<Project, String> {
    let canonical = PathBuf::from(path)
        .canonicalize()
        .map_err(|error| opaque(error, "invalid_project_path"))?;
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
        .map_err(|error| opaque(error, "storage_unavailable"))?;
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
        .map_err(|error| opaque(error, "storage_unavailable"))?;
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
    let result = discover_projects(path).map_err(|error| opaque(error, "invalid_project_path"))?;
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
