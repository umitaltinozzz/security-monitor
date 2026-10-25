use super::*;

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
pub async fn get_ai_configuration(
    state: State<'_, AppState>,
) -> Result<AiConfigurationView, String> {
    let settings = state.ai_settings.read().await.clone();
    let providers = state
        .database
        .repository::<AiProvider>()
        .list()
        .await
        .map_err(|_| "storage_unavailable".to_owned())?;
    let runs = state
        .database
        .repository::<AiRun>()
        .list()
        .await
        .map_err(|_| "storage_unavailable".to_owned())?;
    Ok(AiConfigurationView {
        settings,
        providers,
        runs,
    })
}

#[tauri::command]
pub async fn save_ai_settings(
    state: State<'_, AppState>,
    settings: AiSettings,
) -> Result<(), String> {
    save_ai_settings_for_app(&state, settings).await
}

pub(super) async fn save_ai_settings_for_app(
    state: &AppState,
    settings: AiSettings,
) -> Result<(), String> {
    settings
        .validate()
        .map_err(|_| "invalid_input".to_owned())?;
    let providers = state
        .database
        .repository::<AiProvider>()
        .list()
        .await
        .map_err(|_| "storage_unavailable".to_owned())?;
    let provider_ids = providers
        .iter()
        .map(|provider| provider.id.as_str())
        .collect::<Vec<_>>();
    let api_provider_ids = providers
        .iter()
        .filter(|provider| provider.kind != AiProviderKind::AgentCli)
        .map(|provider| provider.id.as_str())
        .collect::<Vec<_>>();
    for assignment in &settings.assignments {
        if assignment
            .provider_id
            .as_deref()
            .is_some_and(|id| !api_provider_ids.contains(&id))
            || assignment
                .fallback_provider_id
                .as_deref()
                .is_some_and(|id| !api_provider_ids.contains(&id))
        {
            return Err("invalid_input".to_owned());
        }
    }
    if settings
        .budget
        .daily_by_provider_usd
        .keys()
        .chain(settings.budget.monthly_by_provider_usd.keys())
        .any(|id| !provider_ids.contains(&id.as_str()))
    {
        return Err("invalid_input".to_owned());
    }
    let supported = supported_tools()
        .into_iter()
        .map(|tool| tool.name)
        .collect::<Vec<_>>();
    if settings
        .enabled_tools
        .iter()
        .any(|name| !supported.contains(name))
    {
        return Err("invalid_input".to_owned());
    }
    let projects = state
        .database
        .repository::<Project>()
        .list()
        .await
        .map_err(|_| "storage_unavailable".to_owned())?;
    if settings
        .mcp_source_access_projects
        .iter()
        .any(|project_id| !projects.iter().any(|project| project.id == *project_id))
    {
        return Err("invalid_input".to_owned());
    }
    let previous = state.ai_settings.read().await.clone();
    let now = Utc::now();
    let enabled_tools = settings
        .enabled_tools
        .iter()
        .filter(|tool| !previous.enabled_tools.contains(tool))
        .cloned()
        .collect::<Vec<_>>();
    for tool in &enabled_tools {
        write_audit_event(
            &state.database,
            "ai_tool_permission_enable_approved",
            "ai_tool",
            Some(tool.clone()),
            now,
            AuditResult::Succeeded,
        )
        .await?;
    }
    let revoked_tools = previous
        .enabled_tools
        .iter()
        .filter(|tool| !settings.enabled_tools.contains(tool))
        .cloned()
        .collect::<Vec<_>>();
    let approved_source_projects = settings
        .mcp_source_access_projects
        .iter()
        .filter(|project_id| !previous.mcp_source_access_projects.contains(project_id))
        .cloned()
        .collect::<Vec<_>>();
    let revoked_source_projects = previous
        .mcp_source_access_projects
        .iter()
        .filter(|project_id| !settings.mcp_source_access_projects.contains(project_id))
        .cloned()
        .collect::<Vec<_>>();
    for tool in &revoked_tools {
        // Revocation remains possible during an audit-storage failure; it reduces access.
        let _ = write_audit_event(
            &state.database,
            "ai_tool_permission_revocation_requested",
            "ai_tool",
            Some(tool.clone()),
            now,
            AuditResult::Succeeded,
        )
        .await;
    }
    for project_id in &approved_source_projects {
        write_audit_event(
            &state.database,
            "mcp_source_access_permission_enable_approved",
            "project",
            Some(project_id.clone()),
            now,
            AuditResult::Succeeded,
        )
        .await?;
    }
    for project_id in &revoked_source_projects {
        // Revocation remains possible during an audit-storage failure because it reduces access.
        let _ = write_audit_event(
            &state.database,
            "mcp_source_access_permission_revocation_requested",
            "project",
            Some(project_id.clone()),
            now,
            AuditResult::Succeeded,
        )
        .await;
    }
    state.save_ai_settings(settings).await?;
    let persisted_at = Utc::now();
    for tool in enabled_tools {
        write_audit_event(
            &state.database,
            "ai_tool_permission_enabled",
            "ai_tool",
            Some(tool),
            persisted_at,
            AuditResult::Succeeded,
        )
        .await?;
    }
    for tool in revoked_tools {
        write_audit_event(
            &state.database,
            "ai_tool_permission_revoked",
            "ai_tool",
            Some(tool),
            persisted_at,
            AuditResult::Succeeded,
        )
        .await?;
    }
    for project_id in approved_source_projects {
        write_audit_event(
            &state.database,
            "mcp_source_access_permission_enabled",
            "project",
            Some(project_id),
            persisted_at,
            AuditResult::Succeeded,
        )
        .await?;
    }
    for project_id in revoked_source_projects {
        write_audit_event(
            &state.database,
            "mcp_source_access_permission_revoked",
            "project",
            Some(project_id),
            persisted_at,
            AuditResult::Succeeded,
        )
        .await?;
    }
    Ok(())
}
