use super::*;

#[tauri::command]
pub async fn list_news_signals(state: State<'_, AppState>) -> Result<Vec<NewsSignal>, String> {
    state
        .database
        .repository::<NewsSignal>()
        .list()
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))
}

#[tauri::command]
pub async fn refresh_news_signals(state: State<'_, AppState>) -> Result<NewsSyncReport, String> {
    let settings = state.settings.read().await.clone();
    if !settings.public_downloads_enabled {
        return Err("permission_denied".to_owned());
    }
    NewsSignalService::new(
        HttpPolicy {
            public_downloads_enabled: true,
        },
        state.database.clone(),
        state.app_data_dir.clone(),
    )
    .map_err(|error| opaque(error, "unknown"))?
    .refresh()
    .await
    .map_err(|error| opaque(error, "unknown"))
}
