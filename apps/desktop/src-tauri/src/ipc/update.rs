use super::*;

const UPDATE_MANIFEST_URL: &str =
    "https://github.com/umitaltinozzz/security-monitor/releases/latest/download/latest.json";

fn ensure_update_downloads_enabled(settings: &AppSettings) -> Result<(), &'static str> {
    if settings.public_downloads_enabled {
        Ok(())
    } else {
        Err("public_downloads_disabled")
    }
}

fn update_public_key() -> Result<&'static str, &'static str> {
    option_env!("SECMON_UPDATE_PUBLIC_KEY")
        .filter(|key| !key.trim().is_empty())
        .ok_or("updater_not_configured")
}

fn map_update_destination_error(error: ProviderError) -> &'static str {
    match error {
        ProviderError::NetworkDisabled => "public_downloads_disabled",
        ProviderError::InvalidUrl | ProviderError::DestinationNotAllowed => {
            "update_destination_rejected"
        }
        _ => "update_check_failed",
    }
}

fn bounded_update_notes(notes: Option<String>) -> Option<String> {
    notes.map(|notes| notes.chars().take(4_096).collect())
}

fn validate_expected_update_version(version: &str) -> Result<(), &'static str> {
    if version.is_empty()
        || version.len() > 64
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
    {
        return Err("invalid_input");
    }
    Ok(())
}

#[tauri::command]
pub async fn check_for_updates(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<UpdateCheckResult, String> {
    let _guard = state.update_run_guard.lock().await;
    let settings = state.settings.read().await.clone();
    ensure_update_downloads_enabled(&settings).map_err(str::to_owned)?;
    let public_key = update_public_key().map_err(str::to_owned)?;
    authorize_updater_destination(
        UPDATE_MANIFEST_URL,
        HttpPolicy {
            public_downloads_enabled: settings.public_downloads_enabled,
        },
    )
    .map_err(map_update_destination_error)
    .map_err(str::to_owned)?;

    let endpoint = Url::parse(UPDATE_MANIFEST_URL).map_err(|_| "update_check_failed".to_owned())?;
    let updater = app
        .updater_builder()
        .timeout(Duration::from_secs(30))
        .pubkey(public_key)
        .endpoints(vec![endpoint])
        .map_err(|_| "update_check_failed".to_owned())?
        .configure_client(configure_updater_client)
        .build()
        .map_err(|_| "update_check_failed".to_owned())?;
    let update = updater
        .check()
        .await
        .map_err(|_| "update_check_failed".to_owned())?;
    let Some(update) = update else {
        return Ok(UpdateCheckResult {
            available: false,
            version: None,
            notes: None,
        });
    };

    authorize_updater_destination(
        update.download_url.as_str(),
        HttpPolicy {
            public_downloads_enabled: settings.public_downloads_enabled,
        },
    )
    .map_err(map_update_destination_error)
    .map_err(str::to_owned)?;
    Ok(UpdateCheckResult {
        available: true,
        version: Some(update.version.to_string()),
        notes: bounded_update_notes(update.body),
    })
}

#[tauri::command]
pub async fn install_update(
    app: AppHandle,
    state: State<'_, AppState>,
    expected_version: String,
) -> Result<(), String> {
    validate_expected_update_version(&expected_version).map_err(str::to_owned)?;
    let _guard = state.update_run_guard.lock().await;
    let settings = state.settings.read().await.clone();
    ensure_update_downloads_enabled(&settings).map_err(str::to_owned)?;
    let public_key = update_public_key().map_err(str::to_owned)?;
    authorize_updater_destination(
        UPDATE_MANIFEST_URL,
        HttpPolicy {
            public_downloads_enabled: settings.public_downloads_enabled,
        },
    )
    .map_err(map_update_destination_error)
    .map_err(str::to_owned)?;

    let endpoint =
        Url::parse(UPDATE_MANIFEST_URL).map_err(|_| "update_install_failed".to_owned())?;
    let updater = app
        .updater_builder()
        .timeout(Duration::from_secs(30))
        .pubkey(public_key)
        .endpoints(vec![endpoint])
        .map_err(|_| "update_install_failed".to_owned())?
        .configure_client(configure_updater_client)
        .build()
        .map_err(|_| "update_install_failed".to_owned())?;
    let update = updater
        .check()
        .await
        .map_err(|_| "update_install_failed".to_owned())?
        .filter(|update| update.version == expected_version)
        .ok_or_else(|| "update_changed".to_owned())?;
    authorize_updater_destination(
        update.download_url.as_str(),
        HttpPolicy {
            public_downloads_enabled: settings.public_downloads_enabled,
        },
    )
    .map_err(map_update_destination_error)
    .map_err(str::to_owned)?;
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|_| "update_install_failed".to_owned())?;
    app.restart();
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AdvisoryUpdateStatus {
    pub ecosystem: String,
    pub stale: bool,
    pub updated_at: Option<chrono::DateTime<Utc>>,
}
