use std::sync::Arc;

use chrono::{DateTime, Duration, NaiveDate, Utc};
use security_monitor_core::{
    Asset, AuditEvent, AuditResult, AuditScope, Finding, FindingStatus, NotificationChannel,
    NotificationChannelKind, Severity,
};
use security_monitor_notify::{
    ChannelSecretConfig, ConfiguredTransport, CredentialStore, NotificationError,
    NotificationEvent, NotificationService, NotificationSettings, OsCredentialStore, SmtpTlsMode,
    approved_http_destination, approved_smtp_destination, store_channel_config,
};
use tauri::State;
use uuid::Uuid;

use super::*;

const SNAPSHOT_MAX_AGE: Duration = Duration::hours(24);
const HIGH_PRIORITY: u8 = 70;
const CRITICAL_PRIORITY: u8 = 90;

pub async fn ensure_desktop_channel(database: &Database) -> Result<(), String> {
    let repository = database.repository::<NotificationChannel>();
    if repository
        .get("desktop-default")
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?
        .is_some()
    {
        return Ok(());
    }
    let now = Utc::now();
    repository
        .create(&NotificationChannel {
            id: "desktop-default".to_owned(),
            kind: NotificationChannelKind::Desktop,
            config_ref: None,
            min_priority: HIGH_PRIORITY,
            enabled: true,
            network_approved_at: None,
            network_approved_destination: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))
}

fn service(
    database: Database,
    outbound_notifications_enabled: bool,
    desktop_notifications_enabled: bool,
) -> Result<NotificationService<ConfiguredTransport>, String> {
    let transport = ConfiguredTransport::with_public_data_http(Arc::new(OsCredentialStore))
        .map_err(notification_error)?;
    Ok(NotificationService::new(
        database,
        transport,
        NotificationSettings {
            outbound_notifications_enabled,
            desktop_notifications_enabled,
        },
    ))
}

async fn service_for_state(
    state: &AppState,
) -> Result<NotificationService<ConfiguredTransport>, String> {
    let settings = state.settings.read().await;
    service(
        state.database.clone(),
        settings.outbound_notifications_enabled,
        settings.desktop_notifications_enabled,
    )
}

fn notification_error(error: NotificationError) -> String {
    opaque(error, "notification_failed")
}

#[tauri::command]
pub async fn list_notification_channels(
    state: State<'_, AppState>,
) -> Result<Vec<NotificationChannelView>, String> {
    state
        .database
        .repository::<NotificationChannel>()
        .list()
        .await
        .map(|channels| {
            channels
                .into_iter()
                .filter(|channel| channel.kind != NotificationChannelKind::Desktop)
                .map(|channel| NotificationChannelView {
                    id: channel.id,
                    kind: channel.kind,
                    enabled: channel.enabled,
                    min_priority: channel.min_priority,
                    approved_destination: channel.network_approved_destination,
                })
                .collect()
        })
        .map_err(|error| opaque(error, "storage_unavailable"))
}

#[tauri::command]
pub async fn save_notification_channel(
    state: State<'_, AppState>,
    input: SaveNotificationChannelInput,
) -> Result<NotificationChannelView, String> {
    if input.min_priority > 100 {
        return Err("invalid_input".to_owned());
    }
    let id = input.id.unwrap_or_else(|| Uuid::new_v4().to_string());
    if !valid_channel_id(&id) {
        return Err("invalid_input".to_owned());
    }
    let config = channel_secret_config(input.config)?;
    let kind = channel_kind(&config);
    let destination = channel_destination(&config)?;
    let credential_store = OsCredentialStore;
    let config_ref =
        store_channel_config(&credential_store, &config).map_err(notification_error)?;
    let now = Utc::now();
    let previous = state
        .database
        .repository::<NotificationChannel>()
        .get(&id)
        .await
        .map_err(|error| {
            let _ = credential_store.delete(&config_ref);
            opaque(error, "storage_unavailable")
        })?;
    let channel = NotificationChannel {
        id: id.clone(),
        kind,
        config_ref: Some(config_ref.clone()),
        min_priority: input.min_priority,
        enabled: input.enabled,
        network_approved_at: input.outbound_approved.then_some(now),
        network_approved_destination: input.outbound_approved.then_some(destination),
        created_at: previous.as_ref().map_or(now, |old| old.created_at),
        updated_at: now,
    };
    if input.outbound_approved {
        state
            .database
            .repository::<AuditEvent>()
            .create(&AuditEvent {
                id: Uuid::new_v4().to_string(),
                timestamp: now,
                actor: "user".to_owned(),
                action: "notification_channel_delivery_approved".to_owned(),
                scope: AuditScope {
                    resource_type: "notification_channel".to_owned(),
                    resource_id: Some(id.clone()),
                },
                result: AuditResult::Succeeded,
            })
            .await
            .map_err(|error| {
                let _ = credential_store.delete(&config_ref);
                opaque(error, "storage_unavailable")
            })?;
    }
    let repository = state.database.repository::<NotificationChannel>();
    let persisted = if previous.is_some() {
        repository.update(&channel).await.map(|_| ())
    } else {
        repository.create(&channel).await
    };
    if let Err(error) = persisted {
        let _ = credential_store.delete(&config_ref);
        return Err(opaque(error, "storage_unavailable"));
    }
    if let Some(old_ref) = previous.and_then(|channel| channel.config_ref)
        && old_ref != config_ref
    {
        let _ = credential_store.delete(&old_ref);
    }
    Ok(NotificationChannelView {
        id,
        kind,
        enabled: channel.enabled,
        min_priority: channel.min_priority,
        approved_destination: channel.network_approved_destination,
    })
}

#[tauri::command]
pub async fn delete_notification_channel(
    state: State<'_, AppState>,
    channel_id: String,
) -> Result<(), String> {
    let repository = state.database.repository::<NotificationChannel>();
    let channel = repository
        .get(&channel_id)
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?
        .ok_or_else(|| "not_found".to_owned())?;
    if channel.kind == NotificationChannelKind::Desktop {
        return Err("permission_denied".to_owned());
    }
    repository
        .delete(&channel_id)
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?;
    if let Some(reference) = channel.config_ref {
        OsCredentialStore
            .delete(&reference)
            .map_err(|error| opaque(error, "credential_store_unavailable"))?;
    }
    Ok(())
}

#[tauri::command]
pub async fn update_notification_channel(
    state: State<'_, AppState>,
    input: UpdateNotificationChannelInput,
) -> Result<NotificationChannelView, String> {
    if input.min_priority > 100 {
        return Err("invalid_input".to_owned());
    }
    let repository = state.database.repository::<NotificationChannel>();
    let mut channel = repository
        .get(&input.id)
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?
        .ok_or_else(|| "not_found".to_owned())?;
    if channel.kind == NotificationChannelKind::Desktop {
        return Err("permission_denied".to_owned());
    }
    channel.enabled = input.enabled;
    channel.min_priority = input.min_priority;
    channel.updated_at = Utc::now();
    repository
        .update(&channel)
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?;
    Ok(NotificationChannelView {
        id: channel.id,
        kind: channel.kind,
        enabled: channel.enabled,
        min_priority: channel.min_priority,
        approved_destination: channel.network_approved_destination,
    })
}

#[tauri::command]
pub fn preview_notification(
    input: SaveNotificationChannelInput,
) -> Result<NotificationPreview, String> {
    let config = channel_secret_config(input.config)?;
    Ok(NotificationPreview {
        title: "Security Monitor — test notification".to_owned(),
        message: "This preview shows the notification format. No data has been sent.".to_owned(),
        destination: Some(channel_destination(&config)?),
    })
}

#[tauri::command]
pub async fn send_test_notification(
    state: State<'_, AppState>,
    channel_id: String,
) -> Result<(), String> {
    let service = service_for_state(&state).await?;
    let event = NotificationEvent {
        kind: "test".to_owned(),
        fingerprint: format!("sha256:{}", "0".repeat(64)),
        finding_id: format!("test-{}", Uuid::new_v4()),
        advisory_id: "SECMON-TEST".to_owned(),
        asset_alias: None,
        priority_score: 100,
        severity: "test".to_owned(),
        title: "Security Monitor — test notification".to_owned(),
        message: "Test notification sent from Security Monitor settings.".to_owned(),
    };
    service
        .test_channel(&channel_id, &event)
        .await
        .map_err(notification_error)
}

fn valid_channel_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn channel_secret_config(
    input: NotificationChannelSecretInput,
) -> Result<ChannelSecretConfig, String> {
    let config = match input {
        NotificationChannelSecretInput::Webhook { url } => ChannelSecretConfig::Webhook { url },
        NotificationChannelSecretInput::Slack { url } => ChannelSecretConfig::Slack { url },
        NotificationChannelSecretInput::Discord { url } => ChannelSecretConfig::Discord { url },
        NotificationChannelSecretInput::Ntfy { url, token } => {
            if token.as_deref().is_some_and(|token| token.len() > 4096) {
                return Err("invalid_input".to_owned());
            }
            ChannelSecretConfig::Ntfy { url, token }
        }
        NotificationChannelSecretInput::Smtp {
            host,
            port,
            tls,
            username,
            password,
            from,
            to,
        } => {
            if password
                .as_deref()
                .is_some_and(|password| password.len() > 4096)
                || username
                    .as_deref()
                    .is_some_and(|username| username.len() > 512)
            {
                return Err("invalid_input".to_owned());
            }
            ChannelSecretConfig::Smtp {
                host,
                port,
                tls: match tls {
                    NotificationSmtpTlsMode::ImplicitTls => SmtpTlsMode::ImplicitTls,
                    NotificationSmtpTlsMode::StartTls => SmtpTlsMode::StartTls,
                },
                username,
                password,
                from,
                to,
            }
        }
    };
    let _ = channel_destination(&config)?;
    Ok(config)
}

fn channel_kind(config: &ChannelSecretConfig) -> NotificationChannelKind {
    match config {
        ChannelSecretConfig::Webhook { .. } => NotificationChannelKind::Webhook,
        ChannelSecretConfig::Slack { .. } => NotificationChannelKind::Slack,
        ChannelSecretConfig::Discord { .. } => NotificationChannelKind::Discord,
        ChannelSecretConfig::Ntfy { .. } => NotificationChannelKind::Ntfy,
        ChannelSecretConfig::Smtp { .. } => NotificationChannelKind::Smtp,
    }
}

fn channel_destination(config: &ChannelSecretConfig) -> Result<String, String> {
    match config {
        ChannelSecretConfig::Webhook { url }
        | ChannelSecretConfig::Slack { url }
        | ChannelSecretConfig::Discord { url }
        | ChannelSecretConfig::Ntfy { url, .. } => {
            approved_http_destination(url).map_err(|error| opaque(error, "invalid_input"))
        }
        ChannelSecretConfig::Smtp {
            host, port, tls, ..
        } => approved_smtp_destination(host, *port, *tls)
            .map_err(|error| opaque(error, "invalid_input")),
    }
}

fn event_fingerprint(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

fn event_for_finding(
    finding: &Finding,
    kind: &str,
    title: String,
    message: String,
) -> NotificationEvent {
    NotificationEvent {
        kind: kind.to_owned(),
        fingerprint: if kind == "finding" {
            finding.fingerprint.clone()
        } else {
            event_fingerprint(&format!(
                "{}|{}|{:?}|{:?}",
                finding.fingerprint, kind, finding.repo_status, finding.production_status
            ))
        },
        finding_id: finding.id.clone(),
        advisory_id: finding.advisory_id.clone(),
        asset_alias: None,
        priority_score: finding.priority_score,
        severity: format!("{:?}", finding.severity).to_ascii_lowercase(),
        title,
        message,
    }
}

pub async fn refresh_project_drift_and_notify(
    state: &AppState,
    project_id: &str,
    now: DateTime<Utc>,
) -> Result<(), String> {
    let before = state
        .database
        .repository::<Finding>()
        .list()
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?
        .into_iter()
        .map(|finding| (finding.id, (finding.repo_status, finding.production_status)))
        .collect::<std::collections::HashMap<_, _>>();
    crate::drift_sync::refresh_project_drift(&state.database, &state.app_data_dir, project_id, now)
        .await?;
    let changed = state
        .database
        .repository::<Finding>()
        .list()
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?
        .into_iter()
        .filter(|finding| {
            before.get(&finding.id)
                != Some(&(
                    finding.repo_status.clone(),
                    finding.production_status.clone(),
                ))
        })
        .map(|finding| finding.id)
        .collect::<Vec<_>>();
    publish_drift_changes(state, &changed).await;
    Ok(())
}

pub async fn publish_new_high_findings(state: &AppState, project_id: Option<&str>) {
    let findings = match state.database.repository::<Finding>().list().await {
        Ok(findings) => findings,
        Err(error) => {
            tracing::warn!(error = %opaque(error, "storage_unavailable"), "notification findings could not be loaded");
            return;
        }
    };
    let instances = state
        .database
        .repository::<security_monitor_core::ComponentInstance>()
        .list()
        .await;
    let Ok(instances) = instances else {
        tracing::warn!("notification components could not be loaded");
        return;
    };
    let projects = state
        .database
        .repository::<security_monitor_core::Project>()
        .list()
        .await;
    let Ok(projects) = projects else {
        tracing::warn!("notification project names could not be loaded");
        return;
    };
    let project_names = projects
        .into_iter()
        .map(|project| (project.id, project.name))
        .collect::<std::collections::HashMap<_, _>>();
    let instance_projects = instances
        .into_iter()
        .map(|instance| (instance.id, instance.project_id))
        .collect::<std::collections::HashMap<_, _>>();
    let Ok(service) = service_for_state(state).await else {
        tracing::warn!("notification transport is unavailable");
        return;
    };
    for finding in findings
        .into_iter()
        .filter(|finding| {
            matches!(
                finding.status,
                FindingStatus::New
                    | FindingStatus::NeedsReview
                    | FindingStatus::ConfirmedAffected
                    | FindingStatus::FixProposed
            ) && matches!(finding.severity, Severity::Critical | Severity::High)
        })
        .filter(|finding| {
            project_id.is_none_or(|project_id| {
                instance_projects
                    .get(&finding.component_instance_id)
                    .and_then(Option::as_deref)
                    == Some(project_id)
            })
        })
    {
        let project_name = instance_projects
            .get(&finding.component_instance_id)
            .and_then(Option::as_ref)
            .and_then(|id| project_names.get(id))
            .map(String::as_str)
            .unwrap_or("local project");
        let message = format!(
            "{} affects {} (priority {}/100).",
            finding.advisory_id, project_name, finding.priority_score
        );
        let mut event = event_for_finding(
            &finding,
            "finding",
            format!("{:?} security finding", finding.severity),
            message,
        );
        event.priority_score = event.priority_score.max(HIGH_PRIORITY);
        if let Err(error) = service.publish(&event).await {
            tracing::warn!(error = %notification_error(error), "finding notification delivery failed");
        }
    }

    let scanner_findings = match state.database.repository::<ScannerFinding>().list().await {
        Ok(findings) => findings,
        Err(error) => {
            tracing::warn!(error = %opaque(error, "storage_unavailable"), "scanner notifications could not load findings");
            return;
        }
    };
    for finding in scanner_findings.into_iter().filter(|finding| {
        matches!(finding.severity, Severity::Critical | Severity::High)
            && project_id.is_none_or(|project_id| finding.project_id == project_id)
    }) {
        let project_name = project_names
            .get(&finding.project_id)
            .map(String::as_str)
            .unwrap_or("local project");
        let severity = format!("{:?}", finding.severity).to_ascii_lowercase();
        let event = NotificationEvent {
            kind: "scanner_finding".to_owned(),
            fingerprint: event_fingerprint(&format!("scanner|{}", finding.fingerprint)),
            finding_id: finding.id.clone(),
            advisory_id: finding
                .rule_id
                .clone()
                .unwrap_or_else(|| finding.kind.clone()),
            asset_alias: None,
            priority_score: if finding.severity == Severity::Critical {
                CRITICAL_PRIORITY
            } else {
                HIGH_PRIORITY
            },
            severity: severity.clone(),
            title: format!("{} security observation", finding.scanner),
            message: format!(
                "{} reported a {} {} finding in {}.",
                finding.scanner, severity, finding.kind, project_name
            ),
        };
        if let Err(error) = service.publish(&event).await {
            tracing::warn!(error = %notification_error(error), "scanner finding notification delivery failed");
        }
    }
}

pub async fn publish_drift_changes(state: &AppState, changed_finding_ids: &[String]) {
    if changed_finding_ids.is_empty() {
        return;
    }
    let repo = state.database.repository::<Finding>();
    let Ok(service) = service_for_state(state).await else {
        return;
    };
    for id in changed_finding_ids {
        let Ok(Some(finding)) = repo.get(id).await else {
            continue;
        };
        let event = event_for_finding(
            &finding,
            "drift",
            "Deployment drift changed".to_owned(),
            format!(
                "{} deployment status changed: repository {:?}, production {:?}.",
                finding.advisory_id, finding.repo_status, finding.production_status
            ),
        );
        if let Err(error) = service.publish(&event).await {
            tracing::warn!(error = %notification_error(error), "drift notification delivery failed");
        }
    }
}

pub async fn publish_stale_server_snapshots(state: &AppState, now: DateTime<Utc>) {
    let Ok(assets) = state.database.repository::<Asset>().list().await else {
        tracing::warn!("stale snapshot check could not load servers");
        return;
    };
    let Ok(service) = service_for_state(state).await else {
        return;
    };
    for asset in assets.into_iter().filter(|asset| {
        asset.last_success_at.is_none_or(|captured| {
            captured > now || now.signed_duration_since(captured) > SNAPSHOT_MAX_AGE
        })
    }) {
        let snapshot_marker = asset
            .last_success_at
            .map_or_else(|| "never-collected".to_owned(), |time| time.to_rfc3339());
        let display_name = safe_asset_alias(&asset.hostname_alias).unwrap_or("server");
        let event = NotificationEvent {
            kind: "snapshot_stale".to_owned(),
            fingerprint: event_fingerprint(&format!("{}|{}", asset.id, snapshot_marker)),
            finding_id: asset.id.clone(),
            advisory_id: "SERVER-SNAPSHOT-STALE".to_owned(),
            asset_alias: safe_asset_alias(&asset.hostname_alias).map(str::to_owned),
            priority_score: HIGH_PRIORITY,
            severity: "warning".to_owned(),
            title: "Server inventory is stale".to_owned(),
            message: format!(
                "The last complete inventory for {} is older than 24 hours or unavailable.",
                display_name
            ),
        };
        if let Err(error) = service.publish(&event).await {
            tracing::warn!(error = %notification_error(error), "snapshot notification delivery failed");
        }
    }
}

fn safe_asset_alias(value: &str) -> Option<&str> {
    (!value.is_empty()
        && value.len() <= 120
        && !value.contains('/')
        && !value.contains('\\')
        && !value.chars().any(char::is_control))
    .then_some(value)
}

pub async fn publish_daily_summary(state: &AppState, date: NaiveDate) {
    let enabled = state.settings.read().await.daily_summary_enabled;
    if !enabled {
        return;
    }
    let Ok(findings) = state.database.repository::<Finding>().list().await else {
        tracing::warn!("daily notification summary could not load findings");
        return;
    };
    let count = findings
        .iter()
        .filter(|finding| {
            finding.status == FindingStatus::New
                && matches!(finding.severity, Severity::Critical | Severity::High)
        })
        .count();
    let event = NotificationEvent {
        kind: "daily_summary".to_owned(),
        fingerprint: event_fingerprint(&format!("daily-summary|{date}")),
        finding_id: "daily-summary".to_owned(),
        advisory_id: "DAILY-SUMMARY".to_owned(),
        asset_alias: None,
        priority_score: 0,
        severity: "info".to_owned(),
        title: "Daily security summary".to_owned(),
        message: format!("{count} new critical or high findings are open."),
    };
    let Ok(service) = service_for_state(state).await else {
        return;
    };
    if let Err(error) = service.publish(&event).await {
        tracing::warn!(error = %notification_error(error), "daily summary delivery failed");
    }
}
