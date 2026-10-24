use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use security_monitor_core::{
    NotificationChannel, NotificationChannelKind, NotificationDeliveryState,
};
use security_monitor_database::{Database, DatabaseError};
use thiserror::Error;

const LEASE_DURATION: Duration = Duration::minutes(2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationEvent {
    pub fingerprint: String,
    pub finding_id: String,
    pub advisory_id: String,
    pub asset_alias: Option<String>,
    pub priority_score: u8,
    pub severity: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotificationSettings {
    /// Global privacy control. External channels require this and a timestamped channel approval.
    pub outbound_notifications_enabled: bool,
    pub deduplication_window: Duration,
}

impl Default for NotificationSettings {
    fn default() -> Self {
        Self {
            outbound_notifications_enabled: false,
            deduplication_window: Duration::minutes(15),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryStatus {
    Delivered,
    Suppressed,
    BelowThreshold,
    Disabled,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryResult {
    pub channel_id: String,
    pub status: DeliveryStatus,
}

#[derive(Debug, Error)]
pub enum NotificationError {
    #[error("notification event is invalid")]
    InvalidEvent,
    #[error("notification settings are invalid")]
    InvalidSettings,
    #[error("external notification channel is missing recorded approval")]
    ApprovalRequired,
    #[error("notification destination configuration is invalid")]
    InvalidConfiguration,
    #[error("operating-system credential store is unavailable")]
    CredentialStore,
    #[error("notification delivery failed")]
    DeliveryFailed,
    #[error("notification snooze must end in the future")]
    InvalidSnooze,
    #[error("database operation failed")]
    Database(#[from] DatabaseError),
}

#[async_trait]
pub trait ChannelTransport: Send + Sync {
    async fn deliver(
        &self,
        channel: &NotificationChannel,
        event: &NotificationEvent,
        outbound_notifications_enabled: bool,
    ) -> Result<(), NotificationError>;
}

pub struct NotificationService<T> {
    database: Database,
    transport: Arc<T>,
    settings: NotificationSettings,
}

impl<T> NotificationService<T>
where
    T: ChannelTransport + 'static,
{
    pub fn new(database: Database, transport: T, settings: NotificationSettings) -> Self {
        Self {
            database,
            transport: Arc::new(transport),
            settings,
        }
    }

    pub async fn publish(
        &self,
        event: &NotificationEvent,
    ) -> Result<Vec<DeliveryResult>, NotificationError> {
        self.publish_at(event, Utc::now()).await
    }

    pub async fn publish_at(
        &self,
        event: &NotificationEvent,
        now: DateTime<Utc>,
    ) -> Result<Vec<DeliveryResult>, NotificationError> {
        validate_event(event)?;
        if self.settings.deduplication_window < Duration::zero()
            || self.settings.deduplication_window > Duration::days(30)
        {
            return Err(NotificationError::InvalidSettings);
        }
        let channels = self
            .database
            .repository::<NotificationChannel>()
            .list()
            .await?;
        let states = self.database.repository::<NotificationDeliveryState>();
        let mut results = Vec::new();
        for channel in channels {
            if !channel.enabled {
                results.push(result(&channel, DeliveryStatus::Disabled));
                continue;
            }
            if event.priority_score < channel.min_priority {
                results.push(result(&channel, DeliveryStatus::BelowThreshold));
                continue;
            }
            let external = channel.kind != NotificationChannelKind::Desktop;
            if external
                && (!self.settings.outbound_notifications_enabled
                    || channel.network_approved_at.is_none()
                    || channel.network_approved_destination.is_none()
                    || channel.config_ref.is_none())
            {
                results.push(result(&channel, DeliveryStatus::Failed));
                continue;
            }
            let Some(state_id) = states
                .claim_delivery(
                    &channel.id,
                    &event.fingerprint,
                    now,
                    self.settings.deduplication_window,
                    LEASE_DURATION,
                )
                .await?
            else {
                results.push(result(&channel, DeliveryStatus::Suppressed));
                continue;
            };
            match self
                .transport
                .deliver(
                    &channel,
                    event,
                    self.settings.outbound_notifications_enabled,
                )
                .await
            {
                Ok(()) => {
                    states.finish_delivery(&state_id, true, now).await?;
                    results.push(result(&channel, DeliveryStatus::Delivered));
                }
                Err(_) => {
                    states.finish_delivery(&state_id, false, now).await?;
                    results.push(result(&channel, DeliveryStatus::Failed));
                }
            }
        }
        Ok(results)
    }

    pub async fn snooze(
        &self,
        channel_id: &str,
        event_fingerprint: &str,
        until: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<(), NotificationError> {
        validate_fingerprint(event_fingerprint)?;
        if until <= now || until > now + Duration::days(30) {
            return Err(NotificationError::InvalidSnooze);
        }
        self.database
            .repository::<NotificationDeliveryState>()
            .snooze(channel_id, event_fingerprint, until, now)
            .await?;
        Ok(())
    }
}

pub(crate) fn validate_event(event: &NotificationEvent) -> Result<(), NotificationError> {
    validate_fingerprint(&event.fingerprint)?;
    if event.priority_score > 100
        || !safe_identifier(&event.finding_id, 128)
        || !safe_advisory_id(&event.advisory_id)
        || event.severity.len() > 32
        || event.severity.chars().any(char::is_control)
        || event.asset_alias.as_deref().is_some_and(|alias| {
            alias.len() > 120
                || alias.chars().any(char::is_control)
                || alias.contains('/')
                || alias.contains('\\')
        })
    {
        return Err(NotificationError::InvalidEvent);
    }
    Ok(())
}

fn validate_fingerprint(value: &str) -> Result<(), NotificationError> {
    let Some(hash) = value.strip_prefix("sha256:") else {
        return Err(NotificationError::InvalidEvent);
    };
    if hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(NotificationError::InvalidEvent)
    }
}

fn safe_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn safe_advisory_id(value: &str) -> bool {
    safe_identifier(value, 128)
}

fn result(channel: &NotificationChannel, status: DeliveryStatus) -> DeliveryResult {
    DeliveryResult {
        channel_id: channel.id.clone(),
        status,
    }
}
