use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use chrono::{Duration, TimeZone, Utc};
use security_monitor_core::{NotificationChannel, NotificationChannelKind};
use security_monitor_database::Database;

use crate::{
    ChannelSecretConfig, ChannelTransport, CredentialError, CredentialStore, DeliveryStatus,
    NotificationError, NotificationEvent, NotificationService, NotificationSettings, SmtpTlsMode,
    approved_http_destination, approved_smtp_destination, store_channel_config,
};

#[derive(Default, Clone)]
struct RecordingTransport {
    deliveries: Arc<Mutex<Vec<NotificationEvent>>>,
}

#[async_trait]
impl ChannelTransport for RecordingTransport {
    async fn deliver(
        &self,
        _channel: &NotificationChannel,
        event: &NotificationEvent,
        _outbound_notifications_enabled: bool,
    ) -> Result<(), NotificationError> {
        self.deliveries.lock().unwrap().push(event.clone());
        Ok(())
    }
}

#[derive(Default)]
struct MemoryCredentials {
    values: Mutex<HashMap<String, String>>,
}

impl CredentialStore for MemoryCredentials {
    fn put(&self, secret: &str) -> Result<String, CredentialError> {
        let reference = "secmon-keyring:v1:00000000-0000-0000-0000-000000000001".to_owned();
        self.values
            .lock()
            .unwrap()
            .insert(reference.clone(), secret.to_owned());
        Ok(reference)
    }

    fn get(&self, reference: &str) -> Result<String, CredentialError> {
        self.values
            .lock()
            .unwrap()
            .get(reference)
            .cloned()
            .ok_or(CredentialError::InvalidReference)
    }

    fn delete(&self, reference: &str) -> Result<(), CredentialError> {
        self.values.lock().unwrap().remove(reference);
        Ok(())
    }
}

fn event() -> NotificationEvent {
    NotificationEvent {
        fingerprint: format!("sha256:{}", "a".repeat(64)),
        finding_id: format!("finding-{}", "b".repeat(64)),
        advisory_id: "CVE-2026-12345".to_owned(),
        asset_alias: Some("production-api".to_owned()),
        priority_score: 92,
        severity: "critical".to_owned(),
    }
}

fn desktop_channel() -> NotificationChannel {
    let now = Utc.with_ymd_and_hms(2026, 10, 24, 12, 0, 0).unwrap();
    NotificationChannel {
        id: "desktop-channel".to_owned(),
        kind: NotificationChannelKind::Desktop,
        config_ref: None,
        min_priority: 70,
        enabled: true,
        network_approved_at: None,
        network_approved_destination: None,
        created_at: now,
        updated_at: now,
    }
}

#[tokio::test]
async fn notification_delivery_deduplicates_and_respects_persisted_snooze() {
    let database = Database::in_memory().await.unwrap();
    database
        .repository::<NotificationChannel>()
        .create(&desktop_channel())
        .await
        .unwrap();
    let transport = RecordingTransport::default();
    let service = NotificationService::new(
        database,
        transport.clone(),
        NotificationSettings {
            outbound_notifications_enabled: false,
            deduplication_window: Duration::minutes(15),
        },
    );
    let now = Utc.with_ymd_and_hms(2026, 10, 24, 12, 0, 0).unwrap();
    let alert = event();

    let first = service.publish_at(&alert, now).await.unwrap();
    assert_eq!(first[0].status, DeliveryStatus::Delivered);
    let duplicate = service
        .publish_at(&alert, now + Duration::minutes(5))
        .await
        .unwrap();
    assert_eq!(duplicate[0].status, DeliveryStatus::Suppressed);

    let until = now + Duration::hours(1);
    service
        .snooze(
            "desktop-channel",
            &alert.fingerprint,
            until,
            now + Duration::minutes(5),
        )
        .await
        .unwrap();
    let snoozed = service
        .publish_at(&alert, now + Duration::minutes(30))
        .await
        .unwrap();
    assert_eq!(snoozed[0].status, DeliveryStatus::Suppressed);
    let resumed = service
        .publish_at(&alert, until + Duration::seconds(1))
        .await
        .unwrap();
    assert_eq!(resumed[0].status, DeliveryStatus::Delivered);
    assert_eq!(transport.deliveries.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn global_privacy_setting_blocks_approved_external_delivery() {
    let database = Database::in_memory().await.unwrap();
    let now = Utc.with_ymd_and_hms(2026, 10, 24, 12, 0, 0).unwrap();
    let channel = NotificationChannel {
        id: "webhook-channel".to_owned(),
        kind: NotificationChannelKind::Webhook,
        config_ref: Some("secmon-keyring:v1:00000000-0000-0000-0000-000000000001".to_owned()),
        min_priority: 0,
        enabled: true,
        network_approved_at: Some(now),
        network_approved_destination: Some("https://hooks.example.test".to_owned()),
        created_at: now,
        updated_at: now,
    };
    database
        .repository::<NotificationChannel>()
        .create(&channel)
        .await
        .unwrap();
    let transport = RecordingTransport::default();
    let service =
        NotificationService::new(database, transport.clone(), NotificationSettings::default());

    let result = service.publish_at(&event(), now).await.unwrap();

    assert_eq!(result[0].status, DeliveryStatus::Failed);
    assert!(transport.deliveries.lock().unwrap().is_empty());
}

#[test]
fn stored_external_configuration_uses_an_opaque_reference_and_approval_keeps_only_origin() {
    let credentials = MemoryCredentials::default();
    let secret_url = "https://hooks.example.test/services/private-token";
    let reference = store_channel_config(
        &credentials,
        &ChannelSecretConfig::Webhook {
            url: secret_url.to_owned(),
        },
    )
    .unwrap();

    assert_eq!(
        credentials.get(&reference).unwrap(),
        serde_json::json!({ "kind": "webhook", "url": secret_url }).to_string()
    );
    assert_eq!(
        approved_http_destination(secret_url).unwrap(),
        "https://hooks.example.test"
    );
    assert!(approved_http_destination("http://hooks.example.test/secret").is_err());
    assert_eq!(
        approved_smtp_destination("smtp.example.test", 465, SmtpTlsMode::ImplicitTls).unwrap(),
        "smtps://smtp.example.test:465"
    );
    assert_eq!(
        approved_smtp_destination("2001:db8::1", 465, SmtpTlsMode::ImplicitTls).unwrap(),
        "smtps://[2001:db8::1]:465"
    );
    assert!(
        approved_smtp_destination("smtp.example.test/secret", 465, SmtpTlsMode::ImplicitTls)
            .is_err()
    );
    assert!(
        approved_smtp_destination("user@smtp.example.test", 465, SmtpTlsMode::ImplicitTls).is_err()
    );
}

#[test]
fn finding_event_rejects_path_like_asset_aliases() {
    let mut alert = event();
    alert.asset_alias = Some("C:\\Users\\secret\\project".to_owned());

    assert!(matches!(
        super::dispatcher::validate_event(&alert),
        Err(NotificationError::InvalidEvent)
    ));
}
