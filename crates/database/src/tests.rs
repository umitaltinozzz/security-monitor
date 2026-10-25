use chrono::{Duration, TimeZone, Utc};
use security_monitor_core::{
    Advisory, AiDataTransferApproval, AiProvider, AiRun, Asset, AuditEvent, Component,
    ComponentInstance, Deployment, Finding, FindingEvidence, Memory, MemoryKind, MemoryScope,
    NotificationChannel, NotificationDeliveryState, Project, Remediation, ScanRun, Service,
};
use serde::Deserialize;
use sqlx::Row;

use crate::{Database, DatabaseError, Entity, Repository};

#[test]
fn migration_sources_use_platform_independent_lf_line_endings() {
    let migrations: [&[u8]; 10] = [
        include_bytes!("../migrations/0001_initial.sql"),
        include_bytes!("../migrations/0002_advisory_metadata.sql"),
        include_bytes!("../migrations/0003_finding_disposition.sql"),
        include_bytes!("../migrations/0004_orchestration_notifications.sql"),
        include_bytes!("../migrations/0005_ai_run_model.sql"),
        include_bytes!("../migrations/0006_ai_transfer_approvals.sql"),
        include_bytes!("../migrations/0007_remediation_provider.sql"),
        include_bytes!("../migrations/0008_news_signals.sql"),
        include_bytes!("../migrations/0009_memories.sql"),
        include_bytes!("../migrations/0010_project_server_links.sql"),
    ];

    assert!(
        migrations
            .iter()
            .all(|migration| !migration.contains(&b'\r'))
    );
}

#[derive(Deserialize)]
struct FixtureRecords {
    project: Project,
    asset: Asset,
    service: Service,
    deployment: Deployment,
    component: Component,
    component_instance: ComponentInstance,
    advisory: Advisory,
    finding: Finding,
    finding_evidence: FindingEvidence,
    scan_run: ScanRun,
    remediation: Remediation,
    ai_provider: AiProvider,
    ai_run: AiRun,
    ai_transfer_approval: AiDataTransferApproval,
    notification_channel: NotificationChannel,
    audit_event: AuditEvent,
}

fn records() -> FixtureRecords {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/database/records.json"
    ))
    .unwrap()
}

#[tokio::test]
async fn migration_installs_all_tables_into_an_empty_database() {
    let database = Database::in_memory().await.unwrap();

    assert_eq!(database.schema_version().await.unwrap(), 10);
    let count: i64 = sqlx::query(
        "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name IN \
         ('projects', 'assets', 'services', 'deployments', 'components', \
          'component_instances', 'advisories', 'findings', 'finding_evidence', \
          'scan_runs', 'remediations', 'ai_providers', 'ai_runs', \
         'notification_channels', 'audit_events', 'project_scan_checkpoints', \
          'notification_delivery_states', 'ai_transfer_approvals', 'memories', \
          'project_server_links')",
    )
    .fetch_one(&database.pool)
    .await
    .unwrap()
    .try_get("count")
    .unwrap();
    assert_eq!(count, 20);
}

#[tokio::test]
async fn read_only_database_open_does_not_migrate_or_allow_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("existing.sqlite3");
    let writable = Database::open(&path).await.unwrap();
    let fixture = records();
    writable
        .repository::<Project>()
        .create(&fixture.project)
        .await
        .unwrap();
    writable.close().await;

    let readonly = Database::open_read_only(&path).await.unwrap();
    assert_eq!(readonly.schema_version().await.unwrap(), 10);
    assert_eq!(
        readonly
            .repository::<Project>()
            .get("project-1")
            .await
            .unwrap(),
        Some(fixture.project.clone())
    );
    let error = readonly
        .repository::<Asset>()
        .create(&fixture.asset)
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "database operation failed");
    assert_eq!(
        readonly.repository::<Asset>().list().await.unwrap(),
        Vec::<Asset>::new()
    );
    readonly.close().await;
}

#[tokio::test]
async fn ai_run_budget_reservations_serialize_across_database_connections() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("shared.sqlite3");
    let first_database = Database::open(&path).await.unwrap();
    let second_database = Database::open(&path).await.unwrap();
    let fixture = records();
    first_database
        .repository::<AiProvider>()
        .create(&fixture.ai_provider)
        .await
        .unwrap();
    let mut first_run = fixture.ai_run;
    first_run.id = "reservation-first".into();
    first_run.finding_id = None;
    first_run.cost = Some(0.75);
    first_run.outcome = "in_progress".into();
    let mut second_run = first_run.clone();
    second_run.id = "reservation-second".into();

    let first = first_database.reserve_ai_run(&first_run, |runs| {
        if runs.is_empty() {
            Ok(())
        } else {
            Err("budget exceeded".into())
        }
    });
    let second = second_database.reserve_ai_run(&second_run, |runs| {
        if runs.is_empty() {
            Ok(())
        } else {
            Err("budget exceeded".into())
        }
    });
    let (first, second) = tokio::join!(first, second);
    let outcomes = [first.unwrap(), second.unwrap()];
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(reason) if reason == "budget exceeded"))
            .count(),
        1
    );
    assert_eq!(
        first_database
            .repository::<AiRun>()
            .list()
            .await
            .unwrap()
            .len(),
        1
    );
    first_database.close().await;
    second_database.close().await;
}

#[tokio::test]
async fn notification_delivery_claim_is_atomic_deduplicated_and_snoozable() {
    let database = Database::in_memory().await.unwrap();
    let fixture = records();
    database
        .repository::<NotificationChannel>()
        .create(&fixture.notification_channel)
        .await
        .unwrap();
    let states = database.repository::<NotificationDeliveryState>();
    let now = Utc.with_ymd_and_hms(2026, 10, 24, 12, 0, 0).unwrap();
    let fingerprint = format!("sha256:{}", "a".repeat(64));

    let reservation = states
        .claim_delivery(
            "channel-1",
            &fingerprint,
            now,
            Duration::minutes(15),
            Duration::minutes(2),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(
        states
            .claim_delivery(
                "channel-1",
                &fingerprint,
                now,
                Duration::minutes(15),
                Duration::minutes(2),
            )
            .await
            .unwrap()
            .is_none()
    );
    states
        .finish_delivery(&reservation, true, now)
        .await
        .unwrap();
    assert!(
        states
            .claim_delivery(
                "channel-1",
                &fingerprint,
                now + Duration::minutes(5),
                Duration::minutes(15),
                Duration::minutes(2),
            )
            .await
            .unwrap()
            .is_none()
    );

    let snoozed_until = now + Duration::hours(1);
    states
        .snooze("channel-1", &fingerprint, snoozed_until, now)
        .await
        .unwrap();
    assert!(
        states
            .claim_delivery(
                "channel-1",
                &fingerprint,
                now + Duration::minutes(30),
                Duration::minutes(15),
                Duration::minutes(2),
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        states
            .claim_delivery(
                "channel-1",
                &fingerprint,
                snoozed_until + Duration::seconds(1),
                Duration::minutes(15),
                Duration::minutes(2),
            )
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn enabled_external_notification_requires_recorded_approval_and_keyring_reference() {
    let database = Database::in_memory().await.unwrap();
    let fixture = records();
    database
        .repository::<NotificationChannel>()
        .create(&fixture.notification_channel)
        .await
        .unwrap();
    let mut external = fixture.notification_channel;
    external.id = "unapproved-channel".to_owned();
    external.kind = security_monitor_core::NotificationChannelKind::Webhook;

    let error = database
        .repository::<NotificationChannel>()
        .create(&external)
        .await
        .unwrap_err();

    assert!(matches!(error, DatabaseError::NotificationApprovalRequired));
}

async fn verify_update<T>(
    repository: &Repository<T>,
    original: &T,
    id: &str,
    mutate: impl FnOnce(&mut T),
) where
    T: Entity + Clone + std::fmt::Debug + PartialEq,
{
    assert_eq!(repository.get(id).await.unwrap().as_ref(), Some(original));
    assert_eq!(repository.list().await.unwrap(), vec![original.clone()]);

    let mut updated = original.clone();
    mutate(&mut updated);
    assert!(repository.update(&updated).await.unwrap());
    assert_eq!(repository.get(id).await.unwrap(), Some(updated.clone()));
    assert_eq!(repository.list().await.unwrap(), vec![updated]);
}

async fn verify_delete<T>(database: &Database, id: &str)
where
    T: Entity + std::fmt::Debug + PartialEq,
{
    let repository = database.repository::<T>();
    assert!(repository.delete(id).await.unwrap());
    assert!(!repository.delete(id).await.unwrap());
    assert_eq!(repository.get(id).await.unwrap(), None);
    assert!(repository.list().await.unwrap().is_empty());
}

#[tokio::test]
async fn all_domain_repositories_support_typed_crud_and_json_round_trips() {
    let database = Database::in_memory().await.unwrap();
    let fixture = records();

    database
        .repository::<Project>()
        .create(&fixture.project)
        .await
        .unwrap();
    database
        .repository::<Asset>()
        .create(&fixture.asset)
        .await
        .unwrap();
    database
        .repository::<Service>()
        .create(&fixture.service)
        .await
        .unwrap();
    database
        .repository::<Deployment>()
        .create(&fixture.deployment)
        .await
        .unwrap();
    database
        .repository::<Component>()
        .create(&fixture.component)
        .await
        .unwrap();
    database
        .repository::<ComponentInstance>()
        .create(&fixture.component_instance)
        .await
        .unwrap();
    database
        .repository::<Advisory>()
        .create(&fixture.advisory)
        .await
        .unwrap();
    database
        .repository::<Finding>()
        .create(&fixture.finding)
        .await
        .unwrap();
    database
        .repository::<FindingEvidence>()
        .create(&fixture.finding_evidence)
        .await
        .unwrap();
    database
        .repository::<ScanRun>()
        .create(&fixture.scan_run)
        .await
        .unwrap();
    database
        .repository::<Remediation>()
        .create(&fixture.remediation)
        .await
        .unwrap();
    database
        .repository::<AiProvider>()
        .create(&fixture.ai_provider)
        .await
        .unwrap();
    database
        .repository::<AiRun>()
        .create(&fixture.ai_run)
        .await
        .unwrap();
    database
        .repository::<AiDataTransferApproval>()
        .create(&fixture.ai_transfer_approval)
        .await
        .unwrap();
    database
        .repository::<NotificationChannel>()
        .create(&fixture.notification_channel)
        .await
        .unwrap();
    database
        .repository::<AuditEvent>()
        .create(&fixture.audit_event)
        .await
        .unwrap();

    verify_update(
        &database.repository::<Project>(),
        &fixture.project,
        "project-1",
        |value| value.name = "updated-project".to_owned(),
    )
    .await;
    verify_update(
        &database.repository::<Asset>(),
        &fixture.asset,
        "asset-1",
        |value| value.hostname_alias = "updated-host".to_owned(),
    )
    .await;
    verify_update(
        &database.repository::<Service>(),
        &fixture.service,
        "service-1",
        |value| value.service_name = "updated-service".to_owned(),
    )
    .await;
    verify_update(
        &database.repository::<Deployment>(),
        &fixture.deployment,
        "deployment-1",
        |value| value.release_id = Some("release-2".to_owned()),
    )
    .await;
    verify_update(
        &database.repository::<Component>(),
        &fixture.component,
        "component-1",
        |value| value.version = "1.0.1".to_owned(),
    )
    .await;
    verify_update(
        &database.repository::<ComponentInstance>(),
        &fixture.component_instance,
        "component-instance-1",
        |value| value.evidence.clear(),
    )
    .await;
    verify_update(
        &database.repository::<Advisory>(),
        &fixture.advisory,
        "CVE-2026-1234",
        |value| value.kev = true,
    )
    .await;
    verify_update(
        &database.repository::<Finding>(),
        &fixture.finding,
        "finding-1",
        |value| value.priority_score = 80,
    )
    .await;
    verify_update(
        &database.repository::<FindingEvidence>(),
        &fixture.finding_evidence,
        "evidence-1",
        |value| value.confidence = Some(0.8),
    )
    .await;
    verify_update(
        &database.repository::<ScanRun>(),
        &fixture.scan_run,
        "scan-1",
        |value| value.outcome = security_monitor_core::ScanOutcome::Partial,
    )
    .await;
    verify_update(
        &database.repository::<Remediation>(),
        &fixture.remediation,
        "remediation-1",
        |value| value.approval_state = security_monitor_core::ApprovalState::Approved,
    )
    .await;
    verify_update(
        &database.repository::<AiProvider>(),
        &fixture.ai_provider,
        "provider-1",
        |value| value.display_name = "Updated fixture provider".to_owned(),
    )
    .await;
    verify_update(
        &database.repository::<AiRun>(),
        &fixture.ai_run,
        "ai-run-1",
        |value| value.tokens_out = 60,
    )
    .await;
    verify_update(
        &database.repository::<AiDataTransferApproval>(),
        &fixture.ai_transfer_approval,
        "ai-approval-1",
        |value| value.data_category = "inventory".to_owned(),
    )
    .await;
    verify_update(
        &database.repository::<NotificationChannel>(),
        &fixture.notification_channel,
        "channel-1",
        |value| value.enabled = false,
    )
    .await;
    verify_update(
        &database.repository::<AuditEvent>(),
        &fixture.audit_event,
        "audit-1",
        |value| value.action = "updated_fixture".to_owned(),
    )
    .await;

    verify_delete::<AuditEvent>(&database, "audit-1").await;
    verify_delete::<NotificationChannel>(&database, "channel-1").await;
    verify_delete::<AiDataTransferApproval>(&database, "ai-approval-1").await;
    verify_delete::<AiRun>(&database, "ai-run-1").await;
    verify_delete::<AiProvider>(&database, "provider-1").await;
    verify_delete::<Remediation>(&database, "remediation-1").await;
    verify_delete::<FindingEvidence>(&database, "evidence-1").await;
    verify_delete::<Finding>(&database, "finding-1").await;
    verify_delete::<Advisory>(&database, "CVE-2026-1234").await;
    verify_delete::<ComponentInstance>(&database, "component-instance-1").await;
    verify_delete::<Deployment>(&database, "deployment-1").await;
    verify_delete::<Service>(&database, "service-1").await;
    verify_delete::<Asset>(&database, "asset-1").await;
    verify_delete::<Project>(&database, "project-1").await;
    verify_delete::<Component>(&database, "component-1").await;
    verify_delete::<ScanRun>(&database, "scan-1").await;
}

#[tokio::test]
async fn repository_errors_do_not_expose_sqlite_details() {
    let database = Database::in_memory().await.unwrap();
    let project = records().project;
    let repository = database.repository::<Project>();
    repository.create(&project).await.unwrap();
    let error = repository.create(&project).await.unwrap_err();

    assert_eq!(error.to_string(), "database operation failed");
}

#[tokio::test]
async fn credential_bearing_provider_urls_are_rejected_before_storage() {
    let database = Database::in_memory().await.unwrap();
    let mut provider = records().ai_provider;
    provider.base_url = Some("https://user:secret@example.invalid/v1".to_owned());

    let error = database
        .repository::<AiProvider>()
        .create(&provider)
        .await
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "database record contains a credential-bearing URL"
    );
    assert!(
        database
            .repository::<AiProvider>()
            .list()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn credential_bearing_project_remotes_are_rejected_before_storage() {
    let database = Database::in_memory().await.unwrap();
    let mut project = records().project;
    project.git_remote = Some("https://token@example.invalid/repository.git".to_owned());

    let error = database
        .repository::<Project>()
        .create(&project)
        .await
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "database record contains a credential-bearing URL"
    );
    assert!(
        database
            .repository::<Project>()
            .list()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn ai_provider_credential_material_is_rejected_before_storage() {
    let database = Database::in_memory().await.unwrap();
    let mut provider = records().ai_provider;
    let secret = "sk_live_example_secret";
    provider.keychain_ref = Some(secret.to_owned());

    let error = database
        .repository::<AiProvider>()
        .create(&provider)
        .await
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "database record contains an invalid credential reference"
    );
    assert!(!error.to_string().contains(secret));
    assert!(
        database
            .repository::<AiProvider>()
            .list()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn notification_channel_secrets_are_rejected_on_create_and_update() {
    let database = Database::in_memory().await.unwrap();
    let channel = records().notification_channel;
    let repository = database.repository::<NotificationChannel>();
    repository.create(&channel).await.unwrap();

    let secret = "https://hooks.example.invalid/private-secret";
    let mut updated = channel.clone();
    updated.config_ref = Some(secret.to_owned());
    let error = repository.update(&updated).await.unwrap_err();

    assert_eq!(
        error.to_string(),
        "database record contains an invalid credential reference"
    );
    assert!(!error.to_string().contains(secret));
    assert_eq!(repository.get(&channel.id).await.unwrap(), Some(channel));

    let mut created = records().notification_channel;
    created.id = "channel-with-secret".to_owned();
    created.config_ref = Some(secret.to_owned());
    let error = repository.create(&created).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "database record contains an invalid credential reference"
    );
    assert!(!error.to_string().contains(secret));
    assert_eq!(repository.list().await.unwrap().len(), 1);
}

#[test]
fn finding_dispositions_require_valid_reason_scope_and_consistent_expiry() {
    let missing = serde_json::json!({"status": "accepted_risk"}).to_string();
    assert!(matches!(
        super::validate_record("findings", &missing),
        Err(DatabaseError::InvalidFindingDisposition)
    ));

    let valid = serde_json::json!({
        "status": "accepted_risk",
        "disposition": {
            "reason": "temporary_exception",
            "scope": "finding",
            "scope_id": "finding-123",
            "set_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-02-01T00:00:00Z"
        },
        "risk_expires_at": "2026-02-01T00:00:00Z"
    })
    .to_string();
    assert!(super::validate_record("findings", &valid).is_ok());

    let mismatched_expiry = valid.replacen("2026-02-01T00:00:00Z", "2026-03-01T00:00:00Z", 1);
    assert!(matches!(
        super::validate_record("findings", &mismatched_expiry),
        Err(DatabaseError::InvalidFindingDisposition)
    ));
}

fn memory(
    id: &str,
    content: &str,
    pinned: bool,
    created_at: chrono::DateTime<Utc>,
    expires_at: Option<chrono::DateTime<Utc>>,
    author: &str,
) -> Memory {
    Memory {
        id: id.into(),
        scope: MemoryScope::Global,
        scope_id: None,
        kind: MemoryKind::AgentSummary,
        content: content.into(),
        author: author.into(),
        source_run_id: None,
        created_at,
        expires_at,
        pinned,
        verified_at: None,
        verified_by: None,
    }
}

#[tokio::test]
async fn memory_search_prioritizes_pinned_notes_and_omits_expired_records() {
    let database = Database::in_memory().await.unwrap();
    let now = Utc.with_ymd_and_hms(2026, 10, 24, 12, 0, 0).unwrap();
    for note in [
        memory("newest", "shared cache", false, now, None, "agent:codex"),
        memory(
            "pinned",
            "shared cache is pinned",
            true,
            now - Duration::days(10),
            None,
            "user",
        ),
        memory(
            "expired",
            "shared cache expired",
            true,
            now - Duration::days(20),
            Some(now),
            "agent:claude-code",
        ),
    ] {
        database.repository::<Memory>().create(&note).await.unwrap();
    }
    let matches = database
        .search_memories("shared cache", now, 10)
        .await
        .unwrap();
    assert_eq!(
        matches
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        ["pinned", "newest"]
    );
    assert_eq!(database.delete_expired_memories(now).await.unwrap(), 1);
    assert!(
        database
            .repository::<Memory>()
            .get("expired")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn memory_delete_is_bound_to_the_original_agent_author() {
    let database = Database::in_memory().await.unwrap();
    let now = Utc::now();
    database
        .repository::<Memory>()
        .create(&memory(
            "note",
            "remember this",
            false,
            now,
            None,
            "agent:codex",
        ))
        .await
        .unwrap();
    assert!(
        database
            .delete_memory_authored_by("note", "agent:claude-code")
            .await
            .is_ok_and(|deleted| !deleted)
    );
    assert!(
        database
            .repository::<Memory>()
            .get("note")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        database
            .delete_memory_authored_by("note", "agent:codex")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn existing_read_write_open_requires_memory_schema_without_migrating() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("db.sqlite3");
    let database = Database::open(&path).await.unwrap();
    assert!(database.schema_version().await.unwrap() >= 9);
    database.close().await;
    let existing = Database::open_existing_read_write(&path).await.unwrap();
    assert!(existing.repository::<Memory>().list().await.is_ok());
    existing.close().await;
}

#[tokio::test]
async fn advisory_rekey_updates_finding_records_before_removing_the_old_id() {
    let database = Database::in_memory().await.unwrap();
    let fixture = records();
    database
        .repository::<Project>()
        .create(&fixture.project)
        .await
        .unwrap();
    database
        .repository::<Asset>()
        .create(&fixture.asset)
        .await
        .unwrap();
    database
        .repository::<Service>()
        .create(&fixture.service)
        .await
        .unwrap();
    database
        .repository::<Deployment>()
        .create(&fixture.deployment)
        .await
        .unwrap();
    database
        .repository::<Component>()
        .create(&fixture.component)
        .await
        .unwrap();
    database
        .repository::<ComponentInstance>()
        .create(&fixture.component_instance)
        .await
        .unwrap();

    let old_id = "GHSA-abcd-efgh-ijkl";
    let new_id = "CVE-2026-9000";
    let mut old_advisory = fixture.advisory.clone();
    old_advisory.canonical_id = old_id.to_owned();
    let mut canonical_advisory = fixture.advisory.clone();
    canonical_advisory.canonical_id = new_id.to_owned();
    database
        .repository::<Advisory>()
        .create(&old_advisory)
        .await
        .unwrap();
    database
        .repository::<Advisory>()
        .create(&canonical_advisory)
        .await
        .unwrap();

    let mut finding = fixture.finding;
    finding.id = "finding-rekey".to_owned();
    finding.advisory_id = old_id.to_owned();
    finding.fingerprint = "fingerprint-rekey".to_owned();
    database
        .repository::<Finding>()
        .create(&finding)
        .await
        .unwrap();

    database
        .rekey_advisory_findings(old_id, new_id)
        .await
        .unwrap();
    assert!(
        database
            .repository::<Advisory>()
            .get(old_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        database
            .repository::<Finding>()
            .get("finding-rekey")
            .await
            .unwrap()
            .expect("finding is retained")
            .advisory_id,
        new_id
    );
}
