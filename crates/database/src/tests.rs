use security_monitor_core::{
    Advisory, AiProvider, AiRun, Asset, AuditEvent, Component, ComponentInstance, Deployment,
    Finding, FindingEvidence, NotificationChannel, Project, Remediation, ScanRun, Service,
};
use serde::Deserialize;
use sqlx::Row;

use crate::{Database, Entity, Repository};

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

    assert_eq!(database.schema_version().await.unwrap(), 2);
    let count: i64 = sqlx::query(
        "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name IN \
         ('projects', 'assets', 'services', 'deployments', 'components', \
          'component_instances', 'advisories', 'findings', 'finding_evidence', \
          'scan_runs', 'remediations', 'ai_providers', 'ai_runs', \
          'notification_channels', 'audit_events')",
    )
    .fetch_one(&database.pool)
    .await
    .unwrap()
    .try_get("count")
    .unwrap();
    assert_eq!(count, 15);
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
