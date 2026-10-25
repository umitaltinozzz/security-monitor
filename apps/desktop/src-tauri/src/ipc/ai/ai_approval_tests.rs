use super::super::settings::save_ai_settings_for_app;
use super::*;
use security_monitor_core::{AiProviderKind, ProviderCapabilities};

#[tokio::test]
async fn mcp_source_access_grants_and_revocations_are_audited() {
    let app_data = tempfile::tempdir().unwrap();
    let project_root = tempfile::tempdir().unwrap();
    let database = Database::in_memory().await.unwrap();
    let now = Utc::now();
    database
        .repository::<Project>()
        .create(&Project {
            id: "project-1".into(),
            name: "fixture".into(),
            root_path: project_root
                .path()
                .canonicalize()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            git_remote: None,
            reference_branch: None,
            allowed_ai_providers: vec![],
            last_scan_at: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();
    let state = AppState::new(
        database.clone(),
        app_data.path().to_path_buf(),
        AppSettings::default(),
    )
    .unwrap();

    save_ai_settings_for_app(
        &state,
        AiSettings {
            mcp_source_access_projects: vec!["project-1".into()],
            ..AiSettings::default()
        },
    )
    .await
    .unwrap();
    save_ai_settings_for_app(&state, AiSettings::default())
        .await
        .unwrap();

    let events = database.repository::<AuditEvent>().list().await.unwrap();
    for action in [
        "mcp_source_access_permission_enable_approved",
        "mcp_source_access_permission_enabled",
        "mcp_source_access_permission_revocation_requested",
        "mcp_source_access_permission_revoked",
    ] {
        assert!(events.iter().any(|event| {
            event.action == action
                && event.scope.resource_type == "project"
                && event.scope.resource_id.as_deref() == Some("project-1")
                && event.result == AuditResult::Succeeded
        }));
    }
}

#[test]
fn approval_digest_changes_when_destination_or_content_changes() {
    let now = Utc::now();
    let project = Project {
        id: "project-1".into(),
        name: "fixture".into(),
        root_path: "C:/fixture".into(),
        git_remote: None,
        reference_branch: None,
        allowed_ai_providers: vec!["provider-1".into()],
        last_scan_at: None,
        created_at: now,
        updated_at: now,
    };
    let mut provider = AiProvider {
        id: "provider-1".into(),
        kind: AiProviderKind::OpenAiCompatible,
        cli_product: None,
        display_name: "Fixture provider".into(),
        base_url: Some("https://provider.example/v1".into()),
        model: Some("user-selected-model".into()),
        capabilities: ProviderCapabilities {
            tool_calling: true,
            context_window: Some(8192),
            json_mode: false,
        },
        price_in: Some(1.0),
        price_out: Some(1.0),
        data_region: Some("EU".into()),
        keychain_ref: None,
        created_at: now,
        updated_at: now,
    };
    let settings = AiSettings::default();
    let budget = security_monitor_ai::BudgetDecision {
        estimated_cost_usd: 0.001,
        daily_total_after_usd: 0.001,
        monthly_total_after_usd: 0.001,
        daily_provider_after_usd: 0.001,
        monthly_provider_after_usd: 0.001,
    };
    let digest = make_ai_approval_digest(
        &project,
        &provider,
        &AiTier::Analysis,
        "user_prompt",
        "redacted prompt",
        &[],
        &settings,
        100,
        100,
        0.001,
        &budget,
        "https://provider.example",
    )
    .unwrap();
    assert_ne!(
        digest,
        make_ai_approval_digest(
            &project,
            &provider,
            &AiTier::Analysis,
            "user_prompt",
            "changed prompt",
            &[],
            &settings,
            100,
            100,
            0.001,
            &budget,
            "https://provider.example",
        )
        .unwrap()
    );
    provider.updated_at += chrono::Duration::seconds(1);
    assert_ne!(
        digest,
        make_ai_approval_digest(
            &project,
            &provider,
            &AiTier::Analysis,
            "user_prompt",
            "redacted prompt",
            &[],
            &settings,
            100,
            100,
            0.001,
            &budget,
            "https://provider.example",
        )
        .unwrap()
    );
}
