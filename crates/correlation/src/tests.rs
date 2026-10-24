use std::collections::BTreeSet;

use chrono::{DateTime, TimeZone, Utc};
use security_monitor_core::{
    Advisory, Component, ComponentEvidence, ComponentInstance, Environment,
    FindingDispositionReason, FindingStatus, Project, Severity,
};
use security_monitor_database::Database;

use crate::{
    AliasMerger, BusinessImpact, CorrelationComponent, DispositionScope, FindingFingerprintInput,
    InventoryFreshness, PriorityContext, PriorityError, PriorityInput, ScopeVerification,
    SsvcAutomatability, SsvcExploitation, SsvcImpact, SsvcSignal, StatusActor, StatusEvidence,
    StatusTransition, TestCost, TransitionError, UserDisposition, apply_transition,
    calculate_priority, correlate, correlate_and_persist, finding_fingerprint, validate_transition,
};

const ALIAS_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/correlation/aliases-three-sources.json");

fn fixture_advisories() -> Vec<Advisory> {
    serde_json::from_slice(ALIAS_FIXTURE).expect("correlation fixture is valid")
}

fn timestamp(day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, day, 0, 0, 0)
        .single()
        .expect("fixture timestamp is valid")
}

fn component() -> Component {
    Component {
        id: "component-1".to_owned(),
        purl: "pkg:npm/fixture-lib@1.0.2".to_owned(),
        ecosystem: "npm".to_owned(),
        name: "fixture-lib".to_owned(),
        version: "1.0.2".to_owned(),
        source_type: "lockfile".to_owned(),
        created_at: timestamp(20),
    }
}

fn instance_with_evidence(evidence: Vec<ComponentEvidence>) -> ComponentInstance {
    ComponentInstance {
        id: "instance-1".to_owned(),
        component_id: "component-1".to_owned(),
        project_id: Some("project-1".to_owned()),
        asset_id: None,
        service_id: None,
        deployment_id: None,
        evidence,
        created_at: timestamp(20),
    }
}

fn priority_context() -> PriorityContext {
    PriorityContext {
        environment: Environment::Production,
        internet_facing: Some(true),
        business_impacts: BTreeSet::from([BusinessImpact::CustomerData]),
        ..PriorityContext::default()
    }
}

#[test]
fn three_sources_with_transitive_aliases_collapse_to_one_stable_cve() {
    let advisories = fixture_advisories();
    let merged = AliasMerger::new(advisories.clone()).into_records();
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].canonical_id, "CVE-2026-9000");
    assert_eq!(
        merged[0].aliases,
        vec!["GHSA-ABCD-EFGH-IJKL", "OSV-2026-9000"]
    );
    assert_eq!(merged[0].source_urls.len(), 3);

    let expected = serde_json::to_value(&merged).expect("merged advisory serializes");
    let mut reversed = advisories;
    reversed.reverse();
    let actual = serde_json::to_value(AliasMerger::new(reversed).into_records())
        .expect("merged advisory serializes");
    assert_eq!(actual, expected);
}

#[test]
fn alias_merge_never_advances_epss_freshness_without_a_valid_score() {
    let mut advisories = fixture_advisories();
    advisories[1].epss_date = Some(timestamp(22));
    let merged = AliasMerger::new(advisories.clone()).into_records();
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].epss, Some(0.7));
    assert_eq!(merged[0].epss_date, Some(timestamp(20)));

    advisories[1].epss = Some(0.3);
    let updated = AliasMerger::new(advisories).into_records();
    assert_eq!(updated[0].epss, Some(0.3));
    assert_eq!(updated[0].epss_date, Some(timestamp(22)));
}

#[test]
fn three_alias_sources_produce_one_confirmed_finding_for_a_location() {
    let advisories = fixture_advisories();
    let component = component();
    let instance = instance_with_evidence(vec![ComponentEvidence {
        evidence_type: "lockfile".to_owned(),
        file_path_redacted: Some("package-lock.json".to_owned()),
        reference: Some("credential-canary-value".to_owned()),
    }]);
    let input = CorrelationComponent {
        component,
        instance,
        scope_verification: ScopeVerification::Verified,
        inventory_freshness: InventoryFreshness::Current,
        priority: priority_context(),
    };

    let findings = correlate(&advisories, &[input], timestamp(24)).expect("correlation succeeds");
    assert_eq!(findings.len(), 1);
    assert!(findings.iter().all(|record| {
        record.finding.advisory_id == "CVE-2026-9000"
            && record.finding.status == FindingStatus::ConfirmedAffected
            && record.finding.fix_version.as_deref() == Some("1.1.0")
            && record
                .finding
                .priority_reasons
                .contains(&"cvss_base".to_owned())
            && record
                .finding
                .priority_reasons
                .contains(&"epss_very_high".to_owned())
            && record
                .finding
                .priority_reasons
                .contains(&"production_internet_facing".to_owned())
            && record
                .finding
                .priority_reasons
                .contains(&"customer_data_impact".to_owned())
            && record.evidence.reference.is_none()
    }));
    assert_eq!(
        findings[0].evidence.file_path_redacted.as_deref(),
        Some("package-lock.json")
    );
}

#[test]
fn stale_inventory_keeps_match_in_needs_review() {
    let input = CorrelationComponent {
        component: component(),
        instance: instance_with_evidence(Vec::new()),
        scope_verification: ScopeVerification::Verified,
        inventory_freshness: InventoryFreshness::Stale,
        priority: PriorityContext::default(),
    };
    let findings = correlate(&fixture_advisories(), &[input], timestamp(24))
        .expect("stale correlation is still represented");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].finding.status, FindingStatus::NeedsReview);
    assert!(
        findings[0]
            .finding
            .priority_reasons
            .contains(&"inventory_stale".to_owned())
    );
}

#[test]
fn unverified_component_scope_needs_review_even_when_version_matches() {
    let input = CorrelationComponent {
        component: component(),
        instance: instance_with_evidence(Vec::new()),
        scope_verification: ScopeVerification::Unverified,
        inventory_freshness: InventoryFreshness::Current,
        priority: PriorityContext::default(),
    };
    let findings = correlate(&fixture_advisories(), &[input], timestamp(24))
        .expect("unverified scope is represented");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].finding.status, FindingStatus::NeedsReview);
    assert!(
        findings[0]
            .finding
            .priority_reasons
            .contains(&"scope_unverified".to_owned())
    );
}

#[test]
fn package_url_version_mismatch_needs_review() {
    let mut component = component();
    component.version = "1.0.3".to_owned();
    let input = CorrelationComponent {
        component,
        instance: instance_with_evidence(Vec::new()),
        scope_verification: ScopeVerification::Verified,
        inventory_freshness: InventoryFreshness::Current,
        priority: PriorityContext::default(),
    };
    let findings = correlate(&fixture_advisories(), &[input], timestamp(24))
        .expect("identity mismatch is represented for review");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].finding.status, FindingStatus::NeedsReview);
    assert!(
        findings[0]
            .finding
            .priority_reasons
            .contains(&"component_identity_unverified".to_owned())
    );
}

#[test]
fn fingerprint_normalizes_relative_path_and_changes_for_a_new_location() {
    let component = component();
    let instance = instance_with_evidence(Vec::new());
    let slash = ComponentEvidence {
        evidence_type: "lockfile".to_owned(),
        file_path_redacted: Some("./packages\\app/package-lock.json".to_owned()),
        reference: None,
    };
    let normalized = ComponentEvidence {
        file_path_redacted: Some("packages/app/package-lock.json".to_owned()),
        ..slash.clone()
    };
    let slash_input = FindingFingerprintInput {
        canonical_advisory_id: "cve-2026-9000",
        component: &component,
        instance: &instance,
        evidence: Some(&slash),
    };
    let normalized_input = FindingFingerprintInput {
        canonical_advisory_id: "CVE-2026-9000",
        component: &component,
        instance: &instance,
        evidence: Some(&normalized),
    };
    let first_fingerprint = finding_fingerprint(&slash_input).expect("fingerprint succeeds");
    let normalized_fingerprint =
        finding_fingerprint(&normalized_input).expect("fingerprint succeeds");
    assert_eq!(first_fingerprint, normalized_fingerprint);
    let other_path = ComponentEvidence {
        file_path_redacted: Some("apps/web/package-lock.json".to_owned()),
        ..normalized
    };
    let other_fingerprint = finding_fingerprint(&FindingFingerprintInput {
        canonical_advisory_id: "CVE-2026-9000",
        component: &component,
        instance: &instance,
        evidence: Some(&other_path),
    })
    .expect("fingerprint succeeds");
    assert_ne!(first_fingerprint, other_fingerprint);
}

#[test]
fn priority_uses_freshness_and_reports_each_contributing_signal() {
    let input = PriorityInput {
        cvss: Some(8.0),
        severity: Some(Severity::High),
        kev_listed: true,
        epss_score: Some(0.5),
        epss_date: Some(timestamp(20)),
        context: PriorityContext {
            environment: Environment::Production,
            internet_facing: Some(true),
            user_confirmed_reachable: true,
            business_impacts: BTreeSet::from([BusinessImpact::CustomerData]),
            fix_available: true,
            test_cost: Some(TestCost::High),
            ..PriorityContext::default()
        },
    };
    let assessment = calculate_priority(&input, timestamp(24)).expect("valid inputs score");
    assert_eq!(assessment.score, 100);
    for reason in [
        "cvss_base",
        "kev_listed",
        "epss_very_high",
        "user_confirmed_reachable",
        "customer_data_impact",
        "fix_available",
        "high_test_cost",
        "score_capped_at_100",
    ] {
        assert!(assessment.reasons.iter().any(|value| value == reason));
    }

    let stale = PriorityInput {
        epss_date: Some(timestamp(1)),
        ..input
    };
    let stale_assessment = calculate_priority(&stale, timestamp(1) + chrono::Duration::days(31))
        .expect("stale data is scored");
    assert!(stale_assessment.reasons.contains(&"epss_stale".to_owned()));
    assert!(
        !stale_assessment
            .reasons
            .contains(&"epss_very_high".to_owned())
    );
}

#[test]
fn invalid_priority_scores_are_rejected_without_silent_clamping() {
    let invalid = PriorityInput {
        cvss: Some(10.1),
        severity: Some(Severity::Critical),
        kev_listed: false,
        epss_score: None,
        epss_date: None,
        context: PriorityContext::default(),
    };
    assert_eq!(
        calculate_priority(&invalid, timestamp(24)),
        Err(PriorityError::InvalidCvss)
    );
}

#[test]
fn system_cannot_assign_user_only_states_and_user_dispositions_expire() {
    let denied = StatusTransition {
        from: FindingStatus::ConfirmedAffected,
        to: FindingStatus::AcceptedRisk,
        actor: StatusActor::System,
        evidence: StatusEvidence::AffectedVersionVerified,
        disposition: None,
        current_risk_expires_at: None,
        at: timestamp(20),
    };
    assert_eq!(
        validate_transition(&denied),
        Err(TransitionError::UserActionRequired)
    );

    let accepted = StatusTransition {
        actor: StatusActor::User,
        evidence: StatusEvidence::UserAction,
        disposition: Some(UserDisposition {
            reason: FindingDispositionReason::TemporaryException,
            scope: DispositionScope::Finding,
            scope_id: "finding-123".to_owned(),
            expires_at: Some(timestamp(24)),
        }),
        ..denied.clone()
    };
    let disposition = validate_transition(&accepted)
        .expect("user risk decision is valid")
        .expect("risk decision is persisted");
    assert_eq!(
        disposition.reason,
        FindingDispositionReason::TemporaryException
    );
    assert_eq!(disposition.scope, "finding");
    assert_eq!(disposition.scope_id, "finding-123");
    assert_eq!(disposition.set_at, timestamp(20));
    assert_eq!(disposition.expires_at, Some(timestamp(24)));

    let mut finding = correlate(
        &fixture_advisories(),
        &[CorrelationComponent {
            component: component(),
            instance: instance_with_evidence(Vec::new()),
            scope_verification: ScopeVerification::Verified,
            inventory_freshness: InventoryFreshness::Current,
            priority: PriorityContext::default(),
        }],
        timestamp(20),
    )
    .expect("finding is correlated")
    .remove(0)
    .finding;
    let applied = StatusTransition {
        from: FindingStatus::ConfirmedAffected,
        to: FindingStatus::AcceptedRisk,
        actor: StatusActor::User,
        evidence: StatusEvidence::UserAction,
        disposition: Some(UserDisposition {
            reason: FindingDispositionReason::TemporaryException,
            scope: DispositionScope::Finding,
            scope_id: finding.id.clone(),
            expires_at: Some(timestamp(24)),
        }),
        current_risk_expires_at: None,
        at: timestamp(20),
    };
    apply_transition(&mut finding, &applied).expect("validated transition is applied");
    assert_eq!(finding.status, FindingStatus::AcceptedRisk);
    assert_eq!(finding.risk_expires_at, Some(timestamp(24)));
    assert_eq!(
        finding
            .disposition
            .as_ref()
            .map(|value| value.scope_id.as_str()),
        Some(finding.id.as_str())
    );

    let expired = StatusTransition {
        from: FindingStatus::AcceptedRisk,
        to: FindingStatus::New,
        actor: StatusActor::System,
        evidence: StatusEvidence::DispositionExpired,
        disposition: None,
        current_risk_expires_at: Some(timestamp(20)),
        at: timestamp(21),
    };
    assert_eq!(validate_transition(&expired), Ok(None));
    let not_yet_expired = StatusTransition {
        current_risk_expires_at: Some(timestamp(22)),
        ..expired
    };
    assert_eq!(
        validate_transition(&not_yet_expired),
        Err(TransitionError::DispositionNotExpired)
    );

    let forged_expiry = StatusTransition {
        from: FindingStatus::AcceptedRisk,
        to: FindingStatus::New,
        actor: StatusActor::System,
        evidence: StatusEvidence::DispositionExpired,
        disposition: None,
        current_risk_expires_at: Some(timestamp(20)),
        at: timestamp(21),
    };
    assert_eq!(
        apply_transition(&mut finding, &forged_expiry),
        Err(TransitionError::RiskExpiryChanged)
    );

    let expired_transition = StatusTransition {
        current_risk_expires_at: Some(timestamp(24)),
        at: timestamp(25),
        ..forged_expiry
    };
    apply_transition(&mut finding, &expired_transition)
        .expect("expired risk decision can be reopened");
    assert_eq!(finding.status, FindingStatus::New);
    assert!(finding.disposition.is_none());
}

#[test]
fn users_cannot_assign_statuses_that_require_verified_system_evidence() {
    let transition = StatusTransition {
        from: FindingStatus::ConfirmedAffected,
        to: FindingStatus::FixedInProduction,
        actor: StatusActor::User,
        evidence: StatusEvidence::UserAction,
        disposition: None,
        current_risk_expires_at: None,
        at: timestamp(20),
    };
    assert_eq!(
        validate_transition(&transition),
        Err(TransitionError::UserCannotAssignVerifiedStatus)
    );
}

#[test]
fn incomplete_data_can_only_move_a_system_finding_to_review() {
    let transition = StatusTransition {
        from: FindingStatus::ConfirmedAffected,
        to: FindingStatus::NeedsReview,
        actor: StatusActor::System,
        evidence: StatusEvidence::CurrentDataIncomplete,
        disposition: None,
        current_risk_expires_at: None,
        at: timestamp(20),
    };
    assert_eq!(validate_transition(&transition), Ok(None));
}

#[test]
fn ssvc_signal_is_a_deterministic_priority_input() {
    let input = PriorityInput {
        cvss: Some(5.0),
        severity: Some(Severity::Medium),
        kev_listed: false,
        epss_score: None,
        epss_date: None,
        context: PriorityContext {
            ssvc: Some(SsvcSignal {
                exploitation: SsvcExploitation::ProofOfConcept,
                automatable: SsvcAutomatability::Yes,
                technical_impact: SsvcImpact::Partial,
            }),
            ..PriorityContext::default()
        },
    };
    let result = calculate_priority(&input, timestamp(24)).expect("valid SSVC inputs score");
    assert_eq!(result.score, 50);
    assert_eq!(
        result.reasons,
        vec![
            "cvss_base",
            "environment_unknown",
            "epss_missing",
            "internet_exposure_unknown",
            "ssvc_automatable",
            "ssvc_exploitation_poc",
            "ssvc_technical_impact_partial",
        ]
    );
}

#[tokio::test]
async fn correlation_persists_findings_idempotently_and_drops_untrusted_references() {
    let database = Database::in_memory()
        .await
        .expect("in-memory database opens");
    let advisories = fixture_advisories();
    let merged = AliasMerger::new(advisories.clone()).into_records();
    let advisory = merged.first().expect("fixture has an advisory");
    database
        .repository::<Advisory>()
        .create(advisory)
        .await
        .expect("advisory fixture persists");
    let project = Project {
        id: "project-1".to_owned(),
        name: "fixture project".to_owned(),
        root_path: "C:/workspace/project".to_owned(),
        git_remote: None,
        reference_branch: None,
        allowed_ai_providers: Vec::new(),
        last_scan_at: None,
        created_at: timestamp(20),
        updated_at: timestamp(20),
    };
    database
        .repository::<Project>()
        .create(&project)
        .await
        .expect("project fixture persists");
    let component = component();
    database
        .repository::<Component>()
        .create(&component)
        .await
        .expect("component fixture persists");
    let instance = instance_with_evidence(vec![ComponentEvidence {
        evidence_type: "lockfile".to_owned(),
        file_path_redacted: Some("package-lock.json".to_owned()),
        reference: Some("credential-canary-value".to_owned()),
    }]);
    database
        .repository::<ComponentInstance>()
        .create(&instance)
        .await
        .expect("component instance fixture persists");
    let input = CorrelationComponent {
        component,
        instance,
        scope_verification: ScopeVerification::Unverified,
        inventory_freshness: InventoryFreshness::Current,
        priority: PriorityContext::default(),
    };

    let first = correlate_and_persist(
        &database,
        &advisories,
        std::slice::from_ref(&input),
        timestamp(24),
    )
    .await
    .expect("first correlation persists");
    let second = correlate_and_persist(
        &database,
        &advisories,
        std::slice::from_ref(&input),
        timestamp(24),
    )
    .await
    .expect("repeat correlation updates");
    assert_eq!(first[0].finding.id, second[0].finding.id);
    assert_eq!(
        database
            .repository::<security_monitor_core::Finding>()
            .list()
            .await
            .expect("findings list")
            .len(),
        1
    );
    let mut accepted_finding = first[0].finding.clone();
    let accepted_finding_id = accepted_finding.id.clone();
    apply_transition(
        &mut accepted_finding,
        &StatusTransition {
            from: FindingStatus::ConfirmedAffected,
            to: FindingStatus::AcceptedRisk,
            actor: StatusActor::User,
            evidence: StatusEvidence::UserAction,
            disposition: Some(UserDisposition {
                reason: FindingDispositionReason::TemporaryException,
                scope: DispositionScope::Finding,
                scope_id: accepted_finding_id,
                expires_at: Some(timestamp(31)),
            }),
            current_risk_expires_at: None,
            at: timestamp(24),
        },
    )
    .expect("user disposition is applied");
    database
        .repository::<security_monitor_core::Finding>()
        .update(&accepted_finding)
        .await
        .expect("disposition writes to database");
    let stored_finding = database
        .repository::<security_monitor_core::Finding>()
        .get(&accepted_finding.id)
        .await
        .expect("finding lookup succeeds")
        .expect("finding is retained");
    assert_eq!(stored_finding.status, FindingStatus::AcceptedRisk);
    assert_eq!(stored_finding.disposition, accepted_finding.disposition);
    assert_eq!(stored_finding.risk_expires_at, Some(timestamp(31)));
    correlate_and_persist(
        &database,
        &advisories,
        std::slice::from_ref(&input),
        timestamp(24),
    )
    .await
    .expect("active user decision survives correlation refresh");
    let active_after_refresh = database
        .repository::<security_monitor_core::Finding>()
        .get(&accepted_finding.id)
        .await
        .expect("finding lookup succeeds")
        .expect("finding is retained");
    assert_eq!(active_after_refresh.status, FindingStatus::AcceptedRisk);
    assert_eq!(active_after_refresh.risk_expires_at, Some(timestamp(31)));

    correlate_and_persist(
        &database,
        &advisories,
        std::slice::from_ref(&input),
        timestamp(31),
    )
    .await
    .expect("expired user decision reopens on correlation refresh");
    let reopened = database
        .repository::<security_monitor_core::Finding>()
        .get(&accepted_finding.id)
        .await
        .expect("finding lookup succeeds")
        .expect("finding is retained");
    assert_eq!(reopened.status, FindingStatus::ConfirmedAffected);
    assert!(reopened.disposition.is_none());
    assert!(reopened.risk_expires_at.is_none());
    let saved_evidence = database
        .repository::<security_monitor_core::FindingEvidence>()
        .list()
        .await
        .expect("evidence list");
    assert_eq!(saved_evidence.len(), 1);
    assert!(saved_evidence[0].reference.is_none());
    assert!(
        !serde_json::to_string(&saved_evidence)
            .expect("evidence serializes")
            .contains("credential-canary-value")
    );
}
