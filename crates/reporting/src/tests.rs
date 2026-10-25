use super::*;
use chrono::TimeZone;
use security_monitor_core::{
    AffectedRange, AuditScope, ComponentEvidence, FindingDisposition, RangeEvent,
};

#[derive(serde::Deserialize)]
struct ReportingFixture {
    project_id: String,
    project_name: String,
    component_id: String,
    instance_id: String,
    purl: String,
    ecosystem: String,
    component_name: String,
    version: String,
    source_path: String,
    advisory_id: String,
    advisory_alias: String,
    advisory_title: String,
    source_url: String,
    fixed_version: String,
    finding_id: String,
    finding_severity: String,
    priority_score: u8,
    finding_fingerprint: String,
}

fn fixture_snapshot() -> ReportSnapshot {
    let fixture: ReportingFixture = serde_json::from_str(include_str!(
        "../../../tests/fixtures/reporting/vulnerable-node.json"
    ))
    .expect("checked-in reporting fixture must parse");
    let timestamp = Utc.with_ymd_and_hms(2026, 10, 24, 10, 0, 0).unwrap();
    let project = Project {
        id: fixture.project_id.clone(),
        name: fixture.project_name.clone(),
        root_path: "C:/private/workspace".into(),
        git_remote: None,
        reference_branch: None,
        allowed_ai_providers: vec![],
        last_scan_at: Some(timestamp),
        created_at: timestamp,
        updated_at: timestamp,
    };
    let component = Component {
        id: fixture.component_id.clone(),
        purl: fixture.purl.clone(),
        ecosystem: fixture.ecosystem.clone(),
        name: fixture.component_name.clone(),
        version: fixture.version.clone(),
        source_type: "package-lock".into(),
        created_at: timestamp,
    };
    let instance = ComponentInstance {
        id: fixture.instance_id.clone(),
        component_id: component.id.clone(),
        project_id: Some(project.id.clone()),
        asset_id: None,
        service_id: None,
        deployment_id: None,
        evidence: vec![ComponentEvidence {
            evidence_type: "package-lock".into(),
            file_path_redacted: Some(fixture.source_path.clone()),
            reference: None,
        }],
        created_at: timestamp,
    };
    let advisory = Advisory {
        canonical_id: fixture.advisory_id.clone(),
        title: fixture.advisory_title.clone(),
        summary: None,
        summary_model: None,
        description: None,
        source_attributions: vec![],
        aliases: vec![fixture.advisory_alias.clone()],
        affected_ranges: vec![AffectedRange {
            ecosystem: "npm".into(),
            package: Some(fixture.component_name.clone()),
            source: None,
            range_type: Some("SEMVER".into()),
            events: vec![RangeEvent {
                introduced: Some("0".into()),
                fixed: Some(fixture.fixed_version.clone()),
                last_affected: None,
                limit: None,
            }],
        }],
        fixed_versions: vec![fixture.fixed_version.clone()],
        cvss: Some(8.1),
        severity: Some(Severity::High),
        kev: false,
        epss: Some(0.04),
        epss_date: None,
        source_urls: vec![fixture.source_url.clone()],
        source_updated_at: None,
        created_at: timestamp,
        updated_at: timestamp,
    };
    let finding = Finding {
        id: fixture.finding_id.clone(),
        advisory_id: advisory.canonical_id.clone(),
        component_instance_id: instance.id.clone(),
        status: FindingStatus::NeedsReview,
        severity: match fixture.finding_severity.as_str() {
            "high" => Severity::High,
            _ => Severity::Unknown,
        },
        priority_score: fixture.priority_score,
        priority_reasons: vec!["version_in_affected_range".into()],
        fingerprint: fixture.finding_fingerprint,
        repo_status: security_monitor_core::RepoStatus::StillAffected,
        production_status: security_monitor_core::ProductionStatus::Unknown,
        disposition: None,
        risk_expires_at: None,
        fix_version: Some("4.17.21".into()),
        created_at: timestamp,
        updated_at: timestamp,
    };
    ReportSnapshot {
        generated_at: timestamp,
        project: Some(ProjectSummary {
            id: project.id,
            name: project.name,
            last_scan_at: Some(timestamp),
        }),
        inventory_complete: true,
        verification: VerificationState::Verified,
        components: vec![component],
        instances: vec![instance],
        advisories: vec![advisory],
        findings: vec![finding],
        evidence: vec![FindingEvidence {
            id: "evidence-1".into(),
            finding_id: "finding-1".into(),
            evidence_type: "package-lock".into(),
            file_path_redacted: Some("<project>/package-lock.json".into()),
            reference: None,
            confidence: Some(1.0),
            created_at: timestamp,
        }],
    }
}

#[test]
fn cyclonedx_enums_match_the_vendored_1_6_schema() {
    let schema: Value = serde_json::from_str(CYCLONEDX_SCHEMA).expect("valid schema JSON");
    let schema_values = |path: &str| {
        schema
            .pointer(path)
            .and_then(Value::as_array)
            .expect("schema enum array")
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
    };
    let serialized_values = |values: Vec<Value>| {
        values
            .into_iter()
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect::<BTreeSet<_>>()
    };

    let justifications = serialized_values(vec![
        json!(CycloneDxJustification::CodeNotPresent),
        json!(CycloneDxJustification::CodeNotReachable),
        json!(CycloneDxJustification::RequiresConfiguration),
        json!(CycloneDxJustification::RequiresDependency),
        json!(CycloneDxJustification::RequiresEnvironment),
        json!(CycloneDxJustification::ProtectedByCompiler),
        json!(CycloneDxJustification::ProtectedAtRuntime),
        json!(CycloneDxJustification::ProtectedAtPerimeter),
        json!(CycloneDxJustification::ProtectedByMitigatingControl),
    ]);
    let responses = serialized_values(vec![
        json!(CycloneDxResponse::CanNotFix),
        json!(CycloneDxResponse::WillNotFix),
        json!(CycloneDxResponse::Update),
        json!(CycloneDxResponse::Rollback),
        json!(CycloneDxResponse::WorkaroundAvailable),
    ]);

    assert_eq!(
        justifications,
        schema_values("/definitions/impactAnalysisJustification/enum")
    );
    assert_eq!(
        responses,
        schema_values(
            "/definitions/vulnerability/properties/analysis/properties/response/items/enum"
        )
    );
}

#[test]
fn all_external_formats_validate_against_vendored_official_schemas() {
    let snapshot = fixture_snapshot();
    for format in [
        ReportFormat::Sarif,
        ReportFormat::Cyclonedx,
        ReportFormat::Openvex,
    ] {
        let encoded = render(&snapshot, format).unwrap();
        let value: Value = serde_json::from_str(&encoded).unwrap();
        validate(format, &value).unwrap_or_else(|error| panic!("{format:?}: {error}"));
    }
    let value: Value =
        serde_json::from_str(&render(&snapshot, ReportFormat::Json).unwrap()).unwrap();
    validate(ReportFormat::Json, &value).unwrap();
}

#[test]
fn reports_omit_absolute_source_paths_and_never_mark_unknown_findings_safe() {
    let mut snapshot = fixture_snapshot();
    snapshot.evidence[0].file_path_redacted = Some("C:/private/workspace/package-lock.json".into());
    snapshot.verification = VerificationState::NeedsReview;
    let json_value: Value =
        serde_json::from_str(&render(&snapshot, ReportFormat::Json).unwrap()).unwrap();
    let sarif_value: Value =
        serde_json::from_str(&render(&snapshot, ReportFormat::Sarif).unwrap()).unwrap();
    let vex_value: Value =
        serde_json::from_str(&render(&snapshot, ReportFormat::Openvex).unwrap()).unwrap();
    assert!(!json_value.to_string().contains("C:/private"));
    assert!(!sarif_value.to_string().contains("C:/private"));
    assert_eq!(
        vex_value
            .pointer("/statements/0/status")
            .and_then(Value::as_str),
        Some("under_investigation")
    );
    assert!(sarif_value.to_string().contains("needs_review"));
    assert_eq!(assess(&snapshot, None), ReportExit::NeedsReview);
}

#[test]
fn fail_on_thresholds_ignore_user_closed_findings_and_preserve_review_exit() {
    let mut snapshot = fixture_snapshot();
    assert_eq!(
        assess(&snapshot, Some(FailOn::High)),
        ReportExit::ThresholdExceeded
    );
    snapshot.findings[0].status = FindingStatus::AcceptedRisk;
    assert_eq!(assess(&snapshot, Some(FailOn::High)), ReportExit::Success);
    snapshot.verification = VerificationState::NeedsReview;
    assert_eq!(
        assess(&snapshot, Some(FailOn::High)),
        ReportExit::NeedsReview
    );
    assert_eq!(ReportExit::ThresholdExceeded.code(), 2);
    assert_eq!(ReportExit::NeedsReview.code(), 3);
}

#[test]
fn vex_not_affected_requires_a_supported_user_disposition() {
    let mut snapshot = fixture_snapshot();
    snapshot.findings[0].status = FindingStatus::NotReachable;
    let before = openvex_report(&snapshot);
    assert_eq!(
        before
            .pointer("/statements/0/status")
            .and_then(Value::as_str),
        Some("under_investigation")
    );
    snapshot.findings[0].disposition = Some(FindingDisposition {
        reason: FindingDispositionReason::NoAffectedCodePath,
        scope: "project".into(),
        scope_id: "project-fixture".into(),
        set_at: snapshot.generated_at,
        expires_at: None,
    });
    let after = openvex_report(&snapshot);
    assert_eq!(
        after
            .pointer("/statements/0/status")
            .and_then(Value::as_str),
        Some("not_affected")
    );
    validate(ReportFormat::Openvex, &after).unwrap();
}

#[test]
fn fixed_production_claims_require_a_current_verified_snapshot() {
    let mut snapshot = fixture_snapshot();
    snapshot.findings[0].status = FindingStatus::FixedInProduction;
    snapshot.findings[0].disposition = Some(FindingDisposition {
        reason: FindingDispositionReason::FixPlanned,
        scope: "project".into(),
        scope_id: "project-fixture".into(),
        set_at: snapshot.generated_at,
        expires_at: None,
    });
    snapshot.verification = VerificationState::NeedsReview;

    let openvex = openvex_report(&snapshot);
    assert_eq!(
        openvex
            .pointer("/statements/0/status")
            .and_then(Value::as_str),
        Some("under_investigation")
    );
    let cyclonedx = cyclonedx_report(&snapshot);
    assert_eq!(
        cyclonedx
            .pointer("/vulnerabilities/0/affects/0/versions/0/status")
            .and_then(Value::as_str),
        Some("unknown")
    );
    assert_eq!(
        cyclonedx
            .pointer("/vulnerabilities/0/analysis/state")
            .and_then(Value::as_str),
        Some("in_triage")
    );

    snapshot.verification = VerificationState::Verified;
    let openvex = openvex_report(&snapshot);
    assert_eq!(
        openvex
            .pointer("/statements/0/status")
            .and_then(Value::as_str),
        Some("fixed")
    );
    validate(ReportFormat::Openvex, &openvex).unwrap();
    let cyclonedx = cyclonedx_report(&snapshot);
    assert_eq!(
        cyclonedx
            .pointer("/vulnerabilities/0/analysis/state")
            .and_then(Value::as_str),
        Some("resolved")
    );
    validate(ReportFormat::Cyclonedx, &cyclonedx).unwrap();
}

#[test]
fn vex_exports_record_official_justification_response_and_skipped_findings() {
    let mut snapshot = fixture_snapshot();
    snapshot.findings[0].status = FindingStatus::FalsePositive;
    snapshot.findings[0].disposition = Some(FindingDisposition {
        reason: FindingDispositionReason::IncorrectPackage,
        scope: "project".into(),
        scope_id: "project-fixture".into(),
        set_at: snapshot.generated_at,
        expires_at: None,
    });
    let cyclone = cyclonedx_report(&snapshot);
    assert_eq!(
        cyclone
            .pointer("/vulnerabilities/0/analysis/justification")
            .and_then(Value::as_str),
        Some("code_not_present")
    );
    assert_eq!(
        cyclone
            .pointer("/vulnerabilities/0/analysis/state")
            .and_then(Value::as_str),
        Some("false_positive")
    );
    validate(ReportFormat::Cyclonedx, &cyclone).unwrap();

    snapshot.findings[0].status = FindingStatus::AcceptedRisk;
    snapshot.findings[0].disposition.as_mut().unwrap().reason =
        FindingDispositionReason::BusinessAccepted;
    let cyclone = cyclonedx_report(&snapshot);
    assert_eq!(
        cyclone
            .pointer("/vulnerabilities/0/analysis/response/0")
            .and_then(Value::as_str),
        Some("will_not_fix")
    );
    validate(ReportFormat::Cyclonedx, &cyclone).unwrap();

    snapshot.instances[0].component_id = "missing-component".into();
    let cyclone = cyclonedx_report(&snapshot);
    assert_eq!(
        cyclone
            .pointer("/metadata/properties/2/value")
            .and_then(Value::as_str),
        Some("1")
    );
    let skipped_id = format!(
        "{}@{}",
        snapshot.findings[0].advisory_id, snapshot.findings[0].component_instance_id
    );
    assert_eq!(
        cyclone
            .pointer("/metadata/properties/3/value")
            .and_then(Value::as_str),
        Some(skipped_id.as_str())
    );
    let openvex = openvex_report(&snapshot);
    assert!(
        openvex
            .pointer("/tooling")
            .and_then(Value::as_str)
            .unwrap()
            .contains("skipped findings without verifiable product scope (1)")
    );
    validate(ReportFormat::Cyclonedx, &cyclone).unwrap();
    validate(ReportFormat::Openvex, &openvex).unwrap();
}

#[test]
fn schema_documents_are_pinned_and_fixture_has_only_redacted_paths() {
    let fixture = fixture_snapshot();
    assert_eq!(fixture.project.as_ref().unwrap().id, "project-fixture");
    assert_eq!(
        relative_evidence_path("<project>/package-lock.json").as_deref(),
        Some("package-lock.json")
    );
    assert_eq!(relative_evidence_path("../../secrets.env"), None);
    assert_eq!(relative_evidence_path("C:/private/key.pem"), None);
    assert!(CYCLONEDX_SCHEMA.contains("1.6"));
    assert!(SARIF_SCHEMA.contains("2.1.0"));
    assert!(OPENVEX_SCHEMA.contains("0.2.0"));
    let _: AuditScope = AuditScope {
        resource_type: "fixture".into(),
        resource_id: None,
    };
}
