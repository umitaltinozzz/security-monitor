use chrono::{DateTime, Utc};
use security_monitor_agent_protocol::{
    AgentInventory, CheckKind, CheckStatus, DeploymentIdentity, DiagnosticCode,
};
use security_monitor_core::{
    Advisory, Finding, FindingStatus, ProductionStatus, RepoStatus, Severity,
};
use security_monitor_inventory::Inventory;

use crate::{
    DriftTarget, InventoryFreshness, ProductionSnapshot, ReferenceSnapshot,
    WorkingTreePackageStatus, WorkingTreeStatus, assess_drift,
};

const ADVISORY: &str = include_str!("../../../tests/fixtures/drift/advisory.json");
const REFERENCE: &str = include_str!("../../../tests/fixtures/drift/reference-fixed.json");
const PRODUCTION_AFFECTED: &str =
    include_str!("../../../tests/fixtures/drift/production-affected.json");
const PRODUCTION_FIXED: &str = include_str!("../../../tests/fixtures/drift/production-fixed.json");
const DEPLOYMENT_UNKNOWN: &str = include_str!("../../../tests/fixtures/drift/deploy-unknown.json");
const WORKING_TREE_AFFECTED: &str =
    include_str!("../../../tests/fixtures/drift/working-tree-affected.json");
const EXPECTED: &str = include_str!("../../../tests/fixtures/drift/expected.json");

#[derive(serde::Deserialize)]
struct ExpectedCases {
    repo_fixed_production_affected: ExpectedAssessment,
    both_fixed: ExpectedAssessment,
    unknown_deployment: ExpectedAssessment,
}

#[derive(serde::Deserialize)]
struct ExpectedAssessment {
    repo_status: RepoStatus,
    production_status: ProductionStatus,
    recommended_finding_status: FindingStatus,
}

fn now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-10-24T12:00:00Z")
        .expect("fixed timestamp is valid")
        .with_timezone(&Utc)
}

fn parse<T: serde::de::DeserializeOwned>(value: &str) -> T {
    serde_json::from_str(value).expect("fixture JSON is valid")
}

fn finding(status: FindingStatus) -> Finding {
    Finding {
        id: "finding-lodash".to_owned(),
        advisory_id: "CVE-2021-23337".to_owned(),
        component_instance_id: "component-instance-lodash".to_owned(),
        status,
        severity: Severity::High,
        priority_score: 80,
        priority_reasons: vec!["fixture".to_owned()],
        fingerprint: "sha256:fixture".to_owned(),
        repo_status: RepoStatus::Unknown,
        production_status: ProductionStatus::Unknown,
        disposition: None,
        risk_expires_at: None,
        fix_version: Some("4.17.21".to_owned()),
        created_at: now(),
        updated_at: now(),
    }
}

fn run_case(
    finding: &Finding,
    reference_inventory: &Inventory,
    working_inventory: Option<&Inventory>,
    production_inventory: &AgentInventory,
    deployment: Option<&DeploymentIdentity>,
    working_tree: WorkingTreeStatus,
) -> crate::DriftAssessment {
    let advisory: Advisory = parse(ADVISORY);
    assess_drift(
        &[DriftTarget {
            finding,
            advisory: &advisory,
            component_purl: "pkg:npm/lodash@4.17.20",
        }],
        Some(ReferenceSnapshot {
            branch: "main",
            commit_sha: "0123456789abcdef0123456789abcdef01234567",
            inventory: reference_inventory,
            reference_head_verified: true,
        }),
        working_inventory,
        Some(ProductionSnapshot {
            inventory: production_inventory,
            deployment,
            project_association_confirmed: true,
            freshness: InventoryFreshness::Current,
        }),
        working_tree,
        now(),
    )
    .expect("fixture inputs produce an assessment")
    .remove(0)
}

#[test]
fn repository_fix_with_affected_production_matches_fixture_expectation() {
    let expected: ExpectedCases = parse(EXPECTED);
    let reference: Inventory = parse(REFERENCE);
    let deployment_inventory: AgentInventory = parse(PRODUCTION_AFFECTED);
    let deployment = deployment_inventory.deployments.first();
    let assessment = run_case(
        &finding(FindingStatus::ConfirmedAffected),
        &reference,
        None,
        &deployment_inventory,
        deployment,
        WorkingTreeStatus::Clean,
    );

    assert_eq!(
        assessment.repo_status,
        expected.repo_fixed_production_affected.repo_status
    );
    assert_eq!(
        assessment.production_status,
        expected.repo_fixed_production_affected.production_status
    );
    assert_eq!(
        assessment.recommended_finding_status,
        expected
            .repo_fixed_production_affected
            .recommended_finding_status
    );
    assert!(assessment.proposed_transition.is_some());
    assert_eq!(assessment.reference_versions, ["4.17.22"]);
    assert_eq!(assessment.production_versions, ["4.17.20"]);
    let serialized = serde_json::to_value(&assessment).expect("assessment serializes cleanly");
    assert_eq!(
        serialized["proposed_transition"]["evidence"],
        "reference_branch_fix_verified"
    );
}

#[test]
fn fixed_production_transition_requires_current_complete_inventory() {
    let expected: ExpectedCases = parse(EXPECTED);
    let reference: Inventory = parse(REFERENCE);
    let deployment_inventory: AgentInventory = parse(PRODUCTION_FIXED);
    let deployment = deployment_inventory.deployments.first();
    let assessment = run_case(
        &finding(FindingStatus::FixedInRepo),
        &reference,
        None,
        &deployment_inventory,
        deployment,
        WorkingTreeStatus::Clean,
    );

    assert_eq!(assessment.repo_status, expected.both_fixed.repo_status);
    assert_eq!(
        assessment.production_status,
        expected.both_fixed.production_status
    );
    assert_eq!(
        assessment.recommended_finding_status,
        expected.both_fixed.recommended_finding_status
    );
    assert_eq!(
        assessment
            .proposed_transition
            .as_ref()
            .map(|transition| &transition.to),
        Some(&FindingStatus::FixedInProduction)
    );
}

#[test]
fn unknown_deployment_id_never_produces_a_fixed_production_state() {
    let expected: ExpectedCases = parse(EXPECTED);
    let reference: Inventory = parse(REFERENCE);
    let deployment_inventory: AgentInventory = parse(DEPLOYMENT_UNKNOWN);
    let deployment = deployment_inventory.deployments.first();
    let assessment = run_case(
        &finding(FindingStatus::ConfirmedAffected),
        &reference,
        None,
        &deployment_inventory,
        deployment,
        WorkingTreeStatus::Clean,
    );

    assert_eq!(
        assessment.repo_status,
        expected.unknown_deployment.repo_status
    );
    assert_eq!(
        assessment.production_status,
        expected.unknown_deployment.production_status
    );
    assert_eq!(
        assessment.recommended_finding_status,
        expected.unknown_deployment.recommended_finding_status
    );
    assert!(
        assessment
            .reasons
            .contains(&crate::DriftReason::DeploymentIdentityMissing)
    );
}

#[test]
fn uncommitted_workspace_changes_are_reported_separately_from_reference_status() {
    let reference: Inventory = parse(REFERENCE);
    let working_inventory: Inventory = parse(WORKING_TREE_AFFECTED);
    let deployment_inventory: AgentInventory = parse(PRODUCTION_AFFECTED);
    let assessment = run_case(
        &finding(FindingStatus::ConfirmedAffected),
        &reference,
        Some(&working_inventory),
        &deployment_inventory,
        deployment_inventory.deployments.first(),
        WorkingTreeStatus::HasUncommittedChanges,
    );

    assert_eq!(assessment.repo_status, RepoStatus::FixedInRepo);
    assert_eq!(
        assessment.working_tree,
        WorkingTreeStatus::HasUncommittedChanges
    );
    assert_eq!(
        assessment.working_tree_package_status,
        WorkingTreePackageStatus::Affected
    );
    assert_eq!(assessment.working_tree_versions, ["4.17.20"]);
    assert_eq!(assessment.repo_status, RepoStatus::FixedInRepo);
}

#[test]
fn absent_reference_or_unconfirmed_association_cannot_be_marked_fixed() {
    let advisory: Advisory = parse(ADVISORY);
    let finding = finding(FindingStatus::ConfirmedAffected);
    let reference: Inventory = parse(REFERENCE);
    let deployment_inventory: AgentInventory = parse(PRODUCTION_FIXED);
    let result = assess_drift(
        &[DriftTarget {
            finding: &finding,
            advisory: &advisory,
            component_purl: "pkg:npm/lodash@4.17.20",
        }],
        None,
        None,
        Some(ProductionSnapshot {
            inventory: &deployment_inventory,
            deployment: deployment_inventory.deployments.first(),
            project_association_confirmed: false,
            freshness: InventoryFreshness::Current,
        }),
        WorkingTreeStatus::GitUnavailable,
        now(),
    )
    .expect("missing evidence is an assessment result");
    let assessment = &result[0];

    assert_eq!(assessment.repo_status, RepoStatus::Unknown);
    assert_eq!(assessment.production_status, ProductionStatus::Unknown);
    assert_eq!(
        assessment.recommended_finding_status,
        FindingStatus::NeedsReview
    );
    assert_eq!(assessment.working_tree, WorkingTreeStatus::GitUnavailable);
    assert!(
        assessment
            .reasons
            .contains(&crate::DriftReason::NoReferenceSnapshot)
    );
    assert!(
        assessment
            .reasons
            .contains(&crate::DriftReason::ProductionAssociationUnconfirmed)
    );
    assert!(reference.complete);
}

#[test]
fn stale_production_inventory_cannot_produce_a_fix_transition() {
    let advisory: Advisory = parse(ADVISORY);
    let finding = finding(FindingStatus::ConfirmedAffected);
    let reference: Inventory = parse(REFERENCE);
    let deployment_inventory: AgentInventory = parse(PRODUCTION_FIXED);
    let result = assess_drift(
        &[DriftTarget {
            finding: &finding,
            advisory: &advisory,
            component_purl: "pkg:npm/lodash@4.17.20",
        }],
        Some(ReferenceSnapshot {
            branch: "main",
            commit_sha: "0123456789abcdef0123456789abcdef01234567",
            inventory: &reference,
            reference_head_verified: true,
        }),
        None,
        Some(ProductionSnapshot {
            inventory: &deployment_inventory,
            deployment: deployment_inventory.deployments.first(),
            project_association_confirmed: true,
            freshness: InventoryFreshness::Stale,
        }),
        WorkingTreeStatus::Clean,
        now(),
    )
    .expect("stale data is represented as review evidence");
    let assessment = &result[0];

    assert_eq!(assessment.repo_status, RepoStatus::FixedInRepo);
    assert_eq!(assessment.production_status, ProductionStatus::Unknown);
    assert_eq!(
        assessment.recommended_finding_status,
        FindingStatus::NeedsReview
    );
    assert_eq!(
        assessment
            .proposed_transition
            .as_ref()
            .map(|transition| &transition.to),
        Some(&FindingStatus::NeedsReview)
    );
    assert!(
        assessment
            .reasons
            .contains(&crate::DriftReason::ProductionInventoryStale)
    );
}

#[test]
fn future_dated_deployment_inventory_stays_unverified() {
    let advisory: Advisory = parse(ADVISORY);
    let finding = finding(FindingStatus::ConfirmedAffected);
    let reference: Inventory = parse(REFERENCE);
    let mut deployment_inventory: AgentInventory = parse(PRODUCTION_FIXED);
    deployment_inventory.captured_at = now() + chrono::Duration::seconds(1);
    let result = assess_drift(
        &[DriftTarget {
            finding: &finding,
            advisory: &advisory,
            component_purl: "pkg:npm/lodash@4.17.20",
        }],
        Some(ReferenceSnapshot {
            branch: "main",
            commit_sha: "0123456789abcdef0123456789abcdef01234567",
            inventory: &reference,
            reference_head_verified: true,
        }),
        None,
        Some(ProductionSnapshot {
            inventory: &deployment_inventory,
            deployment: deployment_inventory.deployments.first(),
            project_association_confirmed: true,
            freshness: InventoryFreshness::Current,
        }),
        WorkingTreeStatus::Clean,
        now(),
    )
    .expect("future timestamp remains an unverified status");
    let assessment = &result[0];

    assert_eq!(assessment.production_status, ProductionStatus::Unknown);
    assert_eq!(
        assessment.recommended_finding_status,
        FindingStatus::NeedsReview
    );
    assert!(
        assessment
            .reasons
            .contains(&crate::DriftReason::ProductionInventoryFreshnessUnknown)
    );
}

#[test]
fn incomplete_production_inventory_cannot_confirm_absence_of_the_vulnerable_package() {
    let advisory: Advisory = parse(ADVISORY);
    let finding = finding(FindingStatus::ConfirmedAffected);
    let reference: Inventory = parse(REFERENCE);
    let mut deployment_inventory: AgentInventory = parse(PRODUCTION_FIXED);
    let package_check = deployment_inventory
        .checks
        .iter_mut()
        .find(|check| check.kind == CheckKind::PackageInventory)
        .expect("fixture includes the package inventory check");
    package_check.status = CheckStatus::Partial;
    package_check.diagnostic = Some(DiagnosticCode::CommandFailed);
    deployment_inventory.complete = false;

    let result = assess_drift(
        &[DriftTarget {
            finding: &finding,
            advisory: &advisory,
            component_purl: "pkg:npm/lodash@4.17.20",
        }],
        Some(ReferenceSnapshot {
            branch: "main",
            commit_sha: "0123456789abcdef0123456789abcdef01234567",
            inventory: &reference,
            reference_head_verified: true,
        }),
        None,
        Some(ProductionSnapshot {
            inventory: &deployment_inventory,
            deployment: deployment_inventory.deployments.first(),
            project_association_confirmed: true,
            freshness: InventoryFreshness::Current,
        }),
        WorkingTreeStatus::Clean,
        now(),
    )
    .expect("partial data is represented as review evidence");
    let assessment = &result[0];

    assert_eq!(assessment.production_status, ProductionStatus::Unknown);
    assert_eq!(
        assessment.recommended_finding_status,
        FindingStatus::NeedsReview
    );
    assert!(
        assessment
            .reasons
            .contains(&crate::DriftReason::ProductionInventoryIncomplete)
    );
}

#[test]
fn missing_package_url_keeps_an_affected_match_unverified() {
    let advisory: Advisory = parse(ADVISORY);
    let finding = finding(FindingStatus::ConfirmedAffected);
    let reference: Inventory = parse(REFERENCE);
    let mut deployment_inventory: AgentInventory = parse(PRODUCTION_AFFECTED);
    deployment_inventory.packages[0].purl = None;

    let result = assess_drift(
        &[DriftTarget {
            finding: &finding,
            advisory: &advisory,
            component_purl: "pkg:npm/lodash@4.17.20",
        }],
        Some(ReferenceSnapshot {
            branch: "main",
            commit_sha: "0123456789abcdef0123456789abcdef01234567",
            inventory: &reference,
            reference_head_verified: true,
        }),
        None,
        Some(ProductionSnapshot {
            inventory: &deployment_inventory,
            deployment: deployment_inventory.deployments.first(),
            project_association_confirmed: true,
            freshness: InventoryFreshness::Current,
        }),
        WorkingTreeStatus::Clean,
        now(),
    )
    .expect("unverified identity is represented as review evidence");
    let assessment = &result[0];

    assert_eq!(assessment.production_status, ProductionStatus::Unknown);
    assert_eq!(
        assessment.recommended_finding_status,
        FindingStatus::NeedsReview
    );
    assert!(
        assessment
            .reasons
            .contains(&crate::DriftReason::ComponentIdentityInvalid)
    );
}

#[test]
fn abbreviated_reference_revision_cannot_establish_a_repo_fix() {
    let advisory: Advisory = parse(ADVISORY);
    let finding = finding(FindingStatus::ConfirmedAffected);
    let reference: Inventory = parse(REFERENCE);
    let deployment_inventory: AgentInventory = parse(PRODUCTION_AFFECTED);
    let result = assess_drift(
        &[DriftTarget {
            finding: &finding,
            advisory: &advisory,
            component_purl: "pkg:npm/lodash@4.17.20",
        }],
        Some(ReferenceSnapshot {
            branch: "main",
            commit_sha: "0123456",
            inventory: &reference,
            reference_head_verified: true,
        }),
        None,
        Some(ProductionSnapshot {
            inventory: &deployment_inventory,
            deployment: deployment_inventory.deployments.first(),
            project_association_confirmed: true,
            freshness: InventoryFreshness::Current,
        }),
        WorkingTreeStatus::Clean,
        now(),
    )
    .expect("invalid ref metadata remains unverified evidence");
    let assessment = &result[0];

    assert_eq!(assessment.repo_status, RepoStatus::Unknown);
    assert!(
        assessment
            .reasons
            .contains(&crate::DriftReason::InvalidReferenceSnapshot)
    );
}
