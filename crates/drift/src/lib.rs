use std::str::FromStr;

use purl::GenericPurl;
use security_monitor_agent_protocol::{
    AgentInventory, DeploymentIdentity, DeploymentSource, PackageRecord,
};
use security_monitor_core::{Advisory, Finding, FindingStatus, ProductionStatus, RepoStatus};
use security_monitor_correlation::{
    FindingReason, StatusActor, StatusEvidence, StatusTransition, evaluate_inventory,
    normalize_package_name, validate_transition,
};
use security_monitor_inventory::{Inventory, InventoryComponent};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkingTreeStatus {
    Clean,
    HasUncommittedChanges,
    GitUnavailable,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryFreshness {
    Current,
    Stale,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkingTreePackageStatus {
    NotAvailable,
    Affected,
    Unaffected,
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftReason {
    NoReferenceSnapshot,
    InvalidReferenceSnapshot,
    ReferenceHeadNotVerified,
    ReferenceInventoryIncomplete,
    NoProductionSnapshot,
    ProductionAssociationUnconfirmed,
    DeploymentIdentityMissing,
    DeploymentIdentityNotInInventory,
    ProductionInventoryInvalid,
    ProductionInventoryStale,
    ProductionInventoryFreshnessUnknown,
    ProductionInventoryIncomplete,
    KernelRestartRequired,
    KernelStateUnknown,
    ComponentIdentityInvalid,
    ComponentIdentityMismatch,
    ComponentVersionMissing,
    AdvisoryRangeUnverified,
    WorkingTreeInventoryIncomplete,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DriftAssessment {
    pub finding_id: String,
    pub advisory_id: String,
    pub component_purl: String,
    pub reference_branch: Option<String>,
    pub reference_commit: Option<String>,
    pub deployed_commit: Option<String>,
    pub deployed_image_digest: Option<String>,
    pub repo_status: RepoStatus,
    pub production_status: ProductionStatus,
    pub recommended_finding_status: FindingStatus,
    pub reference_versions: Vec<String>,
    pub production_versions: Vec<String>,
    pub working_tree: WorkingTreeStatus,
    pub working_tree_package_status: WorkingTreePackageStatus,
    pub working_tree_versions: Vec<String>,
    pub working_tree_reasons: Vec<DriftReason>,
    pub reasons: Vec<DriftReason>,
    pub proposed_transition: Option<StatusTransition>,
}

pub struct DriftTarget<'a> {
    pub finding: &'a Finding,
    pub advisory: &'a Advisory,
    pub component_purl: &'a str,
}

pub struct ReferenceSnapshot<'a> {
    pub branch: &'a str,
    pub commit_sha: &'a str,
    pub inventory: &'a Inventory,
    /// Set only after the configured reference branch tip has been verified.
    pub reference_head_verified: bool,
}

pub struct ProductionSnapshot<'a> {
    pub inventory: &'a AgentInventory,
    pub deployment: Option<&'a DeploymentIdentity>,
    /// Set only after the user confirms this deployment belongs to the project.
    pub project_association_confirmed: bool,
    pub freshness: InventoryFreshness,
}

#[derive(Debug, Error)]
pub enum DriftError {
    #[error("the target component package URL is invalid")]
    InvalidComponentPurl,
    #[error("finding and advisory identifiers do not match")]
    FindingAdvisoryMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PackageState {
    Affected,
    Unaffected,
    Unknown,
}

struct PackageObservation {
    component: InventoryComponent,
    base_purl: Option<String>,
    identity_matches_component: bool,
}

struct SideAssessment {
    state: PackageState,
    versions: Vec<String>,
    reasons: Vec<DriftReason>,
}

/// Compares existing findings with a verified reference-branch snapshot and a user-associated,
/// current deployment inventory. It does not fetch Git refs, write findings, or make network calls.
pub fn assess_drift(
    targets: &[DriftTarget<'_>],
    reference: Option<ReferenceSnapshot<'_>>,
    working_tree_inventory: Option<&Inventory>,
    production: Option<ProductionSnapshot<'_>>,
    working_tree: WorkingTreeStatus,
    assessed_at: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<DriftAssessment>, DriftError> {
    let mut assessments = Vec::with_capacity(targets.len());
    for target in targets {
        if target.finding.advisory_id != target.advisory.canonical_id {
            return Err(DriftError::FindingAdvisoryMismatch);
        }
        let target_identity =
            package_identity(target.component_purl).ok_or(DriftError::InvalidComponentPurl)?;

        let mut reasons = Vec::new();
        let (reference_branch, reference_commit, repo_status, reference_versions) =
            assess_reference(reference.as_ref(), target, &target_identity, &mut reasons);
        let (deployment, production_status, production_versions) = assess_production(
            production.as_ref(),
            target,
            &target_identity,
            assessed_at,
            &mut reasons,
        );
        let (working_tree_package_status, working_tree_versions, working_tree_reasons) =
            assess_working_tree(working_tree_inventory, target, &target_identity);
        let recommended_finding_status = recommended_status(&repo_status, &production_status);
        let proposed_transition = proposed_transition(
            target.finding,
            recommended_finding_status.clone(),
            assessed_at,
        );

        reasons.sort();
        reasons.dedup();
        assessments.push(DriftAssessment {
            finding_id: target.finding.id.clone(),
            advisory_id: target.advisory.canonical_id.clone(),
            component_purl: target.component_purl.to_owned(),
            reference_branch,
            reference_commit,
            deployed_commit: deployment.and_then(|identity| identity.commit_sha.clone()),
            deployed_image_digest: deployment.and_then(|identity| identity.image_digest.clone()),
            repo_status,
            production_status,
            recommended_finding_status,
            reference_versions,
            production_versions,
            working_tree,
            working_tree_package_status,
            working_tree_versions,
            working_tree_reasons,
            reasons,
            proposed_transition,
        });
    }
    assessments.sort_by(|left, right| {
        (&left.advisory_id, &left.component_purl, &left.finding_id).cmp(&(
            &right.advisory_id,
            &right.component_purl,
            &right.finding_id,
        ))
    });
    Ok(assessments)
}

fn assess_working_tree(
    inventory: Option<&Inventory>,
    target: &DriftTarget<'_>,
    target_identity: &PackageIdentity,
) -> (WorkingTreePackageStatus, Vec<String>, Vec<DriftReason>) {
    let Some(inventory) = inventory else {
        return (
            WorkingTreePackageStatus::NotAvailable,
            Vec::new(),
            Vec::new(),
        );
    };
    let observations = inventory
        .components
        .iter()
        .cloned()
        .map(observe_inventory_component)
        .collect::<Vec<_>>();
    let complete = inventory.complete && inventory.diagnostics.is_empty();
    let mut assessment = assess_side(target.advisory, target_identity, &observations, complete);
    if !complete {
        assessment
            .reasons
            .push(DriftReason::WorkingTreeInventoryIncomplete);
    }
    let status = match assessment.state {
        PackageState::Affected => WorkingTreePackageStatus::Affected,
        PackageState::Unaffected => WorkingTreePackageStatus::Unaffected,
        PackageState::Unknown => WorkingTreePackageStatus::Unverified,
    };
    assessment.reasons.sort();
    assessment.reasons.dedup();
    (status, assessment.versions, assessment.reasons)
}

fn assess_reference(
    reference: Option<&ReferenceSnapshot<'_>>,
    target: &DriftTarget<'_>,
    target_identity: &PackageIdentity,
    reasons: &mut Vec<DriftReason>,
) -> (Option<String>, Option<String>, RepoStatus, Vec<String>) {
    let Some(reference) = reference else {
        reasons.push(DriftReason::NoReferenceSnapshot);
        return (None, None, RepoStatus::Unknown, Vec::new());
    };
    if !valid_reference(reference) {
        reasons.push(DriftReason::InvalidReferenceSnapshot);
        return (
            Some(reference.branch.to_owned()),
            Some(reference.commit_sha.to_owned()),
            RepoStatus::Unknown,
            Vec::new(),
        );
    }
    if !reference.reference_head_verified {
        reasons.push(DriftReason::ReferenceHeadNotVerified);
        return (
            Some(reference.branch.to_owned()),
            Some(reference.commit_sha.to_owned()),
            RepoStatus::Unknown,
            Vec::new(),
        );
    }

    let observations = reference
        .inventory
        .components
        .iter()
        .cloned()
        .map(observe_inventory_component)
        .collect::<Vec<_>>();
    let inventory_complete =
        reference.inventory.complete && reference.inventory.diagnostics.is_empty();
    if !inventory_complete {
        reasons.push(DriftReason::ReferenceInventoryIncomplete);
    }
    let assessment = assess_side(
        target.advisory,
        target_identity,
        &observations,
        inventory_complete,
    );
    reasons.extend(assessment.reasons);
    let status = match assessment.state {
        PackageState::Affected => RepoStatus::StillAffected,
        PackageState::Unaffected => RepoStatus::FixedInRepo,
        PackageState::Unknown => RepoStatus::Unknown,
    };
    (
        Some(reference.branch.to_owned()),
        Some(reference.commit_sha.to_owned()),
        status,
        assessment.versions,
    )
}

fn assess_production<'p>(
    production: Option<&ProductionSnapshot<'p>>,
    target: &DriftTarget<'_>,
    target_identity: &PackageIdentity,
    assessed_at: chrono::DateTime<chrono::Utc>,
    reasons: &mut Vec<DriftReason>,
) -> (
    Option<&'p DeploymentIdentity>,
    ProductionStatus,
    Vec<String>,
) {
    let Some(production) = production else {
        reasons.push(DriftReason::NoProductionSnapshot);
        return (None, ProductionStatus::Unknown, Vec::new());
    };
    if !production.project_association_confirmed {
        reasons.push(DriftReason::ProductionAssociationUnconfirmed);
        return (production.deployment, ProductionStatus::Unknown, Vec::new());
    }
    match production.freshness {
        InventoryFreshness::Current => {}
        InventoryFreshness::Stale => {
            reasons.push(DriftReason::ProductionInventoryStale);
            return (production.deployment, ProductionStatus::Unknown, Vec::new());
        }
        InventoryFreshness::Unknown => {
            reasons.push(DriftReason::ProductionInventoryFreshnessUnknown);
            return (production.deployment, ProductionStatus::Unknown, Vec::new());
        }
    }
    if production.inventory.validate().is_err() {
        reasons.push(DriftReason::ProductionInventoryInvalid);
        return (production.deployment, ProductionStatus::Unknown, Vec::new());
    }
    if production.inventory.captured_at > assessed_at {
        reasons.push(DriftReason::ProductionInventoryFreshnessUnknown);
        return (production.deployment, ProductionStatus::Unknown, Vec::new());
    }
    let Some(deployment) = production.deployment else {
        reasons.push(DriftReason::DeploymentIdentityMissing);
        return (None, ProductionStatus::Unknown, Vec::new());
    };
    if !known_deployment_identity(deployment) {
        reasons.push(DriftReason::DeploymentIdentityMissing);
        return (Some(deployment), ProductionStatus::Unknown, Vec::new());
    }
    if !inventory_contains_deployment(production.inventory, deployment) {
        reasons.push(DriftReason::DeploymentIdentityNotInInventory);
        return (Some(deployment), ProductionStatus::Unknown, Vec::new());
    }

    if is_kernel_product(&target_identity.name) {
        match production
            .inventory
            .operating_system
            .as_ref()
            .and_then(|os| os.kernel_restart_required)
        {
            Some(false) => {}
            Some(true) => {
                reasons.push(DriftReason::KernelRestartRequired);
                return (Some(deployment), ProductionStatus::Unknown, Vec::new());
            }
            None => {
                reasons.push(DriftReason::KernelStateUnknown);
                return (Some(deployment), ProductionStatus::Unknown, Vec::new());
            }
        }
    }

    let observations = production
        .inventory
        .packages
        .iter()
        .enumerate()
        .map(|(index, package)| observe_package_record(package, index))
        .collect::<Vec<_>>();
    if !production.inventory.complete {
        reasons.push(DriftReason::ProductionInventoryIncomplete);
    }
    let assessment = assess_side(
        target.advisory,
        target_identity,
        &observations,
        production.inventory.complete,
    );
    reasons.extend(assessment.reasons);
    let status = match assessment.state {
        PackageState::Affected => ProductionStatus::StillAffected,
        PackageState::Unaffected => ProductionStatus::FixedInProduction,
        PackageState::Unknown => ProductionStatus::Unknown,
    };
    (Some(deployment), status, assessment.versions)
}

fn assess_side(
    advisory: &Advisory,
    target: &PackageIdentity,
    observations: &[PackageObservation],
    complete: bool,
) -> SideAssessment {
    let relevant = observations
        .iter()
        .filter(|observation| same_package(target, observation))
        .collect::<Vec<_>>();
    let mut versions = relevant
        .iter()
        .filter_map(|observation| observation.component.version.clone())
        .collect::<Vec<_>>();
    versions.sort();
    versions.dedup();

    let incomplete_identity = relevant
        .iter()
        .any(|observation| !observation.identity_matches_component);
    let inventory = Inventory {
        components: relevant
            .iter()
            .map(|observation| observation.component.clone())
            .collect(),
        project_roots: Vec::new(),
        detected_files: Vec::new(),
        diagnostics: Vec::new(),
        complete,
    };
    let findings = evaluate_inventory(std::slice::from_ref(advisory), &inventory);
    let affected = findings.iter().any(|finding| {
        finding.reason == FindingReason::AffectedVersion
            && relevant.iter().any(|observation| {
                observation.component.purl == finding.component_purl
                    && observation.identity_matches_component
                    && observation.base_purl.is_some()
            })
    });
    let unverified_range = findings
        .iter()
        .any(|finding| finding.reason != FindingReason::AffectedVersion);

    let mut reasons = Vec::new();
    if relevant
        .iter()
        .any(|observation| observation.base_purl.is_none())
    {
        reasons.push(DriftReason::ComponentIdentityInvalid);
    }
    if relevant.iter().any(|observation| {
        observation.base_purl.is_some() && !observation.identity_matches_component
    }) {
        reasons.push(DriftReason::ComponentIdentityMismatch);
    }
    if relevant
        .iter()
        .any(|observation| observation.component.version.is_none())
    {
        reasons.push(DriftReason::ComponentVersionMissing);
    }
    if unverified_range {
        reasons.push(DriftReason::AdvisoryRangeUnverified);
    }

    let state = if affected && !incomplete_identity {
        PackageState::Affected
    } else if !complete || incomplete_identity || unverified_range {
        PackageState::Unknown
    } else {
        PackageState::Unaffected
    };
    SideAssessment {
        state,
        versions,
        reasons,
    }
}

fn observe_inventory_component(component: InventoryComponent) -> PackageObservation {
    let identity = package_identity(&component.purl);
    let Some(identity) = identity else {
        return PackageObservation {
            component,
            base_purl: None,
            identity_matches_component: false,
        };
    };
    let matches_component = identity.version.as_deref() == component.version.as_deref()
        && package_name_matches(&identity, &component.ecosystem, &component.name);
    PackageObservation {
        component,
        base_purl: Some(identity.base),
        identity_matches_component: matches_component,
    }
}

fn observe_package_record(package: &PackageRecord, index: usize) -> PackageObservation {
    let component_purl = package
        .purl
        .clone()
        .unwrap_or_else(|| format!("unverified:agent-package-{index}"));
    let component = InventoryComponent {
        purl: component_purl,
        ecosystem: package.ecosystem.clone(),
        name: package.name.clone(),
        version: package.version.clone(),
        source_type: format!("agent_{:?}", package.source).to_ascii_lowercase(),
        evidence_paths: package.evidence_path.iter().cloned().collect(),
    };
    observe_inventory_component(component)
}

fn same_package(target: &PackageIdentity, observation: &PackageObservation) -> bool {
    if observation.base_purl.as_deref() == Some(target.base.as_str()) {
        return true;
    }
    if observation.component.ecosystem == "unknown"
        && observation.component.source_type == "agent_manual"
    {
        return normalize_package_name(&target.ecosystem, &target.name)
            == normalize_package_name(&target.ecosystem, &observation.component.name);
    }
    package_name_matches(
        target,
        &observation.component.ecosystem,
        &observation.component.name,
    )
}

fn is_kernel_product(value: &str) -> bool {
    let package = value
        .rsplit('/')
        .next()
        .unwrap_or(value)
        .to_ascii_lowercase();
    matches!(package.as_str(), "linux-image" | "linux-image-generic")
        || package.starts_with("linux-image-")
        || matches!(
            package.as_str(),
            "linux" | "linux-kernel" | "linux-lts" | "kernel" | "kernel-core"
        )
}

fn package_name_matches(identity: &PackageIdentity, ecosystem: &str, name: &str) -> bool {
    security_monitor_correlation::canonical_ecosystem(&identity.ecosystem)
        == security_monitor_correlation::canonical_ecosystem(ecosystem)
        && security_monitor_correlation::normalize_package_name(&identity.ecosystem, &identity.name)
            == security_monitor_correlation::normalize_package_name(ecosystem, name)
}

struct PackageIdentity {
    base: String,
    ecosystem: String,
    name: String,
    version: Option<String>,
}

fn package_identity(value: &str) -> Option<PackageIdentity> {
    let parsed = GenericPurl::<String>::from_str(value).ok()?;
    let ecosystem = parsed.package_type().clone();
    let name = match (ecosystem.as_str(), parsed.namespace()) {
        ("maven", Some(namespace)) => format!("{namespace}:{}", parsed.name()),
        (_, Some(namespace)) => format!("{namespace}/{}", parsed.name()),
        (_, None) => parsed.name().to_owned(),
    };
    let version = parsed.version().map(str::to_owned);
    let base = parsed
        .into_builder()
        .without_version()
        .build()
        .ok()?
        .to_string();
    Some(PackageIdentity {
        base,
        ecosystem,
        name,
        version,
    })
}

fn valid_reference(reference: &ReferenceSnapshot<'_>) -> bool {
    valid_branch_name(reference.branch) && valid_full_commit_sha(reference.commit_sha)
}

fn valid_branch_name(value: &str) -> bool {
    !value.is_empty()
        && value != "@"
        && !value.starts_with('-')
        && !value.ends_with('/')
        && !value.ends_with('.')
        && !value.contains("..")
        && !value.contains("//")
        && !value.contains("@{")
        && !value.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
        && value.split('/').all(|segment| {
            !segment.is_empty() && !segment.starts_with('.') && !segment.ends_with(".lock")
        })
}

fn valid_full_commit_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_commit_sha(value: &str) -> bool {
    (7..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn known_deployment_identity(identity: &DeploymentIdentity) -> bool {
    identity.source != DeploymentSource::Unknown
        && (identity.commit_sha.as_deref().is_some_and(valid_commit_sha)
            || identity
                .image_digest
                .as_deref()
                .is_some_and(valid_image_digest))
}

fn valid_image_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn inventory_contains_deployment(
    inventory: &AgentInventory,
    deployment: &DeploymentIdentity,
) -> bool {
    inventory
        .deployments
        .iter()
        .any(|candidate| candidate == deployment)
        || inventory
            .services
            .iter()
            .filter_map(|service| service.deploy_identity.as_ref())
            .any(|candidate| candidate == deployment)
}

fn recommended_status(
    repo_status: &RepoStatus,
    production_status: &ProductionStatus,
) -> FindingStatus {
    match (repo_status, production_status) {
        (_, ProductionStatus::FixedInProduction) => FindingStatus::FixedInProduction,
        (RepoStatus::FixedInRepo, ProductionStatus::StillAffected) => FindingStatus::FixedInRepo,
        (_, ProductionStatus::StillAffected) => FindingStatus::ConfirmedAffected,
        _ => FindingStatus::NeedsReview,
    }
}

fn proposed_transition(
    finding: &Finding,
    to: FindingStatus,
    assessed_at: chrono::DateTime<chrono::Utc>,
) -> Option<StatusTransition> {
    if finding.status == to {
        return None;
    }
    let evidence = match to {
        FindingStatus::FixedInRepo => StatusEvidence::ReferenceBranchFixVerified,
        FindingStatus::FixedInProduction => StatusEvidence::ProductionFixVerified,
        FindingStatus::ConfirmedAffected => StatusEvidence::AffectedVersionVerified,
        FindingStatus::NeedsReview => StatusEvidence::CurrentDataIncomplete,
        _ => return None,
    };
    let transition = StatusTransition {
        from: finding.status.clone(),
        to,
        actor: StatusActor::System,
        evidence,
        disposition: None,
        current_risk_expires_at: finding.risk_expires_at,
        at: assessed_at,
    };
    validate_transition(&transition).ok().map(|_| transition)
}
