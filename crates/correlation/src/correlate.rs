use std::collections::BTreeSet;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use purl::GenericPurl;
use security_monitor_core::{
    Advisory, Asset, Component, ComponentEvidence, ComponentInstance, Deployment, Finding,
    FindingEvidence, FindingStatus, ProductionStatus, Project, RepoStatus, Service, Severity,
};
use security_monitor_database::{Database, DatabaseError};
use security_monitor_inventory::{Inventory, InventoryComponent};
use thiserror::Error;

use crate::{
    AliasMerger, FindingFingerprintInput, FindingReason, PriorityContext, PriorityInput,
    calculate_priority, evaluate_inventory, finding_fingerprint,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryFreshness {
    Current,
    Stale,
    Incomplete,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeVerification {
    Verified,
    Unverified,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CorrelationComponent {
    pub component: Component,
    pub instance: ComponentInstance,
    pub scope_verification: ScopeVerification,
    pub inventory_freshness: InventoryFreshness,
    pub priority: PriorityContext,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CorrelatedFinding {
    pub finding: Finding,
    pub evidence: FindingEvidence,
}

#[derive(Debug, Error)]
pub enum CorrelationError {
    #[error("component instance does not match its component")]
    ComponentInstanceMismatch,
    #[error("component instance has no verified project or asset scope")]
    MissingScope,
    #[error("component or its project/asset relationships could not be verified in the database")]
    ScopeNotVerified,
    #[error("finding fingerprint could not be generated")]
    Fingerprint(#[from] crate::FingerprintError),
    #[error("finding priority could not be calculated")]
    Priority(#[from] crate::PriorityError),
    #[error("finding persistence failed")]
    Database(#[from] DatabaseError),
}

pub fn correlate(
    advisories: &[Advisory],
    components: &[CorrelationComponent],
    evaluated_at: DateTime<Utc>,
) -> Result<Vec<CorrelatedFinding>, CorrelationError> {
    let merged_advisories = AliasMerger::new(advisories.iter().cloned()).into_records();
    let mut components = components.iter().collect::<Vec<_>>();
    components.sort_by(|left, right| stable_component_key(left).cmp(&stable_component_key(right)));
    let mut results = Vec::new();
    for context in components {
        if context.component.id != context.instance.component_id {
            return Err(CorrelationError::ComponentInstanceMismatch);
        }
        if context.instance.project_id.is_none()
            && context.instance.asset_id.is_none()
            && context.instance.service_id.is_none()
            && context.instance.deployment_id.is_none()
        {
            return Err(CorrelationError::MissingScope);
        }
        let identity_reason = (!purl_version_matches_component(&context.component))
            .then_some("component_identity_unverified");
        let inventory = inventory_for(context);
        for candidate in evaluate_inventory(&merged_advisories, &inventory) {
            let Some(advisory) = merged_advisories
                .iter()
                .find(|advisory| advisory.canonical_id == candidate.advisory_id)
            else {
                continue;
            };
            let freshness_reason = match context.inventory_freshness {
                InventoryFreshness::Current => None,
                InventoryFreshness::Stale => Some("inventory_stale"),
                InventoryFreshness::Incomplete => Some("inventory_incomplete"),
                InventoryFreshness::Unknown => Some("inventory_freshness_unknown"),
            };
            let scope_reason = (context.scope_verification == ScopeVerification::Unverified)
                .then_some("scope_unverified");
            let affected = candidate.reason == FindingReason::AffectedVersion;
            let status = if affected
                && freshness_reason.is_none()
                && scope_reason.is_none()
                && identity_reason.is_none()
            {
                FindingStatus::ConfirmedAffected
            } else {
                FindingStatus::NeedsReview
            };
            let mut priority_context = context.priority.clone();
            priority_context.fix_available |=
                candidate.fix_version.is_some() || !advisory.fixed_versions.is_empty();
            let priority = calculate_priority(
                &PriorityInput {
                    cvss: advisory.cvss,
                    severity: advisory.severity.clone(),
                    kev_listed: advisory.kev,
                    epss_score: advisory.epss,
                    epss_date: advisory.epss_date,
                    context: priority_context,
                },
                evaluated_at,
            )?;
            let evidence = evidence_for(&context.instance.evidence);
            let evidence = if evidence.is_empty() {
                vec![None]
            } else {
                evidence.into_iter().map(Some).collect()
            };
            let severity = advisory
                .severity
                .clone()
                .unwrap_or_else(|| severity_from_cvss(advisory.cvss));
            for evidence_input in evidence {
                let sanitized_evidence =
                    evidence_input.map(|evidence| sanitize_evidence(&evidence));
                let fingerprint = finding_fingerprint(&FindingFingerprintInput {
                    canonical_advisory_id: &advisory.canonical_id,
                    component: &context.component,
                    instance: &context.instance,
                    evidence: sanitized_evidence.as_ref(),
                })?;
                let id = format!("finding-{}", fingerprint.trim_start_matches("sha256:"));
                let evidence_id = format!("evidence-{}", fingerprint.trim_start_matches("sha256:"));
                let finding_id = id.clone();
                let mut reasons = priority.reasons.clone();
                if let Some(reason) = freshness_reason {
                    reasons.push(reason.to_owned());
                }
                if let Some(reason) = scope_reason {
                    reasons.push(reason.to_owned());
                }
                if let Some(reason) = identity_reason {
                    reasons.push(reason.to_owned());
                }
                if freshness_reason.is_some() || scope_reason.is_some() || identity_reason.is_some()
                {
                    reasons.sort();
                    reasons.dedup();
                }
                results.push(CorrelatedFinding {
                    finding: Finding {
                        id: finding_id.clone(),
                        advisory_id: advisory.canonical_id.clone(),
                        component_instance_id: context.instance.id.clone(),
                        status: status.clone(),
                        severity: severity.clone(),
                        priority_score: priority.score,
                        priority_reasons: reasons,
                        fingerprint,
                        repo_status: RepoStatus::Unknown,
                        production_status: ProductionStatus::Unknown,
                        disposition: None,
                        risk_expires_at: None,
                        fix_version: candidate.fix_version.clone(),
                        created_at: evaluated_at,
                        updated_at: evaluated_at,
                    },
                    evidence: FindingEvidence {
                        id: evidence_id,
                        finding_id,
                        evidence_type: evidence_type(candidate.reason).to_owned(),
                        file_path_redacted: sanitized_evidence
                            .as_ref()
                            .and_then(|evidence| evidence.file_path_redacted.clone()),
                        reference: None,
                        confidence: None,
                        created_at: evaluated_at,
                    },
                });
            }
        }
    }
    results.sort_by(|left, right| left.finding.fingerprint.cmp(&right.finding.fingerprint));
    results.dedup_by(|left, right| left.finding.fingerprint == right.finding.fingerprint);
    Ok(results)
}

fn purl_version_matches_component(component: &Component) -> bool {
    let Ok(purl) = GenericPurl::<String>::from_str(&component.purl) else {
        return false;
    };
    match (purl.version(), component.version.trim()) {
        (Some(purl_version), component_version) => purl_version == component_version,
        (None, "") => true,
        (None, _) => false,
    }
}

fn stable_component_key(
    context: &CorrelationComponent,
) -> (&str, &str, &str, &str, &str, &str, &str) {
    (
        context.component.purl.as_str(),
        context.component.version.as_str(),
        context.instance.project_id.as_deref().unwrap_or_default(),
        context.instance.asset_id.as_deref().unwrap_or_default(),
        context.instance.service_id.as_deref().unwrap_or_default(),
        context
            .instance
            .deployment_id
            .as_deref()
            .unwrap_or_default(),
        context.instance.id.as_str(),
    )
}

pub async fn correlate_and_persist(
    database: &Database,
    advisories: &[Advisory],
    components: &[CorrelationComponent],
    evaluated_at: DateTime<Utc>,
) -> Result<Vec<CorrelatedFinding>, CorrelationError> {
    let component_repository = database.repository::<Component>();
    let instance_repository = database.repository::<ComponentInstance>();
    let mut verified_components = Vec::with_capacity(components.len());
    for context in components {
        if component_repository.get(&context.component.id).await? != Some(context.component.clone())
            || instance_repository.get(&context.instance.id).await?
                != Some(context.instance.clone())
            || !scope_is_verified(database, &context.instance).await?
        {
            return Err(CorrelationError::ScopeNotVerified);
        }
        let mut verified = context.clone();
        verified.scope_verification = ScopeVerification::Verified;
        verified_components.push(verified);
    }
    let correlated = correlate(advisories, &verified_components, evaluated_at)?;
    let findings = database.repository::<Finding>();
    let evidence = database.repository::<FindingEvidence>();
    for record in &correlated {
        if let Some(existing) = findings.get(&record.finding.id).await? {
            let mut updated = record.finding.clone();
            updated.created_at = existing.created_at;
            updated.repo_status = existing.repo_status.clone();
            updated.production_status = existing.production_status.clone();
            if has_active_user_disposition(&existing, evaluated_at) {
                updated.status = existing.status.clone();
                updated.disposition = existing.disposition.clone();
                updated.risk_expires_at = existing.risk_expires_at;
            }
            findings.update(&updated).await?;
        } else {
            findings.create(&record.finding).await?;
        }
        if evidence.get(&record.evidence.id).await?.is_some() {
            evidence.update(&record.evidence).await?;
        } else {
            evidence.create(&record.evidence).await?;
        }
    }
    Ok(correlated)
}

fn has_active_user_disposition(finding: &Finding, evaluated_at: DateTime<Utc>) -> bool {
    let Some(disposition) = finding.disposition.as_ref() else {
        return false;
    };
    match &finding.status {
        FindingStatus::AcceptedRisk | FindingStatus::FalsePositive => disposition
            .expires_at
            .is_some_and(|expires_at| expires_at > evaluated_at),
        FindingStatus::NotReachable => disposition
            .expires_at
            .is_none_or(|expires_at| expires_at > evaluated_at),
        _ => false,
    }
}

async fn scope_is_verified(
    database: &Database,
    instance: &ComponentInstance,
) -> Result<bool, DatabaseError> {
    if let Some(project_id) = instance.project_id.as_deref()
        && database
            .repository::<Project>()
            .get(project_id)
            .await?
            .is_none()
    {
        return Ok(false);
    }
    if let Some(asset_id) = instance.asset_id.as_deref()
        && database
            .repository::<Asset>()
            .get(asset_id)
            .await?
            .is_none()
    {
        return Ok(false);
    }
    let service = if let Some(service_id) = instance.service_id.as_deref() {
        let Some(service) = database.repository::<Service>().get(service_id).await? else {
            return Ok(false);
        };
        if instance
            .asset_id
            .as_deref()
            .is_some_and(|asset_id| service.asset_id != asset_id)
        {
            return Ok(false);
        }
        Some(service)
    } else {
        None
    };
    if let Some(deployment_id) = instance.deployment_id.as_deref() {
        let Some(deployment) = database
            .repository::<Deployment>()
            .get(deployment_id)
            .await?
        else {
            return Ok(false);
        };
        if instance
            .service_id
            .as_deref()
            .is_some_and(|service_id| deployment.service_id != service_id)
        {
            return Ok(false);
        }
        let deployment_service = match service {
            Some(service) if service.id == deployment.service_id => service,
            Some(_) => return Ok(false),
            None => {
                let Some(service) = database
                    .repository::<Service>()
                    .get(&deployment.service_id)
                    .await?
                else {
                    return Ok(false);
                };
                service
            }
        };
        if instance
            .asset_id
            .as_deref()
            .is_some_and(|asset_id| deployment_service.asset_id != asset_id)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn inventory_for(context: &CorrelationComponent) -> Inventory {
    let evidence_paths = context
        .instance
        .evidence
        .iter()
        .filter_map(|evidence| evidence.file_path_redacted.clone())
        .collect();
    Inventory {
        components: vec![InventoryComponent {
            purl: context.component.purl.clone(),
            ecosystem: context.component.ecosystem.clone(),
            name: context.component.name.clone(),
            version: (!context.component.version.trim().is_empty())
                .then(|| context.component.version.clone()),
            source_type: context.component.source_type.clone(),
            evidence_paths,
        }],
        project_roots: Vec::new(),
        detected_files: Vec::new(),
        diagnostics: Vec::new(),
        complete: context.inventory_freshness == InventoryFreshness::Current,
    }
}

fn evidence_for(evidence: &[ComponentEvidence]) -> Vec<ComponentEvidence> {
    let mut output = BTreeSet::new();
    for item in evidence {
        output.insert(sanitize_evidence(item));
    }
    output.into_iter().collect()
}

fn sanitize_evidence(evidence: &ComponentEvidence) -> ComponentEvidence {
    ComponentEvidence {
        evidence_type: "component_inventory".to_owned(),
        file_path_redacted: evidence
            .file_path_redacted
            .as_deref()
            .and_then(sanitize_relative_path),
        reference: None,
    }
}

fn sanitize_relative_path(value: &str) -> Option<String> {
    let normalized = value.trim().replace('\\', "/");
    if normalized.is_empty()
        || normalized.starts_with('/')
        || normalized.contains(':')
        || normalized.chars().any(char::is_control)
    {
        return None;
    }
    let mut segments = Vec::new();
    for segment in normalized.split('/') {
        match segment {
            "" | "." => {}
            ".." => return None,
            segment => segments.push(segment),
        }
    }
    (!segments.is_empty()).then(|| segments.join("/"))
}

fn evidence_type(reason: FindingReason) -> &'static str {
    match reason {
        FindingReason::AffectedVersion => "affected_version_match",
        FindingReason::VersionDataPending => "version_data_pending",
        FindingReason::SourceDisagreement => "source_disagreement",
        FindingReason::VersionRangeUnverified => "version_range_unverified",
    }
}

fn severity_from_cvss(cvss: Option<f64>) -> Severity {
    match cvss {
        Some(score) if score >= 9.0 => Severity::Critical,
        Some(score) if score >= 7.0 => Severity::High,
        Some(score) if score >= 4.0 => Severity::Medium,
        Some(score) if score > 0.0 => Severity::Low,
        _ => Severity::Unknown,
    }
}
