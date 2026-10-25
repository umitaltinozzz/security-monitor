use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use jsonschema::{Retrieve, Uri};
use security_monitor_core::{
    Advisory, Component, ComponentInstance, Finding, FindingDispositionReason, FindingEvidence,
    FindingStatus, Project, ProjectScanCheckpoint, ScanOutcome, ScanRun, Severity,
};
use security_monitor_database::Database;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CycloneDxJustification {
    CodeNotPresent,
    CodeNotReachable,
    RequiresConfiguration,
    RequiresDependency,
    RequiresEnvironment,
    ProtectedByCompiler,
    ProtectedAtRuntime,
    ProtectedAtPerimeter,
    ProtectedByMitigatingControl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CycloneDxResponse {
    CanNotFix,
    WillNotFix,
    Update,
    Rollback,
    WorkaroundAvailable,
}

const SARIF_SCHEMA: &str = include_str!("../schemas/sarif-2.1.0.schema.json");
const CYCLONEDX_SCHEMA: &str = include_str!("../schemas/cyclonedx-bom-1.6.schema.json");
const OPENVEX_SCHEMA: &str = include_str!("../schemas/openvex-0.2.0.schema.json");
const SPDX_SCHEMA: &str = include_str!("../schemas/spdx.schema.json");
const JSF_SCHEMA: &str = include_str!("../schemas/jsf-0.82.schema.json");
const REPORT_FRESHNESS: Duration = Duration::hours(24);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    Json,
    Sarif,
    Cyclonedx,
    Openvex,
}

impl ReportFormat {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "json" => Some(Self::Json),
            "sarif" => Some(Self::Sarif),
            "cyclonedx" => Some(Self::Cyclonedx),
            "openvex" => Some(Self::Openvex),
            _ => None,
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Sarif => "sarif",
            Self::Cyclonedx => "cdx.json",
            Self::Openvex => "openvex.json",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportSnapshot {
    pub generated_at: DateTime<Utc>,
    pub project: Option<ProjectSummary>,
    pub inventory_complete: bool,
    pub verification: VerificationState,
    pub components: Vec<Component>,
    pub instances: Vec<ComponentInstance>,
    pub advisories: Vec<Advisory>,
    pub findings: Vec<Finding>,
    pub evidence: Vec<FindingEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectSummary {
    pub id: String,
    pub name: String,
    pub last_scan_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    Verified,
    NeedsReview,
}

#[derive(Debug, Error)]
pub enum ReportingError {
    #[error("database operation failed")]
    Database(#[from] security_monitor_database::DatabaseError),
    #[error("project does not exist")]
    ProjectNotFound,
    #[error("report serialization failed")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailOn {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportExit {
    Success,
    ThresholdExceeded,
    NeedsReview,
}

impl ReportExit {
    pub const fn code(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::ThresholdExceeded => 2,
            Self::NeedsReview => 3,
        }
    }
}

impl FailOn {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "critical" => Some(Self::Critical),
            "high" => Some(Self::High),
            "medium" => Some(Self::Medium),
            "low" => Some(Self::Low),
            _ => None,
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Critical => 4,
            Self::High => 3,
            Self::Medium => 2,
            Self::Low => 1,
        }
    }
}

pub async fn load_snapshot(
    database: &Database,
    project_id: Option<&str>,
    generated_at: DateTime<Utc>,
) -> Result<ReportSnapshot, ReportingError> {
    let all_projects = database.repository::<Project>().list().await?;
    let project = if let Some(project_id) = project_id {
        Some(
            all_projects
                .iter()
                .find(|project| project.id == project_id)
                .ok_or(ReportingError::ProjectNotFound)?,
        )
    } else {
        None
    };
    let project_ids = if let Some(project) = project {
        BTreeSet::from([project.id.clone()])
    } else {
        all_projects
            .iter()
            .map(|project| project.id.clone())
            .collect()
    };
    let instances = database
        .repository::<ComponentInstance>()
        .list()
        .await?
        .into_iter()
        .filter(|instance| {
            instance
                .project_id
                .as_ref()
                .is_some_and(|id| project_ids.contains(id))
        })
        .collect::<Vec<_>>();
    let component_ids = instances
        .iter()
        .map(|instance| instance.component_id.as_str())
        .collect::<BTreeSet<_>>();
    let components = database
        .repository::<Component>()
        .list()
        .await?
        .into_iter()
        .filter(|component| component_ids.contains(component.id.as_str()))
        .collect::<Vec<_>>();
    let instance_ids = instances
        .iter()
        .map(|instance| instance.id.as_str())
        .collect::<BTreeSet<_>>();
    let findings = database
        .repository::<Finding>()
        .list()
        .await?
        .into_iter()
        .filter(|finding| instance_ids.contains(finding.component_instance_id.as_str()))
        .collect::<Vec<_>>();
    let finding_ids = findings
        .iter()
        .map(|finding| finding.id.as_str())
        .collect::<BTreeSet<_>>();
    let evidence = database
        .repository::<FindingEvidence>()
        .list()
        .await?
        .into_iter()
        .filter(|item| finding_ids.contains(item.finding_id.as_str()))
        .collect::<Vec<_>>();
    let advisory_ids = findings
        .iter()
        .map(|finding| finding.advisory_id.as_str())
        .collect::<BTreeSet<_>>();
    let advisories = database
        .repository::<Advisory>()
        .list()
        .await?
        .into_iter()
        .filter(|advisory| advisory_ids.contains(advisory.canonical_id.as_str()))
        .collect::<Vec<_>>();
    let project_summary = project.map(|project| ProjectSummary {
        id: project.id.clone(),
        name: project.name.clone(),
        last_scan_at: project.last_scan_at,
    });
    let checkpoints = database
        .repository::<ProjectScanCheckpoint>()
        .list()
        .await?;
    let checkpoint_by_project = checkpoints
        .iter()
        .map(|checkpoint| (checkpoint.project_id.as_str(), checkpoint))
        .collect::<BTreeMap<_, _>>();
    let inventory_complete = !project_ids.is_empty()
        && project_ids.iter().all(|id| {
            checkpoint_by_project
                .get(id.as_str())
                .is_some_and(|checkpoint| checkpoint.inventory_complete)
        });
    let runs = database.repository::<ScanRun>().list().await?;
    let latest_scan = runs
        .iter()
        .filter(|run| {
            run.scope.resource_type == "project"
                && run
                    .scope
                    .resource_id
                    .as_ref()
                    .is_some_and(|id| project_ids.contains(id))
        })
        .max_by_key(|run| run.finished_at.or(Some(run.started_at)));
    let scan_is_fresh = latest_scan.is_some_and(|run| {
        run.outcome == ScanOutcome::Succeeded
            && run.finished_at.is_some_and(|finished| {
                generated_at.signed_duration_since(finished) >= Duration::zero()
                    && generated_at.signed_duration_since(finished) <= REPORT_FRESHNESS
            })
    });
    let verification = if inventory_complete && scan_is_fresh {
        VerificationState::Verified
    } else {
        VerificationState::NeedsReview
    };

    Ok(ReportSnapshot {
        generated_at,
        project: project_summary,
        inventory_complete,
        verification,
        components,
        instances,
        advisories,
        findings,
        evidence,
    })
}

pub fn render(snapshot: &ReportSnapshot, format: ReportFormat) -> Result<String, ReportingError> {
    let value = match format {
        ReportFormat::Json => json::json_report(snapshot),
        ReportFormat::Sarif => sarif::sarif_report(snapshot),
        ReportFormat::Cyclonedx => cyclonedx::cyclonedx_report(snapshot),
        ReportFormat::Openvex => openvex::openvex_report(snapshot),
    };
    Ok(serde_json::to_string_pretty(&value)?)
}

pub fn assess(snapshot: &ReportSnapshot, fail_on: Option<FailOn>) -> ReportExit {
    if let Some(threshold) = fail_on
        && snapshot.findings.iter().any(|finding| {
            !is_closed(&finding.status)
                && severity_rank(&finding.severity) >= threshold.rank()
                && severity_rank(&finding.severity) > 0
        })
    {
        return ReportExit::ThresholdExceeded;
    }
    if snapshot.verification == VerificationState::NeedsReview {
        ReportExit::NeedsReview
    } else {
        ReportExit::Success
    }
}

pub fn validate(format: ReportFormat, document: &Value) -> Result<(), String> {
    let schema_text = match format {
        ReportFormat::Json => return json::validate_json_report(document),
        ReportFormat::Sarif => SARIF_SCHEMA,
        ReportFormat::Cyclonedx => CYCLONEDX_SCHEMA,
        ReportFormat::Openvex => OPENVEX_SCHEMA,
    };
    let mut schema: Value =
        serde_json::from_str(schema_text).map_err(|_| "invalid vendored schema")?;
    if format == ReportFormat::Sarif {
        sarif::patch_oasis_sarif_language_pattern(&mut schema);
    }
    let validator = if format == ReportFormat::Cyclonedx {
        let spdx_schema =
            serde_json::from_str(SPDX_SCHEMA).map_err(|_| "invalid vendored SPDX schema")?;
        let jsf_schema =
            serde_json::from_str(JSF_SCHEMA).map_err(|_| "invalid vendored JSF schema")?;
        jsonschema::options()
            .with_retriever(cyclonedx::VendoredCycloneDxRetriever {
                spdx_schema,
                jsf_schema,
            })
            .build(&schema)
    } else {
        jsonschema::validator_for(&schema)
    }
    .map_err(|error| format!("invalid vendored schema: {error}"))?;
    let mut errors = validator
        .iter_errors(document)
        .map(|error| format!("{}: {}", error.instance_path(), error))
        .collect::<Vec<_>>();
    errors.sort();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

mod common;
mod cyclonedx;
mod json;
mod openvex;
mod sarif;
#[cfg(test)]
mod tests;

pub(crate) use common::*;
#[cfg(test)]
pub(crate) use cyclonedx::cyclonedx_report;
pub(crate) use cyclonedx::is_verified_fixed;
pub(crate) use json::relative_evidence_path;
#[cfg(test)]
pub(crate) use openvex::openvex_report;
