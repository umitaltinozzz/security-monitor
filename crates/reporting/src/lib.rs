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
        ReportFormat::Json => json_report(snapshot),
        ReportFormat::Sarif => sarif_report(snapshot),
        ReportFormat::Cyclonedx => cyclonedx_report(snapshot),
        ReportFormat::Openvex => openvex_report(snapshot),
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
        ReportFormat::Json => return validate_json_report(document),
        ReportFormat::Sarif => SARIF_SCHEMA,
        ReportFormat::Cyclonedx => CYCLONEDX_SCHEMA,
        ReportFormat::Openvex => OPENVEX_SCHEMA,
    };
    let mut schema: Value =
        serde_json::from_str(schema_text).map_err(|_| "invalid vendored schema")?;
    if format == ReportFormat::Sarif {
        patch_oasis_sarif_language_pattern(&mut schema);
    }
    let validator = if format == ReportFormat::Cyclonedx {
        let spdx_schema =
            serde_json::from_str(SPDX_SCHEMA).map_err(|_| "invalid vendored SPDX schema")?;
        let jsf_schema =
            serde_json::from_str(JSF_SCHEMA).map_err(|_| "invalid vendored JSF schema")?;
        jsonschema::options()
            .with_retriever(VendoredCycloneDxRetriever {
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

struct VendoredCycloneDxRetriever {
    spdx_schema: Value,
    jsf_schema: Value,
}

impl Retrieve for VendoredCycloneDxRetriever {
    fn retrieve(
        &self,
        uri: &Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        match uri.as_str().split('#').next().unwrap_or(uri.as_str()) {
            "http://cyclonedx.org/schema/spdx.schema.json"
            | "https://cyclonedx.org/schema/spdx.schema.json" => Ok(self.spdx_schema.clone()),
            "http://cyclonedx.org/schema/jsf-0.82.schema.json"
            | "https://cyclonedx.org/schema/jsf-0.82.schema.json" => Ok(self.jsf_schema.clone()),
            _ => Err(format!("schema is not vendored: {uri}").into()),
        }
    }
}

fn patch_oasis_sarif_language_pattern(value: &mut Value) {
    const INVALID: &str = "^[a-zA-Z]{2}|^[a-zA-Z]{2}-[a-zA-Z]{2}]?$";
    const CORRECTED: &str = "^[a-zA-Z]{2}(-[a-zA-Z]{2})?$";
    match value {
        Value::Object(properties) => {
            if properties.get("pattern").and_then(Value::as_str) == Some(INVALID) {
                properties.insert("pattern".to_owned(), json!(CORRECTED));
            }
            for nested in properties.values_mut() {
                patch_oasis_sarif_language_pattern(nested);
            }
        }
        Value::Array(values) => {
            for nested in values {
                patch_oasis_sarif_language_pattern(nested);
            }
        }
        _ => {}
    }
}

fn validate_json_report(document: &Value) -> Result<(), String> {
    let valid = document.get("format").and_then(Value::as_str) == Some("security-monitor-json")
        && document
            .get("generated_at")
            .and_then(Value::as_str)
            .is_some()
        && document
            .get("verification")
            .and_then(Value::as_str)
            .is_some_and(|value| matches!(value, "verified" | "needs_review"))
        && document.get("findings").and_then(Value::as_array).is_some()
        && document
            .get("components")
            .and_then(Value::as_array)
            .is_some();
    if valid {
        Ok(())
    } else {
        Err("document does not match the Security Monitor JSON report shape".to_owned())
    }
}

fn json_report(snapshot: &ReportSnapshot) -> Value {
    let component_by_id = component_map(snapshot);
    let instance_by_id = instance_map(snapshot);
    let advisory_by_id = advisory_map(snapshot);
    json!({
        "format":"security-monitor-json",
        "version":1,
        "generated_at":snapshot.generated_at,
        "project":snapshot.project,
        "inventory_complete":snapshot.inventory_complete,
        "verification":verification_text(snapshot.verification),
        "components":snapshot.instances.iter().filter_map(|instance| {
            let component = component_by_id.get(instance.component_id.as_str())?;
            Some(json!({"purl":component.purl,"name":component.name,"version":component.version,
                "ecosystem":component.ecosystem,"evidence":instance.evidence.iter().map(|item| json!({
                    "type":item.evidence_type,"path":item.file_path_redacted.as_deref().and_then(relative_evidence_path)
                })).collect::<Vec<_>>() }))
        }).collect::<Vec<_>>(),
        "findings":snapshot.findings.iter().filter_map(|finding| {
            let instance = instance_by_id.get(finding.component_instance_id.as_str())?;
            let component = component_by_id.get(instance.component_id.as_str())?;
            let advisory = advisory_by_id.get(finding.advisory_id.as_str());
            Some(json!({"id":finding.id,"advisory_id":finding.advisory_id,
                "title":advisory.map_or(finding.advisory_id.as_str(), |item| item.title.as_str()),
                "component":{"purl":component.purl,"name":component.name,"version":component.version},
                "severity":finding.severity,"status":finding.status,"repo_status":finding.repo_status,
                "production_status":finding.production_status,"priority_score":finding.priority_score,
                "priority_reasons":finding.priority_reasons,
                "evidence":snapshot.evidence.iter().filter(|item| item.finding_id == finding.id)
                    .map(|item| json!({"type":item.evidence_type,"path":item.file_path_redacted.as_deref().and_then(relative_evidence_path),"confidence":item.confidence})).collect::<Vec<_>>() }))
        }).collect::<Vec<_>>()
    })
}

fn sarif_report(snapshot: &ReportSnapshot) -> Value {
    let component_by_id = component_map(snapshot);
    let instance_by_id = instance_map(snapshot);
    let advisory_by_id = advisory_map(snapshot);
    let rules = snapshot
        .findings
        .iter()
        .map(|finding| finding.advisory_id.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|id| {
            let advisory = advisory_by_id.get(id);
            let mut rule = json!({"id":id,"shortDescription":{"text":advisory.map_or(id, |item| item.title.as_str())}});
            if let Some(uri) = advisory
                .and_then(|item| item.source_urls.first())
                .and_then(|uri| safe_reference_uri(uri))
            {
                rule["helpUri"] = json!(uri);
            }
            rule
        })
        .collect::<Vec<_>>();
    let rule_indexes = rules
        .iter()
        .enumerate()
        .filter_map(|(index, rule)| Some((rule.get("id")?.as_str()?, index)))
        .collect::<BTreeMap<_, _>>();
    let results = snapshot
        .findings
        .iter()
        .map(|finding| {
            let instance = instance_by_id.get(finding.component_instance_id.as_str());
            let component = instance.and_then(|instance| component_by_id.get(instance.component_id.as_str()));
            let advisory = advisory_by_id.get(finding.advisory_id.as_str());
            let locations = snapshot.evidence.iter().filter(|item| item.finding_id == finding.id)
                .filter_map(|item| item.file_path_redacted.as_deref().and_then(relative_evidence_path))
                .map(|path| json!({"physicalLocation":{"artifactLocation":{"uri":path}}})).collect::<Vec<_>>();
            let mut result = json!({"ruleId":finding.advisory_id,"ruleIndex":rule_indexes.get(finding.advisory_id.as_str()).copied().unwrap_or(0),
                "level":sarif_level(&finding.severity),
                "message":{"text":format!("{} affects {}@{}; verification: {}",
                    advisory.map_or(finding.advisory_id.as_str(), |item| item.title.as_str()),
                    component.map_or("unknown component", |item| item.name.as_str()),
                    component.map_or("unknown version", |item| item.version.as_str()), verification_text(snapshot.verification))},
                "partialFingerprints":{"securityMonitorFindingId":finding.id},
                "properties":{"status":finding_status(&finding.status),"repo_status":finding.repo_status,"production_status":finding.production_status,
                    "verification":verification_text(snapshot.verification),"priority_score":finding.priority_score}});
            if !locations.is_empty() {
                result["locations"] = json!(locations);
            }
            result
        })
        .collect::<Vec<_>>();
    json!({"$schema":"https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json",
        "version":"2.1.0","runs":[{"tool":{"driver":{"name":"Security Monitor","informationUri":"https://github.com/umitaltinozzz/security-monitor",
            "rules":rules}},"results":results,"properties":{"verification":verification_text(snapshot.verification),
                "inventory_complete":snapshot.inventory_complete,"project":snapshot.project}}]})
}

fn cyclonedx_report(snapshot: &ReportSnapshot) -> Value {
    let component_by_id = component_map(snapshot);
    let instance_by_id = instance_map(snapshot);
    let advisory_by_id = advisory_map(snapshot);
    let components = snapshot
        .instances
        .iter()
        .filter_map(|instance| component_by_id.get(instance.component_id.as_str()))
        .map(|component| {
            json!({"type":"library","bom-ref":component.purl,"name":component.name,"version":component.version,
                "purl":component.purl,"properties":[{"name":"security-monitor:ecosystem","value":component.ecosystem}]})
        })
        .collect::<Vec<_>>();
    let components = unique_values(components);
    let vulnerabilities = snapshot
        .findings
        .iter()
        .filter_map(|finding| {
            let instance = instance_by_id.get(finding.component_instance_id.as_str())?;
            let component = component_by_id.get(instance.component_id.as_str())?;
            let advisory = advisory_by_id.get(finding.advisory_id.as_str());
            let mut vulnerability = json!({"id":finding.advisory_id,"source":{"name":"OSV"},
                "ratings":[{"severity":cyclonedx_severity(&finding.severity)}],
                "affects":[{"ref":component.purl,"versions":[{"version":component.version,"status":cyclonedx_version_status(&finding.status, snapshot.verification)}]}],
                "analysis":{"state":cyclonedx_analysis_state(&finding.status, snapshot.verification)},
                "properties":[{"name":"security-monitor:verification","value":verification_text(snapshot.verification)},
                    {"name":"security-monitor:finding-status","value":finding_status(&finding.status)}]});
            if let Some(title) = advisory.map(|item| item.title.as_str()).filter(|title| !title.is_empty()) {
                vulnerability["description"] = json!(title);
            }
            let references = advisory
                .into_iter()
                .flat_map(|item| item.source_urls.iter())
                .filter_map(|uri| safe_reference_uri(uri))
                .map(|uri| json!({"title":"Advisory reference","url":uri}))
                .collect::<Vec<_>>();
            if !references.is_empty() {
                vulnerability["advisories"] = json!(references);
            }
            Some(vulnerability)
        })
        .collect::<Vec<_>>();
    let vulnerabilities = unique_values(vulnerabilities);
    json!({"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":format!("urn:uuid:{}", deterministic_uuid(snapshot)),
        "version":1,"metadata":{"timestamp":snapshot.generated_at,"component":{"type":"application","bom-ref":"secmon-report",
            "name":snapshot.project.as_ref().map_or("Security Monitor workspace", |project| project.name.as_str()),"version":"0.1.0"},
            "properties":[{"name":"security-monitor:verification","value":verification_text(snapshot.verification)},
                {"name":"security-monitor:inventory-complete","value":snapshot.inventory_complete.to_string()}]},
        "components":components,"vulnerabilities":vulnerabilities})
}

fn openvex_report(snapshot: &ReportSnapshot) -> Value {
    let component_by_id = component_map(snapshot);
    let instance_by_id = instance_map(snapshot);
    let advisory_by_id = advisory_map(snapshot);
    let statements = snapshot
        .findings
        .iter()
        .filter_map(|finding| {
            let instance = instance_by_id.get(finding.component_instance_id.as_str())?;
            let component = component_by_id.get(instance.component_id.as_str())?;
            let advisory = advisory_by_id.get(finding.advisory_id.as_str());
            let status = openvex_status(finding, snapshot.verification);
            let mut statement = json!({"vulnerability":{"name":finding.advisory_id},
                "products":[{"@id":component.purl,"identifiers":{"purl":component.purl}}],
                "status":status,"timestamp":snapshot.generated_at,"last_updated":snapshot.generated_at,
                "status_notes":format!("Security Monitor finding status: {}; verification: {}.",
                    finding_status(&finding.status),verification_text(snapshot.verification))});
            if let Some(title) = advisory.map(|item| item.title.as_str()).filter(|title| !title.is_empty()) {
                statement["vulnerability"]["description"] = json!(title);
            }
            if let Some(justification) = openvex_justification(finding) {
                statement["justification"] = json!(justification);
            }
            if status == "affected" {
                statement["action_statement"] = json!("Review the advisory and apply a verified fixed version where available.");
            }
            if status == "not_affected" {
                statement["impact_statement"] = json!("A user-reviewed disposition records that the vulnerable code does not affect this product.");
            }
            Some(statement)
        })
        .collect::<Vec<_>>();
    let statements = unique_values(statements);
    json!({"@context":"https://openvex.dev/ns/v0.2.0","@id":format!("https://openvex.dev/docs/secmon/{}",deterministic_uuid(snapshot)),
        "author":"Security Monitor","role":"Document Creator","timestamp":snapshot.generated_at,"last_updated":snapshot.generated_at,"version":1,
        "tooling":concat!("Security Monitor ",env!("CARGO_PKG_VERSION")),"statements":statements})
}

fn component_map(snapshot: &ReportSnapshot) -> BTreeMap<&str, &Component> {
    snapshot
        .components
        .iter()
        .map(|component| (component.id.as_str(), component))
        .collect()
}

fn instance_map(snapshot: &ReportSnapshot) -> BTreeMap<&str, &ComponentInstance> {
    snapshot
        .instances
        .iter()
        .map(|instance| (instance.id.as_str(), instance))
        .collect()
}

fn advisory_map(snapshot: &ReportSnapshot) -> BTreeMap<&str, &Advisory> {
    snapshot
        .advisories
        .iter()
        .map(|advisory| (advisory.canonical_id.as_str(), advisory))
        .collect()
}

fn unique_values(values: Vec<Value>) -> Vec<Value> {
    let mut unique = BTreeMap::new();
    for value in values {
        unique.entry(value.to_string()).or_insert(value);
    }
    unique.into_values().collect()
}

fn safe_reference_uri(value: &str) -> Option<String> {
    let mut uri = Url::parse(value).ok()?;
    if uri.scheme() != "https"
        || uri.host_str().is_none()
        || !uri.username().is_empty()
        || uri.password().is_some()
    {
        return None;
    }
    uri.set_query(None);
    uri.set_fragment(None);
    Some(uri.to_string())
}

fn deterministic_uuid(snapshot: &ReportSnapshot) -> String {
    let input = format!(
        "{}:{}",
        snapshot
            .project
            .as_ref()
            .map_or("workspace", |project| project.id.as_str()),
        snapshot.generated_at
    );
    let mut digest = Sha256::digest(input.as_bytes());
    digest[6] = (digest[6] & 0x0f) | 0x50;
    digest[8] = (digest[8] & 0x3f) | 0x80;
    let hex = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Unknown => 0,
    }
}

fn is_closed(status: &FindingStatus) -> bool {
    matches!(
        status,
        FindingStatus::FixedInProduction
            | FindingStatus::AcceptedRisk
            | FindingStatus::FalsePositive
            | FindingStatus::NotReachable
    )
}

fn verification_text(state: VerificationState) -> &'static str {
    match state {
        VerificationState::Verified => "verified",
        VerificationState::NeedsReview => "needs_review",
    }
}

fn finding_status(status: &FindingStatus) -> &'static str {
    match status {
        FindingStatus::New => "new",
        FindingStatus::NeedsReview => "needs_review",
        FindingStatus::ConfirmedAffected => "confirmed_affected",
        FindingStatus::NotReachable => "not_reachable",
        FindingStatus::Mitigated => "mitigated",
        FindingStatus::FixProposed => "fix_proposed",
        FindingStatus::FixedInRepo => "fixed_in_repo",
        FindingStatus::FixedInProduction => "fixed_in_production",
        FindingStatus::AcceptedRisk => "accepted_risk",
        FindingStatus::FalsePositive => "false_positive",
    }
}

fn sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium | Severity::Unknown => "warning",
        Severity::Low => "note",
    }
}

fn cyclonedx_severity(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Unknown => "unknown",
    }
}

fn cyclonedx_version_status(
    status: &FindingStatus,
    verification: VerificationState,
) -> &'static str {
    match status {
        FindingStatus::FixedInProduction if verification == VerificationState::Verified => {
            "unaffected"
        }
        FindingStatus::FixedInProduction => "unknown",
        FindingStatus::FalsePositive | FindingStatus::NotReachable => "unknown",
        _ => "affected",
    }
}

fn cyclonedx_analysis_state(
    status: &FindingStatus,
    verification: VerificationState,
) -> &'static str {
    match status {
        FindingStatus::FixedInProduction if verification == VerificationState::Verified => {
            "resolved"
        }
        FindingStatus::FixedInProduction => "in_triage",
        FindingStatus::ConfirmedAffected | FindingStatus::AcceptedRisk => "exploitable",
        _ => "in_triage",
    }
}

fn openvex_status(finding: &Finding, verification: VerificationState) -> &'static str {
    match &finding.status {
        FindingStatus::FixedInProduction if verification == VerificationState::Verified => "fixed",
        FindingStatus::FixedInProduction => "under_investigation",
        FindingStatus::ConfirmedAffected | FindingStatus::AcceptedRisk => "affected",
        FindingStatus::NotReachable | FindingStatus::FalsePositive
            if openvex_justification(finding).is_some() =>
        {
            "not_affected"
        }
        _ => "under_investigation",
    }
}

fn openvex_justification(finding: &Finding) -> Option<&'static str> {
    match finding.disposition.as_ref()?.reason {
        FindingDispositionReason::NoAffectedCodePath
        | FindingDispositionReason::ConfigurationPreventsReachability => {
            Some("vulnerable_code_not_in_execute_path")
        }
        FindingDispositionReason::UnaffectedVersion => Some("vulnerable_code_not_present"),
        FindingDispositionReason::IncorrectPackage => Some("component_not_present"),
        FindingDispositionReason::CompensatingControl => Some("inline_mitigations_already_exist"),
        _ => None,
    }
}

fn relative_evidence_path(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let relative = normalized.strip_prefix("<project>/").unwrap_or(&normalized);
    if relative.is_empty()
        || relative.starts_with('/')
        || relative.contains(':')
        || relative
            .split('/')
            .any(|segment| segment == ".." || segment.is_empty())
    {
        return None;
    }
    Some(relative.to_owned())
}

#[cfg(test)]
mod tests {
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
        snapshot.evidence[0].file_path_redacted =
            Some("C:/private/workspace/package-lock.json".into());
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
}
