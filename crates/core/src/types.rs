use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DomainValidationError {
    #[error("finding disposition is incomplete or inconsistent")]
    InvalidFindingDisposition,
    #[error("memory record is invalid")]
    InvalidMemory,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum AssetType {
    Server,
    Container,
    Runtime,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum Environment {
    Production,
    Staging,
    Development,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum FindingStatus {
    New,
    NeedsReview,
    ConfirmedAffected,
    NotReachable,
    Mitigated,
    FixProposed,
    FixedInRepo,
    FixedInProduction,
    AcceptedRisk,
    FalsePositive,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ScannerFindingStatus {
    #[default]
    NeedsReview,
    Confirmed,
    AcceptedRisk,
    FalsePositive,
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum RepoStatus {
    Unknown,
    StillAffected,
    FixedInRepo,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ProductionStatus {
    Unknown,
    StillAffected,
    FixedInProduction,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ScanOutcome {
    Queued,
    Running,
    Succeeded,
    Partial,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum AiProviderKind {
    AgentCli,
    OpenAiCompatible,
    Anthropic,
    Local,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum AgentCliProduct {
    ClaudeCode,
    Codex,
    #[serde(rename = "opencode")]
    #[ts(rename = "opencode")]
    OpenCode,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum AiTier {
    Triage,
    Analysis,
    Patch,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ApprovalState {
    Pending,
    Approved,
    Rejected,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum NotificationChannelKind {
    Desktop,
    Webhook,
    Slack,
    Discord,
    Ntfy,
    Smtp,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Project {
    pub id: String,
    pub name: String,
    // Absolute paths stay local and are excluded from provider requests.
    pub root_path: String,
    pub git_remote: Option<String>,
    pub reference_branch: Option<String>,
    pub allowed_ai_providers: Vec<String>,
    pub last_scan_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Asset {
    pub id: String,
    pub asset_type: AssetType,
    pub hostname_alias: String,
    pub environment: Environment,
    pub ssh_target_ref: Option<String>,
    pub host_key_fingerprint: Option<String>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub last_success_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub removed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Service {
    pub id: String,
    pub asset_id: String,
    pub service_name: String,
    pub runtime_binary: Option<String>,
    pub runtime_version: Option<String>,
    pub internet_facing: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Deployment {
    pub id: String,
    pub service_id: String,
    pub commit_sha: Option<String>,
    pub image_digest: Option<String>,
    pub release_id: Option<String>,
    pub id_source: String,
    pub observed_at: DateTime<Utc>,
}

/// A user-confirmed statement that a server runs deployments of a project. Production drift is
/// assessed only for confirmed links, so an unlinked server never changes a project's findings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProjectServerLink {
    pub id: String,
    pub project_id: String,
    pub asset_id: String,
    pub confirmed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Component {
    pub id: String,
    pub purl: String,
    pub ecosystem: String,
    pub name: String,
    pub version: Option<String>,
    pub source_type: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ComponentEvidence {
    pub evidence_type: String,
    pub file_path_redacted: Option<String>,
    pub reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ComponentInstance {
    pub id: String,
    pub component_id: String,
    pub project_id: Option<String>,
    pub asset_id: Option<String>,
    pub service_id: Option<String>,
    pub deployment_id: Option<String>,
    pub evidence: Vec<ComponentEvidence>,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// A product-matched public security news item. It is separate from vulnerability findings
/// until an advisory provider supplies an exact CVE or GHSA identifier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct NewsSignal {
    pub id: String,
    pub feed_id: String,
    pub external_id: String,
    pub title: String,
    pub summary: Option<String>,
    pub url: String,
    pub published_at: Option<DateTime<Utc>>,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub matched_projects: Vec<String>,
    pub matched_products: Vec<String>,
    pub advisory_id: Option<String>,
    pub archived_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RangeEvent {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
    pub last_affected: Option<String>,
    pub limit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AffectedRange {
    pub ecosystem: String,
    #[serde(default)]
    pub package: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub range_type: Option<String>,
    pub events: Vec<RangeEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AdvisorySource {
    pub name: String,
    pub url: String,
    pub license: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Advisory {
    pub canonical_id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub summary_model: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub source_attributions: Vec<AdvisorySource>,
    pub aliases: Vec<String>,
    pub affected_ranges: Vec<AffectedRange>,
    pub fixed_versions: Vec<String>,
    pub cvss: Option<f64>,
    pub severity: Option<Severity>,
    pub kev: bool,
    pub epss: Option<f64>,
    pub epss_date: Option<DateTime<Utc>>,
    pub source_urls: Vec<String>,
    pub source_updated_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Finding {
    pub id: String,
    pub advisory_id: String,
    pub component_instance_id: String,
    pub status: FindingStatus,
    pub severity: Severity,
    pub priority_score: u8,
    pub priority_reasons: Vec<String>,
    pub fingerprint: String,
    pub repo_status: RepoStatus,
    pub production_status: ProductionStatus,
    #[serde(default)]
    pub disposition: Option<FindingDisposition>,
    pub risk_expires_at: Option<DateTime<Utc>>,
    pub fix_version: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Finding {
    pub fn validate(&self) -> Result<(), DomainValidationError> {
        let requires_disposition = matches!(
            &self.status,
            FindingStatus::NotReachable
                | FindingStatus::AcceptedRisk
                | FindingStatus::FalsePositive
        );
        if requires_disposition != self.disposition.is_some() {
            return Err(DomainValidationError::InvalidFindingDisposition);
        }
        let Some(disposition) = &self.disposition else {
            return Ok(());
        };
        let expiry_required = matches!(
            &self.status,
            FindingStatus::AcceptedRisk | FindingStatus::FalsePositive
        );
        let reason_matches_status = matches!(
            (&self.status, &disposition.reason),
            (
                FindingStatus::AcceptedRisk,
                FindingDispositionReason::BusinessAccepted
                    | FindingDispositionReason::CompensatingControl
                    | FindingDispositionReason::TemporaryException
                    | FindingDispositionReason::FixPlanned,
            ) | (
                FindingStatus::FalsePositive,
                FindingDispositionReason::DuplicateFinding
                    | FindingDispositionReason::IncorrectPackage
                    | FindingDispositionReason::UnaffectedVersion
                    | FindingDispositionReason::NoAffectedCodePath
                    | FindingDispositionReason::OtherReviewed,
            ) | (
                FindingStatus::NotReachable,
                FindingDispositionReason::NoAffectedCodePath
                    | FindingDispositionReason::ConfigurationPreventsReachability
                    | FindingDispositionReason::OtherReviewed,
            )
        );
        if !reason_matches_status
            || disposition.scope_id.trim().is_empty()
            || !matches!(
                disposition.scope.as_str(),
                "finding" | "project" | "asset" | "deployment"
            )
            || (expiry_required && disposition.expires_at.is_none())
            || disposition
                .expires_at
                .is_some_and(|expiry| expiry <= disposition.set_at)
            || disposition.expires_at != self.risk_expires_at
        {
            return Err(DomainValidationError::InvalidFindingDisposition);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum FindingDispositionReason {
    BusinessAccepted,
    CompensatingControl,
    TemporaryException,
    FixPlanned,
    DuplicateFinding,
    IncorrectPackage,
    UnaffectedVersion,
    NoAffectedCodePath,
    ConfigurationPreventsReachability,
    OtherReviewed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FindingDisposition {
    pub reason: FindingDispositionReason,
    pub scope: String,
    pub scope_id: String,
    pub set_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FindingEvidence {
    pub id: String,
    pub finding_id: String,
    pub evidence_type: String,
    pub file_path_redacted: Option<String>,
    pub reference: Option<String>,
    pub confidence: Option<f64>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ScanRun {
    pub id: String,
    pub scope: AuditScope,
    pub scanner: String,
    pub scanner_version: Option<String>,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub outcome: ScanOutcome,
    pub error: Option<String>,
}

/// A normalized third-party scanner observation. It stays separate from advisory findings because
/// scanner results can describe code, secrets, or configuration without an advisory/component FK.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ScannerFinding {
    pub id: String,
    pub project_id: String,
    pub scan_run_id: String,
    pub scanner: String,
    pub mode: String,
    pub kind: String,
    pub rule_id: Option<String>,
    pub aliases: Vec<String>,
    pub package_name: Option<String>,
    pub package_ecosystem: Option<String>,
    pub package_version: Option<String>,
    pub severity: Severity,
    pub title: Option<String>,
    pub fixed_version: Option<String>,
    pub path: Option<String>,
    pub line_start: Option<u32>,
    pub line_end: Option<u32>,
    pub fingerprint: String,
    #[serde(default)]
    pub status: ScannerFindingStatus,
    #[serde(default)]
    pub review_reason: Option<String>,
    #[serde(default)]
    pub reviewed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

// This checkpoint detects dependency-input changes without retaining source code.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProjectScanCheckpoint {
    pub id: String,
    pub project_id: String,
    pub input_hash: Option<String>,
    // The serialized inventory contains component metadata only.
    pub inventory_json: String,
    pub inventory_complete: bool,
    pub checked_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RemediationTest {
    pub name: String,
    pub passed: bool,
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub output: Option<String>,
    #[serde(default)]
    pub output_truncated: bool,
    pub log_reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Remediation {
    pub id: String,
    pub finding_id: String,
    pub worktree_path: String,
    pub branch: String,
    #[serde(default)]
    pub provider_id: Option<String>,
    pub diff_hash: Option<String>,
    pub tests: Vec<RemediationTest>,
    pub approval_state: ApprovalState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProviderCapabilities {
    pub tool_calling: bool,
    pub context_window: Option<u64>,
    pub json_mode: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AiProvider {
    pub id: String,
    pub kind: AiProviderKind,
    #[serde(default)]
    pub cli_product: Option<AgentCliProduct>,
    pub display_name: String,
    pub base_url: Option<String>,
    pub model: Option<String>,
    pub capabilities: ProviderCapabilities,
    pub price_in: Option<f64>,
    pub price_out: Option<f64>,
    pub data_region: Option<String>,
    // Store only `secmon-keyring:v1:<lowercase UUID>`, never credential material.
    pub keychain_ref: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AiRun {
    pub id: String,
    pub provider_id: String,
    #[serde(default)]
    pub model: String,
    pub tier: AiTier,
    pub finding_id: Option<String>,
    #[ts(type = "number")]
    pub tokens_in: u64,
    #[ts(type = "number")]
    pub tokens_out: u64,
    pub cost: Option<f64>,
    pub files_sent: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub outcome: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AiDataTransferApproval {
    pub id: String,
    pub project_id: Option<String>,
    pub provider_id: String,
    pub destination_origin: String,
    pub data_category: String,
    pub tier: AiTier,
    pub content_sha256: String,
    pub approved_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct NotificationChannel {
    pub id: String,
    pub kind: NotificationChannelKind,
    // Store only `secmon-keyring:v1:<lowercase UUID>`, never a URL or password.
    pub config_ref: Option<String>,
    pub min_priority: u8,
    pub enabled: bool,
    // This timestamp records the user's explicit approval for external summaries.
    #[serde(default)]
    pub network_approved_at: Option<DateTime<Utc>>,
    // Store only the approved authority; complete destinations and passwords stay in the keyring.
    #[serde(default)]
    pub network_approved_destination: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct NotificationDeliveryState {
    pub id: String,
    pub channel_id: String,
    pub event_fingerprint: String,
    pub last_delivered_at: Option<DateTime<Utc>>,
    pub snoozed_until: Option<DateTime<Utc>>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AuditScope {
    pub resource_type: String,
    pub resource_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum AuditResult {
    Succeeded,
    Denied,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub scope: AuditScope,
    pub result: AuditResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum MemoryScope {
    Global,
    Project,
    Server,
    Finding,
}

impl MemoryScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Project => "project",
            Self::Server => "server",
            Self::Finding => "finding",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum MemoryKind {
    FindingNote,
    UserDecision,
    ProjectContext,
    FailedFix,
    AgentSummary,
}

/// Local, untrusted context shared between the user and coding agents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Memory {
    pub id: String,
    pub scope: MemoryScope,
    pub scope_id: Option<String>,
    pub kind: MemoryKind,
    pub content: String,
    pub author: String,
    pub source_run_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub pinned: bool,
    pub verified_at: Option<DateTime<Utc>>,
    pub verified_by: Option<String>,
}

impl Memory {
    pub fn validate(&self) -> Result<(), DomainValidationError> {
        let global_without_id = self.scope == MemoryScope::Global && self.scope_id.is_none();
        let scoped_with_id = matches!(
            self.scope,
            MemoryScope::Project | MemoryScope::Server | MemoryScope::Finding
        ) && self
            .scope_id
            .as_deref()
            .is_some_and(|id| !id.trim().is_empty());
        if !(global_without_id || scoped_with_id)
            || self.author.trim().is_empty()
            || self.author.len() > 96
            || (self.author.starts_with("agent:") && self.kind == MemoryKind::UserDecision)
            || is_source_code_like(&self.content)
            || self.verified_at.is_some() != (self.verified_by.as_deref() == Some("user"))
        {
            return Err(DomainValidationError::InvalidMemory);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct MemoryArchiveEntry {
    pub scope: MemoryScope,
    pub scope_id: Option<String>,
    pub kind: MemoryKind,
    pub content: String,
    pub pinned: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct MemoryArchive {
    pub version: u32,
    pub exported_at: DateTime<Utc>,
    pub memories: Vec<MemoryArchiveEntry>,
}

/// Conservatively rejects code-shaped text from persistent shared notes.
pub fn is_source_code_like(content: &str) -> bool {
    let normalized = content.trim();
    if normalized.is_empty()
        || normalized.contains("-----BEGIN ")
        || normalized.contains("-----END ")
    {
        return true;
    }

    let lower = normalized.to_ascii_lowercase();
    let code_markers = [
        "fn ",
        "pub fn ",
        "async fn ",
        "function ",
        "class ",
        "def ",
        "#include",
        "package main",
        "console.log(",
        "std::",
        "=> {",
        "#!/",
        "<?php",
        "<script",
        "select * from ",
    ];
    if code_markers.iter().any(|marker| lower.contains(marker)) {
        return true;
    }

    let lines = normalized
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.iter().any(|line| {
        let line = line.to_ascii_lowercase();
        line.starts_with("import ") || (line.starts_with("from ") && line.contains(" import "))
    }) {
        return true;
    }
    if lines.len() < 2 {
        return normalized.ends_with(';')
            || normalized.starts_with('{')
            || normalized.starts_with("let ")
            || normalized.starts_with("const ");
    }

    let code_shaped = lines
        .iter()
        .filter(|line| {
            line.ends_with(';')
                || line.ends_with('{')
                || **line == "}"
                || line.contains(" = ")
                || line.contains("->")
                || line.contains("=>")
        })
        .count();
    code_shaped * 3 >= lines.len() * 2
}

#[cfg(test)]
mod memory_tests {
    use super::*;

    #[test]
    fn source_code_notes_are_rejected_but_security_prose_is_allowed() {
        for content in [
            "fn main() { println!(\"secret\"); }",
            "const token = \"abc\";",
            "let user = await load_user();",
            "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
            "server {\n  listen 443;\n  proxy_pass http://upstream;\n}",
        ] {
            assert!(is_source_code_like(content), "{content}");
        }
        for content in [
            "This finding is reachable only from the administrative code path.",
            "The owner confirmed the service is not exposed to the public internet.",
        ] {
            assert!(!is_source_code_like(content), "{content}");
        }
    }

    #[test]
    fn memory_rules_live_on_the_domain_record() {
        let mut memory = Memory {
            id: "memory-1".to_owned(),
            scope: MemoryScope::Global,
            scope_id: None,
            kind: MemoryKind::AgentSummary,
            content: "The service is internal-only.".to_owned(),
            author: "agent:reviewer".to_owned(),
            source_run_id: None,
            created_at: Utc::now(),
            expires_at: None,
            pinned: false,
            verified_at: None,
            verified_by: None,
        };
        assert!(memory.validate().is_ok());

        memory.kind = MemoryKind::UserDecision;
        assert_eq!(memory.validate(), Err(DomainValidationError::InvalidMemory));
    }

    #[test]
    fn finding_disposition_rules_live_on_the_domain_record() {
        let now = Utc::now();
        let mut finding = Finding {
            id: "finding-1".to_owned(),
            advisory_id: "CVE-2026-1".to_owned(),
            component_instance_id: "instance-1".to_owned(),
            status: FindingStatus::AcceptedRisk,
            severity: Severity::High,
            priority_score: 50,
            priority_reasons: Vec::new(),
            fingerprint: "fingerprint".to_owned(),
            repo_status: RepoStatus::Unknown,
            production_status: ProductionStatus::Unknown,
            disposition: Some(FindingDisposition {
                reason: FindingDispositionReason::TemporaryException,
                scope: "finding".to_owned(),
                scope_id: "finding-1".to_owned(),
                set_at: now,
                expires_at: Some(now + chrono::Duration::days(7)),
            }),
            risk_expires_at: Some(now + chrono::Duration::days(7)),
            fix_version: None,
            created_at: now,
            updated_at: now,
        };
        assert!(finding.validate().is_ok());

        finding.risk_expires_at = None;
        assert_eq!(
            finding.validate(),
            Err(DomainValidationError::InvalidFindingDisposition)
        );
    }
}
