use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum NotificationChannelKind {
    Desktop,
    Webhook,
    Slack,
    Discord,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Component {
    pub id: String,
    pub purl: String,
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub source_type: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
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
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RangeEvent {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
    pub last_affected: Option<String>,
    pub limit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AffectedRange {
    pub ecosystem: String,
    pub events: Vec<RangeEvent>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Advisory {
    pub canonical_id: String,
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
    pub risk_expires_at: Option<DateTime<Utc>>,
    pub fix_version: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RemediationTest {
    pub name: String,
    pub passed: bool,
    pub exit_code: Option<i32>,
    pub log_reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Remediation {
    pub id: String,
    pub finding_id: String,
    pub worktree_path: String,
    pub branch: String,
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
    pub display_name: String,
    pub base_url: Option<String>,
    pub model: Option<String>,
    pub capabilities: ProviderCapabilities,
    pub price_in: Option<f64>,
    pub price_out: Option<f64>,
    pub data_region: Option<String>,
    // Store only an OS credential-store reference, never the credential itself.
    pub keychain_ref: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AiRun {
    pub id: String,
    pub provider_id: String,
    pub tier: AiTier,
    pub finding_id: Option<String>,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub cost: Option<f64>,
    pub files_sent: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub outcome: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct NotificationChannel {
    pub id: String,
    pub kind: NotificationChannelKind,
    // Store only an OS credential-store reference, never a webhook URL or password.
    pub config_ref: Option<String>,
    pub min_priority: u8,
    pub enabled: bool,
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
