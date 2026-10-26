use chrono::{DateTime, Utc};
use security_monitor_ai::AiSettings;
use security_monitor_core::{
    AgentCliProduct, AiProviderKind, AiTier, Asset, Environment, Finding, FindingDispositionReason,
    FindingStatus, NotificationChannelKind, ProviderCapabilities, ScanOutcome,
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum UiLanguage {
    En,
    Tr,
}

impl UiLanguage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Tr => "tr",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ThemePreference {
    System,
    Light,
    Dark,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
#[ts(export)]
pub struct AppSettings {
    pub language: UiLanguage,
    pub theme: ThemePreference,
    pub onboarding_completed: bool,
    pub public_downloads_enabled: bool,
    pub scan_interval_hours: u16,
    pub ecosystems: Vec<String>,
    #[serde(default = "default_true")]
    pub desktop_notifications_enabled: bool,
    #[serde(default)]
    pub outbound_notifications_enabled: bool,
    #[serde(default)]
    pub daily_summary_enabled: bool,
}

fn default_true() -> bool {
    true
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            language: UiLanguage::En,
            theme: ThemePreference::System,
            onboarding_completed: false,
            public_downloads_enabled: false,
            scan_interval_hours: 24,
            ecosystems: vec!["npm".to_owned(), "pypi".to_owned(), "cargo".to_owned()],
            desktop_notifications_enabled: true,
            outbound_notifications_enabled: false,
            daily_summary_enabled: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[ts(export)]
pub enum NotificationChannelSecretInput {
    Webhook {
        url: String,
    },
    Slack {
        url: String,
    },
    Discord {
        url: String,
    },
    Ntfy {
        url: String,
        token: Option<String>,
    },
    Smtp {
        host: String,
        port: u16,
        tls: NotificationSmtpTlsMode,
        username: Option<String>,
        password: Option<String>,
        from: String,
        to: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum NotificationSmtpTlsMode {
    ImplicitTls,
    StartTls,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SaveNotificationChannelInput {
    pub id: Option<String>,
    pub config: NotificationChannelSecretInput,
    pub enabled: bool,
    pub min_priority: u8,
    pub outbound_approved: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct UpdateNotificationChannelInput {
    pub id: String,
    pub enabled: bool,
    pub min_priority: u8,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct NotificationChannelView {
    pub id: String,
    pub kind: NotificationChannelKind,
    pub enabled: bool,
    pub min_priority: u8,
    pub approved_destination: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct NotificationPreview {
    pub title: String,
    pub message: String,
    pub destination: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ScanResult {
    pub scan_id: String,
    pub outcome: ScanOutcome,
    pub inventory_complete: bool,
    pub component_count: usize,
    pub finding_count: usize,
    pub scanner_finding_count: usize,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FindingPageView {
    pub findings: Vec<Finding>,
    #[ts(type = "number")]
    pub total_count: u64,
    pub offset: u32,
    pub limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProjectCandidateView {
    pub name: String,
    pub root_path: String,
    pub component_count: usize,
    pub inventory_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProjectDiscoveryView {
    pub candidates: Vec<ProjectCandidateView>,
    pub diagnostics: usize,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ScannerAvailability {
    pub engine: String,
    pub status: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SshTargetInput {
    pub alias: String,
    pub hostname: String,
    pub username: String,
    pub port: u16,
    pub environment: Environment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SshHostSummary {
    pub alias: String,
    pub hostname: String,
    pub username: String,
    pub port: u16,
    pub has_proxy_jump: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PairingInstructionsView {
    pub asset: Asset,
    pub fingerprint: String,
    pub authorized_keys_line: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct UnpairServerResult {
    pub history_deleted: bool,
    pub credential_cleanup_warning: bool,
    pub snapshot_cleanup_warning: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CollectionSummary {
    pub asset_id: String,
    pub complete: bool,
    pub package_count: usize,
    pub service_count: usize,
    pub container_count: usize,
    pub deployment_count: usize,
    pub running_kernel_release: Option<String>,
    pub installed_kernel_release: Option<String>,
    pub kernel_restart_required: Option<bool>,
    pub services_needing_restart: Vec<String>,
    pub deleted_shared_library_count: usize,
    pub maps_unverified_process_count: usize,
    pub os_package_evaluation_status: OsPackageEvaluationStatus,
    pub os_package_findings: Vec<ServerOsPackageFinding>,
    pub approved_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum OsPackageEvaluationStatus {
    Evaluated,
    Unverified,
    UnverifiedScope,
    NoDataSource,
    NotEvaluated,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ServerOsPackageFinding {
    pub advisory_id: String,
    pub package_name: String,
    pub installed_version: String,
    pub severity: security_monitor_core::Severity,
    pub status: FindingStatus,
    pub fix_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FindingStatusChange {
    pub finding_id: String,
    pub status: FindingStatus,
    pub reason: FindingDispositionReason,
    pub scope: String,
    pub scope_id: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AiProviderInput {
    pub id: Option<String>,
    pub kind: AiProviderKind,
    pub cli_product: Option<AgentCliProduct>,
    pub display_name: String,
    pub base_url: Option<String>,
    pub model: Option<String>,
    pub capabilities: ProviderCapabilities,
    pub price_in: Option<f64>,
    pub price_out: Option<f64>,
    pub data_region: Option<String>,
    // Keep this transient: the key is consumed into the OS credential store only.
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RemediationSandboxStatus {
    pub available: bool,
    pub engine: Option<security_monitor_remediation::SandboxEngine>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SafeTestInput {
    pub executable: String,
    pub args: Vec<String>,
    pub image: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AiRequestEstimate {
    pub project_id: String,
    pub approval_digest: String,
    pub provider_id: String,
    pub provider_name: String,
    pub model: String,
    pub destination_origin: String,
    pub data_region: Option<String>,
    pub tier: AiTier,
    pub data_category: String,
    pub enabled_tools: Vec<String>,
    pub redacted_values: usize,
    pub redacted_prompt: String,
    #[ts(type = "number")]
    pub estimated_input_tokens: u64,
    #[ts(type = "number")]
    pub estimated_output_tokens: u64,
    pub estimated_cost_usd: f64,
    pub budget: security_monitor_ai::BudgetDecision,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AiRunResult {
    pub run_id: String,
    pub response: String,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub cost_usd: f64,
    pub files_sent: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AiConfigurationView {
    pub settings: AiSettings,
    pub providers: Vec<security_monitor_core::AiProvider>,
    pub runs: Vec<security_monitor_core::AiRun>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct UpdateCheckResult {
    pub available: bool,
    pub version: Option<String>,
    pub notes: Option<String>,
}
