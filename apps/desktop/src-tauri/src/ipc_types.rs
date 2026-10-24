use chrono::{DateTime, Utc};
use security_monitor_core::{
    Asset, Environment, FindingDispositionReason, FindingStatus, ScanOutcome,
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
    pub notifications_enabled: bool,
    pub scan_interval_hours: u16,
    pub ecosystems: Vec<String>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            language: UiLanguage::En,
            theme: ThemePreference::System,
            onboarding_completed: false,
            public_downloads_enabled: false,
            notifications_enabled: true,
            scan_interval_hours: 24,
            ecosystems: vec!["npm".to_owned(), "pypi".to_owned(), "cargo".to_owned()],
        }
    }
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
pub struct CollectionSummary {
    pub asset_id: String,
    pub complete: bool,
    pub package_count: usize,
    pub service_count: usize,
    pub container_count: usize,
    pub deployment_count: usize,
    pub approved_at: DateTime<Utc>,
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
