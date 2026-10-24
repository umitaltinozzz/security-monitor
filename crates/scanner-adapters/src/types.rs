use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EngineKind {
    OsvScanner,
    Trivy,
    Semgrep,
}

impl EngineKind {
    pub fn executable_name(self) -> &'static str {
        match (self, std::env::consts::OS) {
            (Self::OsvScanner, "windows") => "osv-scanner.exe",
            (Self::Trivy, "windows") => "trivy.exe",
            (Self::Semgrep, "windows") => "semgrep.exe",
            (Self::OsvScanner, _) => "osv-scanner",
            (Self::Trivy, _) => "trivy",
            (Self::Semgrep, _) => "semgrep",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::OsvScanner => "osv-scanner",
            Self::Trivy => "trivy",
            Self::Semgrep => "semgrep",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineStatus {
    Available,
    Missing,
    Outdated,
    UnsupportedPlatform,
    Unverified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineDetection {
    pub engine: EngineKind,
    pub status: EngineStatus,
    pub version: Option<String>,
    pub executable: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalizedSeverity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Vulnerability,
    Secret,
    Misconfiguration,
    Code,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageEvidence {
    pub name: String,
    pub ecosystem: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedFinding {
    pub kind: FindingKind,
    pub rule_id: Option<String>,
    pub aliases: Vec<String>,
    pub package: Option<PackageEvidence>,
    pub severity: NormalizedSeverity,
    pub title: Option<String>,
    pub fixed_version: Option<String>,
    pub path: Option<String>,
    pub line_start: Option<u32>,
    pub line_end: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanDiagnosticKind {
    MalformedRecord,
    PathOutsideProject,
    ScannerReportedError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanDiagnostic {
    pub kind: ScanDiagnosticKind,
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedScan {
    pub engine: EngineKind,
    pub complete: bool,
    pub findings: Vec<NormalizedFinding>,
    pub diagnostics: Vec<ScanDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanExecution {
    pub detection: EngineDetection,
    pub result: Option<NormalizedScan>,
}

#[derive(Debug, Error)]
pub enum ScannerError {
    #[error("scanner output is invalid")]
    InvalidOutput,
    #[error("scanner configuration is invalid")]
    InvalidConfiguration,
    #[error("scanner invocation failed")]
    Invocation,
    #[error("scanner output exceeded its size limit")]
    OutputTooLarge,
    #[error("scanner download requires explicit user approval")]
    DownloadNotApproved,
    #[error("scanner download is disabled by privacy settings")]
    DownloadDisabled,
    #[error("scanner is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("scanner download failed")]
    Download,
    #[error("scanner download checksum did not match the pinned value")]
    ChecksumMismatch,
    #[error("scanner installation destination is unsafe")]
    UnsafePath,
    #[error("scanner installation destination already contains different data")]
    DestinationOccupied,
    #[error("scanner installation archive is invalid")]
    InvalidArchive,
    #[error("scanner installation file operation failed")]
    Io(#[source] std::io::Error),
    #[error("scanner version configuration is invalid")]
    VersionConfiguration,
    #[error("scanner process returned an unsuccessful result")]
    ProcessFailed,
    #[error("scanner process exceeded its time limit")]
    ProcessTimedOut,
    #[error("scanner version could not be verified")]
    VersionUnverified,
    #[error("scanner target is invalid")]
    InvalidTarget,
    #[error("scanner configuration in the repository requires explicit user approval")]
    RepositoryConfigurationRequiresApproval,
}
