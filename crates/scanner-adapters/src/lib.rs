mod commands;
mod install;
mod normalize;
mod process;
mod runner;
mod types;
mod version;

pub use commands::{ScanMode, ScanRequest};
pub use install::ScannerAdapters;
pub use normalize::{normalize_osv_scanner, normalize_semgrep, normalize_trivy};
pub use types::{
    EngineDetection, EngineKind, EngineStatus, FindingKind, NormalizedFinding, NormalizedScan,
    NormalizedSeverity, PackageEvidence, ScanDiagnostic, ScanDiagnosticKind, ScanExecution,
    ScannerError,
};
pub use version::minimum_supported_version;

#[cfg(test)]
mod tests;
