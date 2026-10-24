use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    pub components: Vec<InventoryComponent>,
    pub project_roots: Vec<String>,
    pub detected_files: Vec<DetectedFile>,
    pub diagnostics: Vec<Diagnostic>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryComponent {
    pub purl: String,
    pub ecosystem: String,
    pub name: String,
    pub version: Option<String>,
    pub source_type: String,
    pub evidence_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedFile {
    pub path: String,
    pub kind: DetectedFileKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectedFileKind {
    Dockerfile,
    GithubWorkflow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub path: String,
    pub kind: DiagnosticKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticKind {
    UnreadableDirectory,
    UnreadableFile,
    InvalidPath,
    SymlinkOutsideRoot,
    MalformedLockfile,
    UnsupportedRequirement,
    InvalidPackageIdentifier,
}
