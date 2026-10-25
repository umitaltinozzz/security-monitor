use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    io::{self, Read},
    path::{Component as PathComponent, Path, PathBuf},
    sync::Arc,
};

use cap_std::{ambient_authority, fs::Dir as CapabilityDir};
use security_monitor_ai::{
    AiTool, ToolCall, ToolError, ToolExecutor, ToolPermission, authorize_tool, is_sensitive_path,
    redact_text_with_host_aliases,
};
use security_monitor_core::{
    Advisory, AiProvider, AiProviderKind, ApprovalState, Asset, AuditEvent, AuditResult,
    AuditScope, Component, ComponentInstance, Finding, FindingEvidence, Memory, MemoryKind,
    MemoryScope, Project, ProjectServerLink, Remediation, is_source_code_like,
};
use security_monitor_database::Database;
use security_monitor_remediation::{
    McpRemediationAction, McpRemediationRequest, write_mcp_remediation_request,
};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

const MCP_VERSION: &str = "2025-11-25";
const MCP_DISCOVERY_VERSION: &str = "2026-07-28";
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_FILE_BYTES: u64 = 256 * 1024;
const MAX_SEARCH_FILES: usize = 1000;
const MAX_SEARCH_RESULTS: usize = 30;
const MAX_SEARCH_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum McpError {
    #[error("MCP database is unavailable")]
    Database(#[source] security_monitor_database::DatabaseError),
    #[error("MCP tool arguments are invalid")]
    InvalidArguments,
    #[error("MCP resource is unavailable or outside its approved project")]
    ResourceUnavailable,
    #[error("MCP request exceeds the configured size limit")]
    RequestTooLarge,
    #[error("MCP stdio transport failed")]
    Transport(#[source] io::Error),
    #[error("MCP tool permission was denied")]
    PermissionDenied,
}

mod memory;
mod protocol;
#[cfg(test)]
mod tests;
mod tools;

pub use protocol::{McpServer, supported_tools};
pub(crate) use protocol::{optional_string, required_string};
pub use tools::WorkspaceTools;
