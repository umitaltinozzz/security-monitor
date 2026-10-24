use std::{
    collections::{BTreeMap, HashSet},
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
    Advisory, Asset, Component, ComponentInstance, Finding, FindingEvidence, Project,
};
use security_monitor_database::Database;
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

pub struct WorkspaceTools {
    database: Database,
    source_access_project: Option<String>,
    host_aliases: BTreeMap<String, String>,
}

impl WorkspaceTools {
    pub fn new(database: Database, source_access_project: Option<String>) -> Self {
        Self {
            database,
            source_access_project,
            host_aliases: BTreeMap::new(),
        }
    }

    pub fn with_host_aliases(
        mut self,
        aliases: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        self.host_aliases = aliases
            .into_iter()
            .map(|(hostname, alias)| (hostname.to_ascii_lowercase(), alias))
            .collect();
        self
    }

    async fn call(&self, name: &str, arguments: &Value) -> Result<Value, McpError> {
        match name {
            "list_projects" => {
                let projects = self
                    .database
                    .repository::<Project>()
                    .list()
                    .await
                    .map_err(McpError::Database)?;
                Ok(json!(
                    projects
                        .into_iter()
                        .map(|project| json!({"id":project.id,"name":project.name,
                    "last_scan_at":project.last_scan_at}))
                        .collect::<Vec<_>>()
                ))
            }
            "list_assets" => {
                let assets = self
                    .database
                    .repository::<Asset>()
                    .list()
                    .await
                    .map_err(McpError::Database)?;
                Ok(json!(assets.into_iter().map(|asset| json!({"id":asset.id,"alias":asset.hostname_alias,
                    "environment":asset.environment,"last_success_at":asset.last_success_at,
                    "verification":if asset.last_success_at.is_some() {"observed"} else {"needs_review"}})).collect::<Vec<_>>()))
            }
            "list_findings" => self.list_findings(arguments).await,
            "get_finding_evidence" => self.get_finding_evidence(arguments).await,
            "compare_repo_deployment" => self.compare_repo_deployment(arguments).await,
            "read_project_file" => self.read_project_file(arguments).await,
            "search_project" => self.search_project(arguments).await,
            "analyze_impact" => self.analyze_impact(arguments).await,
            _ => Err(McpError::ResourceUnavailable),
        }
    }

    async fn project(&self, id: &str) -> Result<Project, McpError> {
        self.database
            .repository::<Project>()
            .get(id)
            .await
            .map_err(McpError::Database)?
            .ok_or(McpError::ResourceUnavailable)
    }

    async fn list_findings(&self, arguments: &Value) -> Result<Value, McpError> {
        let project_id = optional_string(arguments, "project_id")?;
        let findings = self
            .database
            .repository::<Finding>()
            .list()
            .await
            .map_err(McpError::Database)?;
        let instances = self
            .database
            .repository::<ComponentInstance>()
            .list()
            .await
            .map_err(McpError::Database)?;
        let components = self
            .database
            .repository::<Component>()
            .list()
            .await
            .map_err(McpError::Database)?;
        let advisories = self
            .database
            .repository::<Advisory>()
            .list()
            .await
            .map_err(McpError::Database)?;
        let instance_by_id: BTreeMap<_, _> = instances
            .into_iter()
            .map(|item| (item.id.clone(), item))
            .collect();
        let component_by_id: BTreeMap<_, _> = components
            .into_iter()
            .map(|item| (item.id.clone(), item))
            .collect();
        let advisory_by_id: BTreeMap<_, _> = advisories
            .into_iter()
            .map(|item| (item.canonical_id.clone(), item))
            .collect();
        let output = findings.into_iter().filter_map(|finding| {
            let instance = instance_by_id.get(&finding.component_instance_id)?;
            if project_id.as_deref().is_some_and(|id| instance.project_id.as_deref() != Some(id)) { return None; }
            let component = component_by_id.get(&instance.component_id)?;
            let advisory = advisory_by_id.get(&finding.advisory_id)?;
            Some(json!({"id":finding.id,"advisory_id":advisory.canonical_id,"title":advisory.title,
                "component":component.name,"version":component.version,"purl":component.purl,
                "status":finding.status,"severity":finding.severity,"priority_score":finding.priority_score,
                "priority_reasons":finding.priority_reasons,"repo_status":finding.repo_status,
                "production_status":finding.production_status}))
        }).collect::<Vec<_>>();
        Ok(json!(output))
    }

    async fn get_finding_evidence(&self, arguments: &Value) -> Result<Value, McpError> {
        let finding_id = required_string(arguments, "finding_id")?;
        let evidence = self
            .database
            .repository::<FindingEvidence>()
            .list()
            .await
            .map_err(McpError::Database)?;
        Ok(json!(
            evidence
                .into_iter()
                .filter(|item| item.finding_id == finding_id)
                .map(
                    |item| json!({"evidence_type":item.evidence_type,"path":item.file_path_redacted,
                "reference":item.reference,"confidence":item.confidence})
                )
                .collect::<Vec<_>>()
        ))
    }

    async fn compare_repo_deployment(&self, arguments: &Value) -> Result<Value, McpError> {
        let finding_id = required_string(arguments, "finding_id")?;
        let finding = self
            .database
            .repository::<Finding>()
            .get(finding_id)
            .await
            .map_err(McpError::Database)?
            .ok_or(McpError::ResourceUnavailable)?;
        Ok(
            json!({"finding_id":finding.id,"repo_status":finding.repo_status,
            "production_status":finding.production_status,
            "verification":if format!("{:?}",finding.repo_status) == "Unknown" || format!("{:?}",finding.production_status) == "Unknown" {"needs_review"} else {"observed"}}),
        )
    }

    async fn analyze_impact(&self, arguments: &Value) -> Result<Value, McpError> {
        let finding_id = required_string(arguments, "finding_id")?;
        let finding = self
            .database
            .repository::<Finding>()
            .get(finding_id)
            .await
            .map_err(McpError::Database)?
            .ok_or(McpError::ResourceUnavailable)?;
        let instance = self
            .database
            .repository::<ComponentInstance>()
            .get(&finding.component_instance_id)
            .await
            .map_err(McpError::Database)?
            .ok_or(McpError::ResourceUnavailable)?;
        let component = self
            .database
            .repository::<Component>()
            .get(&instance.component_id)
            .await
            .map_err(McpError::Database)?
            .ok_or(McpError::ResourceUnavailable)?;
        let advisory = self
            .database
            .repository::<Advisory>()
            .get(&finding.advisory_id)
            .await
            .map_err(McpError::Database)?
            .ok_or(McpError::ResourceUnavailable)?;
        let evidence = self
            .database
            .repository::<FindingEvidence>()
            .list()
            .await
            .map_err(McpError::Database)?
            .into_iter()
            .filter(|item| item.finding_id == finding.id)
            .collect::<Vec<_>>();
        Ok(
            json!({"finding_id":finding.id,"advisory":{"id":advisory.canonical_id,"title":advisory.title,
                "description":advisory.description,"affected_ranges":advisory.affected_ranges},
            "component":{"name":component.name,"version":component.version,"purl":component.purl},
            "status":finding.status,"repo_status":finding.repo_status,"production_status":finding.production_status,
            "evidence":evidence.into_iter().map(|item| json!({"type":item.evidence_type,"path":item.file_path_redacted,
                "reference":item.reference,"confidence":item.confidence})).collect::<Vec<_>>(),
            "priority_score_is_read_only":true}),
        )
    }

    async fn read_project_file(&self, arguments: &Value) -> Result<Value, McpError> {
        let project = self
            .project(required_string(arguments, "project_id")?)
            .await?;
        self.require_source_project(&project.id)?;
        let relative = safe_relative_path(required_string(arguments, "path")?)?;
        let root = CapabilityDir::open_ambient_dir(&project.root_path, ambient_authority())
            .map_err(|_| McpError::ResourceUnavailable)?;
        let resolved = root
            .canonicalize(&relative)
            .map_err(|_| McpError::ResourceUnavailable)?;
        if is_sensitive_path(&resolved.to_string_lossy()) {
            return Err(McpError::ResourceUnavailable);
        }
        let file = root
            .open(&resolved)
            .map_err(|_| McpError::ResourceUnavailable)?;
        if !file
            .metadata()
            .map_err(|_| McpError::ResourceUnavailable)?
            .is_file()
        {
            return Err(McpError::ResourceUnavailable);
        }
        let mut contents = String::new();
        file.take(MAX_FILE_BYTES + 1)
            .read_to_string(&mut contents)
            .map_err(|_| McpError::ResourceUnavailable)?;
        if contents.len() as u64 > MAX_FILE_BYTES {
            return Err(McpError::ResourceUnavailable);
        }
        let redacted = redact_text_with_host_aliases(&contents, &self.host_aliases);
        Ok(
            json!({"path":format!("<project>/{}",resolved.to_string_lossy().replace('\\',"/")),
            "contents":redacted.text,"redacted_values":redacted.redacted_values,"untrusted_data":true}),
        )
    }

    async fn search_project(&self, arguments: &Value) -> Result<Value, McpError> {
        let project = self
            .project(required_string(arguments, "project_id")?)
            .await?;
        self.require_source_project(&project.id)?;
        let query = required_string(arguments, "query")?.to_ascii_lowercase();
        if query.is_empty() || query.len() > 256 {
            return Err(McpError::InvalidArguments);
        }
        let root = CapabilityDir::open_ambient_dir(&project.root_path, ambient_authority())
            .map_err(|_| McpError::ResourceUnavailable)?;
        let mut pending = vec![(root, PathBuf::new())];
        let mut files_seen = 0_usize;
        let mut bytes_seen = 0_u64;
        let mut results = Vec::new();
        'walk: while let Some((directory, relative_directory)) = pending.pop() {
            let entries = match directory.entries() {
                Ok(entries) => entries,
                Err(_) => continue,
            };
            for entry in entries {
                let Ok(entry) = entry else { continue };
                let name = entry.file_name();
                let Some(name_text) = name.to_str() else {
                    continue;
                };
                if name_text.starts_with('.') {
                    continue;
                }
                let relative = relative_directory.join(&name);
                let relative_text = relative.to_string_lossy().replace('\\', "/");
                if is_sensitive_path(&relative_text) {
                    continue;
                }
                let file_type = match entry.file_type() {
                    Ok(file_type) => file_type,
                    Err(_) => continue,
                };
                if file_type.is_symlink() {
                    continue;
                }
                if file_type.is_dir() {
                    if !matches!(
                        name_text,
                        "node_modules" | "target" | "vendor" | "dist" | "build"
                    ) && let Ok(child) = entry.open_dir()
                    {
                        pending.push((child, relative));
                    }
                    continue;
                }
                if !file_type.is_file() {
                    continue;
                }
                files_seen += 1;
                if files_seen > MAX_SEARCH_FILES || results.len() >= MAX_SEARCH_RESULTS {
                    break 'walk;
                }
                let Ok(mut file) = entry.open() else { continue };
                let Ok(metadata) = file.metadata() else {
                    continue;
                };
                if metadata.len() > 512 * 1024 {
                    continue;
                }
                bytes_seen = bytes_seen.saturating_add(metadata.len());
                if bytes_seen > MAX_SEARCH_BYTES {
                    break 'walk;
                }
                let mut contents = String::new();
                if file
                    .by_ref()
                    .take(512 * 1024 + 1)
                    .read_to_string(&mut contents)
                    .is_err()
                {
                    continue;
                }
                let redacted_contents =
                    redact_text_with_host_aliases(&contents, &self.host_aliases).text;
                for (line_index, line) in redacted_contents.lines().enumerate() {
                    if line.to_ascii_lowercase().contains(&query) {
                        results.push(json!({"path":format!("<project>/{relative_text}"),"line":line_index + 1,
                            "snippet":line,"untrusted_data":true}));
                        if results.len() >= MAX_SEARCH_RESULTS {
                            break 'walk;
                        }
                    }
                }
            }
        }
        Ok(
            json!({"results":results,"files_examined":files_seen,"truncated":files_seen >= MAX_SEARCH_FILES || results.len() >= MAX_SEARCH_RESULTS || bytes_seen > MAX_SEARCH_BYTES}),
        )
    }

    fn require_source_project(&self, project_id: &str) -> Result<(), McpError> {
        self.source_access_project
            .as_deref()
            .filter(|allowed| *allowed == project_id)
            .map(|_| ())
            .ok_or(McpError::PermissionDenied)
    }
}

#[async_trait::async_trait]
impl ToolExecutor for WorkspaceTools {
    async fn execute(&self, call: &ToolCall) -> Result<Value, ToolError> {
        self.call(&call.name, &call.arguments)
            .await
            .map_err(|_| ToolError::InvalidArguments)
    }
}

#[derive(Clone)]
pub struct McpServer {
    tools: Arc<Vec<AiTool>>,
    enabled_tool_names: Arc<Vec<String>>,
    approved_permissions: Arc<Vec<ToolPermission>>,
    executor: Arc<dyn ToolExecutor>,
}

impl McpServer {
    pub fn new(executor: Arc<dyn ToolExecutor>, enabled_tool_names: Vec<String>) -> Self {
        let known: HashSet<_> = mcp_supported_tools()
            .into_iter()
            .map(|tool| tool.name.clone())
            .collect();
        let enabled_tool_names = enabled_tool_names
            .into_iter()
            .filter(|name| known.contains(name))
            .collect::<Vec<_>>();
        let approved_permissions = if enabled_tool_names
            .iter()
            .any(|name| matches!(name.as_str(), "analyze_impact"))
        {
            vec![ToolPermission::AiApproval]
        } else {
            vec![]
        };
        Self {
            tools: Arc::new(mcp_supported_tools()),
            enabled_tool_names: Arc::new(enabled_tool_names),
            approved_permissions: Arc::new(approved_permissions),
            executor,
        }
    }

    pub async fn process(&self, request: &Value) -> Option<Value> {
        let id = request.get("id").cloned();
        let Some(method) = request.get("method").and_then(Value::as_str) else {
            return id.map(|id| rpc_error(id, -32600, "Invalid request"));
        };
        let id = id?;
        let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
        let result = match method {
            "initialize" => {
                let requested = params.get("protocolVersion").and_then(Value::as_str);
                let version = match requested {
                    Some("2025-11-25" | "2024-11-05") => requested.unwrap_or(MCP_VERSION),
                    _ => MCP_VERSION,
                };
                Ok(
                    json!({"protocolVersion":version,"capabilities":{"tools":{"listChanged":false}},
                    "serverInfo":{"name":"security-monitor","version":env!("CARGO_PKG_VERSION")}}),
                )
            }
            "server/discover" => Ok(json!({"protocolVersion":MCP_DISCOVERY_VERSION,
                "capabilities":{"tools":{"listChanged":false}},
                "serverInfo":{"name":"security-monitor","version":env!("CARGO_PKG_VERSION")}})),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(
                json!({"tools":self.tools.iter().filter(|tool| self.enabled_tool_names.contains(&tool.name))
                .map(|tool| json!({"name":tool.name,"description":tool.description,"inputSchema":tool.input_schema})).collect::<Vec<_>>()}),
            ),
            "tools/call" => return Some(self.call_tool(id, &params).await),
            _ => Err((-32601, "Method not found")),
        };
        Some(match result {
            Ok(result) => rpc_result(id, result),
            Err((code, message)) => rpc_error(id, code, message),
        })
    }

    async fn call_tool(&self, id: Value, params: &Value) -> Value {
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return rpc_error(id, -32602, "Invalid tool arguments");
        };
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let Some(tool) = self.tools.iter().find(|tool| tool.name == name) else {
            return rpc_error(id, -32602, "Tool is not available");
        };
        if authorize_tool(tool, &self.enabled_tool_names, &self.approved_permissions).is_err() {
            return rpc_result(
                id,
                json!({"isError":true,"content":[{"type":"text","text":"Permission denied"}]}),
            );
        }
        let call = ToolCall {
            id: "mcp-call".into(),
            name: name.to_owned(),
            arguments,
        };
        let executor = self.executor.clone();
        let value = match executor.execute(&call).await {
            Ok(value) => value,
            Err(_) => {
                return rpc_result(
                    id,
                    json!({"isError":true,"content":[{"type":"text","text":"Tool execution failed"}]}),
                );
            }
        };
        rpc_result(
            id,
            json!({"isError":false,"structuredContent":value,
            "content":[{"type":"text","text":value.to_string()}]}),
        )
    }

    pub async fn serve_stdio<R, W>(&self, mut reader: R, mut writer: W) -> Result<(), McpError>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut buffer = Vec::new();
        while read_limited_line(&mut reader, &mut buffer).await? {
            if buffer.iter().all(u8::is_ascii_whitespace) {
                buffer.clear();
                continue;
            }
            let response = match serde_json::from_slice::<Value>(&buffer) {
                Ok(request) => self.process(&request).await,
                Err(_) => Some(rpc_error(Value::Null, -32700, "Parse error")),
            };
            buffer.clear();
            if let Some(response) = response {
                writer
                    .write_all(
                        &serde_json::to_vec(&response).map_err(|_| McpError::InvalidArguments)?,
                    )
                    .await
                    .map_err(McpError::Transport)?;
                writer.write_all(b"\n").await.map_err(McpError::Transport)?;
                writer.flush().await.map_err(McpError::Transport)?;
            }
        }
        Ok(())
    }
}

async fn read_limited_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut Vec<u8>,
) -> Result<bool, McpError> {
    line.clear();
    loop {
        let available = reader.fill_buf().await.map_err(McpError::Transport)?;
        if available.is_empty() {
            return Ok(!line.is_empty());
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let count = newline.map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(count) > MAX_REQUEST_BYTES {
            reader.consume(count);
            while newline.is_none() {
                let available = reader.fill_buf().await.map_err(McpError::Transport)?;
                if available.is_empty() {
                    break;
                }
                let newline_at = available.iter().position(|byte| *byte == b'\n');
                let end = newline_at.map_or(available.len(), |index| index + 1);
                reader.consume(end);
                if newline_at.is_some() {
                    break;
                }
            }
            return Err(McpError::RequestTooLarge);
        }
        line.extend_from_slice(&available[..count]);
        reader.consume(count);
        if newline.is_some() {
            return Ok(true);
        }
    }
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}
fn rpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, McpError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty() && text.len() <= 4096)
        .ok_or(McpError::InvalidArguments)
}

fn optional_string(value: &Value, key: &str) -> Result<Option<String>, McpError> {
    value
        .get(key)
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(McpError::InvalidArguments)
        })
        .transpose()
}

pub fn supported_tools() -> Vec<AiTool> {
    vec![
        tool(
            "list_projects",
            "List configured project names and scan times.",
            json!({"type":"object","properties":{},"additionalProperties":false}),
            ToolPermission::Read,
        ),
        tool(
            "list_assets",
            "List server aliases and whether a successful observation exists.",
            json!({"type":"object","properties":{},"additionalProperties":false}),
            ToolPermission::Read,
        ),
        tool(
            "list_findings",
            "List known findings, optionally scoped to a project.",
            json!({"type":"object","properties":{"project_id":{"type":"string"}},"additionalProperties":false}),
            ToolPermission::Read,
        ),
        tool(
            "get_finding_evidence",
            "Read evidence already recorded for one finding.",
            json!({"type":"object","properties":{"finding_id":{"type":"string"}},"required":["finding_id"],"additionalProperties":false}),
            ToolPermission::Read,
        ),
        tool(
            "compare_repo_deployment",
            "Read current repository and deployment verification states for one finding.",
            json!({"type":"object","properties":{"finding_id":{"type":"string"}},"required":["finding_id"],"additionalProperties":false}),
            ToolPermission::Read,
        ),
        tool(
            "read_project_file",
            "Read one redacted project file during a reviewed provider request.",
            json!({"type":"object","properties":{"project_id":{"type":"string"},"path":{"type":"string"}},"required":["project_id","path"],"additionalProperties":false}),
            ToolPermission::AiApproval,
        ),
        tool(
            "search_project",
            "Search redacted project files during a reviewed provider request.",
            json!({"type":"object","properties":{"project_id":{"type":"string"},"query":{"type":"string"}},"required":["project_id","query"],"additionalProperties":false}),
            ToolPermission::AiApproval,
        ),
        tool(
            "analyze_impact",
            "Gather current finding, package, advisory, and evidence records for the caller to analyze.",
            json!({"type":"object","properties":{"finding_id":{"type":"string"}},"required":["finding_id"],"additionalProperties":false}),
            ToolPermission::AiApproval,
        ),
    ]
}

fn mcp_supported_tools() -> Vec<AiTool> {
    supported_tools()
        .into_iter()
        .filter(|tool| !matches!(tool.name.as_str(), "read_project_file" | "search_project"))
        .collect()
}

fn safe_relative_path(path: &str) -> Result<PathBuf, McpError> {
    let path = Path::new(path);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, PathComponent::Normal(_)))
    {
        return Err(McpError::ResourceUnavailable);
    }
    Ok(path.to_path_buf())
}

fn tool(name: &str, description: &str, input_schema: Value, permission: ToolPermission) -> AiTool {
    AiTool {
        name: name.to_owned(),
        description: description.to_owned(),
        input_schema,
        permission,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use security_monitor_core::Project;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    struct NoopExecutor;
    #[async_trait::async_trait]
    impl ToolExecutor for NoopExecutor {
        async fn execute(&self, call: &ToolCall) -> Result<Value, ToolError> {
            Ok(json!({"name":call.name}))
        }
    }

    #[tokio::test]
    async fn tools_list_contains_only_user_enabled_names() {
        let server = McpServer::new(
            Arc::new(NoopExecutor),
            vec![
                "list_projects".into(),
                "read_project_file".into(),
                "unknown".into(),
            ],
        );
        let response = server
            .process(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
            .await
            .unwrap();
        let names: Vec<_> = response
            .pointer("/result/tools")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        assert_eq!(names, vec!["list_projects"]);
    }

    #[tokio::test]
    async fn disabled_and_missing_approval_tools_are_denied() {
        let server = McpServer::new(Arc::new(NoopExecutor), vec!["list_projects".into()]);
        let response = server.process(&json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_project_file","arguments":{"project_id":"p","path":"README.md"}}})).await.unwrap();
        assert_eq!(response.pointer("/error/code"), Some(&json!(-32602)));
        let response = server.process(&json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_projects","arguments":{}}})).await.unwrap();
        assert_eq!(response.pointer("/result/isError"), Some(&json!(false)));
    }

    #[tokio::test]
    async fn stdio_protocol_handles_initialize_tools_and_notifications() {
        let server = McpServer::new(Arc::new(NoopExecutor), vec!["list_projects".into()]);
        let (mut client, server_io) = duplex(4096);
        let (read, write) = tokio::io::split(server_io);
        let read = tokio::io::BufReader::new(read);
        let task = tokio::spawn(async move { server.serve_stdio(read, write).await });
        client.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n").await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        task.await.unwrap().unwrap();
        let lines = response
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["result"]["protocolVersion"], MCP_VERSION);
        assert_eq!(lines[1]["result"]["tools"][0]["name"], "list_projects");
    }

    async fn database_with_project(root: &Path) -> Database {
        let database = Database::in_memory().await.unwrap();
        let now = Utc::now();
        database
            .repository::<Project>()
            .create(&Project {
                id: "project-1".into(),
                name: "fixture".into(),
                root_path: root.canonicalize().unwrap().to_string_lossy().into_owned(),
                git_remote: None,
                reference_branch: None,
                allowed_ai_providers: vec!["approved-provider".into()],
                last_scan_at: None,
                created_at: now,
                updated_at: now,
            })
            .await
            .unwrap();
        database
    }

    fn read_call(path: &str) -> ToolCall {
        ToolCall {
            id: "read-1".into(),
            name: "read_project_file".into(),
            arguments: json!({"project_id":"project-1","path":path}),
        }
    }

    #[tokio::test]
    async fn reviewed_ai_source_reads_are_capability_limited_and_redacted() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("config.json"),
            r#"{"password":"letmein123","DATABASE_HOST":"prod-db.internal","ServerName":"prod-db.internal","HOST_NAME":"prod-db.internal","HOSTS":["prod-db.internal","admin-db.internal"],"ALLOWED_HOSTS":["prod-db.internal","admin-db.internal"],"GIT_REMOTE":"git@prod-db.internal:team/repo.git","externalName":"prod-db.internal","ORIGIN":"https://[::ffff:192.0.2.1]/v1","RAW_IPV6_HOST":"fe80::1%eth0","SCOPED_ORIGIN":"https://[fe80::1%25eth0]/api"}"#,
        )
        .unwrap();
        std::fs::write(outside.path().join("secret.txt"), "outside-secret").unwrap();
        let database = database_with_project(root.path()).await;
        let denied = WorkspaceTools::new(database.clone(), None)
            .execute(&read_call("config.json"))
            .await;
        assert_eq!(denied, Err(ToolError::InvalidArguments));
        let tools = WorkspaceTools::new(database.clone(), Some("project-1".into()))
            .with_host_aliases([("prod-db.internal".into(), "payments-db".into())]);
        let approved = tools.execute(&read_call("config.json")).await.unwrap();
        assert!(
            !approved["contents"]
                .as_str()
                .unwrap()
                .contains("letmein123")
        );
        assert_eq!(approved["redacted_values"], 13);
        assert!(
            approved["contents"]
                .as_str()
                .unwrap()
                .contains("payments-db")
        );
        assert!(
            !approved["contents"]
                .as_str()
                .unwrap()
                .contains("prod-db.internal")
        );
        assert!(
            !approved["contents"]
                .as_str()
                .unwrap()
                .contains("admin-db.internal")
        );
        assert!(!approved["contents"].as_str().unwrap().contains("192.0.2.1"));
        assert!(!approved["contents"].as_str().unwrap().contains("fe80::1"));
        assert!(
            approved["contents"]
                .as_str()
                .unwrap()
                .contains("git@payments-db:team/repo.git")
        );
        std::fs::write(
            root.path().join("hosts.yaml"),
            "allowed_hosts:\n  - prod-db.internal\n  - admin-db.internal\n",
        )
        .unwrap();
        let host_list = tools.execute(&read_call("hosts.yaml")).await.unwrap();
        assert_eq!(host_list["redacted_values"], 2);
        assert!(
            !host_list["contents"]
                .as_str()
                .unwrap()
                .contains("prod-db.internal")
        );
        assert!(
            !host_list["contents"]
                .as_str()
                .unwrap()
                .contains("admin-db.internal")
        );
        std::fs::write(
            root.path().join("nginx.conf"),
            "upstream backend {\n    server prod-db.internal:8080;\n    server admin-db.internal;\n}\nupstream inline { server prod-db.internal:8090; }\n",
        )
        .unwrap();
        let nginx = tools.execute(&read_call("nginx.conf")).await.unwrap();
        assert_eq!(nginx["redacted_values"], 3);
        assert!(
            nginx["contents"]
                .as_str()
                .unwrap()
                .contains("payments-db:8080;")
        );
        assert!(
            nginx["contents"]
                .as_str()
                .unwrap()
                .contains("payments-db:8090;")
        );
        assert!(
            !nginx["contents"]
                .as_str()
                .unwrap()
                .contains("admin-db.internal")
        );
        std::fs::write(
            root.path().join("src.rs"),
            "// DATABASE_HOST=prod-db.internal; ServerName=prod-db.internal; HOST_NAME=prod-db.internal; HOSTS: [prod-db.internal, admin-db.internal]; ALLOWED_HOSTS: [\"prod-db.internal\", \"admin-db.internal\"]; GIT_REMOTE=git@prod-db.internal:team/repo.git; externalName=prod-db.internal; RAW_IPV6_HOST=fe80::1%eth0; ORIGIN=https://[fe80::1%25eth0]/api\nallowed_hosts:\n  - prod-db.internal\n  - admin-db.internal\nupstream backend {\n    server prod-db.internal:8080; # unique_search_marker\n    server admin-db.internal;\n}\n",
        )
        .unwrap();
        let search = tools
            .execute(&ToolCall {
                id: "search-1".into(),
                name: "search_project".into(),
                arguments: json!({"project_id":"project-1","query":"unique_search_marker"}),
            })
            .await
            .unwrap();
        assert_eq!(search["results"].as_array().unwrap().len(), 1);
        let snippet = search["results"][0]["snippet"].as_str().unwrap();
        assert!(snippet.contains("payments-db"));
        assert!(!snippet.contains("prod-db.internal"));
        assert!(!snippet.contains("admin-db.internal"));
        assert!(snippet.contains("payments-db:8080;"));
        assert!(!snippet.contains("192.0.2.1"));
        assert!(!snippet.contains("fe80::1"));
        let host_search = tools
            .execute(&ToolCall {
                id: "search-hosts".into(),
                name: "search_project".into(),
                arguments: json!({"project_id":"project-1","query":"admin-db.internal"}),
            })
            .await
            .unwrap();
        assert!(host_search["results"].as_array().unwrap().is_empty());
        assert_eq!(
            tools.execute(&read_call("../secret.txt")).await,
            Err(ToolError::InvalidArguments)
        );
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                outside.path().join("secret.txt"),
                root.path().join("escape.txt"),
            )
            .unwrap();
            assert_eq!(
                tools.execute(&read_call("escape.txt")).await,
                Err(ToolError::InvalidArguments)
            );
        }
        database.close().await;
    }
}
