use std::{env, path::PathBuf, sync::Arc};

use clap::{Parser, Subcommand};
use security_monitor_ai::{AiSettings, ToolPermission};
use security_monitor_core::{AuditEvent, AuditResult};
use security_monitor_database::Database;
use security_monitor_mcp_server::{McpServer, WorkspaceTools, supported_tools};

#[derive(Debug, Parser)]
#[command(version, about = "Security Monitor command-line interface")]
struct Arguments {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the local stdio MCP server. Tools come from local AI permissions.
    Mcp {
        /// Use a specific existing Security Monitor database.
        #[arg(long)]
        database: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() {
    let arguments = Arguments::parse();
    if let Some(Command::Mcp { database }) = arguments.command
        && let Err(error) = run_mcp(database).await
    {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run_mcp(database: Option<PathBuf>) -> Result<(), &'static str> {
    let database_path = database
        .unwrap_or_else(default_database_path)
        .canonicalize()
        .map_err(|_| "database_unavailable")?;
    let app_data = database_path
        .parent()
        .ok_or("database_unavailable")?
        .to_path_buf();
    let settings_path = app_data.join("ai-settings.json");
    let ai_settings = std::fs::read(settings_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<AiSettings>(&bytes).ok())
        .filter(|settings| settings.validate().is_ok())
        .unwrap_or_default();
    let database = Database::open_read_only(database_path)
        .await
        .map_err(|_| "database_unavailable")?;
    let enabled_tools = audited_enabled_tool_names(&database, &ai_settings).await?;
    let executor = Arc::new(workspace_tools(&database, &ai_settings, &app_data).await);
    let server = McpServer::new(executor, enabled_tools);
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    server
        .serve_stdio(tokio::io::BufReader::new(stdin), stdout)
        .await
        .map_err(|_| "mcp_transport_failed")?;
    database.close().await;
    Ok(())
}

async fn audited_enabled_tool_names(
    database: &Database,
    settings: &AiSettings,
) -> Result<Vec<String>, &'static str> {
    let events = database
        .repository::<AuditEvent>()
        .list()
        .await
        .map_err(|_| "database_unavailable")?;
    let mut latest = std::collections::BTreeMap::new();
    for event in events.into_iter().filter(|event| {
        event.actor == "user"
            && event.result == AuditResult::Succeeded
            && event.scope.resource_type == "ai_tool"
    }) {
        let enabled = match event.action.as_str() {
            "ai_tool_permission_enabled" => true,
            "ai_tool_permission_revocation_requested" | "ai_tool_permission_revoked" => false,
            _ => continue,
        };
        let Some(tool_name) = event.scope.resource_id else {
            continue;
        };
        let replace = latest
            .get(&tool_name)
            .is_none_or(|(timestamp, current_enabled)| {
                event.timestamp > *timestamp
                    || (event.timestamp == *timestamp && !enabled && *current_enabled)
            });
        if replace {
            latest.insert(tool_name, (event.timestamp, enabled));
        }
    }
    let permissions = supported_tools()
        .into_iter()
        .map(|tool| (tool.name, tool.permission))
        .collect::<std::collections::BTreeMap<_, _>>();
    Ok(settings
        .enabled_tools
        .iter()
        .filter(|name| {
            let Some(permission) = permissions.get(*name) else {
                return false;
            };
            if *permission == ToolPermission::Read {
                return true;
            }
            latest.get(*name).is_some_and(|(_, enabled)| *enabled)
        })
        .cloned()
        .collect())
}

async fn workspace_tools(
    database: &Database,
    settings: &AiSettings,
    app_data_dir: &std::path::Path,
) -> WorkspaceTools {
    let events = database
        .repository::<AuditEvent>()
        .list()
        .await
        .unwrap_or_default();
    let mut latest_source_access = std::collections::BTreeMap::new();
    for event in events.into_iter().filter(|event| {
        event.actor == "user"
            && event.result == AuditResult::Succeeded
            && event.scope.resource_type == "project"
    }) {
        let enabled = match event.action.as_str() {
            "mcp_source_access_permission_enabled" => true,
            "mcp_source_access_permission_revoked" => false,
            _ => continue,
        };
        let Some(project_id) = event.scope.resource_id else {
            continue;
        };
        let replace =
            latest_source_access
                .get(&project_id)
                .is_none_or(|(timestamp, current_enabled)| {
                    event.timestamp > *timestamp
                        || (event.timestamp == *timestamp && !enabled && *current_enabled)
                });
        if replace {
            latest_source_access.insert(project_id, (event.timestamp, enabled));
        }
    }
    let approved_projects = settings
        .mcp_source_access_projects
        .iter()
        .filter(|project_id| {
            latest_source_access
                .get(*project_id)
                .is_some_and(|(_, enabled)| *enabled)
        })
        .cloned()
        .collect::<Vec<_>>();
    WorkspaceTools::with_approved_source_projects(database.clone(), approved_projects)
        .with_remediation_queue_dir(app_data_dir)
}

fn default_database_path() -> PathBuf {
    let directory = if cfg!(target_os = "windows") {
        env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir)
            .join("org.securitymonitor.desktop")
    } else if cfg!(target_os = "macos") {
        env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir)
            .join("Library")
            .join("Application Support")
            .join("org.securitymonitor.desktop")
    } else {
        env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(env::temp_dir)
                    .join(".local")
                    .join("share")
            })
            .join("org.securitymonitor.desktop")
    };
    directory.join("security-monitor.sqlite3")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use security_monitor_core::{AuditScope, Project};
    use serde_json::json;

    #[tokio::test]
    async fn cli_mcp_denies_source_tools_for_a_project_without_recorded_approval() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("private.txt"), "never expose this content").unwrap();
        let database = Database::in_memory().await.unwrap();
        let now = Utc::now();
        database
            .repository::<Project>()
            .create(&Project {
                id: "project-1".into(),
                name: "fixture".into(),
                root_path: root
                    .path()
                    .canonicalize()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                git_remote: None,
                reference_branch: None,
                allowed_ai_providers: vec![],
                last_scan_at: None,
                created_at: now,
                updated_at: now,
            })
            .await
            .unwrap();

        for (id, tool_name) in [
            ("audit-read-enabled", "read_project_file"),
            ("audit-search-enabled", "search_project"),
        ] {
            database
                .repository::<AuditEvent>()
                .create(&AuditEvent {
                    id: id.into(),
                    timestamp: Utc::now(),
                    actor: "user".into(),
                    action: "ai_tool_permission_enabled".into(),
                    scope: AuditScope {
                        resource_type: "ai_tool".into(),
                        resource_id: Some(tool_name.into()),
                    },
                    result: AuditResult::Succeeded,
                })
                .await
                .unwrap();
        }

        let settings = AiSettings {
            enabled_tools: vec!["read_project_file".into(), "search_project".into()],
            ..AiSettings::default()
        };
        let executor = Arc::new(workspace_tools(&database, &settings, root.path()).await);
        let server = McpServer::new(
            executor,
            audited_enabled_tool_names(&database, &settings)
                .await
                .unwrap(),
        );
        for (name, arguments) in [
            (
                "read_project_file",
                json!({"project_id":"project-1","path":"private.txt"}),
            ),
            (
                "search_project",
                json!({"project_id":"project-1","query":"never expose"}),
            ),
        ] {
            let call = json!({
                "jsonrpc":"2.0",
                "id":1,
                "method":"tools/call",
                "params":{"name":name,"arguments":arguments}
            });
            let response = server.process(&call).await.unwrap();
            assert_eq!(response.pointer("/result/isError"), Some(&json!(true)));
            assert!(!response.to_string().contains("never expose this content"));
        }

        let settings_with_unrecorded_project = AiSettings {
            enabled_tools: vec!["read_project_file".into()],
            mcp_source_access_projects: vec!["project-1".into()],
            ..AiSettings::default()
        };
        let server = McpServer::new(
            Arc::new(
                workspace_tools(&database, &settings_with_unrecorded_project, root.path()).await,
            ),
            audited_enabled_tool_names(&database, &settings_with_unrecorded_project)
                .await
                .unwrap(),
        );
        let response = server
            .process(&json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_project_file","arguments":{"project_id":"project-1","path":"private.txt"}}}))
            .await
            .unwrap();
        assert_eq!(response.pointer("/result/isError"), Some(&json!(true)));

        database
            .repository::<AuditEvent>()
            .create(&AuditEvent {
                id: "audit-revoke".into(),
                timestamp: Utc::now(),
                actor: "user".into(),
                action: "mcp_source_access_permission_revoked".into(),
                scope: AuditScope {
                    resource_type: "project".into(),
                    resource_id: Some("project-1".into()),
                },
                result: AuditResult::Succeeded,
            })
            .await
            .unwrap();
        let server = McpServer::new(
            Arc::new(
                workspace_tools(&database, &settings_with_unrecorded_project, root.path()).await,
            ),
            audited_enabled_tool_names(&database, &settings_with_unrecorded_project)
                .await
                .unwrap(),
        );
        let response = server
            .process(&json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_project_file","arguments":{"project_id":"project-1","path":"private.txt"}}}))
            .await
            .unwrap();
        assert_eq!(response.pointer("/result/isError"), Some(&json!(true)));
    }

    #[tokio::test]
    async fn cli_mcp_uses_only_project_ids_approved_in_settings_and_audit() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("reviewed.txt"), "approved content").unwrap();
        let database = Database::in_memory().await.unwrap();
        let now = Utc::now();
        database
            .repository::<Project>()
            .create(&Project {
                id: "project-1".into(),
                name: "fixture".into(),
                root_path: root
                    .path()
                    .canonicalize()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                git_remote: None,
                reference_branch: None,
                allowed_ai_providers: vec![],
                last_scan_at: None,
                created_at: now,
                updated_at: now,
            })
            .await
            .unwrap();

        let settings = AiSettings {
            enabled_tools: vec!["read_project_file".into()],
            mcp_source_access_projects: vec!["project-1".into()],
            ..AiSettings::default()
        };
        database
            .repository::<AuditEvent>()
            .create(&AuditEvent {
                id: "audit-1".into(),
                timestamp: Utc::now(),
                actor: "user".into(),
                action: "mcp_source_access_permission_enabled".into(),
                scope: AuditScope {
                    resource_type: "project".into(),
                    resource_id: Some("project-1".into()),
                },
                result: AuditResult::Succeeded,
            })
            .await
            .unwrap();
        database
            .repository::<AuditEvent>()
            .create(&AuditEvent {
                id: "audit-tool-enabled".into(),
                timestamp: Utc::now(),
                actor: "user".into(),
                action: "ai_tool_permission_enabled".into(),
                scope: AuditScope {
                    resource_type: "ai_tool".into(),
                    resource_id: Some("read_project_file".into()),
                },
                result: AuditResult::Succeeded,
            })
            .await
            .unwrap();
        let executor = Arc::new(workspace_tools(&database, &settings, root.path()).await);
        let server = McpServer::new(
            executor,
            audited_enabled_tool_names(&database, &settings)
                .await
                .unwrap(),
        );
        let call = json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"tools/call",
            "params":{
                "name":"read_project_file",
                "arguments":{"project_id":"project-1","path":"reviewed.txt"}
            }
        });

        let response = server.process(&call).await.unwrap();
        assert_eq!(response.pointer("/result/isError"), Some(&json!(false)));
        assert!(response.to_string().contains("approved content"));
    }

    #[tokio::test]
    async fn cli_mcp_requires_a_recorded_user_grant_for_write_and_execute_tools() {
        let database = Database::in_memory().await.unwrap();
        let settings = AiSettings {
            enabled_tools: vec!["prepare_patch".into(), "run_safe_tests".into()],
            ..AiSettings::default()
        };
        assert!(
            audited_enabled_tool_names(&database, &settings)
                .await
                .unwrap()
                .is_empty()
        );
        for (id, action, tool_name) in [
            (
                "write-enable",
                "ai_tool_permission_enabled",
                "prepare_patch",
            ),
            (
                "execute-enable",
                "ai_tool_permission_enabled",
                "run_safe_tests",
            ),
            (
                "execute-revoke",
                "ai_tool_permission_revocation_requested",
                "run_safe_tests",
            ),
        ] {
            database
                .repository::<AuditEvent>()
                .create(&AuditEvent {
                    id: id.into(),
                    timestamp: Utc::now(),
                    actor: "user".into(),
                    action: action.into(),
                    scope: AuditScope {
                        resource_type: "ai_tool".into(),
                        resource_id: Some(tool_name.into()),
                    },
                    result: AuditResult::Succeeded,
                })
                .await
                .unwrap();
        }
        assert_eq!(
            audited_enabled_tool_names(&database, &settings)
                .await
                .unwrap(),
            vec!["prepare_patch"]
        );
    }
}
