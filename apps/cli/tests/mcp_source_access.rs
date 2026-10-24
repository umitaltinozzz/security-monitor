use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use chrono::{Duration, Utc};
use security_monitor_ai::AiSettings;
use security_monitor_core::{AuditEvent, AuditResult, AuditScope, Project};
use security_monitor_database::Database;
use serde_json::{Value, json};

fn run_mcp(database_path: &Path, agent: &str, request: &Value) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_secmon"))
        .args(["mcp", "--agent", agent, "--database"])
        .arg(database_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut request = serde_json::to_vec(request).unwrap();
    request.push(b'\n');
    child.stdin.take().unwrap().write_all(&request).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    serde_json::from_str(stdout.lines().next().unwrap()).unwrap()
}

fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_directory(&source_path, &destination_path);
        } else if entry.file_type().unwrap().is_file() {
            fs::copy(source_path, destination_path).unwrap();
        }
    }
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

#[tokio::test]
async fn secmon_mcp_denies_project_source_without_recorded_project_approval() {
    let app_data = tempfile::tempdir().unwrap();
    let project_root = app_data.path().join("project");
    std::fs::create_dir(&project_root).unwrap();
    std::fs::write(
        project_root.join("private.txt"),
        "source that must stay local",
    )
    .unwrap();

    let database_path = app_data.path().join("security-monitor.sqlite3");
    let database = Database::open(&database_path).await.unwrap();
    let now = Utc::now();
    database
        .repository::<Project>()
        .create(&Project {
            id: "project-1".into(),
            name: "fixture".into(),
            root_path: project_root
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
    for tool in ["read_project_file", "search_project"] {
        database
            .repository::<AuditEvent>()
            .create(&AuditEvent {
                id: format!("audit-{tool}-enabled"),
                timestamp: now,
                actor: "user".into(),
                action: "ai_tool_permission_enabled".into(),
                scope: AuditScope {
                    resource_type: "ai_tool".into(),
                    resource_id: Some(tool.into()),
                },
                result: AuditResult::Succeeded,
            })
            .await
            .unwrap();
    }
    database.close().await;

    let settings = AiSettings {
        enabled_tools: vec!["read_project_file".into(), "search_project".into()],
        mcp_source_access_projects: vec![],
        ..AiSettings::default()
    };
    std::fs::write(
        app_data.path().join("ai-settings.json"),
        serde_json::to_vec(&settings).unwrap(),
    )
    .unwrap();

    let source_requests = [
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_project_file","arguments":{"project_id":"project-1","path":"private.txt"}}}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_project","arguments":{"project_id":"project-1","query":"source that must stay local"}}}),
    ];
    for request in &source_requests {
        let response = run_mcp(&database_path, "test-agent", request);
        assert_eq!(response.pointer("/result/isError"), Some(&json!(true)));
        assert!(response.to_string().contains("Tool execution failed"));
        assert!(!response.to_string().contains("source that must stay local"));
    }

    // A settings entry alone cannot authorize source access without an audit grant.
    let settings = AiSettings {
        mcp_source_access_projects: vec!["project-1".into()],
        ..settings
    };
    std::fs::write(
        app_data.path().join("ai-settings.json"),
        serde_json::to_vec(&settings).unwrap(),
    )
    .unwrap();
    for request in &source_requests {
        let response = run_mcp(&database_path, "test-agent", request);
        assert_eq!(response.pointer("/result/isError"), Some(&json!(true)));
        assert!(!response.to_string().contains("source that must stay local"));
    }

    let database = Database::open(&database_path).await.unwrap();
    database
        .repository::<AuditEvent>()
        .create(&AuditEvent {
            id: "audit-source-enabled".into(),
            timestamp: now + Duration::seconds(1),
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
    database.close().await;

    for request in &source_requests {
        let response = run_mcp(&database_path, "test-agent", request);
        assert_eq!(response.pointer("/result/isError"), Some(&json!(false)));
        assert!(response.to_string().contains("source that must stay local"));
    }

    let database = Database::open(&database_path).await.unwrap();
    database
        .repository::<AuditEvent>()
        .create(&AuditEvent {
            id: "audit-source-revocation-requested".into(),
            timestamp: now + Duration::seconds(2),
            actor: "user".into(),
            action: "mcp_source_access_permission_revocation_requested".into(),
            scope: AuditScope {
                resource_type: "project".into(),
                resource_id: Some("project-1".into()),
            },
            result: AuditResult::Succeeded,
        })
        .await
        .unwrap();
    database.close().await;

    for request in &source_requests {
        let response = run_mcp(&database_path, "test-agent", request);
        assert_eq!(response.pointer("/result/isError"), Some(&json!(true)));
        assert!(!response.to_string().contains("source that must stay local"));
    }
}

#[tokio::test]
async fn separate_secmon_mcp_agents_share_redacted_notes_without_finding_mutations() {
    let app_data = tempfile::tempdir().unwrap();
    let database_path = app_data.path().join("security-monitor.sqlite3");
    let database = Database::open(&database_path).await.unwrap();
    let now = Utc::now();
    for tool in ["recall", "remember", "forget"] {
        database
            .repository::<AuditEvent>()
            .create(&AuditEvent {
                id: format!("audit-{tool}"),
                timestamp: now,
                actor: "user".into(),
                action: "ai_tool_permission_enabled".into(),
                scope: AuditScope {
                    resource_type: "ai_tool".into(),
                    resource_id: Some(tool.into()),
                },
                result: AuditResult::Succeeded,
            })
            .await
            .unwrap();
    }
    database.close().await;
    fs::write(
        app_data.path().join("ai-settings.json"),
        serde_json::to_vec(&AiSettings {
            enabled_tools: vec!["recall".into(), "remember".into(), "forget".into()],
            memory_agent_writes_enabled: true,
            ..AiSettings::default()
        })
        .unwrap(),
    )
    .unwrap();

    let create = run_mcp(
        &database_path,
        "codex",
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"remember","arguments":{"scope":"global","kind":"agent_summary","content":"Review note: the finding is reachable only from the admin route. token=github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"}}}),
    );
    assert_eq!(create.pointer("/result/isError"), Some(&json!(false)));
    assert!(create.to_string().contains("[REDACTED]"));
    assert!(!create.to_string().contains("github_pat_"));
    let memory_id = create
        .pointer("/result/structuredContent/memory/id")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();

    let recall = run_mcp(
        &database_path,
        "opencode",
        &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"recall","arguments":{"scope":"global","query":"admin route"}}}),
    );
    assert_eq!(recall.pointer("/result/isError"), Some(&json!(false)));
    assert!(recall.to_string().contains(&memory_id));
    assert!(recall.to_string().contains("agent:codex"));
    assert!(!recall.to_string().contains("github_pat_"));
    assert_eq!(
        recall.pointer("/result/structuredContent/untrusted_data"),
        Some(&json!(true))
    );

    for name in ["set_finding_status", "set_priority_score"] {
        let response = run_mcp(
            &database_path,
            "codex",
            &json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":name,"arguments":{"finding_id":"finding-1","status":"false_positive","priority_score":0}}}),
        );
        assert_eq!(
            response.pointer("/error/code"),
            Some(&json!(-32602)),
            "{name}"
        );
    }

    let other_agent_forget = run_mcp(
        &database_path,
        "opencode",
        &json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"forget","arguments":{"id":memory_id}}}),
    );
    assert_eq!(
        other_agent_forget.pointer("/result/isError"),
        Some(&json!(true))
    );
    let owner_forget = run_mcp(
        &database_path,
        "codex",
        &json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"forget","arguments":{"id":memory_id}}}),
    );
    assert_eq!(owner_forget.pointer("/result/isError"), Some(&json!(false)));
}

#[tokio::test]
async fn installed_claude_plugin_in_temporary_home_exposes_memory_tools() {
    let temporary_home = tempfile::tempdir().unwrap();
    let root = repository_root();
    let plugin_install = temporary_home
        .path()
        .join(".claude/plugins/cache/security-monitor/secmon/0.1.0");
    copy_directory(&root.join("plugins/claude-code"), &plugin_install);
    let mcp_config: Value =
        serde_json::from_slice(&fs::read(plugin_install.join(".mcp.json")).unwrap()).unwrap();
    let server = &mcp_config["mcpServers"]["security-monitor"];
    assert_eq!(server["command"], "secmon");
    assert_eq!(server["args"], json!(["mcp", "--agent", "claude-code"]));

    let codex_install = temporary_home
        .path()
        .join(".agents/plugins/cache/security-monitor/secmon/0.1.0");
    copy_directory(&root.join("plugins/codex"), &codex_install);
    let codex_config: Value =
        serde_json::from_slice(&fs::read(codex_install.join("mcp.json")).unwrap()).unwrap();
    assert_eq!(
        codex_config["mcpServers"]["security-monitor"]["command"],
        "secmon"
    );
    assert_eq!(
        codex_config["mcpServers"]["security-monitor"]["args"],
        json!(["mcp", "--agent", "codex"])
    );

    let opencode_install = temporary_home
        .path()
        .join(".config/opencode/plugins/secmon");
    copy_directory(&root.join("plugins/opencode"), &opencode_install);
    let opencode_config: Value =
        serde_json::from_slice(&fs::read(opencode_install.join("opencode.json")).unwrap()).unwrap();
    assert_eq!(
        opencode_config["mcp"]["security-monitor"]["command"],
        json!(["secmon", "mcp", "--agent", "opencode"])
    );

    let app_data = temporary_home.path().join("app-data");
    fs::create_dir_all(&app_data).unwrap();
    let database_path = app_data.join("security-monitor.sqlite3");
    let database = Database::open(&database_path).await.unwrap();
    for tool in ["recall", "remember", "forget"] {
        database
            .repository::<AuditEvent>()
            .create(&AuditEvent {
                id: format!("audit-{tool}"),
                timestamp: Utc::now(),
                actor: "user".into(),
                action: "ai_tool_permission_enabled".into(),
                scope: AuditScope {
                    resource_type: "ai_tool".into(),
                    resource_id: Some(tool.into()),
                },
                result: AuditResult::Succeeded,
            })
            .await
            .unwrap();
    }
    database.close().await;
    fs::write(
        app_data.join("ai-settings.json"),
        serde_json::to_vec(&AiSettings {
            enabled_tools: vec!["recall".into(), "remember".into(), "forget".into()],
            memory_agent_writes_enabled: true,
            ..AiSettings::default()
        })
        .unwrap(),
    )
    .unwrap();
    for agent in ["claude-code", "codex", "opencode"] {
        let tools = run_mcp(
            &database_path,
            agent,
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        );
        let names = tools["result"]["tools"].as_array().unwrap();
        for name in ["recall", "remember", "forget"] {
            assert!(
                names.iter().any(|tool| tool["name"] == name),
                "{agent}: {name}"
            );
        }
    }
}
