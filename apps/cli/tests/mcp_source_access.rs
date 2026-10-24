use std::{
    io::Write,
    process::{Command, Stdio},
};

use chrono::Utc;
use security_monitor_ai::AiSettings;
use security_monitor_core::{AuditEvent, AuditResult, AuditScope, Project};
use security_monitor_database::Database;
use serde_json::{Value, json};

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
    database
        .repository::<AuditEvent>()
        .create(&AuditEvent {
            id: "audit-read-tool-enabled".into(),
            timestamp: now,
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
    database.close().await;

    let settings = AiSettings {
        enabled_tools: vec!["read_project_file".into()],
        mcp_source_access_projects: vec![],
        ..AiSettings::default()
    };
    std::fs::write(
        app_data.path().join("ai-settings.json"),
        serde_json::to_vec(&settings).unwrap(),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_secmon"))
        .args(["mcp", "--database"])
        .arg(&database_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_project_file","arguments":{"project_id":"project-1","path":"private.txt"}}}
"#,
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let response: Value = serde_json::from_str(stdout.lines().next().unwrap()).unwrap();
    assert_eq!(response.pointer("/result/isError"), Some(&json!(true)));
    assert!(response.to_string().contains("Tool execution failed"));
    assert!(!stdout.contains("source that must stay local"));
}
