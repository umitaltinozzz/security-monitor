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
    assert_eq!(names, vec!["list_projects", "read_project_file"]);
}

#[tokio::test]
async fn disabled_and_missing_approval_tools_are_denied() {
    let server = McpServer::new(Arc::new(NoopExecutor), vec!["list_projects".into()]);
    let response = server.process(&json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_project_file","arguments":{"project_id":"p","path":"README.md"}}})).await.unwrap();
    assert_eq!(response.pointer("/result/isError"), Some(&json!(true)));
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
