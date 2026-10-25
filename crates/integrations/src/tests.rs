use super::*;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

#[derive(Default, Clone)]
struct MemoryCredentialStore {
    values: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    delete_calls: Arc<Mutex<usize>>,
    fail_delete_at: Arc<Mutex<Option<usize>>>,
    max_secret_bytes: Arc<Mutex<Option<usize>>>,
}

impl MemoryCredentialStore {
    fn fail_delete_on_call(&self, call: usize) {
        *self.fail_delete_at.lock().unwrap() = Some(call);
    }

    fn limit_secret_size(&self, max_bytes: usize) {
        *self.max_secret_bytes.lock().unwrap() = Some(max_bytes);
    }
}

impl CredentialStore for MemoryCredentialStore {
    fn put(
        &self,
        secret: &[u8],
    ) -> Result<String, security_monitor_agent_transport::CredentialError> {
        if self
            .max_secret_bytes
            .lock()
            .unwrap()
            .is_some_and(|limit| secret.len() > limit)
        {
            return Err(security_monitor_agent_transport::CredentialError::StoreUnavailable);
        }
        let reference = format!("secmon-keyring:v1:{}", uuid::Uuid::new_v4());
        self.values
            .lock()
            .unwrap()
            .insert(reference.clone(), secret.to_vec());
        Ok(reference)
    }

    fn get(
        &self,
        reference: &str,
    ) -> Result<Zeroizing<Vec<u8>>, security_monitor_agent_transport::CredentialError> {
        self.values
            .lock()
            .unwrap()
            .get(reference)
            .cloned()
            .map(Zeroizing::new)
            .ok_or(security_monitor_agent_transport::CredentialError::StoreUnavailable)
    }

    fn delete(
        &self,
        reference: &str,
    ) -> Result<(), security_monitor_agent_transport::CredentialError> {
        let mut calls = self.delete_calls.lock().unwrap();
        *calls += 1;
        if *self.fail_delete_at.lock().unwrap() == Some(*calls) {
            return Err(security_monitor_agent_transport::CredentialError::StoreUnavailable);
        }
        self.values.lock().unwrap().remove(reference);
        Ok(())
    }
}

#[test]
fn dry_run_shows_agent_specific_mcp_skill_and_hook_changes_without_writing() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    for agent in [Agent::ClaudeCode, Agent::Codex, Agent::Opencode] {
        let service = IntegrationService::new(MemoryCredentialStore::default());
        let plan = service
            .plan(agent, Scope::Project, home.path(), Some(project.path()))
            .unwrap();
        assert_eq!(plan.changes.len(), 3);
        let diff = plan.diff(agent);
        assert!(diff.contains("local Security Monitor MCP"));
        assert!(diff.contains("Security Monitor skill"));
        assert!(diff.contains("pre-tool Git hook"));
        assert!(!project.path().join(".mcp.json").exists());
    }
}

#[test]
fn generated_agent_configs_match_vendor_supported_shapes() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let service = IntegrationService::new(MemoryCredentialStore::default());

    let claude = service
        .plan(
            Agent::ClaudeCode,
            Scope::Project,
            home.path(),
            Some(project.path()),
        )
        .unwrap();
    let claude_mcp = claude
        .changes
        .iter()
        .find(|change| change.relative_path == Path::new(".mcp.json"))
        .unwrap()
        .after
        .as_slice();
    let claude_mcp: Value = serde_json::from_slice(claude_mcp).unwrap();
    assert_eq!(claude_mcp["mcpServers"]["secmon"]["command"], "secmon");
    assert_eq!(claude_mcp["mcpServers"]["secmon"]["args"], json!(["mcp"]));
    let claude_hooks = claude
        .changes
        .iter()
        .find(|change| change.relative_path == Path::new(".claude/settings.json"))
        .unwrap()
        .after
        .as_slice();
    let claude_hooks: Value = serde_json::from_slice(claude_hooks).unwrap();
    assert_eq!(claude_hooks["hooks"]["PreToolUse"][0]["matcher"], "Bash");
    assert_eq!(
        claude_hooks["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
        "secmon hook run --agent-event"
    );

    let codex = service
        .plan(
            Agent::Codex,
            Scope::Project,
            home.path(),
            Some(project.path()),
        )
        .unwrap();
    let codex_mcp = codex
        .changes
        .iter()
        .find(|change| change.relative_path == Path::new(".codex/config.toml"))
        .unwrap()
        .after
        .as_slice();
    let codex_mcp: toml::Value = toml::from_str(std::str::from_utf8(codex_mcp).unwrap()).unwrap();
    assert_eq!(
        codex_mcp["mcp_servers"]["secmon"]["command"].as_str(),
        Some("secmon")
    );
    assert_eq!(
        codex_mcp["mcp_servers"]["secmon"]["args"][0].as_str(),
        Some("mcp")
    );
    let codex_hooks = codex
        .changes
        .iter()
        .find(|change| change.relative_path == Path::new(".codex/hooks.json"))
        .unwrap()
        .after
        .as_slice();
    let codex_hooks: Value = serde_json::from_slice(codex_hooks).unwrap();
    assert_eq!(codex_hooks["hooks"]["PreToolUse"][0]["matcher"], "^Bash$");
    assert_eq!(
        codex_hooks["hooks"]["PreToolUse"][0]["hooks"][0]["commandWindows"],
        "secmon.exe hook run --agent-event"
    );

    let opencode = service
        .plan(
            Agent::Opencode,
            Scope::Project,
            home.path(),
            Some(project.path()),
        )
        .unwrap();
    let opencode_mcp = opencode
        .changes
        .iter()
        .find(|change| change.relative_path == Path::new("opencode.json"))
        .unwrap()
        .after
        .as_slice();
    let opencode_mcp: Value = serde_json::from_slice(opencode_mcp).unwrap();
    assert_eq!(opencode_mcp["mcp"]["secmon"]["type"], "local");
    assert_eq!(
        opencode_mcp["mcp"]["secmon"]["command"],
        json!(["secmon", "mcp"])
    );
    let opencode_plugin = opencode
        .changes
        .iter()
        .find(|change| change.relative_path == Path::new(".opencode/plugins/secmon.js"))
        .unwrap()
        .after
        .as_slice();
    let opencode_plugin = std::str::from_utf8(opencode_plugin).unwrap();
    assert!(opencode_plugin.contains("tool.execute.before"));
    assert!(
        opencode_plugin.contains("Bun.spawn([\"secmon\", \"hook\", \"run\", \"--agent-event\"]")
    );
    assert!(opencode_plugin.contains("hook_event_name: \"PreToolUse\""));
    assert!(opencode_plugin.contains("stdin: \"pipe\""));
}

#[test]
fn json_merge_preserves_existing_key_order() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    fs::write(
        project.path().join(".mcp.json"),
        br#"{"z":1,"mcpServers":{"other":{"command":"other"}},"a":2}"#,
    )
    .unwrap();
    let service = IntegrationService::new(MemoryCredentialStore::default());

    let plan = service
        .plan(
            Agent::ClaudeCode,
            Scope::Project,
            home.path(),
            Some(project.path()),
        )
        .unwrap();
    let merged = String::from_utf8(
        plan.changes
            .iter()
            .find(|change| change.relative_path == Path::new(".mcp.json"))
            .unwrap()
            .after
            .clone(),
    )
    .unwrap();
    assert!(merged.find("\"z\"").unwrap() < merged.find("\"mcpServers\"").unwrap());
    assert!(merged.find("\"mcpServers\"").unwrap() < merged.find("\"a\"").unwrap());
}

#[test]
fn json_agent_hook_merge_does_not_duplicate_the_secmon_handler() {
    let handler = json!({
        "type": "command",
        "command": "secmon hook run --agent-event",
        "timeout": 30,
    });
    let group = json!({"matcher":"Bash","hooks":[handler]});
    let once = common::merge_hook_json(
        &None,
        "PreToolUse",
        group.clone(),
        "secmon hook run --agent-event",
    )
    .unwrap()
    .unwrap();
    let twice = common::merge_hook_json(
        &Some(once),
        "PreToolUse",
        group,
        "secmon hook run --agent-event",
    )
    .unwrap()
    .unwrap();
    let merged: Value = serde_json::from_slice(&twice).unwrap();
    let matching_handlers = merged["hooks"]["PreToolUse"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|group| group["hooks"].as_array().unwrap())
        .filter(|handler| handler["command"] == "secmon hook run --agent-event")
        .count();
    assert_eq!(matching_handlers, 1);
}

#[test]
fn install_and_remove_preserve_existing_values_without_file_backup_secrets() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let project_root = project.path();
    let config_path = project_root.join(".codex/config.toml");
    let hooks_path = project_root.join(".codex/hooks.json");
    fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    fs::write(
            &config_path,
            "# keep formatting exactly on remove\n[mcp_servers.other]\ncommand = \"other\"\napi_key = \"fixture-secret\"\n",
        )
        .unwrap();
    fs::write(
            &hooks_path,
            "{\"hooks\":{\"SessionStart\":[{\"hooks\":[{\"type\":\"command\",\"command\":\"keep-me\"}]}]}}",
        )
        .unwrap();
    let store = MemoryCredentialStore::default();
    let service = IntegrationService::new(store.clone());
    let plan = service
        .plan(
            Agent::Codex,
            Scope::Project,
            home.path(),
            Some(project_root),
        )
        .unwrap();
    assert_eq!(plan.changes.len(), 3);
    let diff = plan.diff(Agent::Codex);
    assert!(diff.contains("api_key = \"[REDACTED]\""));
    assert!(!diff.contains("fixture-secret"));
    service
        .install(
            Agent::Codex,
            Scope::Project,
            home.path(),
            Some(project_root),
        )
        .unwrap();
    let manifest_files = fs::read_dir(home.path().join(".secmon/integrations"))
        .unwrap()
        .map(|entry| fs::read(entry.unwrap().path()).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(manifest_files.len(), 1);
    assert!(!String::from_utf8_lossy(&manifest_files[0]).contains("fixture-secret"));
    assert!(String::from_utf8_lossy(&fs::read(&config_path).unwrap()).contains("fixture-secret"));
    assert!(String::from_utf8_lossy(&fs::read(&hooks_path).unwrap()).contains("keep-me"));

    service
        .remove(
            Agent::Codex,
            Scope::Project,
            home.path(),
            Some(project_root),
        )
        .unwrap();
    let removed_config: toml::Value =
        toml::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
    assert_eq!(
        removed_config["mcp_servers"]["other"]["command"].as_str(),
        Some("other")
    );
    assert!(removed_config["mcp_servers"].get("secmon").is_none());
    assert!(
        fs::read_to_string(&config_path)
            .unwrap()
            .contains("keep formatting exactly on remove")
    );
    let removed_hooks: Value = serde_json::from_slice(&fs::read(&hooks_path).unwrap()).unwrap();
    assert_eq!(
        removed_hooks["hooks"]["SessionStart"][0]["hooks"][0]["command"],
        "keep-me"
    );
    assert!(!project_root.join(".agents/skills/secmon/SKILL.md").exists());
    assert!(store.values.lock().unwrap().is_empty());
}

#[test]
fn codex_uninstall_preserves_comments_and_values_added_after_install() {
    use std::io::Write as _;

    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let config_path = project.path().join(".codex/config.toml");
    fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    fs::write(
        &config_path,
        "# keep this comment\n[mcp_servers.other]\ncommand = \"other\"\n",
    )
    .unwrap();
    let service = IntegrationService::new(MemoryCredentialStore::default());
    service
        .install(
            Agent::Codex,
            Scope::Project,
            home.path(),
            Some(project.path()),
        )
        .unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(&config_path)
        .unwrap()
        .write_all(b"\n[custom]\nvalue = \"added after install\"\n")
        .unwrap();

    service
        .remove(
            Agent::Codex,
            Scope::Project,
            home.path(),
            Some(project.path()),
        )
        .unwrap();

    let after = fs::read_to_string(config_path).unwrap();
    let parsed: toml::Value = toml::from_str(&after).unwrap();
    assert!(parsed["mcp_servers"].get("secmon").is_none());
    assert_eq!(
        parsed["custom"]["value"].as_str(),
        Some("added after install")
    );
    assert!(after.contains("keep this comment"));
}

#[test]
fn large_claude_configuration_is_chunked_and_only_secmon_is_removed() {
    let home = tempfile::tempdir().unwrap();
    let config_path = home.path().join(".claude.json");
    let original = serde_json::to_vec(&json!({"other": {"value": "x".repeat(8192)}})).unwrap();
    assert!(original.len() > 2560);
    fs::write(&config_path, &original).unwrap();

    let store = MemoryCredentialStore::default();
    store.limit_secret_size(2560);
    let service = IntegrationService::new(store.clone());
    service
        .install(Agent::ClaudeCode, Scope::User, home.path(), None)
        .unwrap();
    assert!(
        store
            .values
            .lock()
            .unwrap()
            .values()
            .all(|chunk| chunk.len() <= 2560)
    );

    service
        .remove(Agent::ClaudeCode, Scope::User, home.path(), None)
        .unwrap();
    let after: Value = serde_json::from_slice(&fs::read(config_path).unwrap()).unwrap();
    assert_eq!(after["other"]["value"], "x".repeat(8192));
    assert!(after.get("mcpServers").is_none());
    assert!(store.values.lock().unwrap().is_empty());
}

#[test]
fn every_agent_restores_existing_config_bytes_after_remove() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    for agent in [Agent::ClaudeCode, Agent::Codex, Agent::Opencode] {
        let spec = agent_spec(agent).unwrap();
        let root = project.path();
        let mcp_path = scoped_path(&spec, "mcp", Scope::Project).unwrap();
        let hook_path = scoped_path(&spec, "hook", Scope::Project).unwrap();
        let mcp_before = match spec.mcp_format.as_str() {
            "claude_json" => br#"{ "mcpServers": { "other": { "command": "other" } } }"#.to_vec(),
            "opencode_json" => {
                br#"{ "mcp": { "other": { "type": "local", "command": ["other"] } } }"#.to_vec()
            }
            "codex_toml" => {
                b"# preserve this comment\n[mcp_servers.other]\ncommand = \"other\"\n".to_vec()
            }
            _ => panic!("agent MCP format is covered"),
        };
        let hook_before = match spec.hook_format.as_str() {
            "claude_json" | "codex_json" => br#"{ "hooks": {} }"#.to_vec(),
            "opencode_plugin" => OPENCODE_PLUGIN.as_bytes().to_vec(),
            _ => panic!("agent hook format is covered"),
        };
        for (path, contents) in [(&mcp_path, &mcp_before), (&hook_path, &hook_before)] {
            let target = root.join(path);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(target, contents).unwrap();
        }
        let store = MemoryCredentialStore::default();
        let service = IntegrationService::new(store.clone());
        service
            .install(agent, Scope::Project, home.path(), Some(root))
            .unwrap();
        service
            .remove(agent, Scope::Project, home.path(), Some(root))
            .unwrap();
        let mcp_after = fs::read(root.join(&mcp_path)).unwrap();
        match spec.mcp_format.as_str() {
            "codex_toml" => {
                let parsed: toml::Value =
                    toml::from_str(std::str::from_utf8(&mcp_after).unwrap()).unwrap();
                assert!(parsed["mcp_servers"].get("secmon").is_none());
                assert!(
                    String::from_utf8(mcp_after)
                        .unwrap()
                        .contains("preserve this comment")
                );
            }
            _ => {
                let parsed: Value = serde_json::from_slice(&mcp_after).unwrap();
                let section = if spec.mcp_format == "claude_json" {
                    "mcpServers"
                } else {
                    "mcp"
                };
                assert!(parsed[section].get("secmon").is_none());
            }
        }
        if spec.hook_format == "opencode_plugin" {
            assert_eq!(fs::read(root.join(&hook_path)).unwrap(), hook_before);
        } else {
            let hook_after: Value =
                serde_json::from_slice(&fs::read(root.join(&hook_path)).unwrap()).unwrap();
            assert!(
                !hook_after
                    .to_string()
                    .contains("secmon hook run --agent-event")
            );
        }
        assert!(
            !root
                .join(scoped_path(&spec, "skill", Scope::Project).unwrap())
                .exists()
        );
        assert!(store.values.lock().unwrap().is_empty());
    }
}

#[test]
fn remove_can_retry_after_credential_cleanup_partially_fails() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let config_path = project.path().join(".mcp.json");
    let hooks_path = project.path().join(".claude/settings.json");
    fs::create_dir_all(hooks_path.parent().unwrap()).unwrap();
    fs::write(
        &config_path,
        br#"{"mcpServers":{"other":{"command":"other"}}}"#,
    )
    .unwrap();
    fs::write(&hooks_path, br#"{"hooks":{"SessionStart":[]}}"#).unwrap();
    let store = MemoryCredentialStore::default();
    let service = IntegrationService::new(store.clone());
    service
        .install(
            Agent::ClaudeCode,
            Scope::Project,
            home.path(),
            Some(project.path()),
        )
        .unwrap();
    store.fail_delete_on_call(2);

    assert!(matches!(
        service.remove(
            Agent::ClaudeCode,
            Scope::Project,
            home.path(),
            Some(project.path())
        ),
        Err(IntegrationError::BackupUnavailable)
    ));
    let config_after_first_remove: Value =
        serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    assert_eq!(
        config_after_first_remove["mcpServers"]["other"]["command"],
        "other"
    );
    assert!(
        config_after_first_remove["mcpServers"]
            .get("secmon")
            .is_none()
    );
    let hooks_after_first_remove: Value =
        serde_json::from_slice(&fs::read(&hooks_path).unwrap()).unwrap();
    assert!(
        !hooks_after_first_remove
            .to_string()
            .contains("secmon hook run --agent-event")
    );

    service
        .remove(
            Agent::ClaudeCode,
            Scope::Project,
            home.path(),
            Some(project.path()),
        )
        .unwrap();
    assert!(store.values.lock().unwrap().is_empty());
    let config_after_retry: Value =
        serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    assert_eq!(
        config_after_retry["mcpServers"]["other"]["command"],
        "other"
    );
    assert!(config_after_retry["mcpServers"].get("secmon").is_none());
    let hooks_after_retry: Value = serde_json::from_slice(&fs::read(&hooks_path).unwrap()).unwrap();
    assert!(
        !hooks_after_retry
            .to_string()
            .contains("secmon hook run --agent-event")
    );
}

#[test]
fn remove_preserves_user_edits_and_removes_only_secmon_entries() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let service = IntegrationService::new(MemoryCredentialStore::default());
    service
        .install(
            Agent::ClaudeCode,
            Scope::Project,
            home.path(),
            Some(project.path()),
        )
        .unwrap();
    let mcp_path = project.path().join(".mcp.json");
    let mut mcp: Value = serde_json::from_slice(&fs::read(&mcp_path).unwrap()).unwrap();
    mcp["user_edit"] = json!(true);
    fs::write(&mcp_path, serde_json::to_vec_pretty(&mcp).unwrap()).unwrap();
    let hook_path = project.path().join(".claude/settings.json");
    let mut hooks: Value = serde_json::from_slice(&fs::read(&hook_path).unwrap()).unwrap();
    hooks["hooks"]["SessionStart"] = json!([{"hooks":[{"type":"command","command":"keep-me"}]}]);
    hooks["hooks"]["MalformedEvent"] = json!("preserve this user value");
    fs::write(&hook_path, serde_json::to_vec_pretty(&hooks).unwrap()).unwrap();

    service
        .remove(
            Agent::ClaudeCode,
            Scope::Project,
            home.path(),
            Some(project.path()),
        )
        .unwrap();

    let remaining_mcp: Value = serde_json::from_slice(&fs::read(mcp_path).unwrap()).unwrap();
    assert_eq!(remaining_mcp["user_edit"], true);
    assert!(remaining_mcp.get("mcpServers").is_none());
    let remaining_hooks: Value = serde_json::from_slice(&fs::read(hook_path).unwrap()).unwrap();
    assert_eq!(
        remaining_hooks["hooks"]["SessionStart"][0]["hooks"][0]["command"],
        "keep-me"
    );
    assert_eq!(
        remaining_hooks["hooks"]["MalformedEvent"],
        "preserve this user value"
    );
    assert!(
        !remaining_hooks
            .to_string()
            .contains("secmon hook run --agent-event")
    );
}

#[test]
fn agent_config_paths_are_relative_and_path_traversal_is_rejected() {
    let service = IntegrationService::new(MemoryCredentialStore::default());
    assert!(
        service
            .plan(Agent::Opencode, Scope::User, Path::new("."), None)
            .is_ok()
    );
    assert!(validate_relative(Path::new("../outside")).is_err());
    assert!(validate_relative(Path::new("C:/outside")).is_err());
    assert!(validate_relative(Path::new(r"C:\outside")).is_err());
    assert!(validate_relative(Path::new(r"C:outside")).is_err());
    assert!(validate_relative(Path::new(r"..\outside")).is_err());
    assert!(validate_relative(Path::new(r"\server\share")).is_err());
    assert_eq!(Agent::parse("claude-code"), Some(Agent::ClaudeCode));
}
