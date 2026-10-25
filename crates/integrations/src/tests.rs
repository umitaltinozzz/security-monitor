use super::*;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

#[derive(Default, Clone)]
struct MemoryCredentialStore {
    values: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    delete_calls: Arc<Mutex<usize>>,
    fail_delete_at: Arc<Mutex<Option<usize>>>,
}

impl MemoryCredentialStore {
    fn fail_delete_on_call(&self, call: usize) {
        *self.fail_delete_at.lock().unwrap() = Some(call);
    }
}

impl CredentialStore for MemoryCredentialStore {
    fn put(
        &self,
        secret: &[u8],
    ) -> Result<String, security_monitor_agent_transport::CredentialError> {
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
        "secmon hook run"
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
        "secmon.exe hook run"
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
    assert!(opencode_plugin.contains("Bun.spawn([\"secmon\", \"hook\", \"run\"]"));
}

#[test]
fn install_and_remove_restore_existing_files_byte_for_byte_without_file_backup_secrets() {
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
    let original_config = fs::read(&config_path).unwrap();
    let original_hooks = fs::read(&hooks_path).unwrap();
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
    assert_eq!(fs::read(config_path).unwrap(), original_config);
    assert_eq!(fs::read(hooks_path).unwrap(), original_hooks);
    assert!(!project_root.join(".agents/skills/secmon/SKILL.md").exists());
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
        assert_eq!(fs::read(root.join(mcp_path)).unwrap(), mcp_before);
        assert_eq!(fs::read(root.join(hook_path)).unwrap(), hook_before);
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
    let original_config = fs::read(&config_path).unwrap();
    let original_hooks = fs::read(&hooks_path).unwrap();
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
    assert_eq!(fs::read(&config_path).unwrap(), original_config);
    assert_eq!(fs::read(&hooks_path).unwrap(), original_hooks);

    service
        .remove(
            Agent::ClaudeCode,
            Scope::Project,
            home.path(),
            Some(project.path()),
        )
        .unwrap();
    assert!(store.values.lock().unwrap().is_empty());
    assert_eq!(fs::read(&config_path).unwrap(), original_config);
    assert_eq!(fs::read(&hooks_path).unwrap(), original_hooks);
}

#[test]
fn remove_refuses_to_overwrite_user_edits_after_install() {
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
    fs::write(project.path().join(".mcp.json"), "{\"user_edit\":true}").unwrap();
    assert!(matches!(
        service.remove(
            Agent::ClaudeCode,
            Scope::Project,
            home.path(),
            Some(project.path())
        ),
        Err(IntegrationError::ModifiedAfterInstall)
    ));
    assert_eq!(
        fs::read_to_string(project.path().join(".mcp.json")).unwrap(),
        "{\"user_edit\":true}"
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
