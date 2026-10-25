use super::*;

pub(crate) enum ManagedRemoval {
    NotManaged,
    Managed(Option<Vec<u8>>),
}

pub(crate) fn remove_managed_config(
    agent: Agent,
    scope: Scope,
    relative_path: &Path,
    bytes: Option<&[u8]>,
    existed_before: bool,
) -> Result<ManagedRemoval, IntegrationError> {
    let spec = agent_spec(agent)?;
    let mcp_path = scoped_path(&spec, "mcp", scope)?;
    let hook_path = scoped_path(&spec, "hook", scope)?;
    if relative_path == mcp_path {
        let contents = match spec.mcp_format.as_str() {
            "claude_json" => remove_json_entry(bytes, "mcpServers", existed_before)?,
            "opencode_json" => remove_json_entry(bytes, "mcp", existed_before)?,
            "codex_toml" => remove_codex_entry(bytes)?,
            _ => return Err(IntegrationError::InvalidConfiguration),
        };
        return Ok(ManagedRemoval::Managed(contents));
    }
    if relative_path == hook_path && spec.hook_format != "opencode_plugin" {
        return Ok(ManagedRemoval::Managed(remove_hook_entry(
            bytes,
            existed_before,
        )?));
    }
    Ok(ManagedRemoval::NotManaged)
}

fn remove_json_entry(
    bytes: Option<&[u8]>,
    section: &str,
    existed_before: bool,
) -> Result<Option<Vec<u8>>, IntegrationError> {
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let mut root =
        serde_json::from_slice::<Value>(bytes).map_err(|_| IntegrationError::Conflict)?;
    let root_object = root.as_object_mut().ok_or(IntegrationError::Conflict)?;
    let Some(section_value) = root_object.get_mut(section) else {
        return Ok(Some(bytes.to_vec()));
    };
    let section_object = section_value
        .as_object_mut()
        .ok_or(IntegrationError::Conflict)?;
    if section_object.remove("secmon").is_none() {
        return Ok(Some(bytes.to_vec()));
    }
    if section_object.is_empty() {
        root_object.remove(section);
    }
    if root_object.is_empty() && !existed_before {
        return Ok(None);
    }
    serde_json::to_vec_pretty(&root)
        .map(Some)
        .map_err(|_| IntegrationError::InvalidConfiguration)
}

fn remove_hook_entry(
    bytes: Option<&[u8]>,
    existed_before: bool,
) -> Result<Option<Vec<u8>>, IntegrationError> {
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let mut root =
        serde_json::from_slice::<Value>(bytes).map_err(|_| IntegrationError::Conflict)?;
    let root_object = root.as_object_mut().ok_or(IntegrationError::Conflict)?;
    let Some(hooks_value) = root_object.get_mut("hooks") else {
        return Ok(Some(bytes.to_vec()));
    };
    let hooks = hooks_value
        .as_object_mut()
        .ok_or(IntegrationError::Conflict)?;
    let Some(groups_value) = hooks.get_mut("PreToolUse") else {
        return Ok(Some(bytes.to_vec()));
    };
    let groups = groups_value
        .as_array_mut()
        .ok_or(IntegrationError::Conflict)?;
    for group in groups.iter() {
        if group
            .get("hooks")
            .is_some_and(|handlers| !handlers.is_array())
        {
            return Err(IntegrationError::Conflict);
        }
    }
    let mut changed = false;
    groups.retain_mut(|group| {
        let Some(group_object) = group.as_object_mut() else {
            return true;
        };
        let matcher_is_secmon =
            group_object.get("matcher").and_then(Value::as_str) == Some("^Bash$");
        let (removed, empty) =
            if let Some(handlers) = group_object.get_mut("hooks").and_then(Value::as_array_mut) {
                let old_len = handlers.len();
                handlers.retain(|handler| !is_secmon_hook(handler));
                (handlers.len() != old_len, handlers.is_empty())
            } else {
                (false, false)
            };
        changed |= removed;
        let has_only_secmon_group_fields = group_object.len() == 2
            && group_object.contains_key("matcher")
            && group_object.contains_key("hooks");
        !(removed && empty && matcher_is_secmon && has_only_secmon_group_fields)
    });
    if !changed {
        return Ok(Some(bytes.to_vec()));
    }
    if groups.is_empty() {
        hooks.remove("PreToolUse");
    }
    if hooks.is_empty() {
        root_object.remove("hooks");
    }
    if root_object.is_empty() && !existed_before {
        return Ok(None);
    }
    serde_json::to_vec_pretty(&root)
        .map(Some)
        .map_err(|_| IntegrationError::InvalidConfiguration)
}

fn is_secmon_hook(handler: &Value) -> bool {
    handler.get("command").and_then(Value::as_str) == Some("secmon hook run --agent-event")
        || handler.get("commandWindows").and_then(Value::as_str)
            == Some("secmon.exe hook run --agent-event")
}

fn remove_codex_entry(bytes: Option<&[u8]>) -> Result<Option<Vec<u8>>, IntegrationError> {
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let text = std::str::from_utf8(bytes).map_err(|_| IntegrationError::Conflict)?;
    let mut document = text
        .parse::<toml_edit::DocumentMut>()
        .map_err(|_| IntegrationError::Conflict)?;
    let Some(servers_item) = document.get_mut("mcp_servers") else {
        return Ok(Some(bytes.to_vec()));
    };
    let servers = servers_item
        .as_table_mut()
        .ok_or(IntegrationError::Conflict)?;
    if servers.remove("secmon").is_none() {
        return Ok(Some(bytes.to_vec()));
    }
    if servers.is_empty() {
        document.as_table_mut().remove("mcp_servers");
    }
    Ok(Some(document.to_string().into_bytes()))
}
