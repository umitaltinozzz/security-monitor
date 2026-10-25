use super::*;

pub(super) fn merge_mcp(before: &Option<Vec<u8>>) -> Result<Option<Vec<u8>>, IntegrationError> {
    let mut root = match before {
        Some(bytes) => {
            let text = std::str::from_utf8(bytes).map_err(|_| IntegrationError::Conflict)?;
            toml::from_str::<toml::Value>(text).map_err(|_| IntegrationError::Conflict)?
        }
        None => toml::Value::Table(toml::map::Map::new()),
    };
    let table = root.as_table_mut().ok_or(IntegrationError::Conflict)?;
    let servers = table
        .entry("mcp_servers")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    let servers = servers.as_table_mut().ok_or(IntegrationError::Conflict)?;
    let entry = toml::Value::try_from(McpServerEntry {
        command: "secmon".to_owned(),
        args: vec!["mcp".to_owned()],
    })
    .map_err(|_| IntegrationError::InvalidConfiguration)?;
    if let Some(existing) = servers.get("secmon") {
        if existing != &entry {
            return Err(IntegrationError::Conflict);
        }
    } else {
        servers.insert("secmon".to_owned(), entry);
    }
    toml::to_string_pretty(&root)
        .map(|text| Some(text.into_bytes()))
        .map_err(|_| IntegrationError::InvalidConfiguration)
}

pub(super) fn merge_hook(before: &Option<Vec<u8>>) -> Result<Option<Vec<u8>>, IntegrationError> {
    let handler = json!({"type":"command","command":"secmon hook run --agent-event","commandWindows":"secmon.exe hook run --agent-event","timeout":30});
    let hook_group = json!({"matcher":"^Bash$","hooks":[handler]});
    common::merge_hook_json(
        before,
        "PreToolUse",
        hook_group,
        "secmon hook run --agent-event",
    )
}
