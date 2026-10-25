use super::*;

pub(super) fn merge_mcp(before: &Option<Vec<u8>>) -> Result<Option<Vec<u8>>, IntegrationError> {
    let mut root = match before {
        Some(bytes) => {
            let text = std::str::from_utf8(bytes).map_err(|_| IntegrationError::Conflict)?;
            text.parse::<toml_edit::DocumentMut>()
                .map_err(|_| IntegrationError::Conflict)?
        }
        None => toml_edit::DocumentMut::new(),
    };
    let table = root.as_table_mut();
    if !table.contains_key("mcp_servers") {
        table.insert(
            "mcp_servers",
            toml_edit::Item::Table(toml_edit::Table::new()),
        );
    }
    let servers = table
        .get_mut("mcp_servers")
        .and_then(toml_edit::Item::as_table_mut)
        .ok_or(IntegrationError::Conflict)?;
    let expected = McpServerEntry {
        command: "secmon".to_owned(),
        args: vec!["mcp".to_owned()],
    };
    if let Some(existing) = servers.get("secmon") {
        if !is_secmon_mcp_entry(existing, &expected) {
            return Err(IntegrationError::Conflict);
        }
    } else {
        let mut entry = toml_edit::Table::new();
        entry.insert("command", toml_edit::value(expected.command));
        let mut args = toml_edit::Array::new();
        args.push("mcp");
        entry.insert("args", toml_edit::value(args));
        servers.insert("secmon", toml_edit::Item::Table(entry));
    }
    Ok(Some(root.to_string().into_bytes()))
}

fn is_secmon_mcp_entry(item: &toml_edit::Item, expected: &McpServerEntry) -> bool {
    if let Some(table) = item.as_table() {
        return table.len() == 2
            && table.get("command").and_then(toml_edit::Item::as_str)
                == Some(expected.command.as_str())
            && table
                .get("args")
                .and_then(toml_edit::Item::as_array)
                .is_some_and(|args| {
                    args.len() == expected.args.len()
                        && args.get(0).and_then(toml_edit::Value::as_str)
                            == Some(expected.args[0].as_str())
                });
    }
    if let Some(table) = item.as_inline_table() {
        return table.len() == 2
            && table.get("command").and_then(toml_edit::Value::as_str)
                == Some(expected.command.as_str())
            && table
                .get("args")
                .and_then(toml_edit::Value::as_array)
                .is_some_and(|args| {
                    args.len() == expected.args.len()
                        && args.get(0).and_then(toml_edit::Value::as_str)
                            == Some(expected.args[0].as_str())
                });
    }
    false
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
