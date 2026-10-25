use super::*;

pub(super) fn mcp_entry() -> Value {
    json!({"command":"secmon","args":["mcp"]})
}

pub(super) fn merge_mcp(before: &Option<Vec<u8>>) -> Result<Option<Vec<u8>>, IntegrationError> {
    common::merge_json(before, "mcpServers", "secmon", mcp_entry())
}

pub(super) fn merge_hook(before: &Option<Vec<u8>>) -> Result<Option<Vec<u8>>, IntegrationError> {
    let handler = json!({"type":"command","command":"secmon hook run --agent-event","timeout":30});
    let hook_group = json!({"matcher":"Bash","hooks":[handler]});
    common::merge_hook_json(
        before,
        "PreToolUse",
        hook_group,
        "secmon hook run --agent-event",
    )
}
