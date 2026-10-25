use super::*;

pub(crate) const OPENCODE_PLUGIN: &str = r#"export const SecmonPlugin = async ({ directory }) => ({
  "tool.execute.before": async (input, output) => {
    if (input.tool !== "bash") return;
    const command = output.args?.command;
    if (typeof command !== "string") return;
    const child = Bun.spawn(["secmon", "hook", "run", "--agent-event"], {
      cwd: directory,
      stdin: "pipe",
      stdout: "ignore",
      stderr: "pipe",
    });
    child.stdin.write(JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: { command },
    }));
    child.stdin.end();
    const exitCode = await child.exited;
    if (exitCode !== 0) {
      const detail = await new Response(child.stderr).text();
      throw new Error(detail || "Security Monitor blocked the Git operation.");
    }
  },
});
"#;

pub(super) fn mcp_entry() -> Value {
    json!({"type":"local","command":["secmon","mcp"],"enabled":true})
}

pub(super) fn merge_mcp(before: &Option<Vec<u8>>) -> Result<Option<Vec<u8>>, IntegrationError> {
    common::merge_json(before, "mcp", "secmon", mcp_entry())
}

pub(super) fn merge_hook(before: &Option<Vec<u8>>) -> Result<Option<Vec<u8>>, IntegrationError> {
    if before.as_deref().is_some_and(|existing| {
        existing != OPENCODE_PLUGIN.as_bytes() && existing != PREVIOUS_OPENCODE_PLUGIN.as_bytes()
    }) {
        return Err(IntegrationError::Conflict);
    }
    Ok(Some(OPENCODE_PLUGIN.as_bytes().to_vec()))
}

const PREVIOUS_OPENCODE_PLUGIN: &str = r#"export const SecmonPlugin = async ({ directory }) => ({
  "tool.execute.before": async (input, output) => {
    if (input.tool !== "bash") return;
    const command = output.args?.command;
    if (typeof command !== "string" || !/\bgit\b[\s\S]{0,96}\b(commit|push)\b/.test(command)) return;
    const child = Bun.spawn(["secmon", "hook", "run"], {
      cwd: directory,
      stdin: "ignore",
      stdout: "ignore",
      stderr: "pipe",
    });
    const exitCode = await child.exited;
    if (exitCode !== 0) {
      const detail = await new Response(child.stderr).text();
      throw new Error(detail || "Security Monitor blocked the Git operation.");
    }
  },
});
"#;
