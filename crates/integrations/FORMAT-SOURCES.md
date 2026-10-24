# Integration format references

The agent paths and formats are data in agents.toml; the behavior below was checked against the vendors' current documentation on 2026-10-24.

- Claude Code project MCP files use `.mcp.json` with the `mcpServers` object; user MCP configuration is stored in `~/.claude.json`. Project and user hooks use `.claude/settings.json` and `~/.claude/settings.json`, with `PreToolUse` command handlers: https://code.claude.com/docs/en/mcp and https://code.claude.com/docs/en/hooks
- Codex loads MCP configuration from `config.toml` under `mcp_servers`; hooks are discovered in `hooks.json` next to user/project config layers. Hooks receive a JSON event on stdin, support `PreToolUse`, and allow a Windows command override: https://developers.openai.com/codex/mcp, https://developers.openai.com/codex/config-reference, and https://developers.openai.com/codex/hooks
- OpenCode's current stable config uses the `mcp` object with named server entries (including local `type` and `command`), project config `opencode.json`, skills under `.opencode/skills/`, plugins under `.opencode/plugins/`, and the `tool.execute.before` hook: https://docs.opencode.ai/docs/mcp-servers/, https://docs.opencode.ai/docs/config/, https://docs.opencode.ai/docs/skills/, and https://docs.opencode.ai/docs/plugins/

Integration hooks inspect pending Git command input and invoke the installed secmon hook run binary with fixed arguments. They do not execute or rewrite the model-provided command. Git hooks remain the authoritative local check when installed.
