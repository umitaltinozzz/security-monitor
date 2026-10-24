---
title: Coding-agent integrations
description: Configure secmon MCP tools, skills, and local hooks for Claude Code, Codex, and OpenCode.
---

# Coding-agent integrations

`secmon integrate` adds the local stdio MCP server, the Security Monitor skill, and a pre-tool hook when the coding agent supports one. The agent runs the `secmon` binary already installed on the same device. These integrations do not upload project files or contact a service.

## Preview, install, and remove

```text
secmon integrate <claude-code|codex|opencode> --dry-run
secmon integrate <claude-code|codex|opencode>
secmon integrate remove <claude-code|codex|opencode>
```

Installation defaults to user scope. Use `--scope project` to install into the current project or `--project <path>` to select a project directory. The preview displays the changes and redacts common secret fields. Installation requires confirmation unless `--yes` is passed.

Before installation, Security Monitor saves any existing configuration bytes in the operating system credential store. The manifest contains only paths, hashes, and opaque credential references. Removal restores the original files byte for byte. If an installed file has changed since installation, removal stops and leaves the user's edits in place.

| Agent | User scope | Project scope | Added hook |
| --- | --- | --- | --- |
| Claude Code | `~/.claude.json`, `~/.claude/settings.json`, `~/.claude/skills/secmon/SKILL.md` | `.mcp.json`, `.claude/settings.json`, `.claude/skills/secmon/SKILL.md` | `PreToolUse` for Bash |
| Codex | `~/.codex/config.toml`, `~/.codex/hooks.json`, `~/.agents/skills/secmon/SKILL.md` | `.codex/config.toml`, `.codex/hooks.json`, `.agents/skills/secmon/SKILL.md` | `PreToolUse` for Bash |
| OpenCode | `~/.config/opencode/opencode.json`, `~/.config/opencode/plugins/secmon.js`, `~/.config/opencode/skills/secmon/SKILL.md` | `opencode.json`, `.opencode/plugins/secmon.js`, `.opencode/skills/secmon/SKILL.md` | `tool.execute.before` |

The MCP server loads the project's current local database and tool permissions. Source reads also require a separate per-project grant recorded by the desktop app. See [Local MCP](local-mcp.md).

Agent hooks are a convenience check. The skill also instructs the agent to call `secmon hook run` before a Git commit or push. Install a repository Git hook with `secmon hook install` when you want the local Git workflow itself to perform the check; Git hooks support `warn` and `block` modes. Agent hooks do not replace that repository-level enforcement.

## Vendor references

- [Claude Code MCP configuration](https://code.claude.com/docs/en/mcp) and [hooks](https://code.claude.com/docs/en/hooks)
- [Codex MCP configuration](https://developers.openai.com/codex/mcp), [configuration reference](https://developers.openai.com/codex/config-reference), and [hooks](https://developers.openai.com/codex/hooks)
- [OpenCode MCP servers](https://docs.opencode.ai/docs/mcp-servers/), [skills](https://docs.opencode.ai/docs/skills/), and [plugins](https://docs.opencode.ai/docs/plugins/)
