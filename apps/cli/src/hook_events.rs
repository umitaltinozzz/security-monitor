use std::io::{self, Read};

use serde::Deserialize;

const MAX_EVENT_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GitOperation {
    Commit,
    Push,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct GitHookActions {
    pub(super) pre_commit: bool,
    pub(super) pre_push: bool,
}

#[derive(Debug, Deserialize)]
struct HookEvent {
    hook_event_name: Option<String>,
    tool_name: Option<String>,
    tool_input: Option<ToolInput>,
}

#[derive(Debug, Deserialize)]
struct ToolInput {
    command: Option<String>,
}

pub(super) fn actions_from_stdin() -> Result<GitHookActions, &'static str> {
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAX_EVENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "hook_input_invalid")?;
    if bytes.len() as u64 > MAX_EVENT_BYTES {
        return Err("hook_input_invalid");
    }
    actions_from_event(&bytes)
}

fn actions_from_event(bytes: &[u8]) -> Result<GitHookActions, &'static str> {
    let event: HookEvent = serde_json::from_slice(bytes).map_err(|_| "hook_input_invalid")?;
    if event.hook_event_name.as_deref() != Some("PreToolUse")
        || event.tool_name.as_deref() != Some("Bash")
    {
        return Ok(GitHookActions::default());
    }
    let command = event
        .tool_input
        .and_then(|input| input.command)
        .ok_or("hook_input_invalid")?;
    Ok(git_actions(&command))
}

fn git_actions(command: &str) -> GitHookActions {
    let mut actions = GitHookActions::default();
    for operation in shell_segments(command)
        .iter()
        .filter_map(|tokens| git_operation_in_segment(tokens))
    {
        match operation {
            GitOperation::Commit => actions.pre_commit = true,
            GitOperation::Push => actions.pre_push = true,
        }
    }
    actions
}

fn shell_segments(command: &str) -> Vec<Vec<String>> {
    let mut segments = Vec::new();
    let mut segment = Vec::new();
    let mut token = String::new();
    let mut quote = None;
    let mut substitution_quote = None;
    let mut substitution_depth = 0usize;
    let mut escaped = false;

    let mut characters = command.chars().peekable();
    while let Some(character) = characters.next() {
        if escaped {
            token.push(character);
            escaped = false;
            continue;
        }

        if substitution_depth > 0 {
            if character == '\\' && substitution_quote != Some('\'') {
                token.push(character);
                escaped = true;
            } else if let Some(active_quote) = substitution_quote {
                if character == active_quote {
                    substitution_quote = None;
                }
                token.push(character);
            } else if matches!(character, '\'' | '"') {
                substitution_quote = Some(character);
                token.push(character);
            } else if character == '(' {
                substitution_depth = substitution_depth.saturating_add(1);
                token.push(character);
            } else if character == ')' {
                substitution_depth = substitution_depth.saturating_sub(1);
                token.push(character);
            } else {
                token.push(character);
            }
            continue;
        }

        if character == '$'
            && quote != Some('\'')
            && characters.peek().is_some_and(|next| *next == '(')
        {
            token.push(character);
            if let Some(open) = characters.next() {
                token.push(open);
                substitution_depth = 1;
            }
            continue;
        }

        if let Some(active_quote) = quote {
            if character == active_quote {
                if active_quote == '`' {
                    token.push(character);
                }
                quote = None;
            } else {
                token.push(character);
            }
            continue;
        }

        if character == '\\' {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = Some(character);
        } else if character == '`' {
            quote = Some(character);
            token.push(character);
        } else if character.is_whitespace() {
            push_token(&mut segment, &mut token);
            if character == '\n' || character == '\r' {
                push_segment(&mut segments, &mut segment);
            }
        } else if matches!(character, ';' | '|' | '&' | '{' | '}' | '(' | ')') {
            push_token(&mut segment, &mut token);
            push_segment(&mut segments, &mut segment);
        } else {
            token.push(character);
        }
    }
    if escaped {
        token.push('\\');
    }
    push_token(&mut segment, &mut token);
    push_segment(&mut segments, &mut segment);
    segments
}

fn push_token(segment: &mut Vec<String>, token: &mut String) {
    if !token.is_empty() {
        segment.push(std::mem::take(token));
    }
}

fn push_segment(segments: &mut Vec<Vec<String>>, segment: &mut Vec<String>) {
    if !segment.is_empty() {
        segments.push(std::mem::take(segment));
    }
}

fn git_operation_in_segment(tokens: &[String]) -> Option<GitOperation> {
    let mut index = 0;
    while tokens.get(index).is_some_and(|token| {
        token == "if" || token == "then" || token == "else" || token == "do" || token == "!"
    }) {
        index += 1;
    }
    loop {
        while tokens
            .get(index)
            .is_some_and(|token| token.contains('=') && !token.starts_with('-'))
        {
            index += 1;
        }
        match tokens.get(index).map(String::as_str) {
            Some("command" | "builtin" | "time" | "exec") => index += 1,
            Some("env") => {
                index += 1;
                while tokens
                    .get(index)
                    .is_some_and(|option| option.starts_with('-'))
                {
                    let option = tokens[index].as_str();
                    index += 1;
                    if matches!(
                        option,
                        "-u" | "--unset" | "-C" | "--chdir" | "-S" | "--split-string"
                    ) {
                        index += 1;
                    }
                }
            }
            Some("sudo") => {
                index += 1;
                while tokens
                    .get(index)
                    .is_some_and(|option| option.starts_with('-'))
                {
                    let option = tokens[index].as_str();
                    index += 1;
                    if matches!(
                        option,
                        "-u" | "--user"
                            | "-g"
                            | "--group"
                            | "-h"
                            | "--host"
                            | "-p"
                            | "--prompt"
                            | "-C"
                            | "--chdir"
                            | "-D"
                    ) {
                        index += 1;
                    }
                }
            }
            _ => break,
        }
    }
    let executable = tokens.get(index)?;
    if is_dynamic_command_name(executable) {
        return git_operation_after_executable(tokens, index);
    }
    let executable_name = executable.rsplit(['/', '\\']).next().unwrap_or(executable);
    if !matches!(
        executable_name.to_ascii_lowercase().as_str(),
        "git" | "git.exe"
    ) {
        return None;
    }
    git_operation_after_executable(tokens, index)
}

fn is_dynamic_command_name(executable: &str) -> bool {
    executable
        .chars()
        .any(|character| matches!(character, '$' | '`' | '*' | '?' | '['))
}

fn git_operation_after_executable(
    tokens: &[String],
    executable_index: usize,
) -> Option<GitOperation> {
    let mut index = executable_index + 1;
    while let Some(option) = tokens.get(index) {
        if matches!(
            option.as_str(),
            "-C" | "-c"
                | "--git-dir"
                | "--work-tree"
                | "--namespace"
                | "--config-env"
                | "--exec-path"
                | "--super-prefix"
        ) {
            index += 2;
        } else if option.starts_with('-') {
            index += 1;
        } else {
            break;
        }
    }
    match tokens.get(index).map(String::as_str) {
        Some("commit") => Some(GitOperation::Commit),
        Some("push") => Some(GitOperation::Push),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(command: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        }))
        .unwrap()
    }

    #[test]
    fn accepts_git_commit_and_push_from_agent_events() {
        assert_eq!(
            actions_from_event(&event("git -C repo commit -m 'update'")),
            Ok(GitHookActions {
                pre_commit: true,
                pre_push: false,
            })
        );
        assert_eq!(
            actions_from_event(&event("git push origin main")),
            Ok(GitHookActions {
                pre_commit: false,
                pre_push: true,
            })
        );
        assert_eq!(
            actions_from_event(&event("echo done && git push")),
            Ok(GitHookActions {
                pre_commit: false,
                pre_push: true,
            })
        );
        assert_eq!(
            actions_from_event(&event("git commit -m ready && git push")),
            Ok(GitHookActions {
                pre_commit: true,
                pre_push: true,
            })
        );
        assert_eq!(
            actions_from_event(&event("env GIT_TRACE=0 git commit -m ready")),
            Ok(GitHookActions {
                pre_commit: true,
                pre_push: false,
            })
        );
        assert_eq!(
            actions_from_event(&event("GIT=git; \"$GIT\" push origin main")),
            Ok(GitHookActions {
                pre_commit: false,
                pre_push: true,
            })
        );
        assert_eq!(
            actions_from_event(&event("$(printf git) commit -m ready")),
            Ok(GitHookActions {
                pre_commit: true,
                pre_push: false,
            })
        );
        assert_eq!(
            actions_from_event(&event("`printf git` push origin main")),
            Ok(GitHookActions {
                pre_commit: false,
                pre_push: true,
            })
        );
    }

    #[test]
    fn ignores_other_commands_and_quoted_mentions() {
        for command in [
            "git status",
            "echo 'git commit'",
            "printf \"git push\\n\"",
            "GIT=git; \"$GIT\" status",
            "echo \"$GIT push\"",
        ] {
            assert_eq!(
                actions_from_event(&event(command)),
                Ok(GitHookActions::default())
            );
        }
    }

    #[test]
    fn validates_agent_event_shape() {
        assert_eq!(
            actions_from_event(br#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"git push"}}"#),
            Ok(GitHookActions::default())
        );
        assert_eq!(
            actions_from_event(
                br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{}}"#
            ),
            Err("hook_input_invalid")
        );
        assert_eq!(actions_from_event(b"{"), Err("hook_input_invalid"));
    }
}
