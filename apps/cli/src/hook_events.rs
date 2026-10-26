use std::{
    collections::BTreeMap,
    io::{self, Read},
};

use serde::Deserialize;

const MAX_EVENT_BYTES: u64 = 256 * 1024;
const MAX_REEVALUATED_SHELL_DEPTH: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GitOperation {
    Commit,
    Push,
    Unknown,
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
    let mut variables = BTreeMap::new();
    collect_git_actions(command, &mut variables, &mut actions, 0);
    actions
}

fn collect_git_actions(
    command: &str,
    variables: &mut BTreeMap<String, String>,
    actions: &mut GitHookActions,
    depth: usize,
) -> bool {
    let mut found_action = false;
    for tokens in shell_segments(command) {
        record_literal_assignments(&tokens, variables);
        if let Some(nested_command) = reevaluated_shell_command(&tokens) {
            if depth >= MAX_REEVALUATED_SHELL_DEPTH {
                actions.pre_commit = true;
                actions.pre_push = true;
                found_action = true;
                continue;
            }
            let nested_action = collect_git_actions(&nested_command, variables, actions, depth + 1);
            if !nested_action && contains_shell_expansion(&nested_command) {
                actions.pre_commit = true;
                actions.pre_push = true;
                found_action = true;
            } else {
                found_action |= nested_action;
            }
            continue;
        }
        let Some(operation) = git_operation_in_segment(&tokens, variables) else {
            continue;
        };
        match operation {
            GitOperation::Commit => actions.pre_commit = true,
            GitOperation::Push => actions.pre_push = true,
            GitOperation::Unknown => {
                actions.pre_commit = true;
                actions.pre_push = true;
            }
        }
        found_action = true;
    }
    found_action
}

fn reevaluated_shell_command(tokens: &[String]) -> Option<String> {
    let executable = tokens.first()?;
    let executable_name = executable.rsplit(['/', '\\']).next()?.to_ascii_lowercase();
    if executable_name == "eval" {
        let command = tokens.get(1..)?.join(" ");
        return (!command.is_empty()).then_some(command);
    }
    if !matches!(
        executable_name.as_str(),
        "sh" | "bash" | "dash" | "zsh" | "ksh" | "ash"
    ) {
        return None;
    }
    let command_flag = tokens
        .iter()
        .enumerate()
        .skip(1)
        .find_map(|(index, token)| {
            (token == "-c" || token == "--command")
                .then_some(index)
                .or_else(|| (token.starts_with('-') && token[1..].contains('c')).then_some(index))
        })?;
    tokens.get(command_flag + 1).cloned()
}

fn contains_shell_expansion(command: &str) -> bool {
    command
        .chars()
        .any(|character| matches!(character, '$' | '`' | '*' | '?' | '['))
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

fn record_literal_assignments(tokens: &[String], variables: &mut BTreeMap<String, String>) {
    if tokens.is_empty() {
        return;
    }
    match tokens[0].as_str() {
        "export" => {
            for token in tokens
                .iter()
                .skip(1)
                .filter(|token| !token.starts_with('-'))
            {
                record_variable_assignment(token, variables);
            }
            return;
        }
        "unset" => {
            for name in tokens.iter().skip(1).filter(|name| !name.starts_with('-')) {
                if valid_shell_variable_name(name) {
                    variables.remove(name);
                }
            }
            return;
        }
        "read" => {
            for name in read_variable_names(tokens) {
                variables.remove(name);
            }
            return;
        }
        _ => {}
    }
    let assignments = tokens
        .iter()
        .map(|token| token.split_once('='))
        .collect::<Option<Vec<_>>>();
    let Some(assignments) = assignments else {
        return;
    };
    for (name, value) in assignments {
        if valid_shell_variable_name(name) {
            record_variable_assignment_parts(name, value, variables);
        }
    }
}

fn read_variable_names(tokens: &[String]) -> Vec<&str> {
    let mut index = 1;
    while let Some(option) = tokens.get(index) {
        if option == "--" {
            index += 1;
            break;
        }
        if !option.starts_with('-') || option == "-" {
            break;
        }
        index += 1;
        if matches!(
            option.as_str(),
            "-a" | "-d" | "-i" | "-n" | "-N" | "-p" | "-t" | "-u"
        ) {
            index = index.saturating_add(1);
        }
    }
    let names: Vec<_> = tokens
        .iter()
        .skip(index)
        .map(String::as_str)
        .filter(|name| valid_shell_variable_name(name))
        .collect();
    if names.is_empty() {
        vec!["REPLY"]
    } else {
        names
    }
}

fn record_variable_assignment(token: &str, variables: &mut BTreeMap<String, String>) {
    if let Some((name, value)) = token
        .split_once('=')
        .filter(|(name, _)| valid_shell_variable_name(name))
    {
        record_variable_assignment_parts(name, value, variables);
    }
}

fn record_variable_assignment_parts(
    name: &str,
    value: &str,
    variables: &mut BTreeMap<String, String>,
) {
    if is_dynamic_command_name(value) {
        variables.remove(name);
    } else {
        variables.insert(name.to_owned(), value.to_owned());
    }
}

fn valid_shell_variable_name(name: &str) -> bool {
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn git_operation_in_segment(
    tokens: &[String],
    variables: &BTreeMap<String, String>,
) -> Option<GitOperation> {
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
    if let Some(value) = simple_variable_value(executable, variables) {
        let mut expanded_tokens = value
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if expanded_tokens.is_empty() {
            return None;
        }
        expanded_tokens.extend_from_slice(&tokens[index + 1..]);
        return git_operation_in_segment(&expanded_tokens, variables);
    }
    if is_dynamic_command_name(executable) {
        return Some(
            git_operation_after_executable(tokens, index).unwrap_or(GitOperation::Unknown),
        );
    }
    if !is_git_executable(executable) {
        return None;
    }
    git_operation_after_executable(tokens, index)
}

fn simple_variable_value<'a>(
    executable: &str,
    variables: &'a BTreeMap<String, String>,
) -> Option<&'a str> {
    let name = executable
        .strip_prefix("${")
        .and_then(|name| name.strip_suffix('}'))
        .or_else(|| executable.strip_prefix('$'))?;
    if !valid_shell_variable_name(name) {
        return None;
    }
    variables.get(name).map(String::as_str)
}

fn is_git_executable(executable: &str) -> bool {
    let executable_name = executable.rsplit(['/', '\\']).next().unwrap_or(executable);
    matches!(
        executable_name.to_ascii_lowercase().as_str(),
        "git" | "git.exe"
    )
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
            actions_from_event(&event("CMD='git push origin main'; $CMD")),
            Ok(GitHookActions {
                pre_commit: false,
                pre_push: true,
            })
        );
        assert_eq!(
            actions_from_event(&event("CMD='git commit -m ready'; $CMD")),
            Ok(GitHookActions {
                pre_commit: true,
                pre_push: false,
            })
        );
        assert_eq!(
            actions_from_event(&event(
                "OTHER=echo; export OTHER=git; \"$OTHER\" commit -m ready"
            )),
            Ok(GitHookActions {
                pre_commit: true,
                pre_push: false,
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
            "OTHER=echo; \"$OTHER\" commit -m ready",
            "CMD='echo git push origin main'; $CMD",
        ] {
            assert_eq!(
                actions_from_event(&event(command)),
                Ok(GitHookActions::default())
            );
        }
    }

    #[test]
    fn detects_git_actions_re_evaluated_by_shells() {
        for (command, expected) in [
            (
                "eval 'git push origin main'",
                GitHookActions {
                    pre_commit: false,
                    pre_push: true,
                },
            ),
            (
                "bash -c 'git push origin main'",
                GitHookActions {
                    pre_commit: false,
                    pre_push: true,
                },
            ),
            (
                "sh -c 'git commit -m ready'",
                GitHookActions {
                    pre_commit: true,
                    pre_push: false,
                },
            ),
            ("bash -c 'echo git push'", GitHookActions::default()),
            (
                "eval \"$COMMAND\"",
                GitHookActions {
                    pre_commit: true,
                    pre_push: true,
                },
            ),
            (
                "CMD=\"$(printf 'git push origin main')\"; $CMD",
                GitHookActions {
                    pre_commit: true,
                    pre_push: true,
                },
            ),
        ] {
            assert_eq!(
                actions_from_event(&event(command)),
                Ok(expected),
                "{command}"
            );
        }
    }

    #[test]
    fn read_builtin_invalidates_tracked_command_aliases() {
        assert_eq!(
            actions_from_event(&event(
                "GIT=echo; read -r GIT <<<git; \"$GIT\" push origin main"
            )),
            Ok(GitHookActions {
                pre_commit: false,
                pre_push: true,
            })
        );
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
