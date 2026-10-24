use regex::Regex;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionResult {
    pub text: String,
    pub redacted_values: usize,
}

pub fn is_sensitive_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    normalized.split('/').any(|part| {
        let lower = part.to_ascii_lowercase();
        lower == ".env"
            || lower.starts_with(".env")
            || lower.ends_with(".pem")
            || lower.ends_with(".key")
            || lower.ends_with(".p12")
            || lower.ends_with(".pfx")
            || lower.ends_with(".secret")
            || lower.starts_with("id_")
            || lower.starts_with("credentials")
            || lower == ".netrc"
            || lower == ".npmrc"
            || lower == ".pypirc"
            || lower == ".git"
            || lower == ".ssh"
            || lower == ".aws"
            || lower == ".gnupg"
    })
}

pub fn redact_relative_path(project_root: &str, path: &str) -> Option<String> {
    if is_sensitive_path(path) {
        return None;
    }
    let root = std::path::Path::new(project_root).canonicalize().ok()?;
    let candidate = std::path::Path::new(path);
    let canonical = if candidate.is_absolute() {
        candidate.canonicalize().ok()?
    } else {
        root.join(candidate).canonicalize().ok()?
    };
    if !canonical.starts_with(&root) {
        return None;
    }
    let relative = canonical.strip_prefix(root).ok()?;
    Some(format!(
        "<project>/{}",
        relative.to_string_lossy().replace('\\', "/")
    ))
}

pub fn redact_text(input: &str) -> RedactionResult {
    redact_text_with_host_aliases(input, &std::collections::BTreeMap::new())
}

pub fn redact_text_with_host_aliases(
    input: &str,
    host_aliases: &std::collections::BTreeMap<String, String>,
) -> RedactionResult {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        [
            r#"(?i)(api[_-]?key|access[_-]?token|token|secret|password|authorization)[\"']?\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"#,
            r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
            r"(?i)\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})\b",
            r"(?i)\bAKIA[0-9A-Z]{16}\b",
            r"(?i)\b[0-9a-f]{32,}\b",
            r"(?i)\b(?:xox[baprs]-[A-Za-z0-9-]{20,}|AIza[A-Za-z0-9_-]{30,}|sk_(?:live|test)_[A-Za-z0-9]{16,})\b",
            r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{20,}={0,2}",
            r"(?i)\b[a-z][a-z0-9+.-]*://[^/@\s:]*:[^/@\s]+@[^/\s?#]+(?:/[^\s?#]*)?(?:\?[^\s#]*)?",
            r#"(^|[\s"'(])([A-Z]:\\(?:[^\\\s"']+\\)*[^\\\s"']*)"#,
            r#"(^|[\s"'(])(/[^/\s"']+(?:/[^/\s"']*)*)"#,
        ]
        .into_iter()
        .filter_map(|pattern| Regex::new(pattern).ok())
        .collect()
    });
    let mut text = input.to_owned();
    let mut redacted_values = 0;
    for pattern in patterns {
        let count = pattern.find_iter(&text).count();
        if count > 0 {
            text = if pattern.captures_len() > 2 {
                pattern.replace_all(&text, "$1[REDACTED_PATH]").into_owned()
            } else {
                pattern.replace_all(&text, "[REDACTED]").into_owned()
            };
            redacted_values += count;
        }
    }
    let (redacted_yaml_lists, yaml_list_redactions) = redact_yaml_host_lists(&text, host_aliases);
    text = redacted_yaml_lists;
    redacted_values += yaml_list_redactions;
    let (redacted_nginx_upstreams, nginx_upstream_redactions) =
        redact_nginx_upstream_servers(&text, host_aliases);
    text = redacted_nginx_upstreams;
    redacted_values += nginx_upstream_redactions;
    static HOST_FIELD: OnceLock<Option<Regex>> = OnceLock::new();
    if let Some(host_field) = HOST_FIELD
        .get_or_init(|| {
            let host_value = r"(?:\[[0-9a-f:.%a-z0-9_-]+\]|(?:[0-9a-f]{0,4}:){2,}[0-9a-z_.:%-]+|[a-z0-9](?:[a-z0-9_.-]{0,252}[a-z0-9])?)";
            let host_sequence = format!(
                r#"(?:{host_value}(?:\s*,\s*{host_value})*|\[[^\]\r\n]*\])"#
            );
            let pattern = format!(
                r#"(?i)(\b[a-z0-9_.-]*(?:hostname|host|server|address|ip|domain|external(?:[_-]?name)?)(?:s|[_-]?names?)?\b[\"']?\s*[:=]\s*[\"']?)({host_sequence})([\"']?)"#
            );
            Regex::new(&pattern).ok()
        })
        .as_ref()
    {
        let mut host_redactions = 0;
        text = host_field
            .replace_all(&text, |captures: &regex::Captures<'_>| {
                let value = captures
                    .get(2)
                    .map(|matched| matched.as_str())
                    .unwrap_or_default();
                let trimmed = value.trim();
                let is_array = trimmed.starts_with('[')
                    && trimmed.ends_with(']')
                    && (trimmed.contains(',')
                        || trimmed.contains('\"')
                        || trimmed.contains('\'')
                        || !trimmed[1..trimmed.len() - 1].contains(':'));
                let array_contents = if is_array {
                    &trimmed[1..trimmed.len() - 1]
                } else {
                    trimmed
                };
                let replacements = array_contents
                    .split(',')
                    .map(|value| {
                        host_redactions += 1;
                        redact_host_token(value, host_aliases)
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                let leading = value.len() - value.trim_start().len();
                let trailing = value.len() - value.trim_end().len();
                let suffix_start = value.len().saturating_sub(trailing);
                let formatted = if is_array {
                    format!("{}[{}]{}", &value[..leading], replacements, &value[suffix_start..])
                } else {
                    format!("{}{}{}", &value[..leading], replacements, &value[suffix_start..])
                };
                format!("{}{}{}", &captures[1], formatted, &captures[3])
            })
            .into_owned();
        redacted_values += host_redactions;
    }
    static URL_HOST: OnceLock<Option<Regex>> = OnceLock::new();
    if let Some(url_host) = URL_HOST
        .get_or_init(|| {
            Regex::new(
                r#"(?i)\b([a-z][a-z0-9+.-]*://)(?:[^/@\s]+@)?(\[[0-9a-f:.%a-z0-9_-]+\]|[^/:?\s#]+)(:[0-9]+)?"#,
            )
            .ok()
        })
        .as_ref()
    {
        let mut host_redactions = 0;
        text = url_host
            .replace_all(&text, |captures: &regex::Captures<'_>| {
                let host = captures
                    .get(2)
                    .map(|matched| matched.as_str())
                    .unwrap_or_default();
                let replacement = host_aliases
                    .get(&host.to_ascii_lowercase())
                    .map(String::as_str)
                    .unwrap_or("[REDACTED_HOST]");
                let port = captures.get(3).map_or("", |matched| matched.as_str());
                host_redactions += 1;
                format!("{}{}{}", &captures[1], replacement, port)
            })
            .into_owned();
        redacted_values += host_redactions;
    }
    static SCP_REMOTE: OnceLock<Option<Regex>> = OnceLock::new();
    if let Some(scp_remote) = SCP_REMOTE
        .get_or_init(|| {
            Regex::new(
                r#"(?i)(^|[\s\"'(=])([a-z0-9_.-]+@)(\[[0-9a-f:.%a-z0-9_-]+\]|[a-z0-9](?:[a-z0-9.-]{0,252}[a-z0-9])?)(:)"#,
            )
            .ok()
        })
        .as_ref()
    {
        let mut host_redactions = 0;
        text = scp_remote
            .replace_all(&text, |captures: &regex::Captures<'_>| {
                let host = captures
                    .get(3)
                    .map(|matched| matched.as_str())
                    .unwrap_or_default();
                let replacement = host_aliases
                    .get(&host.to_ascii_lowercase())
                    .map(String::as_str)
                    .unwrap_or("[REDACTED_HOST]");
                host_redactions += 1;
                format!("{}{}{}{}", &captures[1], &captures[2], replacement, &captures[4])
            })
            .into_owned();
        redacted_values += host_redactions;
    }
    static ENTROPY_TOKEN: OnceLock<Option<Regex>> = OnceLock::new();
    let Some(entropy_token) = ENTROPY_TOKEN
        .get_or_init(|| Regex::new(r"\b[A-Za-z0-9_+/=-]{24,}\b").ok())
        .as_ref()
    else {
        return RedactionResult {
            text,
            redacted_values,
        };
    };
    let mut entropy_redactions = 0;
    text = entropy_token
        .replace_all(&text, |captures: &regex::Captures<'_>| {
            let token = captures
                .get(0)
                .map(|matched| matched.as_str())
                .unwrap_or_default();
            if shannon_entropy(token) >= 3.6
                && token
                    .chars()
                    .any(|character| character.is_ascii_lowercase())
                && token
                    .chars()
                    .any(|character| character.is_ascii_uppercase())
                && token.chars().any(|character| character.is_ascii_digit())
            {
                entropy_redactions += 1;
                "[REDACTED]".to_owned()
            } else {
                token.to_owned()
            }
        })
        .into_owned();
    redacted_values += entropy_redactions;
    RedactionResult {
        text,
        redacted_values,
    }
}

fn redact_yaml_host_lists(
    input: &str,
    host_aliases: &std::collections::BTreeMap<String, String>,
) -> (String, usize) {
    static HOST_LIST_KEY: OnceLock<Option<Regex>> = OnceLock::new();
    let Some(host_list_key) = HOST_LIST_KEY
        .get_or_init(|| {
            Regex::new(
                r#"(?i)^([ \t]*)[\"']?[a-z0-9_.-]*(?:hostname|host|server|address|ip|domain|external(?:[_-]?name)?)(?:s|[_-]?names?)?[\"']?:[ \t]*(?:#.*)?$"#,
            )
            .ok()
        })
        .as_ref()
    else {
        return (input.to_owned(), 0);
    };
    static HOST_LIST_ITEM: OnceLock<Option<Regex>> = OnceLock::new();
    let Some(host_list_item) = HOST_LIST_ITEM
        .get_or_init(|| Regex::new(r"^([ \t]*-[ \t]+)([^ \t#]+)([ \t]*(?:#.*)?)$").ok())
        .as_ref()
    else {
        return (input.to_owned(), 0);
    };

    let mut output = String::with_capacity(input.len());
    let mut list_indent = None;
    let mut redacted_values = 0;
    for line in input.split_inclusive('\n') {
        let (content, newline) = if let Some(content) = line.strip_suffix("\r\n") {
            (content, "\r\n")
        } else if let Some(content) = line.strip_suffix('\n') {
            (content, "\n")
        } else {
            (line, "")
        };
        if let Some(captures) = host_list_key.captures(content) {
            list_indent = captures.get(1).map(|indent| indent.as_str().len());
            output.push_str(line);
            continue;
        }
        if let Some(key_indent) = list_indent {
            if content.trim().is_empty() {
                output.push_str(line);
                continue;
            }
            let indent = content
                .bytes()
                .take_while(|byte| matches!(byte, b' ' | b'\t'))
                .count();
            if indent <= key_indent {
                list_indent = None;
            } else if let Some(captures) = host_list_item.captures(content) {
                let item = captures.get(2).map_or("", |value| value.as_str());
                output.push_str(&captures[1]);
                output.push_str(&redact_host_token(item, host_aliases));
                output.push_str(&captures[3]);
                output.push_str(newline);
                redacted_values += 1;
                continue;
            }
        }
        output.push_str(line);
    }
    (output, redacted_values)
}

fn redact_nginx_upstream_servers(
    input: &str,
    host_aliases: &std::collections::BTreeMap<String, String>,
) -> (String, usize) {
    static UPSTREAM_BLOCK: OnceLock<Option<Regex>> = OnceLock::new();
    let Some(upstream_block) = UPSTREAM_BLOCK
        .get_or_init(|| Regex::new(r"(?is)(\bupstream\s+[a-z0-9_.-]+\s*\{)([^}]*)(\})").ok())
        .as_ref()
    else {
        return (input.to_owned(), 0);
    };
    static SERVER_DIRECTIVE: OnceLock<Option<Regex>> = OnceLock::new();
    let Some(server_directive) = SERVER_DIRECTIVE
        .get_or_init(|| {
            Regex::new(r"(?i)(^[ \t]*|[;{}\r\n][ \t]*)(server[ \t]+)([^\s;#]+)([^;]*;)").ok()
        })
        .as_ref()
    else {
        return (input.to_owned(), 0);
    };

    let mut redacted_values = 0;
    let output = upstream_block
        .replace_all(input, |block: &regex::Captures<'_>| {
            let directives = block.get(2).map_or("", |matched| matched.as_str());
            let redacted_directives =
                server_directive.replace_all(directives, |server: &regex::Captures<'_>| {
                    let target = server.get(3).map_or("", |matched| matched.as_str());
                    let (host, port) = split_host_port(target);
                    redacted_values += 1;
                    format!(
                        "{}{}{}{}{}",
                        &server[1],
                        &server[2],
                        redact_host_token(host, host_aliases),
                        port,
                        &server[4]
                    )
                });
            format!("{}{}{}", &block[1], redacted_directives, &block[3])
        })
        .into_owned();
    (output, redacted_values)
}

fn split_host_port(target: &str) -> (&str, &str) {
    if let Some(bracket_end) = target.find(']') {
        let host_end = bracket_end + 1;
        let suffix = &target[host_end..];
        if suffix
            .strip_prefix(':')
            .is_some_and(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return (&target[..host_end], suffix);
        }
    } else if let Some((host, port)) = target.rsplit_once(':')
        && !host.contains(':')
        && !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
    {
        return (host, &target[host.len()..]);
    }
    (target, "")
}

fn redact_host_token(
    value: &str,
    host_aliases: &std::collections::BTreeMap<String, String>,
) -> String {
    let leading = value.len() - value.trim_start().len();
    let trailing = value.len() - value.trim_end().len();
    let suffix_start = value.len().saturating_sub(trailing);
    let trimmed = &value[leading..suffix_start];
    let quote = trimmed
        .chars()
        .next()
        .filter(|quote| matches!(*quote, '\'' | '\"'))
        .filter(|quote| trimmed.ends_with(*quote));
    let host = if let Some(quote) = quote {
        &trimmed[quote.len_utf8()..trimmed.len() - quote.len_utf8()]
    } else {
        trimmed
    };
    let replacement = host_aliases
        .get(&host.to_ascii_lowercase())
        .map(String::as_str)
        .unwrap_or("[REDACTED_HOST]");
    if let Some(quote) = quote {
        format!(
            "{}{}{}{}{}",
            &value[..leading],
            quote,
            replacement,
            quote,
            &value[suffix_start..]
        )
    } else {
        format!(
            "{}{}{}",
            &value[..leading],
            replacement,
            &value[suffix_start..]
        )
    }
}

fn shannon_entropy(value: &str) -> f64 {
    let mut frequencies = std::collections::BTreeMap::new();
    for character in value.chars() {
        *frequencies.entry(character).or_insert(0_usize) += 1;
    }
    let length = value.chars().count() as f64;
    frequencies
        .values()
        .map(|count| {
            let probability = *count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excludes_secret_files_and_redacts_common_secret_forms() {
        assert!(is_sensitive_path("src/.env.production"));
        assert!(is_sensitive_path("keys/service.pem"));
        assert!(is_sensitive_path(".ssh/id_ed25519"));
        let result =
            redact_text("api_key=secret123 and token: ghp_abcdefghijklmnopqrstuvwxyz123456");
        assert!(!result.text.contains("secret123"));
        assert!(!result.text.contains("ghp_"));
        assert_eq!(result.redacted_values, 2);
        let random = redact_text("token=Q7Jw2N9qK4xT8pL3zV6cB1mR");
        assert!(!random.text.contains("Q7Jw2N9qK4xT8pL3zV6cB1mR"));
        assert!(random.redacted_values > 0);
    }

    #[test]
    fn absolute_local_paths_and_url_hostnames_are_hidden() {
        let redacted = redact_text(
            "Open C:\\Users\\alice\\work\\src.rs and /home/alice/work/main.rs; see https://example.test/path",
        );
        assert!(!redacted.text.contains("C:\\Users\\alice"));
        assert!(!redacted.text.contains("/home/alice"));
        assert!(redacted.text.contains("https://[REDACTED_HOST]/path"));
    }

    #[test]
    fn masks_absolute_paths_and_rejects_symlink_escape() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("source.rs");
        std::fs::write(&file, "safe").unwrap();
        let absolute = file.to_string_lossy().into_owned();
        assert_eq!(
            redact_relative_path(temp.path().to_str().unwrap(), &absolute),
            Some("<project>/source.rs".into())
        );
        assert_eq!(
            redact_relative_path(
                temp.path().to_str().unwrap(),
                &temp.path().join(".env").to_string_lossy()
            ),
            None
        );
    }

    #[test]
    fn redacts_quoted_json_and_yaml_secret_values() {
        let result = redact_text(r#"{"password":"letmein123","api_key": "short-key"}"#);
        assert!(!result.text.contains("letmein123"));
        assert!(!result.text.contains("short-key"));
        assert_eq!(result.redacted_values, 2);
        assert!(is_sensitive_path("config/.envrc"));
    }

    #[test]
    fn redacts_credentials_in_non_http_connection_urls() {
        let fixture = include_str!("../../../tests/fixtures/ai/redaction.txt");
        let result = redact_text(fixture);
        assert!(!result.text.contains("V1TestPass!"));
        assert!(!result.text.contains("postgres://app"));
        assert!(
            result
                .text
                .contains("DATABASE_URL=postgres://[REDACTED_HOST]/app")
        );
        assert!(!result.text.contains("demo-password"));
        assert!(!result.text.contains("mongodb+srv://"));
        assert!(!result.text.contains("RedisPass!"));
        assert!(!result.text.contains("redis://"));
        assert!(!result.text.contains("abc123short"));
        assert!(!result.text.contains("prod-db.internal"));
        assert!(!result.text.contains("192.0.2.1"));
        assert!(!result.text.contains("git@prod-db.internal"));
        assert!(!result.text.contains("admin-db.internal"));
        assert!(result.redacted_values >= 3);
    }

    #[test]
    fn replaces_host_fields_with_user_alias_or_redacted_placeholder() {
        let mut aliases = std::collections::BTreeMap::new();
        aliases.insert("prod-db.internal".into(), "payments-db".into());
        let result = redact_text_with_host_aliases(
            "DATABASE_HOST=prod-db.internal\nSERVERNAME=prod-db.internal\nHOST_NAME=prod-db.internal\nHOSTS=[prod-db.internal, admin-db.internal]\nALLOWED_HOSTS=[\"prod-db.internal\", \"admin-db.internal\"]\nYAML_HOSTS:\n  - prod-db.internal\n  - admin-db.internal\nupstream backend {\n    server prod-db.internal:8080;\n    server admin-db.internal;\n}\nupstream inline { server prod-db.internal:8090; }\nCACHE_HOST: cache.internal\nDATABASE_URL=postgres://prod-db.internal/app\nAPI_ENDPOINT=https://private-api.local/v1\nORIGIN=https://prod-db.internal/v1\nGIT_REMOTE=git@prod-db.internal:team/repo.git\nEXTERNALNAME=prod-db.internal\nIPV6_HOST=[::ffff:192.0.2.1]\nIPV6_URL=https://[::ffff:192.0.2.1]/v1\nSCOPED_IPV6_HOST=[fe80::1%eth0]\nRAW_IPV6_HOST=fe80::1%eth0\nSCOPED_IPV6_URL=https://[fe80::1%25eth0]/api\n",
            &aliases,
        );
        assert!(result.text.contains("DATABASE_HOST=payments-db"));
        assert!(result.text.contains("SERVERNAME=payments-db"));
        assert!(result.text.contains("HOST_NAME=payments-db"));
        assert!(result.text.contains("HOSTS=[payments-db, [REDACTED_HOST]]"));
        assert!(
            result
                .text
                .contains("ALLOWED_HOSTS=[\"payments-db\", \"[REDACTED_HOST]\"]")
        );
        assert!(
            result
                .text
                .contains("YAML_HOSTS:\n  - payments-db\n  - [REDACTED_HOST]")
        );
        assert!(result.text.contains(
            "upstream backend {\n    server payments-db:8080;\n    server [REDACTED_HOST];\n}"
        ));
        assert!(
            result
                .text
                .contains("upstream inline { server payments-db:8090; }")
        );
        assert!(result.text.contains("CACHE_HOST: [REDACTED_HOST]"));
        assert!(
            result
                .text
                .contains("DATABASE_URL=postgres://payments-db/app")
        );
        assert!(result.text.contains("ORIGIN=https://payments-db/v1"));
        assert!(
            result
                .text
                .contains("GIT_REMOTE=git@payments-db:team/repo.git")
        );
        assert!(result.text.contains("EXTERNALNAME=payments-db"));
        assert!(result.text.contains("IPV6_HOST=[REDACTED_HOST]"));
        assert!(result.text.contains("IPV6_URL=https://[REDACTED_HOST]/v1"));
        assert!(result.text.contains("SCOPED_IPV6_HOST=[REDACTED_HOST]"));
        assert!(result.text.contains("RAW_IPV6_HOST=[REDACTED_HOST]"));
        assert!(
            result
                .text
                .contains("SCOPED_IPV6_URL=https://[REDACTED_HOST]/api")
        );
        assert!(
            result
                .text
                .contains("API_ENDPOINT=https://[REDACTED_HOST]/v1")
        );
        assert!(!result.text.contains("prod-db.internal"));
        assert!(!result.text.contains("cache.internal"));
        assert!(!result.text.contains("private-api.local"));
        assert!(!result.text.contains("192.0.2.1"));
        assert!(!result.text.contains("fe80::1"));
        assert_eq!(result.redacted_values, 23);
    }
}
