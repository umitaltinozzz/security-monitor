use std::{
    collections::BTreeSet,
    env,
    fs::{self, OpenOptions},
    io::Read,
    path::PathBuf,
};

#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;

use thiserror::Error;

use crate::{SshTarget, TargetError, host::is_safe_alias};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshHost {
    pub alias: String,
    pub hostname: String,
    pub username: String,
    pub port: u16,
    pub proxy_jump: Option<String>,
}

impl SshHost {
    pub fn target(&self) -> Result<SshTarget, TargetError> {
        SshTarget::new(
            self.alias.clone(),
            self.hostname.clone(),
            self.username.clone(),
            self.port,
            self.proxy_jump.clone(),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshConfigWarning {
    IncludeNotFollowed,
    MatchBlockNotEvaluated,
    UnsupportedDirective,
    InvalidDirective,
    WildcardHostNotListed,
    UnsafeHostSkipped,
}

#[derive(Debug, Error)]
pub enum SshConfigError {
    #[error("SSH configuration is larger than the supported limit")]
    TooLarge,
    #[error("SSH configuration could not be read")]
    Read,
    #[error("SSH configuration path is outside the user's .ssh directory")]
    PathOutsideSshDirectory,
}

#[derive(Debug, Default)]
struct Stanza {
    patterns: Vec<String>,
    settings: Vec<(String, String)>,
}

pub fn load_user_ssh_hosts() -> Result<(Vec<SshHost>, Vec<SshConfigWarning>), SshConfigError> {
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or(SshConfigError::Read)?;
    let ssh_directory = home.join(".ssh");
    let config_path = ssh_directory.join("config");
    let fallback_user = env::var("USER")
        .or_else(|_| env::var("USERNAME"))
        .unwrap_or_default();
    load_ssh_hosts_from(&config_path, &ssh_directory, &fallback_user)
}

pub fn load_ssh_hosts_from(
    config_path: &std::path::Path,
    ssh_directory: &std::path::Path,
    fallback_user: &str,
) -> Result<(Vec<SshHost>, Vec<SshConfigWarning>), SshConfigError> {
    let canonical_ssh_directory = ssh_directory
        .canonicalize()
        .map_err(|_| SshConfigError::Read)?;
    let link_metadata = fs::symlink_metadata(config_path).map_err(|_| SshConfigError::Read)?;
    if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
        return Err(SshConfigError::Read);
    }
    let canonical_config = config_path
        .canonicalize()
        .map_err(|_| SshConfigError::Read)?;
    if !canonical_config.starts_with(&canonical_ssh_directory) {
        return Err(SshConfigError::PathOutsideSshDirectory);
    }
    let metadata = fs::symlink_metadata(&canonical_config).map_err(|_| SshConfigError::Read)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SshConfigError::Read);
    }
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(SshConfigError::TooLarge);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(canonical_config)
        .map_err(|_| SshConfigError::Read)?;
    let metadata = file.metadata().map_err(|_| SshConfigError::Read)?;
    if !metadata.is_file() {
        return Err(SshConfigError::Read);
    }
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(SshConfigError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SshConfigError::Read)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(SshConfigError::TooLarge);
    }
    let contents = String::from_utf8(bytes).map_err(|_| SshConfigError::Read)?;
    parse_ssh_config(&contents, fallback_user)
}

pub fn parse_ssh_config(
    contents: &str,
    fallback_username: &str,
) -> Result<(Vec<SshHost>, Vec<SshConfigWarning>), SshConfigError> {
    if contents.len() as u64 > MAX_CONFIG_BYTES {
        return Err(SshConfigError::TooLarge);
    }

    let mut warnings = Vec::new();
    let mut stanzas = vec![Stanza {
        patterns: vec!["*".to_owned()],
        settings: Vec::new(),
    }];
    let mut current = 0usize;
    let mut in_match_block = false;
    for line in logical_lines(contents) {
        let uncommented = strip_comment(&line);
        let tokens = split_tokens(&uncommented);
        if tokens.is_empty() {
            continue;
        }
        let keyword = tokens[0].to_ascii_lowercase();
        if keyword == "host" {
            if tokens.len() < 2 {
                warnings.push(SshConfigWarning::InvalidDirective);
                in_match_block = false;
                stanzas.push(Stanza::default());
                current = stanzas.len() - 1;
                continue;
            }
            in_match_block = false;
            let patterns = tokens[1..]
                .iter()
                .flat_map(|token| token.split(','))
                .filter(|pattern| !pattern.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if patterns.iter().any(|pattern| contains_glob(pattern)) {
                warnings.push(SshConfigWarning::WildcardHostNotListed);
            }
            stanzas.push(Stanza {
                patterns,
                settings: Vec::new(),
            });
            current = stanzas.len() - 1;
            continue;
        }
        if keyword == "match" {
            in_match_block = true;
            warnings.push(SshConfigWarning::MatchBlockNotEvaluated);
            continue;
        }
        if in_match_block {
            continue;
        }
        if keyword == "include" {
            warnings.push(SshConfigWarning::IncludeNotFollowed);
            continue;
        }
        if !matches!(keyword.as_str(), "hostname" | "user" | "port" | "proxyjump") {
            warnings.push(SshConfigWarning::UnsupportedDirective);
            continue;
        }
        if tokens.len() < 2 {
            warnings.push(SshConfigWarning::InvalidDirective);
            continue;
        }
        stanzas[current].settings.push((keyword, tokens[1].clone()));
    }

    let mut aliases = BTreeSet::new();
    for stanza in &stanzas {
        for pattern in &stanza.patterns {
            if !pattern.starts_with('!') && !contains_glob(pattern) && is_safe_alias(pattern) {
                aliases.insert(pattern.clone());
            }
        }
    }

    let mut hosts = Vec::new();
    for alias in aliases {
        let mut hostname = None;
        let mut username = None;
        let mut port = None;
        let mut proxy_jump = None;
        let mut rejected = false;
        for stanza in &stanzas {
            if !stanza_matches(stanza, &alias) {
                continue;
            }
            for (key, value) in &stanza.settings {
                match key.as_str() {
                    "hostname" if hostname.is_none() => {
                        if !is_safe_config_value(value) {
                            rejected = true;
                        } else {
                            hostname = Some(value.clone());
                        }
                    }
                    "user" if username.is_none() => {
                        if !is_safe_username(value) {
                            rejected = true;
                        } else {
                            username = Some(value.clone());
                        }
                    }
                    "port" if port.is_none() => match value.parse::<u16>() {
                        Ok(value) if value > 0 => port = Some(value),
                        _ => rejected = true,
                    },
                    "proxyjump" if proxy_jump.is_none() => {
                        if value == "none" {
                            proxy_jump = Some(String::new());
                        } else if is_safe_config_value(value) {
                            proxy_jump = Some(value.clone());
                        } else {
                            rejected = true;
                        }
                    }
                    _ => {}
                }
            }
        }
        let username = username.unwrap_or_else(|| fallback_username.to_owned());
        if rejected || !is_safe_username(&username) {
            warnings.push(SshConfigWarning::UnsafeHostSkipped);
            continue;
        }
        let host = SshHost {
            alias: alias.clone(),
            hostname: hostname.unwrap_or(alias),
            username,
            port: port.unwrap_or(22),
            proxy_jump: proxy_jump.filter(|jump| !jump.is_empty()),
        };
        if host.target().is_err() {
            warnings.push(SshConfigWarning::UnsafeHostSkipped);
            continue;
        }
        hosts.push(host);
    }

    Ok((hosts, warnings))
}

fn logical_lines(contents: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for line in contents.lines() {
        let part = line.trim_end();
        if let Some(without_slash) = part.strip_suffix('\\') {
            current.push_str(without_slash);
            current.push(' ');
        } else {
            current.push_str(part);
            lines.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn strip_comment(line: &str) -> String {
    let mut quoted = false;
    let mut escaped = false;
    let mut result = String::new();
    for character in line.chars() {
        if escaped {
            result.push(character);
            escaped = false;
        } else if character == '\\' {
            result.push(character);
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
            result.push(character);
        } else if character == '#' && !quoted {
            break;
        } else {
            result.push(character);
        }
    }
    result
}

fn split_tokens(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for character in line.trim().chars() {
        if escaped {
            token.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if character.is_whitespace() && !quoted {
            if !token.is_empty() {
                tokens.push(std::mem::take(&mut token));
            }
        } else {
            token.push(character);
        }
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    tokens
}

fn stanza_matches(stanza: &Stanza, alias: &str) -> bool {
    let mut positive_match = false;
    for pattern in &stanza.patterns {
        if let Some(negative) = pattern.strip_prefix('!') {
            if glob_matches(negative, alias) {
                return false;
            }
        } else if glob_matches(pattern, alias) {
            positive_match = true;
        }
    }
    positive_match
}

fn contains_glob(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?')
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut p, mut v, mut star, mut retry) = (0, 0, None, 0);
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            retry = v;
        } else if let Some(star_position) = star {
            p = star_position + 1;
            retry += 1;
            v = retry;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

fn is_safe_config_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        && !value.contains('$')
        && !value.contains('`')
        && !value.contains('/')
        && !value.contains('\\')
}

fn is_safe_username(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{SshConfigWarning, parse_ssh_config};

    #[test]
    fn ssh_config_lists_direct_hosts_and_resolves_first_matching_values() {
        let config = r#"
Host *
  User default-user
  Port 2200
  IdentityFile ~/.ssh/must-not-be-opened

Host web-prod
  HostName web.example.test
  ProxyJump bastion

Host *.internal
  User wildcard-user
"#;
        let (hosts, warnings) = parse_ssh_config(config, "fallback").expect("valid config");
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].alias, "web-prod");
        assert_eq!(hosts[0].hostname, "web.example.test");
        assert_eq!(hosts[0].username, "default-user");
        assert_eq!(hosts[0].port, 2200);
        assert_eq!(hosts[0].proxy_jump.as_deref(), Some("bastion"));
        assert!(warnings.contains(&SshConfigWarning::UnsupportedDirective));
        assert!(warnings.contains(&SshConfigWarning::WildcardHostNotListed));
    }

    #[test]
    fn config_skips_unsafe_hosts_and_match_directives_without_shell_expansion() {
        let config = "Host safe\n  HostName safe.example\n  User ops\nHost bad\n  HostName host;id\n  User ops\nMatch exec id\n  HostName ignored\n";
        let (hosts, warnings) = parse_ssh_config(config, "fallback").expect("valid config");
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].alias, "safe");
        assert!(warnings.contains(&SshConfigWarning::UnsafeHostSkipped));
        assert!(warnings.contains(&SshConfigWarning::MatchBlockNotEvaluated));
    }

    #[test]
    fn config_without_user_uses_the_supplied_local_user() {
        let (hosts, _) = parse_ssh_config("Host target\n  HostName 192.0.2.10\n", "localuser")
            .expect("valid config");
        assert_eq!(hosts[0].username, "localuser");
    }

    #[test]
    fn fixture_host_discovery_reads_config_and_never_opens_identity_file() {
        let config = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/agent/ssh-config/.ssh/config");
        let ssh_directory = config.parent().expect(".ssh directory");
        let private_key = ssh_directory.join("private-key-that-must-not-be-read");
        assert!(!private_key.exists());
        let (hosts, warnings) = super::load_ssh_hosts_from(&config, ssh_directory, "fallback")
            .expect("fixture SSH config should load");
        assert_eq!(
            hosts
                .iter()
                .map(|host| host.alias.as_str())
                .collect::<Vec<_>>(),
            vec!["bastion", "web-prod"]
        );
        let web = hosts
            .iter()
            .find(|host| host.alias == "web-prod")
            .expect("web host");
        assert_eq!(web.hostname, "web.example.test");
        assert_eq!(web.username, "deploy");
        assert_eq!(web.port, 2222);
        assert_eq!(web.proxy_jump.as_deref(), Some("bastion"));
        assert!(warnings.contains(&super::SshConfigWarning::UnsupportedDirective));
        assert!(!Path::new(&private_key).exists());
    }
}
