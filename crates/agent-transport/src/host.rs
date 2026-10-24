use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshTarget {
    pub alias: String,
    pub hostname: String,
    pub username: String,
    pub port: u16,
    pub proxy_jump: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TargetError {
    #[error("SSH target is invalid")]
    Invalid,
    #[error("host key fingerprint is invalid")]
    InvalidFingerprint,
}

impl SshTarget {
    pub fn new(
        alias: impl Into<String>,
        hostname: impl Into<String>,
        username: impl Into<String>,
        port: u16,
        proxy_jump: Option<String>,
    ) -> Result<Self, TargetError> {
        let target = Self {
            alias: alias.into(),
            hostname: hostname.into(),
            username: username.into(),
            port,
            proxy_jump,
        };
        target.validate()?;
        Ok(target)
    }

    pub fn validate(&self) -> Result<(), TargetError> {
        if !is_safe_alias(&self.alias)
            || !is_safe_hostname(&self.hostname)
            || !is_safe_username(&self.username)
            || self.port == 0
            || self
                .proxy_jump
                .as_deref()
                .is_some_and(|jump| !is_safe_proxy_jump(jump))
        {
            return Err(TargetError::Invalid);
        }
        Ok(())
    }
}

pub fn validate_fingerprint(fingerprint: &str) -> Result<(), TargetError> {
    let Some(encoded) = fingerprint.strip_prefix("SHA256:") else {
        return Err(TargetError::InvalidFingerprint);
    };
    if encoded.len() < 43
        || encoded.len() > 44
        || encoded.bytes().any(|byte| {
            !byte.is_ascii_alphanumeric() && byte != b'+' && byte != b'/' && byte != b'='
        })
    {
        return Err(TargetError::InvalidFingerprint);
    }
    Ok(())
}

pub(crate) fn is_safe_alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn is_safe_hostname(value: &str) -> bool {
    if value.is_empty() || value.len() > 255 || !value.is_ascii() {
        return false;
    }
    if value.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && label
                .as_bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
    })
}

fn is_safe_username(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn is_safe_proxy_jump(value: &str) -> bool {
    if value.is_empty() || value.len() > 512 || value.contains(',') {
        return false;
    }
    let address = match value.split_once('@') {
        Some((username, address)) if is_safe_username(username) => address,
        Some(_) => return false,
        None => value,
    };
    let (host, port) = match address.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => {
            let Ok(port) = port.parse::<u16>() else {
                return false;
            };
            (host, Some(port))
        }
        _ => (address, None),
    };
    (port.is_none_or(|port| port > 0)) && (is_safe_alias(host) || is_safe_hostname(host))
}

pub(crate) fn proxy_jump_matches(value: &str, target: &SshTarget) -> bool {
    if value == target.alias {
        return true;
    }
    let (requested_user, address) = match value.split_once('@') {
        Some((username, address)) => (Some(username), address),
        None => (None, value),
    };
    let (host, requested_port) = match address.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => {
            let Ok(port) = port.parse::<u16>() else {
                return false;
            };
            if port == 0 {
                return false;
            }
            (host, Some(port))
        }
        Some((_, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => return false,
        _ => (address, None),
    };
    (host == target.alias || host == target.hostname)
        && requested_user.is_none_or(|username| username == target.username)
        && requested_port.is_none_or(|port| port == target.port)
}

#[cfg(test)]
mod tests {
    use super::{SshTarget, TargetError, proxy_jump_matches, validate_fingerprint};

    #[test]
    fn target_rejects_command_and_path_syntax() {
        assert!(SshTarget::new("web", "host;id", "app", 22, None).is_err());
        assert!(SshTarget::new("web", "host", "app", 22, Some("jump$(id)".into())).is_err());
    }

    #[test]
    fn fingerprints_are_sha256_openssh_strings() {
        assert!(validate_fingerprint("SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM").is_ok());
        assert_eq!(
            validate_fingerprint("MD5:00:11"),
            Err(TargetError::InvalidFingerprint)
        );
    }

    #[test]
    fn proxy_jump_support_requires_a_pinned_single_hop_target() {
        let target = SshTarget::new("web", "web.example.test", "deploy", 22, Some("jump".into()))
            .expect("target with a jump alias should validate");
        let jump = SshTarget::new("jump", "bastion.example.test", "ops", 2200, None)
            .expect("bastion should validate");
        assert!(proxy_jump_matches("jump", &jump));
        assert!(proxy_jump_matches("ops@bastion.example.test:2200", &jump));
        assert!(!proxy_jump_matches("ops@bastion.example.test:2201", &jump));
        assert!(
            SshTarget::new(
                "web",
                "web.example.test",
                "deploy",
                22,
                Some("jump,other".into())
            )
            .is_err()
        );
        assert_ne!(target.alias, jump.alias);
    }
}
