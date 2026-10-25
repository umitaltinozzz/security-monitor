use super::*;

pub(crate) fn check(
    kind: CheckKind,
    status: CheckStatus,
    diagnostic: DiagnosticCode,
    count: usize,
) -> CollectionCheck {
    CollectionCheck {
        kind,
        status,
        diagnostic: (status != CheckStatus::Complete).then_some(diagnostic),
        item_count: count.min(u32::MAX as usize) as u32,
    }
}

pub(crate) fn command_diagnostic(error: commands::HostCommandError) -> DiagnosticCode {
    match error {
        commands::HostCommandError::Unavailable => DiagnosticCode::CommandUnavailable,
        commands::HostCommandError::Failed => DiagnosticCode::CommandFailed,
        commands::HostCommandError::Timeout => DiagnosticCode::LimitReached,
        commands::HostCommandError::OutputTooLarge => DiagnosticCode::LimitReached,
        commands::HostCommandError::InvalidArgument => DiagnosticCode::InvalidOutput,
    }
}

pub(crate) fn read_hostname() -> Option<String> {
    read_bounded_text(Path::new("/etc/hostname"), 4096)
        .ok()
        .map(|hostname| hostname.trim().chars().take(255).collect::<String>())
        .filter(|hostname| {
            !hostname.is_empty() && !hostname.bytes().any(|byte| byte.is_ascii_control())
        })
}

pub(crate) fn valid_container_id(id: &str) -> bool {
    (12..=64).contains(&id.len()) && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn valid_sha256_digest(value: &str) -> Option<String> {
    let (algorithm, digest) = value.split_once(':')?;
    if algorithm == "sha256"
        && digest.len() == 64
        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        Some(format!("sha256:{}", digest.to_ascii_lowercase()))
    } else {
        None
    }
}

pub(crate) fn normalize_commit(value: &str) -> Option<String> {
    if (7..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(value.to_ascii_lowercase())
    } else {
        None
    }
}

pub(crate) fn nonempty_bounded(value: &str) -> Option<String> {
    (!value.is_empty() && value.len() <= 512 && !value.bytes().any(|byte| byte.is_ascii_control()))
        .then(|| value.to_owned())
}

pub(crate) fn validate_repository(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > 2048
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return None;
    }
    let url = url::Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    Some(url.to_string().trim_end_matches('/').to_owned())
}
