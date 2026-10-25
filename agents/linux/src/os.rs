use super::*;

pub(super) fn collect_operating_system() -> (Option<OperatingSystem>, Vec<CollectionCheck>) {
    let source_path = Path::new("/etc/os-release");
    let canonical_path = match source_path.canonicalize() {
        Ok(path) if path.starts_with("/etc") || path.starts_with("/usr/lib") => path,
        Ok(_) => {
            return (
                None,
                vec![check(
                    CheckKind::OperatingSystem,
                    CheckStatus::Unavailable,
                    DiagnosticCode::InvalidOutput,
                    0,
                )],
            );
        }
        Err(_) => {
            return (
                None,
                vec![check(
                    CheckKind::OperatingSystem,
                    CheckStatus::Unavailable,
                    DiagnosticCode::PermissionDenied,
                    0,
                )],
            );
        }
    };
    match fs::metadata(&canonical_path) {
        Ok(metadata) if metadata.is_file() && metadata.len() <= MAX_OS_RELEASE_BYTES => {}
        Ok(_) => {
            return (
                None,
                vec![check(
                    CheckKind::OperatingSystem,
                    CheckStatus::Unavailable,
                    DiagnosticCode::InvalidOutput,
                    0,
                )],
            );
        }
        Err(_) => {
            return (
                None,
                vec![check(
                    CheckKind::OperatingSystem,
                    CheckStatus::Unavailable,
                    DiagnosticCode::PermissionDenied,
                    0,
                )],
            );
        }
    }
    let contents = match read_bounded_text(&canonical_path, MAX_OS_RELEASE_BYTES) {
        Ok(contents) => contents,
        Err(_) => {
            return (
                None,
                vec![check(
                    CheckKind::OperatingSystem,
                    CheckStatus::Unavailable,
                    DiagnosticCode::PermissionDenied,
                    0,
                )],
            );
        }
    };
    match parse_os_release(&contents) {
        Some(mut os) => {
            os.kernel_release = read_bounded_text(Path::new("/proc/sys/kernel/osrelease"), 4096)
                .ok()
                .map(|value| value.trim().to_owned());
            let kernel_available = os.kernel_release.is_some();
            (
                Some(os),
                vec![check(
                    CheckKind::OperatingSystem,
                    if kernel_available {
                        CheckStatus::Complete
                    } else {
                        CheckStatus::Partial
                    },
                    DiagnosticCode::PermissionDenied,
                    1,
                )],
            )
        }
        None => (
            None,
            vec![check(
                CheckKind::OperatingSystem,
                CheckStatus::Unavailable,
                DiagnosticCode::InvalidOutput,
                0,
            )],
        ),
    }
}

pub(crate) fn parse_os_release(contents: &str) -> Option<OperatingSystem> {
    security_monitor_agent_protocol::parse_os_release_with_architecture(
        contents,
        std::env::consts::ARCH,
    )
}

pub(crate) fn is_well_formed_version_id(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let mut segment_has_digit = false;
    for byte in value.bytes() {
        match byte {
            b'0'..=b'9' => segment_has_digit = true,
            b'.' if segment_has_digit => segment_has_digit = false,
            _ => return false,
        }
    }
    segment_has_digit
}

pub(super) fn os_collection_is_complete(os: &OperatingSystem) -> bool {
    os.kernel_release.is_some()
        && os.installed_kernel_release.is_some()
        && os.kernel_restart_required.is_some()
        && is_well_formed_version_id(os.version_id.as_deref())
}
