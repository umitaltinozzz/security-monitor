#[cfg(target_os = "linux")]
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use security_monitor_agent_protocol::{
    CheckStatus, CollectionCheck, DiagnosticCode, ProcessRecord, ServiceRecord,
};

#[cfg(target_os = "linux")]
use crate::commands::{CommandOutput, HostCommand, run_allowlisted};

#[derive(Debug)]
pub struct ProcessSnapshot {
    pub processes: Vec<ProcessRecord>,
    pub services: Vec<ServiceRecord>,
    pub process_check: CollectionCheck,
    pub service_check: CollectionCheck,
}

pub async fn collect_processes(max_processes: usize) -> ProcessSnapshot {
    #[cfg(target_os = "linux")]
    {
        collect_linux_processes(max_processes).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = max_processes;
        ProcessSnapshot {
            processes: Vec::new(),
            services: Vec::new(),
            process_check: CollectionCheck {
                kind: security_monitor_agent_protocol::CheckKind::Processes,
                status: CheckStatus::Unavailable,
                diagnostic: Some(DiagnosticCode::UnsupportedPlatform),
                item_count: 0,
            },
            service_check: CollectionCheck {
                kind: security_monitor_agent_protocol::CheckKind::Services,
                status: CheckStatus::Unavailable,
                diagnostic: Some(DiagnosticCode::UnsupportedPlatform),
                item_count: 0,
            },
        }
    }
}

#[cfg(target_os = "linux")]
async fn collect_linux_processes(max_processes: usize) -> ProcessSnapshot {
    use security_monitor_agent_protocol::CheckKind;

    let Some(user_names) = user_name_map() else {
        return unavailable_snapshot(DiagnosticCode::PermissionDenied);
    };
    let entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(_) => return unavailable_snapshot(DiagnosticCode::PermissionDenied),
    };
    let mut processes = Vec::new();
    let mut units = BTreeSet::new();
    let mut had_permission_denied = false;
    let mut hit_limit = false;
    for entry in entries {
        let Ok(entry) = entry else {
            had_permission_denied = true;
            continue;
        };
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|name| name.parse::<u32>().ok()) else {
            continue;
        };
        if processes.len() >= max_processes {
            hit_limit = true;
            break;
        }
        let process_dir = entry.path();
        let executable_path = fs::read_link(process_dir.join("exe"))
            .ok()
            .map(|path| clean_executable_path(&path));
        if executable_path.is_none() {
            had_permission_denied = true;
        }
        let uid = process_uid(&process_dir.join("status"));
        let user_name = uid.and_then(|uid| user_names.get(&uid).cloned());
        let service_unit = process_service_unit(&process_dir.join("cgroup"));
        if let Some(unit) = &service_unit {
            units.insert(unit.clone());
        }
        let container_id = process_container_id(&process_dir.join("cgroup"));
        let runtime_name = executable_path
            .as_deref()
            .and_then(|path| Path::new(path).file_name())
            .and_then(|name| name.to_str())
            .and_then(runtime_name);
        let (deleted_shared_libraries, maps_unavailable) =
            deleted_shared_libraries(&process_dir.join("maps"));
        if maps_unavailable {
            had_permission_denied = true;
        }
        processes.push(ProcessRecord {
            pid,
            executable_path,
            user_name,
            service_unit,
            container_id,
            runtime_name: runtime_name.map(str::to_owned),
            deleted_shared_libraries,
        });
    }
    processes.sort_by_key(|process| process.pid);

    let systemd = run_allowlisted(&HostCommand::SystemdServices).await;
    let systemd_available = systemd.is_ok();
    let mut service_names = units;
    if let Ok(output) = systemd {
        service_names.extend(parse_systemd_units(&output));
    }
    let process_by_unit = processes
        .iter()
        .filter_map(|process| {
            process
                .service_unit
                .as_ref()
                .map(|unit| (unit.clone(), process))
        })
        .fold(BTreeMap::new(), |mut map, (unit, process)| {
            map.entry(unit).or_insert(process);
            map
        });
    let services = service_names
        .into_iter()
        .map(|unit| {
            let process = process_by_unit.get(&unit);
            let name = unit.strip_suffix(".service").unwrap_or(&unit).to_owned();
            ServiceRecord {
                name,
                unit_name: Some(unit),
                pid: process.map(|process| process.pid),
                executable_path: process.and_then(|process| process.executable_path.clone()),
                user_name: process.and_then(|process| process.user_name.clone()),
                container_id: process.and_then(|process| process.container_id.clone()),
                deploy_identity: None,
            }
        })
        .collect::<Vec<_>>();

    let (process_status, process_diagnostic) =
        process_collection_status(hit_limit, had_permission_denied);
    let service_status = if systemd_available {
        CheckStatus::Complete
    } else if services.is_empty() {
        CheckStatus::Unavailable
    } else {
        CheckStatus::Partial
    };
    ProcessSnapshot {
        process_check: CollectionCheck {
            kind: CheckKind::Processes,
            status: process_status,
            diagnostic: process_diagnostic,
            item_count: processes.len().min(u32::MAX as usize) as u32,
        },
        service_check: CollectionCheck {
            kind: CheckKind::Services,
            status: service_status,
            diagnostic: (!systemd_available).then_some(DiagnosticCode::CommandUnavailable),
            item_count: services.len().min(u32::MAX as usize) as u32,
        },
        processes,
        services,
    }
}

#[cfg(target_os = "linux")]
fn process_collection_status(
    hit_limit: bool,
    permission_denied: bool,
) -> (CheckStatus, Option<DiagnosticCode>) {
    if hit_limit {
        (CheckStatus::Partial, Some(DiagnosticCode::LimitReached))
    } else if permission_denied {
        (CheckStatus::Partial, Some(DiagnosticCode::PermissionDenied))
    } else {
        (CheckStatus::Complete, None)
    }
}

#[cfg(target_os = "linux")]
fn deleted_shared_libraries(path: &Path) -> (Vec<String>, bool) {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) => {
            return (
                Vec::new(),
                error.kind() == std::io::ErrorKind::PermissionDenied,
            );
        }
    };
    let mut names = BTreeSet::new();
    for line in contents.lines().take(100_000) {
        let mut fields = line.split_whitespace();
        if fields.nth(4).is_none() {
            continue;
        }
        let mapped_path = fields.collect::<Vec<_>>().join(" ");
        let Some(path) = mapped_path.strip_suffix(" (deleted)") else {
            continue;
        };
        let path = Path::new(path);
        if !path.is_absolute()
            || !["/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/local/lib"]
                .iter()
                .any(|root| path.starts_with(root))
        {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with("lib")
            && name.contains(".so")
            && name.len() <= 256
            && !name.bytes().any(|byte| byte.is_ascii_control())
        {
            names.insert(name.to_owned());
        }
    }
    (names.into_iter().take(256).collect(), false)
}

#[cfg(target_os = "linux")]
fn unavailable_snapshot(diagnostic: DiagnosticCode) -> ProcessSnapshot {
    use security_monitor_agent_protocol::CheckKind;
    ProcessSnapshot {
        processes: Vec::new(),
        services: Vec::new(),
        process_check: CollectionCheck {
            kind: CheckKind::Processes,
            status: CheckStatus::Unavailable,
            diagnostic: Some(diagnostic),
            item_count: 0,
        },
        service_check: CollectionCheck {
            kind: CheckKind::Services,
            status: CheckStatus::Unavailable,
            diagnostic: Some(diagnostic),
            item_count: 0,
        },
    }
}

#[cfg(target_os = "linux")]
fn user_name_map() -> Option<BTreeMap<u32, String>> {
    let contents = fs::read_to_string("/etc/passwd").ok()?;
    Some(
        contents
            .lines()
            .filter_map(|line| {
                let fields = line.split(':').collect::<Vec<_>>();
                let uid = fields.get(2)?.parse::<u32>().ok()?;
                let user = fields.first()?;
                Some((uid, (*user).to_owned()))
            })
            .collect(),
    )
}

#[cfg(target_os = "linux")]
fn process_uid(path: &Path) -> Option<u32> {
    let contents = fs::read_to_string(path).ok()?;
    contents.lines().find_map(|line| {
        line.strip_prefix("Uid:")?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

#[cfg(target_os = "linux")]
fn process_service_unit(path: &Path) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    contents.lines().find_map(|line| {
        let candidate = line
            .rsplit('/')
            .find(|segment| segment.ends_with(".service"))?;
        is_safe_unit_name(candidate).then(|| candidate.to_owned())
    })
}

#[cfg(target_os = "linux")]
fn process_container_id(path: &Path) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    contents.lines().find_map(|line| {
        let token = line.rsplit(['/', '-']).find(|token| token.len() >= 12)?;
        let token = token.strip_suffix(".scope").unwrap_or(token);
        valid_container_id(token).then(|| token.to_owned())
    })
}

#[cfg(target_os = "linux")]
fn parse_systemd_units(output: &CommandOutput) -> BTreeSet<String> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let unit = line.split_whitespace().next()?;
            (unit.ends_with(".service") && is_safe_unit_name(unit)).then(|| unit.to_owned())
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn clean_executable_path(path: &Path) -> String {
    path.to_string_lossy()
        .strip_suffix(" (deleted)")
        .unwrap_or(&path.to_string_lossy())
        .chars()
        .take(1024)
        .collect()
}

#[cfg(target_os = "linux")]
fn is_safe_unit_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._@:-".contains(&byte))
}

#[cfg(target_os = "linux")]
fn runtime_name(value: &str) -> Option<&'static str> {
    match value {
        "node" => Some("node"),
        "php" => Some("php"),
        "python" => Some("python"),
        "python3" => Some("python3"),
        _ => None,
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use security_monitor_agent_protocol::{CheckStatus, DiagnosticCode};

    #[test]
    fn runtime_matching_uses_only_known_executable_names() {
        assert_eq!(super::runtime_name("node"), Some("node"));
        assert_eq!(super::runtime_name("python3"), Some("python3"));
        assert_eq!(super::runtime_name("sh"), None);
    }

    #[test]
    fn deleted_libraries_are_reduced_to_bounded_shared_library_basenames() {
        let path = std::env::temp_dir().join(format!("secmon-maps-{}.txt", std::process::id()));
        std::fs::write(
            &path,
            include_str!("../../../tests/fixtures/agent/process-maps-nginx.txt"),
        )
        .unwrap();
        let (names, unavailable) = super::deleted_shared_libraries(&path);
        let _ = std::fs::remove_file(path);
        assert!(!unavailable);
        assert_eq!(names, ["libssl.so.3"]);
    }

    #[test]
    fn permission_limited_process_collection_stays_partial() {
        assert_eq!(
            super::process_collection_status(false, true),
            (CheckStatus::Partial, Some(DiagnosticCode::PermissionDenied))
        );
    }
}
