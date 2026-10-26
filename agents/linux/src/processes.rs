#[cfg(target_os = "linux")]
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::Path,
};

#[cfg(target_os = "linux")]
use crate::valid_container_id;
use security_monitor_agent_protocol::{
    CheckStatus, CollectionCheck, DiagnosticCode, ProcessRecord, ServiceRecord,
};

#[cfg(target_os = "linux")]
use security_monitor_agent_protocol::MapsStatus;

#[cfg(target_os = "linux")]
use crate::commands::{CommandOutput, HostCommand, run_allowlisted};

#[cfg(target_os = "linux")]
const MAX_PROCESS_MAPS_BYTES: u64 = 8 * 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_PROCESS_MAPS_LINES: usize = 100_000;

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
    let mut process_ids = Vec::new();
    let mut had_permission_denied = false;
    for entry in entries {
        let Ok(entry) = entry else {
            had_permission_denied = true;
            continue;
        };
        if let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        {
            process_ids.push(pid);
        }
    }
    let (process_ids, hit_limit) = select_process_ids(process_ids, max_processes);
    let mut processes = Vec::new();
    let mut units = BTreeSet::new();
    let mut had_stale_observation = false;
    for pid in process_ids {
        let process_dir = Path::new("/proc").join(pid.to_string());
        let mut executable_missing = false;
        let executable_path = match fs::read_link(process_dir.join("exe")) {
            Ok(path) => Some(clean_executable_path(&path)),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                had_permission_denied = true;
                None
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                executable_missing = true;
                None
            }
            Err(_) => {
                had_stale_observation = true;
                None
            }
        };
        let kernel_thread = if executable_missing {
            match process_is_kernel_thread(&process_dir) {
                Some(is_kernel_thread) => is_kernel_thread,
                None => {
                    had_stale_observation = true;
                    false
                }
            }
        } else {
            false
        };
        if executable_path.is_none() && !kernel_thread {
            had_stale_observation = true;
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
        let (deleted_shared_libraries, maps_status, maps_diagnostic) = if kernel_thread {
            (Vec::new(), MapsStatus::NotApplicable, None)
        } else {
            deleted_shared_libraries(&process_dir.join("maps"))
        };
        match maps_diagnostic {
            Some(DiagnosticCode::PermissionDenied) => had_permission_denied = true,
            Some(_) => had_stale_observation = true,
            None => {}
        }
        let process = ProcessRecord {
            pid,
            executable_path,
            user_name,
            service_unit,
            container_id,
            runtime_name: runtime_name.map(str::to_owned),
            maps_status,
            deleted_shared_libraries,
        };
        retain_valid_process(&mut processes, process, &mut had_stale_observation);
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
        process_collection_status(hit_limit, had_permission_denied, had_stale_observation);
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
fn select_process_ids(mut process_ids: Vec<u32>, max_processes: usize) -> (Vec<u32>, bool) {
    process_ids.sort_unstable();
    process_ids.dedup();
    let hit_limit = process_ids.len() > max_processes;
    process_ids.truncate(max_processes);
    (process_ids, hit_limit)
}

#[cfg(target_os = "linux")]
fn process_collection_status(
    hit_limit: bool,
    permission_denied: bool,
    stale_observation: bool,
) -> (CheckStatus, Option<DiagnosticCode>) {
    if hit_limit {
        (CheckStatus::Partial, Some(DiagnosticCode::LimitReached))
    } else if permission_denied {
        (CheckStatus::Partial, Some(DiagnosticCode::PermissionDenied))
    } else if stale_observation {
        (CheckStatus::Partial, Some(DiagnosticCode::StaleObservation))
    } else {
        (CheckStatus::Complete, None)
    }
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn retain_valid_process(
    processes: &mut Vec<ProcessRecord>,
    process: ProcessRecord,
    had_stale_observation: &mut bool,
) -> bool {
    let valid_text = |value: &str| {
        !value.is_empty()
            && value.len() <= 16 * 1024
            && !value.bytes().any(|byte| byte.is_ascii_control())
    };
    let valid_optional_text = |value: Option<&str>| value.is_none_or(valid_text);
    if process.pid == 0
        || process
            .executable_path
            .as_deref()
            .is_some_and(|path| !path.starts_with('/') || !valid_text(path))
        || !valid_optional_text(process.user_name.as_deref())
        || !valid_optional_text(process.service_unit.as_deref())
        || !valid_optional_text(process.container_id.as_deref())
        || !valid_optional_text(process.runtime_name.as_deref())
        || process.deleted_shared_libraries.len() > 256
        || process
            .deleted_shared_libraries
            .iter()
            .any(|name| !valid_text(name) || name.contains('/') || !name.starts_with("lib"))
    {
        *had_stale_observation = true;
        return false;
    }
    processes.push(process);
    true
}

#[cfg(target_os = "linux")]
fn deleted_shared_libraries(path: &Path) -> (Vec<String>, MapsStatus, Option<DiagnosticCode>) {
    // /proc maps is a pseudo-file, so bound the descriptor read directly instead of using
    // the regular-file-only shared bounded reader.
    let mut contents = String::new();
    let bytes_read = match fs::File::open(path).and_then(|file| {
        file.take(MAX_PROCESS_MAPS_BYTES + 1)
            .read_to_string(&mut contents)
    }) {
        Ok(bytes_read) => bytes_read,
        Err(error) => {
            return (
                Vec::new(),
                MapsStatus::Unavailable,
                Some(if error.kind() == std::io::ErrorKind::PermissionDenied {
                    DiagnosticCode::PermissionDenied
                } else {
                    DiagnosticCode::StaleObservation
                }),
            );
        }
    };
    if bytes_read as u64 > MAX_PROCESS_MAPS_BYTES
        || contents.lines().count() > MAX_PROCESS_MAPS_LINES
    {
        return (
            Vec::new(),
            MapsStatus::Unavailable,
            Some(DiagnosticCode::StaleObservation),
        );
    }
    let mut names = BTreeSet::new();
    for line in contents.lines() {
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
    (
        names.into_iter().take(256).collect(),
        MapsStatus::Checked,
        None,
    )
}

#[cfg(target_os = "linux")]
fn process_is_kernel_thread(process_dir: &Path) -> Option<bool> {
    const MAX_STATUS_BYTES: u64 = 64 * 1024;

    let mut cmdline = Vec::with_capacity(1);
    fs::File::open(process_dir.join("cmdline"))
        .ok()?
        .take(1)
        .read_to_end(&mut cmdline)
        .ok()?;
    if !cmdline.is_empty() {
        return Some(false);
    }

    let mut status = String::new();
    let bytes_read = fs::File::open(process_dir.join("status"))
        .ok()?
        .take(MAX_STATUS_BYTES + 1)
        .read_to_string(&mut status)
        .ok()?;
    if bytes_read as u64 > MAX_STATUS_BYTES {
        return None;
    }
    let mut kernel_thread = false;
    let mut non_zombie_state = false;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("Kthread:") {
            kernel_thread = value.trim() == "1";
        } else if let Some(value) = line.strip_prefix("State:") {
            non_zombie_state = value
                .trim()
                .chars()
                .next()
                .is_some_and(|state| !matches!(state, 'Z' | 'X' | 'x'));
        }
    }
    Some(kernel_thread && non_zombie_state)
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
    use security_monitor_agent_protocol::{CheckStatus, DiagnosticCode, MapsStatus, ProcessRecord};

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
        let (names, status, diagnostic) = super::deleted_shared_libraries(&path);
        let _ = std::fs::remove_file(path);
        assert_eq!(status, MapsStatus::Checked);
        assert_eq!(diagnostic, None);
        assert_eq!(names, ["libssl.so.3"]);
    }

    #[test]
    fn permission_limited_process_collection_stays_partial() {
        assert_eq!(
            super::process_collection_status(false, true, false),
            (CheckStatus::Partial, Some(DiagnosticCode::PermissionDenied))
        );
        assert_eq!(
            super::process_collection_status(false, false, true),
            (CheckStatus::Partial, Some(DiagnosticCode::StaleObservation))
        );
        assert_eq!(
            super::process_collection_status(false, false, false),
            (CheckStatus::Complete, None)
        );
    }

    #[test]
    fn invalid_process_record_is_skipped_and_marks_processes_partial() {
        let mut processes = Vec::new();
        let mut had_stale_observation = false;
        super::retain_valid_process(
            &mut processes,
            ProcessRecord {
                pid: 42,
                executable_path: Some("/usr/bin/bad\npath".to_owned()),
                user_name: None,
                service_unit: None,
                container_id: None,
                runtime_name: None,
                maps_status: MapsStatus::Checked,
                deleted_shared_libraries: Vec::new(),
            },
            &mut had_stale_observation,
        );

        assert!(processes.is_empty());
        assert!(had_stale_observation);
        assert_eq!(
            super::process_collection_status(false, false, had_stale_observation),
            (CheckStatus::Partial, Some(DiagnosticCode::StaleObservation))
        );
    }

    #[test]
    fn missing_maps_are_not_reported_as_permission_errors() {
        let path = std::env::temp_dir().join(format!("secmon-missing-maps-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let (_, status, diagnostic) = super::deleted_shared_libraries(&path);
        assert_eq!(status, MapsStatus::Unavailable);
        assert_eq!(diagnostic, Some(DiagnosticCode::StaleObservation));
    }

    #[test]
    fn oversized_maps_are_reported_as_incomplete() {
        let path = std::env::temp_dir().join(format!("secmon-large-maps-{}", std::process::id()));
        std::fs::write(
            &path,
            vec![b'x'; super::MAX_PROCESS_MAPS_BYTES as usize + 1],
        )
        .unwrap();
        let (_, status, diagnostic) = super::deleted_shared_libraries(&path);
        let _ = std::fs::remove_file(path);
        assert_eq!(status, MapsStatus::Unavailable);
        assert_eq!(diagnostic, Some(DiagnosticCode::StaleObservation));
    }

    #[test]
    fn maps_with_too_many_lines_are_reported_as_incomplete() {
        let path = std::env::temp_dir().join(format!("secmon-many-maps-{}", std::process::id()));
        let contents = "x\n".repeat(super::MAX_PROCESS_MAPS_LINES + 1);
        std::fs::write(&path, contents).unwrap();
        let (_, status, diagnostic) = super::deleted_shared_libraries(&path);
        let _ = std::fs::remove_file(path);
        assert_eq!(status, MapsStatus::Unavailable);
        assert_eq!(diagnostic, Some(DiagnosticCode::StaleObservation));
    }

    #[test]
    fn kernel_thread_requires_empty_contents_and_explicit_live_status() {
        let path = std::env::temp_dir().join(format!("secmon-proc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        let cmdline = path.join("cmdline");
        std::fs::write(&cmdline, b"").unwrap();
        std::fs::write(path.join("status"), b"State:\tS (sleeping)\nKthread:\t1\n").unwrap();
        assert_eq!(super::process_is_kernel_thread(&path), Some(true));
        std::fs::write(path.join("status"), b"State:\tZ (zombie)\nKthread:\t1\n").unwrap();
        assert_eq!(super::process_is_kernel_thread(&path), Some(false));
        std::fs::write(path.join("status"), b"State:\tS (sleeping)\n").unwrap();
        assert_eq!(super::process_is_kernel_thread(&path), Some(false));
        std::fs::write(&cmdline, b"/usr/bin/example\0").unwrap();
        assert_eq!(super::process_is_kernel_thread(&path), Some(false));
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn process_limit_selects_the_lowest_pids_independent_of_directory_order() {
        let (selected, hit_limit) = super::select_process_ids(vec![900, 7, 42, 7, 3], 3);
        assert_eq!(selected, vec![3, 7, 42]);
        assert!(hit_limit);
        let (selected, hit_limit) = super::select_process_ids(vec![900, 7, 42, 3], 4);
        assert_eq!(selected, vec![3, 7, 42, 900]);
        assert!(!hit_limit);
    }
}
