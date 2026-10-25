mod commands;
mod config;
mod deploy;
mod processes;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use chrono::Utc;
use commands::{HostCommand, RuntimeExecutable, run_allowlisted};
use config::{AgentConfig, ConfigDiagnostic};
use deploy::{collect_deployments, unknown_identity};
use processes::collect_processes;
use security_monitor_agent_protocol::{
    AgentInventory, CheckKind, CheckStatus, CollectionCheck, ContainerRecord, DeploymentIdentity,
    DeploymentSource, DiagnosticCode, OperatingSystem, PackageRecord, PackageSource, RuntimeRecord,
};
use security_monitor_inventory::scan_repository;
use tokio::task;

const MAX_OS_RELEASE_BYTES: u64 = 64 * 1024;
const MAX_ROOT_SCAN_FILES: usize = 50_000;
const MAX_ROOT_SCAN_DEPTH: usize = 32;
const MAX_ROOT_SCAN_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PACKAGE_RECORDS: usize = 100_000;

#[derive(Debug)]
pub struct CollectionResult {
    pub inventory: AgentInventory,
}

pub async fn collect_default() -> CollectionResult {
    let config = AgentConfig::load_default();
    collect_with_config(config.config, config.diagnostic).await
}

async fn collect_with_config(
    config: AgentConfig,
    config_diagnostic: Option<ConfigDiagnostic>,
) -> CollectionResult {
    let now = Utc::now();
    let (mut operating_system, mut checks) = collect_operating_system();
    let mut packages = collect_os_packages(operating_system.as_ref()).await;
    let manual = collect_manual_binaries();
    packages.records.extend(manual.records);
    if manual.partial
        || packages
            .records
            .iter()
            .any(|record| record.source == PackageSource::Manual)
    {
        packages.check.status = CheckStatus::Partial;
        packages.check.diagnostic = Some(if manual.partial {
            DiagnosticCode::PermissionDenied
        } else {
            DiagnosticCode::StaleObservation
        });
    }
    packages.check.item_count = packages.records.len().min(u32::MAX as usize) as u32;
    if let Some(os) = operating_system.as_mut() {
        os.installed_kernel_release = newest_installed_kernel(&packages.records);
        os.kernel_restart_required = os
            .kernel_release
            .as_deref()
            .zip(os.installed_kernel_release.as_deref())
            .and_then(|(running, installed)| kernel_restart_required(running, installed));
        if let Some(check) = checks
            .iter_mut()
            .find(|check| check.kind == CheckKind::OperatingSystem)
            && !os_collection_is_complete(os)
        {
            check.status = CheckStatus::Partial;
            check.diagnostic = Some(DiagnosticCode::StaleObservation);
        }
    }
    checks.push(packages.check);
    let runtimes = collect_runtimes().await;
    checks.push(runtimes.check);
    let mut process_snapshot = collect_processes(config.max_processes).await;
    checks.push(process_snapshot.process_check.clone());
    checks.push(process_snapshot.service_check.clone());

    let (containers, container_check, container_deployments) =
        collect_containers(config.docker_cli_approved).await;
    checks.push(container_check);
    for service in &mut process_snapshot.services {
        let matched_container = service
            .pid
            .and_then(|pid| {
                process_snapshot
                    .processes
                    .iter()
                    .find(|process| process.pid == pid)
            })
            .and_then(|process| process.container_id.as_deref())
            .and_then(|id| {
                containers
                    .iter()
                    .find(|container| container.id.ends_with(id))
            });
        if let Some(container) = matched_container {
            service.container_id = Some(container.id.clone());
            service.deploy_identity = container_deployments
                .get(&container.id)
                .cloned()
                .or_else(|| Some(unknown_identity()));
        }
    }

    let deployments_unknown = collect_deployments(&mut process_snapshot, &config.allowed_paths);
    let deployment_count = process_snapshot
        .services
        .iter()
        .filter(|service| service.container_id.is_none() && service.deploy_identity.is_some())
        .count()
        + container_deployments.len();
    checks.push(CollectionCheck {
        kind: CheckKind::Deployments,
        status: if deployments_unknown {
            CheckStatus::Partial
        } else {
            CheckStatus::Complete
        },
        diagnostic: deployments_unknown.then_some(DiagnosticCode::StaleObservation),
        item_count: deployment_count.min(u32::MAX as usize) as u32,
    });

    let dependency =
        collect_dependency_inventory(&config.allowed_paths, config_diagnostic.is_some()).await;
    checks.push(dependency.check);
    let mut package_records = packages.records;
    package_records.extend(dependency.records);
    let hostname = read_hostname();
    if hostname.is_none()
        && let Some(operating_system_check) = checks
            .iter_mut()
            .find(|check| check.kind == CheckKind::OperatingSystem)
        && operating_system_check.status == CheckStatus::Complete
    {
        operating_system_check.status = CheckStatus::Partial;
        operating_system_check.diagnostic = Some(DiagnosticCode::PermissionDenied);
    }
    checks.sort_by_key(|check| check.kind);
    let complete = checks
        .iter()
        .all(|check| check.status == CheckStatus::Complete);
    let deployments = container_deployments
        .values()
        .cloned()
        .chain(
            process_snapshot
                .services
                .iter()
                .filter_map(|service| service.deploy_identity.clone()),
        )
        .collect();
    let inventory = AgentInventory {
        protocol_version: security_monitor_agent_protocol::PROTOCOL_VERSION,
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        captured_at: now,
        hostname: hostname.unwrap_or_else(|| "unknown".to_owned()),
        operating_system,
        packages: package_records,
        runtimes: runtimes.records,
        processes: process_snapshot.processes,
        services: process_snapshot.services,
        containers,
        deployments,
        checks,
        complete,
    };
    CollectionResult { inventory }
}

struct PackageCollection {
    records: Vec<PackageRecord>,
    check: CollectionCheck,
}

async fn collect_os_packages(os: Option<&OperatingSystem>) -> PackageCollection {
    let Some((command, ecosystem, source)) = package_command_for_os(os) else {
        return PackageCollection {
            records: Vec::new(),
            check: check(
                CheckKind::PackageInventory,
                CheckStatus::Unavailable,
                DiagnosticCode::UnsupportedPlatform,
                0,
            ),
        };
    };
    match run_allowlisted(&command).await {
        Ok(output) => {
            let parsed = parse_package_output(&output.stdout, ecosystem, source);
            let status = if parsed.partial {
                CheckStatus::Partial
            } else {
                CheckStatus::Complete
            };
            PackageCollection {
                check: check(
                    CheckKind::PackageInventory,
                    status,
                    parsed.diagnostic,
                    parsed.records.len(),
                ),
                records: parsed.records,
            }
        }
        Err(error) => PackageCollection {
            records: Vec::new(),
            check: check(
                CheckKind::PackageInventory,
                CheckStatus::Unavailable,
                command_diagnostic(error),
                0,
            ),
        },
    }
}

fn package_command_for_os(
    os: Option<&OperatingSystem>,
) -> Option<(HostCommand, &'static str, PackageSource)> {
    match os.and_then(|os| os.id.as_deref()) {
        Some("debian" | "ubuntu" | "linuxmint" | "raspbian") => {
            Some((HostCommand::DpkgPackages, "deb", PackageSource::Dpkg))
        }
        Some("alpine") => Some((HostCommand::ApkPackages, "apk", PackageSource::Apk)),
        Some("fedora" | "rhel" | "centos" | "rocky" | "almalinux" | "ol") => {
            Some((HostCommand::RpmPackages, "rpm", PackageSource::Rpm))
        }
        _ => None,
    }
}

struct ManualCollection {
    records: Vec<PackageRecord>,
    partial: bool,
}

#[cfg(target_os = "linux")]
fn collect_manual_binaries() -> ManualCollection {
    collect_manual_binaries_at([Path::new("/opt"), Path::new("/usr/local")])
}

#[cfg(target_os = "linux")]
fn collect_manual_binaries_at(roots: [&Path; 2]) -> ManualCollection {
    use std::os::unix::fs::PermissionsExt;

    const MAX_ENTRIES: usize = 50_000;
    const MAX_DEPTH: usize = 16;
    let allowed_roots = roots
        .into_iter()
        .filter_map(|root| root.canonicalize().ok())
        .collect::<Vec<_>>();
    let mut records = BTreeMap::<String, PackageRecord>::new();
    let mut partial = allowed_roots.len() != 2;
    let mut visited = 0usize;
    for canonical_root in allowed_roots {
        let mut stack = vec![(canonical_root.clone(), 0usize)];
        while let Some((directory, depth)) = stack.pop() {
            if depth > MAX_DEPTH {
                partial = true;
                continue;
            }
            let entries = match fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(_) => {
                    partial = true;
                    continue;
                }
            };
            for entry in entries {
                visited += 1;
                if visited > MAX_ENTRIES {
                    partial = true;
                    break;
                }
                let Ok(entry) = entry else {
                    partial = true;
                    continue;
                };
                let Ok(file_type) = entry.file_type() else {
                    partial = true;
                    continue;
                };
                if file_type.is_symlink() {
                    continue;
                }
                let path = entry.path();
                let Ok(canonical_path) = path.canonicalize() else {
                    partial = true;
                    continue;
                };
                if !canonical_path.starts_with(&canonical_root) {
                    partial = true;
                    continue;
                }
                if file_type.is_dir() {
                    if matches!(entry.file_name().to_str(), Some(".git" | "cache" | "share")) {
                        continue;
                    }
                    stack.push((canonical_path, depth + 1));
                    continue;
                }
                if !file_type.is_file() {
                    continue;
                }
                let Ok(metadata) = fs::metadata(&canonical_path) else {
                    partial = true;
                    continue;
                };
                if metadata.permissions().mode() & 0o111 == 0 {
                    continue;
                }
                let Some(filename) = canonical_path.file_name().and_then(|name| name.to_str())
                else {
                    continue;
                };
                let Some(product) = manual_product_name(filename) else {
                    continue;
                };
                records
                    .entry(product.to_owned())
                    .or_insert_with(|| PackageRecord {
                        name: product.to_owned(),
                        version: None,
                        architecture: None,
                        ecosystem: "unknown".to_owned(),
                        purl: None,
                        source: PackageSource::Manual,
                        evidence_path: None,
                    });
            }
            if visited > MAX_ENTRIES {
                break;
            }
        }
        if visited > MAX_ENTRIES {
            break;
        }
    }
    ManualCollection {
        records: records.into_values().collect(),
        partial,
    }
}

#[cfg(not(target_os = "linux"))]
fn collect_manual_binaries() -> ManualCollection {
    ManualCollection {
        records: Vec::new(),
        partial: false,
    }
}

#[cfg(any(target_os = "linux", test))]
fn manual_product_name(filename: &str) -> Option<&'static str> {
    match filename {
        "nginx" => Some("nginx"),
        "node" => Some("nodejs"),
        "php" => Some("php"),
        "python" | "python3" => Some("python"),
        "redis-server" => Some("redis"),
        "postgres" => Some("postgresql"),
        "mysqld" => Some("mysql"),
        "openssl" => Some("openssl"),
        _ => None,
    }
}

fn newest_installed_kernel(packages: &[PackageRecord]) -> Option<String> {
    let mut candidates = BTreeMap::<Vec<u64>, BTreeSet<String>>::new();
    for package in packages {
        let Some(candidate) = (if let Some(release) = package.name.strip_prefix("linux-image-") {
            Some(release)
        } else if matches!(
            package.name.as_str(),
            "kernel-core" | "kernel" | "linux-lts"
        ) {
            package.version.as_deref()
        } else {
            None
        }) else {
            continue;
        };
        if let Some(key) = numeric_release_key(candidate) {
            candidates
                .entry(key)
                .or_default()
                .insert(candidate.to_owned());
        }
    }
    let (_, releases) = candidates.last_key_value()?;
    if releases.len() == 1 {
        releases.first().cloned()
    } else {
        None
    }
}

fn kernel_restart_required(running: &str, installed: &str) -> Option<bool> {
    let running_key = numeric_release_key(running)?;
    let installed_key = numeric_release_key(installed)?;
    match installed_key.cmp(&running_key) {
        std::cmp::Ordering::Greater => Some(true),
        std::cmp::Ordering::Less => Some(false),
        std::cmp::Ordering::Equal if installed == running => Some(false),
        std::cmp::Ordering::Equal => None,
    }
}

fn numeric_release_key(value: &str) -> Option<Vec<u64>> {
    if value
        .as_bytes()
        .first()
        .is_none_or(|byte| !byte.is_ascii_digit())
    {
        return None;
    }
    let mut numbers = Vec::new();
    let mut current = String::new();
    for character in value.chars() {
        if character.is_ascii_digit() {
            current.push(character);
        } else if !current.is_empty() {
            numbers.push(current.parse().ok()?);
            current.clear();
        }
    }
    if !current.is_empty() {
        numbers.push(current.parse().ok()?);
    }
    (!numbers.is_empty()).then_some(numbers)
}

struct RuntimeCollection {
    records: Vec<RuntimeRecord>,
    check: CollectionCheck,
}

async fn collect_runtimes() -> RuntimeCollection {
    let mut records = Vec::new();
    let mut command_failures = 0usize;
    let mut invalid_outputs = 0usize;
    let mut successful_outputs = 0usize;
    for runtime in RuntimeExecutable::all() {
        match run_allowlisted(&HostCommand::RuntimeVersion(*runtime)).await {
            Ok(output) => {
                successful_outputs += 1;
                let output_text = String::from_utf8_lossy(&output.stdout);
                let version = output_text
                    .lines()
                    .find(|line| line.chars().any(|character| character.is_ascii_digit()))
                    .map(str::trim)
                    .filter(|version| !version.is_empty());
                if let Some(version) = version {
                    records.push(RuntimeRecord {
                        name: runtime.name().to_owned(),
                        version: version.to_owned(),
                        binary_path: runtime.program().to_owned(),
                    });
                } else {
                    invalid_outputs += 1;
                }
            }
            Err(_) => command_failures += 1,
        }
    }
    records.sort_by(|left, right| {
        (left.name.as_str(), left.binary_path.as_str())
            .cmp(&(right.name.as_str(), right.binary_path.as_str()))
    });
    records.dedup_by(|left, right| left.binary_path == right.binary_path);
    let status = if successful_outputs == 0 {
        CheckStatus::Unavailable
    } else if command_failures > 0 || invalid_outputs > 0 {
        CheckStatus::Partial
    } else {
        CheckStatus::Complete
    };
    RuntimeCollection {
        check: check(
            CheckKind::Runtimes,
            status,
            if command_failures > 0 {
                DiagnosticCode::CommandUnavailable
            } else {
                DiagnosticCode::InvalidOutput
            },
            records.len(),
        ),
        records,
    }
}

fn collect_operating_system() -> (Option<OperatingSystem>, Vec<CollectionCheck>) {
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

fn parse_os_release(contents: &str) -> Option<OperatingSystem> {
    let mut values = BTreeMap::new();
    for line in contents.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if !matches!(key, "ID" | "NAME" | "VERSION_ID" | "PRETTY_NAME") {
            continue;
        }
        let value = value.trim().trim_matches('"').trim_matches('\'');
        if !value.is_empty()
            && value.len() <= 512
            && !value.bytes().any(|byte| byte.is_ascii_control())
        {
            values.insert(key, value.to_owned());
        }
    }
    let id = values.get("ID").cloned();
    let name = values.get("NAME").cloned();
    if id.is_none() && name.is_none() {
        return None;
    }
    Some(OperatingSystem {
        id,
        name,
        version_id: values.get("VERSION_ID").cloned(),
        pretty_name: values.get("PRETTY_NAME").cloned(),
        kernel_release: None,
        installed_kernel_release: None,
        kernel_restart_required: None,
        architecture: std::env::consts::ARCH.to_owned(),
    })
}

fn is_well_formed_version_id(value: Option<&str>) -> bool {
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

fn os_collection_is_complete(os: &OperatingSystem) -> bool {
    os.kernel_release.is_some()
        && os.installed_kernel_release.is_some()
        && os.kernel_restart_required.is_some()
        && is_well_formed_version_id(os.version_id.as_deref())
}

struct ParsedPackages {
    records: Vec<PackageRecord>,
    partial: bool,
    diagnostic: DiagnosticCode,
}

fn parse_package_output(output: &[u8], ecosystem: &str, source: PackageSource) -> ParsedPackages {
    let Ok(output) = std::str::from_utf8(output) else {
        return ParsedPackages {
            records: Vec::new(),
            partial: true,
            diagnostic: DiagnosticCode::InvalidOutput,
        };
    };
    let mut records = Vec::new();
    let mut partial = false;
    let mut diagnostic = DiagnosticCode::InvalidOutput;
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let record = if source == PackageSource::Apk {
            parse_apk_package(line, ecosystem)
        } else {
            parse_tabbed_package(line, ecosystem, source)
        };
        let Some(record) = record else {
            partial = true;
            continue;
        };
        if records.len() == MAX_PACKAGE_RECORDS {
            partial = true;
            diagnostic = DiagnosticCode::LimitReached;
            break;
        }
        records.push(record);
    }
    ParsedPackages {
        records,
        partial,
        diagnostic,
    }
}

fn parse_tabbed_package(
    line: &str,
    ecosystem: &str,
    source: PackageSource,
) -> Option<PackageRecord> {
    let mut fields = line.split('\t');
    let name = fields.next()?.trim();
    let version = fields.next()?.trim();
    let architecture = fields
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if fields.next().is_some() {
        return None;
    }
    if name.is_empty()
        || version.is_empty()
        || [name, version]
            .into_iter()
            .chain(architecture)
            .any(|value| value.bytes().any(|byte| byte.is_ascii_control()))
    {
        return None;
    }
    Some(PackageRecord {
        name: name.to_owned(),
        version: Some(version.to_owned()),
        architecture: architecture.map(str::to_owned),
        ecosystem: ecosystem.to_owned(),
        purl: None,
        source,
        evidence_path: None,
    })
}

fn parse_apk_package(line: &str, ecosystem: &str) -> Option<PackageRecord> {
    let (name, version) = line
        .match_indices('-')
        .rev()
        .map(|(index, _)| (&line[..index], &line[index + 1..]))
        .find(|(name, version)| {
            !name.is_empty()
                && version.as_bytes().first().is_some_and(u8::is_ascii_digit)
                && !name
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        })?;
    if version
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return None;
    }
    Some(PackageRecord {
        name: name.to_owned(),
        version: Some(version.to_owned()),
        architecture: None,
        ecosystem: ecosystem.to_owned(),
        purl: None,
        source: PackageSource::Apk,
        evidence_path: None,
    })
}

async fn collect_containers(
    docker_cli_approved: bool,
) -> (
    Vec<ContainerRecord>,
    CollectionCheck,
    BTreeMap<String, DeploymentIdentity>,
) {
    if !docker_cli_approved {
        return (
            Vec::new(),
            check(
                CheckKind::Containers,
                CheckStatus::Unavailable,
                DiagnosticCode::ConfigurationUnavailable,
                0,
            ),
            BTreeMap::new(),
        );
    }
    let output = match run_allowlisted(&HostCommand::DockerList).await {
        Ok(output) => output,
        Err(error) => {
            return (
                Vec::new(),
                check(
                    CheckKind::Containers,
                    CheckStatus::Unavailable,
                    command_diagnostic(error),
                    0,
                ),
                BTreeMap::new(),
            );
        }
    };
    let mut containers = Vec::new();
    let mut deployments = BTreeMap::new();
    let mut partial = false;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if containers.len() >= 4096 {
            partial = true;
            break;
        }
        let row: Result<serde_json::Value, _> = serde_json::from_str(line);
        let Ok(row) = row else {
            partial = true;
            continue;
        };
        let id = row
            .get("ID")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let image = row
            .get("Image")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let name = row
            .get("Names")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .trim_start_matches('/');
        if !valid_container_id(id) || image.is_empty() || name.is_empty() {
            partial = true;
            continue;
        }
        match run_allowlisted(&HostCommand::DockerInspect {
            container_id: id.to_owned(),
        })
        .await
        {
            Ok(inspect) => match parse_docker_inspect(&inspect.stdout, id, name, image) {
                Some((container, deployment)) => {
                    if let Some(deployment) = deployment {
                        deployments.insert(container.id.clone(), deployment);
                    }
                    containers.push(container);
                }
                None => partial = true,
            },
            Err(_) => {
                partial = true;
                containers.push(ContainerRecord {
                    id: id.to_owned(),
                    name: name.to_owned(),
                    image: image.to_owned(),
                    image_digest: None,
                    oci_revision: None,
                    oci_version: None,
                    oci_source: None,
                });
            }
        }
    }
    let status = if partial {
        CheckStatus::Partial
    } else {
        CheckStatus::Complete
    };
    let count = containers.len();
    (
        containers,
        check(
            CheckKind::Containers,
            status,
            DiagnosticCode::InvalidOutput,
            count,
        ),
        deployments,
    )
}

fn parse_docker_inspect(
    output: &[u8],
    fallback_id: &str,
    fallback_name: &str,
    fallback_image: &str,
) -> Option<(ContainerRecord, Option<DeploymentIdentity>)> {
    let line = std::str::from_utf8(output).ok()?.trim();
    let mut fields = line.split('\t');
    let id = fields.next()?.trim().trim_start_matches('/');
    let name = fields.next()?.trim().trim_start_matches('/');
    let image = fields.next()?.trim();
    let image_digest = fields.next()?.trim();
    let revision = fields.next()?.trim();
    let version = fields.next()?.trim();
    let source = fields.next()?.trim();
    let id = if valid_container_id(id) {
        id
    } else {
        fallback_id
    };
    let name = if name.is_empty() { fallback_name } else { name };
    let image = if image.is_empty() {
        fallback_image
    } else {
        image
    };
    let image_digest = valid_sha256_digest(image_digest);
    let oci_revision = if revision.is_empty() {
        None
    } else {
        normalize_commit(revision)
    };
    let oci_version = nonempty_bounded(version);
    let oci_source = validate_repository(source);
    let deploy = if oci_revision.is_some()
        || oci_version.is_some()
        || oci_source.is_some()
        || image_digest.is_some()
    {
        Some(DeploymentIdentity {
            commit_sha: oci_revision.clone(),
            repository: oci_source.clone(),
            release_id: oci_version.clone(),
            image_digest: image_digest.clone(),
            built_at: None,
            source: DeploymentSource::OciLabel,
            integrity_verified: false,
        })
    } else {
        None
    };
    Some((
        ContainerRecord {
            id: id.to_owned(),
            name: name.to_owned(),
            image: image.to_owned(),
            image_digest,
            oci_revision,
            oci_version,
            oci_source,
        },
        deploy,
    ))
}

fn collect_dependency_inventory(
    allowed_roots: &[PathBuf],
    configuration_unavailable: bool,
) -> impl std::future::Future<Output = DependencyCollection> {
    let roots = allowed_roots.to_vec();
    async move {
        if roots.is_empty() {
            return DependencyCollection {
                records: Vec::new(),
                check: check(
                    CheckKind::DependencyFiles,
                    CheckStatus::Partial,
                    if configuration_unavailable {
                        DiagnosticCode::ConfigurationUnavailable
                    } else {
                        DiagnosticCode::NoAllowlistedPaths
                    },
                    0,
                ),
            };
        }
        let mut records = Vec::new();
        let mut partial = false;
        for root in roots {
            if !preflight_root(&root) {
                partial = true;
                continue;
            }
            let scan_root = root.clone();
            let inventory = task::spawn_blocking(move || scan_repository(scan_root)).await;
            let Ok(Ok(inventory)) = inventory else {
                partial = true;
                continue;
            };
            partial |= !inventory.complete;
            for component in inventory
                .components
                .into_iter()
                .take(MAX_PACKAGE_RECORDS.saturating_sub(records.len()))
            {
                let evidence_path = component
                    .evidence_paths
                    .iter()
                    .find(|path| safe_relative_evidence(path))
                    .cloned();
                records.push(PackageRecord {
                    name: component.name,
                    version: component.version,
                    architecture: None,
                    ecosystem: component.ecosystem,
                    purl: Some(component.purl),
                    source: PackageSource::Lockfile,
                    evidence_path,
                });
            }
            if records.len() >= MAX_PACKAGE_RECORDS {
                partial = true;
                break;
            }
        }
        let count = records.len();
        DependencyCollection {
            records,
            check: check(
                CheckKind::DependencyFiles,
                if partial {
                    CheckStatus::Partial
                } else {
                    CheckStatus::Complete
                },
                if partial {
                    DiagnosticCode::LimitReached
                } else {
                    DiagnosticCode::NoAllowlistedPaths
                },
                count,
            ),
        }
    }
}

struct DependencyCollection {
    records: Vec<PackageRecord>,
    check: CollectionCheck,
}

fn preflight_root(root: &Path) -> bool {
    let Ok(canonical_root) = root.canonicalize() else {
        return false;
    };
    let mut stack = vec![(canonical_root.clone(), 0usize)];
    let mut file_count = 0usize;
    let mut total_bytes = 0u64;
    while let Some((directory, depth)) = stack.pop() {
        if depth > MAX_ROOT_SCAN_DEPTH {
            return false;
        }
        let Ok(entries) = fs::read_dir(directory) else {
            return false;
        };
        for entry in entries {
            file_count += 1;
            if file_count > MAX_ROOT_SCAN_FILES {
                return false;
            }
            let Ok(entry) = entry else { return false };
            let Ok(metadata) = fs::symlink_metadata(entry.path()) else {
                return false;
            };
            if metadata.file_type().is_symlink() {
                return false;
            }
            if metadata.is_dir() {
                if matches!(
                    entry.file_name().to_str(),
                    Some(".git" | "node_modules" | "vendor" | "target" | "dist")
                ) {
                    continue;
                }
                stack.push((entry.path(), depth + 1));
            } else if metadata.is_file() {
                total_bytes = total_bytes.saturating_add(metadata.len());
                if total_bytes > MAX_ROOT_SCAN_BYTES {
                    return false;
                }
            }
        }
    }
    canonical_root.is_dir()
}

fn safe_relative_evidence(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn read_bounded_text(path: &Path, limit: u64) -> std::io::Result<String> {
    use std::io::Read;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeds its supported size",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len().min(limit) as usize);
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeds its supported size",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "file is not UTF-8"))
}

fn check(
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

fn command_diagnostic(error: commands::HostCommandError) -> DiagnosticCode {
    match error {
        commands::HostCommandError::Unavailable => DiagnosticCode::CommandUnavailable,
        commands::HostCommandError::Failed => DiagnosticCode::CommandFailed,
        commands::HostCommandError::Timeout => DiagnosticCode::LimitReached,
        commands::HostCommandError::OutputTooLarge => DiagnosticCode::LimitReached,
        commands::HostCommandError::InvalidArgument => DiagnosticCode::InvalidOutput,
    }
}

fn read_hostname() -> Option<String> {
    read_bounded_text(Path::new("/etc/hostname"), 4096)
        .ok()
        .map(|hostname| hostname.trim().chars().take(255).collect::<String>())
        .filter(|hostname| {
            !hostname.is_empty() && !hostname.bytes().any(|byte| byte.is_ascii_control())
        })
}

fn valid_container_id(id: &str) -> bool {
    (12..=64).contains(&id.len()) && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_sha256_digest(value: &str) -> Option<String> {
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

fn normalize_commit(value: &str) -> Option<String> {
    if (7..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(value.to_ascii_lowercase())
    } else {
        None
    }
}

fn nonempty_bounded(value: &str) -> Option<String> {
    (!value.is_empty() && value.len() <= 512 && !value.bytes().any(|byte| byte.is_ascii_control()))
        .then(|| value.to_owned())
}

fn validate_repository(value: &str) -> Option<String> {
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        collect_dependency_inventory, is_well_formed_version_id, kernel_restart_required,
        manual_product_name, newest_installed_kernel, os_collection_is_complete,
        package_command_for_os, parse_docker_inspect, parse_os_release, parse_package_output,
    };
    use security_monitor_agent_protocol::{CheckKind, CheckStatus, DiagnosticCode, PackageSource};

    #[test]
    fn system_metadata_parsers_return_only_allowlisted_fields() {
        let os =
            parse_os_release("ID=debian\nNAME=Debian\nVERSION_ID=12\nSECRET=value\n").expect("OS");
        assert_eq!(os.id.as_deref(), Some("debian"));
        assert_eq!(os.name.as_deref(), Some("Debian"));
        let packages = parse_package_output(
            b"pkg\t1.2.3\tamd64\nmalformed\n",
            "deb",
            PackageSource::Dpkg,
        );
        assert_eq!(packages.records.len(), 1);
        assert_eq!(packages.records[0].version.as_deref(), Some("1.2.3"));
        assert!(packages.partial);

        let alpine = parse_package_output(b"lib-example-2.4.1-r3\n", "apk", PackageSource::Apk);
        assert_eq!(alpine.records[0].name, "lib-example");
        assert_eq!(alpine.records[0].version.as_deref(), Some("2.4.1-r3"));
        assert!(!alpine.partial);
    }

    #[test]
    fn missing_or_malformed_distro_version_id_cannot_be_complete() {
        let mut missing = parse_os_release("ID=debian\nNAME=Debian\n").expect("OS");
        missing.kernel_release = Some("6.1.0".to_owned());
        missing.installed_kernel_release = Some("6.1.0".to_owned());
        missing.kernel_restart_required = Some(false);
        assert!(!os_collection_is_complete(&missing));
        assert!(!is_well_formed_version_id(missing.version_id.as_deref()));

        for version_id in ["unknown", "rolling", "12..1", ".12", "12."] {
            assert!(!is_well_formed_version_id(Some(version_id)));
        }

        for version_id in ["12", "24.04", "9.5", "3.22"] {
            assert!(is_well_formed_version_id(Some(version_id)));
        }

        missing.version_id = Some("12".to_owned());
        assert!(os_collection_is_complete(&missing));
    }

    #[test]
    fn package_inventory_preserves_multiarch_esm_and_kernel_flavor_uncertainty() {
        let multiarch = include_bytes!("../../../tests/fixtures/agent/dpkg-multiarch-esm.txt");
        let parsed = parse_package_output(multiarch, "deb", PackageSource::Dpkg);
        assert!(!parsed.partial);
        assert!(parsed.records.iter().any(|record| {
            record.name == "libfixture:amd64" && record.architecture.as_deref() == Some("amd64")
        }));
        assert!(parsed.records.iter().any(|record| {
            record.name == "libfixture:i386" && record.architecture.as_deref() == Some("i386")
        }));
        assert!(parsed.records.iter().any(|record| {
            record.name == "ubuntu-pro-client"
                && record.version.as_deref() == Some("1.2.3-0ubuntu0.22.04.1+esm1")
        }));
        assert_eq!(
            newest_installed_kernel(&parsed.records).as_deref(),
            Some("6.1.0-21-amd64")
        );

        let flavors = parse_package_output(
            include_bytes!("../../../tests/fixtures/agent/dpkg-kernel-flavors.txt"),
            "deb",
            PackageSource::Dpkg,
        );
        assert_eq!(newest_installed_kernel(&flavors.records), None);
    }

    #[test]
    fn merged_tabbed_package_rows_make_inventory_partial() {
        let parsed = parse_package_output(
            include_bytes!("../../../tests/fixtures/agent/dpkg-merged-rows.txt"),
            "deb",
            PackageSource::Dpkg,
        );
        assert!(parsed.partial);
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.records[0].name, "package-a");
    }

    #[tokio::test]
    async fn unknown_distro_and_malformed_package_output_remain_unverified() {
        let os = parse_os_release(include_str!(
            "../../../tests/fixtures/agent/os-release-unknown.txt"
        ));
        assert_eq!(
            os.as_ref().and_then(|value| value.id.as_deref()),
            Some("unknown-linux")
        );
        assert!(package_command_for_os(os.as_ref()).is_none());
        let unsupported = super::collect_os_packages(os.as_ref()).await;
        assert_eq!(unsupported.check.status, CheckStatus::Unavailable);
        assert_eq!(
            unsupported.check.diagnostic,
            Some(DiagnosticCode::UnsupportedPlatform)
        );

        let malformed = parse_package_output(
            include_bytes!("../../../tests/fixtures/agent/dpkg-malformed.txt"),
            "deb",
            PackageSource::Dpkg,
        );
        assert!(malformed.partial);
        assert_eq!(malformed.records.len(), 1);
        assert_eq!(malformed.diagnostic, DiagnosticCode::InvalidOutput);
    }

    #[test]
    fn kernel_comparison_uses_installed_package_release_and_manual_products_are_closed() {
        let packages = ["6.1.0-18-amd64", "6.1.0-21-amd64"].map(|release| {
            security_monitor_agent_protocol::PackageRecord {
                name: format!("linux-image-{release}"),
                version: Some("6.1".to_owned()),
                architecture: Some("amd64".to_owned()),
                ecosystem: "deb".to_owned(),
                purl: None,
                source: PackageSource::Dpkg,
                evidence_path: None,
            }
        });
        assert_eq!(
            newest_installed_kernel(&packages).as_deref(),
            Some("6.1.0-21-amd64")
        );
        assert_eq!(
            kernel_restart_required("6.1.0-18-amd64", "6.1.0-21-amd64"),
            Some(true)
        );
        assert_eq!(
            kernel_restart_required("6.1.0-18-amd64", "linux-image-amd64"),
            None
        );
        assert_eq!(
            kernel_restart_required("6.1.0-21-amd64", "6.1.0-21-cloud-amd64"),
            None
        );
        let meta_package = security_monitor_agent_protocol::PackageRecord {
            name: "linux-image-amd64".to_owned(),
            version: None,
            architecture: Some("amd64".to_owned()),
            ecosystem: "deb".to_owned(),
            purl: None,
            source: PackageSource::Dpkg,
            evidence_path: None,
        };
        assert_eq!(newest_installed_kernel(&[meta_package]), None);
        assert_eq!(manual_product_name("nginx"), Some("nginx"));
        assert_eq!(manual_product_name("node"), Some("nodejs"));
        assert_eq!(manual_product_name("unknown-bin"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn manual_inventory_records_only_known_executables_below_the_supplied_roots() {
        use std::{fs, os::unix::fs::PermissionsExt};

        let temp_root = std::env::temp_dir().join(format!("secmon-manual-{}", std::process::id()));
        let opt_root = temp_root.join("opt");
        let local_root = temp_root.join("usr-local");
        let nginx = opt_root.join("nginx");
        let node = local_root.join("bin").join("node");
        let unknown = opt_root.join("unknown-bin");
        let _ = fs::remove_dir_all(&temp_root);
        fs::create_dir_all(&opt_root).unwrap();
        fs::create_dir_all(node.parent().unwrap()).unwrap();
        fs::write(
            &nginx,
            include_bytes!("../../../tests/fixtures/agent/manual-binaries/opt/nginx"),
        )
        .unwrap();
        fs::write(
            &node,
            include_bytes!("../../../tests/fixtures/agent/manual-binaries/usr-local/bin/node"),
        )
        .unwrap();
        fs::write(&unknown, "not an allowlisted product").unwrap();
        for path in [&nginx, &node, &unknown] {
            let mut permissions = fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions).unwrap();
        }

        let collection =
            super::collect_manual_binaries_at([opt_root.as_path(), local_root.as_path()]);
        let _ = fs::remove_dir_all(&temp_root);

        assert!(!collection.partial);
        assert_eq!(
            collection
                .records
                .iter()
                .map(|record| record.name.as_str())
                .collect::<Vec<_>>(),
            ["nginx", "nodejs"]
        );
        assert!(collection.records.iter().all(|record| {
            record.source == PackageSource::Manual
                && record.version.is_none()
                && record.ecosystem == "unknown"
                && record.purl.is_none()
        }));
    }

    #[test]
    fn oci_inspection_keeps_only_approved_labels_and_never_verifies_integrity() {
        let line = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t/web\tacme/web:1\tsha256:1111111111111111111111111111111111111111111111111111111111111111\tabcdef0123456\tv1\thttps://github.com/acme/web";
        let (container, deploy) =
            parse_docker_inspect(line.as_bytes(), "bbbbbbbbbbbb", "web", "fallback")
                .expect("inspection should parse");
        assert_eq!(container.oci_revision.as_deref(), Some("abcdef0123456"));
        assert_eq!(
            container.image_digest.as_deref(),
            Some("sha256:1111111111111111111111111111111111111111111111111111111111111111")
        );
        assert!(!deploy.expect("deployment identity").integrity_verified);
    }

    #[tokio::test]
    async fn empty_allowlist_is_partial_and_does_not_scan_the_current_directory() {
        let result = collect_dependency_inventory(&[], false).await;
        assert!(result.records.is_empty());
        assert_eq!(result.check.kind, CheckKind::DependencyFiles);
        assert_eq!(result.check.status, CheckStatus::Partial);
        assert_eq!(
            result.check.diagnostic,
            Some(DiagnosticCode::NoAllowlistedPaths)
        );
        let invalid_config = collect_dependency_inventory(&[], true).await;
        assert_eq!(
            invalid_config.check.diagnostic,
            Some(DiagnosticCode::ConfigurationUnavailable)
        );
    }

    #[tokio::test]
    async fn allowlisted_gitless_fixture_is_scanned_with_relative_evidence_only() {
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/agent/project");
        let result = collect_dependency_inventory(&[root], false).await;
        assert_eq!(result.records.len(), 1);
        assert_eq!(result.records[0].name, "left-pad");
        assert!(
            result.records[0]
                .evidence_path
                .as_deref()
                .is_some_and(|path| !PathBuf::from(path).is_absolute())
        );
    }
}
