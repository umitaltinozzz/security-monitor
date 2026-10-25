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
pub(crate) use security_monitor_agent_protocol::{
    normalize_commit, parse_package_output, valid_container_id,
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

mod containers;
mod dependencies;
mod os;
mod packages;
mod read_bounded;
mod runtimes;
#[cfg(test)]
mod tests;
mod utils;

pub(crate) use containers::collect_containers;
#[cfg(test)]
pub(crate) use containers::parse_docker_inspect;
pub(crate) use dependencies::collect_dependency_inventory;
pub(crate) use os::{collect_operating_system, os_collection_is_complete};
#[cfg(test)]
pub(crate) use os::{is_well_formed_version_id, parse_os_release};
#[cfg(any(target_os = "linux", test))]
pub(crate) use packages::manual_product_name;
#[cfg(test)]
pub(crate) use packages::package_command_for_os;
pub(crate) use packages::{
    collect_manual_binaries, collect_os_packages, kernel_restart_required, newest_installed_kernel,
};
pub(crate) use read_bounded::read_bounded_text;
pub(crate) use runtimes::collect_runtimes;
pub(crate) use utils::{
    check, command_diagnostic, nonempty_bounded, read_hostname, valid_sha256_digest,
    validate_repository,
};
