use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};
use thiserror::Error;
mod parsers;

pub use parsers::{
    ParsedPackages, normalize_commit, parse_agentless_package_output, parse_os_release,
    parse_os_release_with_architecture, parse_package_output, valid_container_id,
};

pub const PROTOCOL_VERSION: u16 = 3;
const MIN_SUPPORTED_PROTOCOL_VERSION: u16 = 1;
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 100_000;
const MAX_TEXT_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentInventory {
    pub protocol_version: u16,
    pub agent_version: String,
    pub captured_at: DateTime<Utc>,
    pub hostname: String,
    pub operating_system: Option<OperatingSystem>,
    pub packages: Vec<PackageRecord>,
    pub runtimes: Vec<RuntimeRecord>,
    pub processes: Vec<ProcessRecord>,
    pub services: Vec<ServiceRecord>,
    pub containers: Vec<ContainerRecord>,
    pub deployments: Vec<DeploymentIdentity>,
    pub checks: Vec<CollectionCheck>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperatingSystem {
    pub id: Option<String>,
    pub name: Option<String>,
    pub version_id: Option<String>,
    pub pretty_name: Option<String>,
    pub kernel_release: Option<String>,
    #[serde(default)]
    pub installed_kernel_release: Option<String>,
    #[serde(default)]
    pub kernel_restart_required: Option<bool>,
    pub architecture: String,
}

/// Returns the OSV ecosystem identifier for Debian and Ubuntu releases supported by the
/// Debian-compatible package version comparator.
pub fn osv_os_package_ecosystem(os: &OperatingSystem) -> Option<String> {
    let version_id = os.version_id.as_deref()?;
    let parts = version_id.split('.').collect::<Vec<_>>();
    if parts.is_empty()
        || parts.len() > 3
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    match os.id.as_deref()? {
        id if id.eq_ignore_ascii_case("debian") => Some(format!("Debian:{}", parts[0])),
        id if id.eq_ignore_ascii_case("ubuntu") && parts.len() >= 2 => {
            let release = format!("{}.{}", parts[0], parts[1]);
            let major = parts[0].parse::<u16>().ok()?;
            let minor = parts[1].parse::<u16>().ok()?;
            let lts = major.is_multiple_of(2) && minor == 4;
            Some(format!("Ubuntu:{release}{}", if lts { ":LTS" } else { "" }))
        }
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackageRecord {
    pub name: String,
    pub version: Option<String>,
    pub architecture: Option<String>,
    pub ecosystem: String,
    pub purl: Option<String>,
    pub source: PackageSource,
    pub evidence_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PackageSource {
    Dpkg,
    Rpm,
    Apk,
    Lockfile,
    ContainerImage,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRecord {
    pub name: String,
    pub version: String,
    pub binary_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessRecord {
    pub pid: u32,
    pub executable_path: Option<String>,
    pub user_name: Option<String>,
    pub service_unit: Option<String>,
    pub container_id: Option<String>,
    pub runtime_name: Option<String>,
    #[serde(default)]
    pub maps_status: MapsStatus,
    /// Basenames of shared libraries still mapped after their files were removed.
    #[serde(default)]
    pub deleted_shared_libraries: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MapsStatus {
    Checked,
    Unavailable,
    NotApplicable,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceRecord {
    pub name: String,
    pub unit_name: Option<String>,
    pub pid: Option<u32>,
    pub executable_path: Option<String>,
    pub user_name: Option<String>,
    pub container_id: Option<String>,
    pub deploy_identity: Option<DeploymentIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContainerRecord {
    pub id: String,
    pub name: String,
    pub image: String,
    pub image_digest: Option<String>,
    pub oci_revision: Option<String>,
    pub oci_version: Option<String>,
    pub oci_source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeploymentIdentity {
    pub commit_sha: Option<String>,
    pub repository: Option<String>,
    pub release_id: Option<String>,
    pub image_digest: Option<String>,
    pub built_at: Option<DateTime<Utc>>,
    pub source: DeploymentSource,
    /// An observed deploy ID identifies a build but does not prove its integrity.
    pub integrity_verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentSource {
    OciLabel,
    ApplicationFile,
    SystemFile,
    ServiceEnvironment,
    GitHead,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CollectionCheck {
    pub kind: CheckKind,
    pub status: CheckStatus,
    pub diagnostic: Option<DiagnosticCode>,
    pub item_count: u32,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    OperatingSystem,
    PackageInventory,
    Runtimes,
    Processes,
    Services,
    Containers,
    Deployments,
    DependencyFiles,
}

impl CheckKind {
    pub const ALL: [Self; 8] = [
        Self::OperatingSystem,
        Self::PackageInventory,
        Self::Runtimes,
        Self::Processes,
        Self::Services,
        Self::Containers,
        Self::Deployments,
        Self::DependencyFiles,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Complete,
    Partial,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCode {
    PermissionDenied,
    UnsupportedPlatform,
    CommandUnavailable,
    CommandFailed,
    InvalidOutput,
    LimitReached,
    ConfigurationUnavailable,
    NoAllowlistedPaths,
    StaleObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolError {
    #[error("agent inventory document exceeds the size limit")]
    TooLarge,
    #[error("agent inventory JSON is invalid")]
    InvalidJson,
    #[error("agent inventory uses an unsupported protocol version")]
    UnsupportedVersion,
    #[error("agent inventory violates protocol constraints")]
    InvalidInventory,
}

impl AgentInventory {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if !(MIN_SUPPORTED_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&self.protocol_version)
            || self.agent_version.is_empty()
            || self.hostname.is_empty()
            || self
                .operating_system
                .as_ref()
                .is_some_and(|os| os.architecture.is_empty())
            || self.packages.len() > MAX_RECORDS
            || self.runtimes.len() > MAX_RECORDS
            || self.processes.len() > MAX_RECORDS
            || self.services.len() > MAX_RECORDS
            || self.containers.len() > MAX_RECORDS
            || self.deployments.len() > MAX_RECORDS
        {
            return Err(ProtocolError::InvalidInventory);
        }

        let kinds = self
            .checks
            .iter()
            .map(|check| check.kind)
            .collect::<BTreeSet<_>>();
        if kinds.len() != self.checks.len()
            || kinds.len() != CheckKind::ALL.len()
            || !CheckKind::ALL.iter().all(|kind| kinds.contains(kind))
            || self.complete
                != self
                    .checks
                    .iter()
                    .all(|check| check.status == CheckStatus::Complete)
        {
            return Err(ProtocolError::InvalidInventory);
        }

        if self
            .checks
            .iter()
            .any(|check| (check.status == CheckStatus::Complete) != check.diagnostic.is_none())
        {
            return Err(ProtocolError::InvalidInventory);
        }

        let mut texts = vec![self.agent_version.as_str(), self.hostname.as_str()];
        if let Some(os) = &self.operating_system {
            texts.extend(
                [
                    os.id.as_deref(),
                    os.name.as_deref(),
                    os.version_id.as_deref(),
                    os.pretty_name.as_deref(),
                    os.kernel_release.as_deref(),
                    os.installed_kernel_release.as_deref(),
                    Some(os.architecture.as_str()),
                ]
                .into_iter()
                .flatten(),
            );
        }
        for package in &self.packages {
            texts.extend(
                [
                    Some(package.name.as_str()),
                    package.version.as_deref(),
                    package.architecture.as_deref(),
                    Some(package.ecosystem.as_str()),
                    package.purl.as_deref(),
                    package.evidence_path.as_deref(),
                ]
                .into_iter()
                .flatten(),
            );
            if package.name.is_empty()
                || package.ecosystem.is_empty()
                || package.version.as_deref().is_some_and(str::is_empty)
                || package
                    .evidence_path
                    .as_deref()
                    .is_some_and(|path| !safe_evidence_path(path))
            {
                return Err(ProtocolError::InvalidInventory);
            }
        }
        for runtime in &self.runtimes {
            texts.extend([
                runtime.name.as_str(),
                runtime.version.as_str(),
                runtime.binary_path.as_str(),
            ]);
            if runtime.name.is_empty()
                || runtime.version.is_empty()
                || !runtime.binary_path.starts_with('/')
            {
                return Err(ProtocolError::InvalidInventory);
            }
        }
        for process in &self.processes {
            texts.extend(
                [
                    process.executable_path.as_deref(),
                    process.user_name.as_deref(),
                    process.service_unit.as_deref(),
                    process.container_id.as_deref(),
                    process.runtime_name.as_deref(),
                ]
                .into_iter()
                .flatten(),
            );
            texts.extend(process.deleted_shared_libraries.iter().map(String::as_str));
            if process.pid == 0
                || process.deleted_shared_libraries.len() > 256
                || process
                    .deleted_shared_libraries
                    .iter()
                    .any(|name| name.is_empty() || name.contains('/') || !name.starts_with("lib"))
                || process
                    .executable_path
                    .as_deref()
                    .is_some_and(|path| !path.starts_with('/'))
            {
                return Err(ProtocolError::InvalidInventory);
            }
        }
        for service in &self.services {
            texts.extend(
                [
                    Some(service.name.as_str()),
                    service.unit_name.as_deref(),
                    service.executable_path.as_deref(),
                    service.user_name.as_deref(),
                    service.container_id.as_deref(),
                ]
                .into_iter()
                .flatten(),
            );
            if service.name.is_empty()
                || service
                    .executable_path
                    .as_deref()
                    .is_some_and(|path| !path.starts_with('/'))
            {
                return Err(ProtocolError::InvalidInventory);
            }
            if let Some(identity) = &service.deploy_identity {
                collect_deployment_text(identity, &mut texts);
                if !valid_deployment_identity(identity) {
                    return Err(ProtocolError::InvalidInventory);
                }
            }
        }
        for container in &self.containers {
            texts.extend([
                container.id.as_str(),
                container.name.as_str(),
                container.image.as_str(),
            ]);
            texts.extend(
                [
                    container.image_digest.as_deref(),
                    container.oci_revision.as_deref(),
                    container.oci_version.as_deref(),
                    container.oci_source.as_deref(),
                ]
                .into_iter()
                .flatten(),
            );
            if !valid_container_id(&container.id)
                || container.name.is_empty()
                || container.image.is_empty()
            {
                return Err(ProtocolError::InvalidInventory);
            }
        }
        for deployment in &self.deployments {
            collect_deployment_text(deployment, &mut texts);
            if !valid_deployment_identity(deployment) {
                return Err(ProtocolError::InvalidInventory);
            }
        }
        if texts.iter().any(|text| {
            text.is_empty()
                || text.len() > MAX_TEXT_BYTES
                || text.bytes().any(|byte| byte.is_ascii_control())
        }) {
            return Err(ProtocolError::InvalidInventory);
        }
        Ok(())
    }
}

fn collect_deployment_text<'a>(identity: &'a DeploymentIdentity, texts: &mut Vec<&'a str>) {
    texts.extend(
        [
            identity.commit_sha.as_deref(),
            identity.repository.as_deref(),
            identity.release_id.as_deref(),
            identity.image_digest.as_deref(),
        ]
        .into_iter()
        .flatten(),
    );
}

fn valid_deployment_identity(identity: &DeploymentIdentity) -> bool {
    if identity.integrity_verified
        || identity.commit_sha.as_deref().is_some_and(|value| {
            !(7..=64).contains(&value.len()) || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        || identity.image_digest.as_deref().is_some_and(|value| {
            let Some((algorithm, digest)) = value.split_once(':') else {
                return true;
            };
            algorithm != "sha256"
                || digest.len() != 64
                || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return false;
    }
    let Some(repository) = identity.repository.as_deref() else {
        return true;
    };
    let Ok(url) = url::Url::parse(repository) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && !repository
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

fn safe_evidence_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.contains(':')
        && value
            .split('/')
            .all(|part| !matches!(part, "" | "." | ".."))
}

pub fn decode_inventory(bytes: &[u8]) -> Result<AgentInventory, ProtocolError> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    let inventory: AgentInventory =
        serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidJson)?;
    if !(MIN_SUPPORTED_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&inventory.protocol_version) {
        return Err(ProtocolError::UnsupportedVersion);
    }
    inventory.validate()?;
    Ok(inventory)
}

pub fn json_schema() -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&schema_for!(AgentInventory))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        AgentInventory, MIN_SUPPORTED_PROTOCOL_VERSION, PROTOCOL_VERSION, decode_inventory,
        json_schema,
    };

    fn fixture(name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/agent")
            .join(name);
        std::fs::read(path).expect("fixture should be readable")
    }

    #[test]
    fn agent_scenarios_decode_as_explicit_inventory_evidence() {
        let scenarios = [
            "single-node.json",
            "kernel-restart-needed.json",
            "multiple-node-runtimes.json",
            "containers-different-digests.json",
            "deploy-unknown.json",
            "realistic-complete.json",
            "stale-inventory.json",
        ];
        for scenario in scenarios {
            let inventory = decode_inventory(&fixture(scenario)).expect("fixture should be valid");
            assert!(
                (MIN_SUPPORTED_PROTOCOL_VERSION..=PROTOCOL_VERSION)
                    .contains(&inventory.protocol_version)
            );
            assert_eq!(
                inventory.complete,
                inventory
                    .checks
                    .iter()
                    .all(|check| { check.status == super::CheckStatus::Complete })
            );
        }
    }

    #[test]
    fn newer_installed_kernel_is_explicit_reboot_evidence() {
        let inventory = decode_inventory(&fixture("kernel-restart-needed.json"))
            .expect("kernel restart fixture should be valid");
        let os = inventory.operating_system.expect("OS record exists");
        assert_eq!(os.kernel_release.as_deref(), Some("6.1.0-18-amd64"));
        assert_eq!(
            os.installed_kernel_release.as_deref(),
            Some("6.1.0-21-amd64")
        );
        assert_eq!(os.kernel_restart_required, Some(true));
        assert_eq!(inventory.protocol_version, 2);
    }

    #[test]
    fn realistic_server_inventory_can_be_complete_with_verified_process_maps() {
        let inventory = decode_inventory(&fixture("realistic-complete.json"))
            .expect("complete server fixture should decode");
        assert!(inventory.complete);
        assert!(
            inventory
                .checks
                .iter()
                .all(|check| { check.status == super::CheckStatus::Complete })
        );
        assert_eq!(inventory.processes.len(), 1);
        assert_eq!(
            inventory.processes[0].maps_status,
            super::MapsStatus::Checked
        );
    }

    #[test]
    fn os_package_ecosystems_are_mapped_only_for_versioned_debian_and_ubuntu() {
        let operating_system = |id: &str, version_id: &str| super::OperatingSystem {
            id: Some(id.to_owned()),
            name: None,
            version_id: Some(version_id.to_owned()),
            pretty_name: None,
            kernel_release: None,
            installed_kernel_release: None,
            kernel_restart_required: None,
            architecture: "x86_64".to_owned(),
        };

        assert_eq!(
            super::osv_os_package_ecosystem(&operating_system("debian", "12")),
            Some("Debian:12".to_owned())
        );
        assert_eq!(
            super::osv_os_package_ecosystem(&operating_system("ubuntu", "22.04.5")),
            Some("Ubuntu:22.04:LTS".to_owned())
        );
        assert_eq!(
            super::osv_os_package_ecosystem(&operating_system("ubuntu", "12.04")),
            Some("Ubuntu:12.04:LTS".to_owned())
        );
        assert_eq!(
            super::osv_os_package_ecosystem(&operating_system("ubuntu", "22.10")),
            Some("Ubuntu:22.10".to_owned())
        );
        assert_eq!(
            super::osv_os_package_ecosystem(&operating_system("rocky", "9.5")),
            None
        );
        assert_eq!(
            super::osv_os_package_ecosystem(&operating_system("ubuntu", "rolling")),
            None
        );
    }

    #[test]
    fn older_inventory_without_maps_status_is_unverified() {
        let inventory = decode_inventory(&fixture("single-node.json"))
            .expect("legacy inventory should remain compatible");
        assert_eq!(
            inventory.processes[0].maps_status,
            super::MapsStatus::Unknown
        );
    }

    #[test]
    fn unknown_fields_and_unsupported_versions_are_rejected() {
        let mut value: serde_json::Value = serde_json::from_slice(&fixture("single-node.json"))
            .expect("fixture JSON should parse");
        value["surprise"] = serde_json::Value::Bool(true);
        assert!(
            decode_inventory(&serde_json::to_vec(&value).expect("JSON should serialize")).is_err()
        );

        let mut inventory: AgentInventory = serde_json::from_slice(&fixture("single-node.json"))
            .expect("fixture should deserialize");
        inventory.protocol_version = 9;
        assert!(inventory.validate().is_err());

        let mut incomplete: AgentInventory = serde_json::from_slice(&fixture("single-node.json"))
            .expect("fixture should deserialize");
        incomplete.checks.pop();
        assert!(incomplete.validate().is_err());
    }

    #[test]
    fn observed_deployment_data_never_claims_integrity_verification() {
        let mut inventory: AgentInventory = serde_json::from_slice(&fixture("single-node.json"))
            .expect("fixture should deserialize");
        inventory.deployments[0].integrity_verified = true;
        assert!(inventory.validate().is_err());

        inventory.deployments[0].integrity_verified = false;
        inventory.deployments[0].commit_sha = Some("not-a-commit".to_owned());
        assert!(inventory.validate().is_err());
    }

    #[test]
    fn generated_schema_matches_the_committed_protocol_schema() {
        let generated = format!("{}\n", json_schema().expect("schema should serialize"));
        let expected = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("schema/agent-inventory.schema.json"),
        )
        .expect("committed schema should exist");
        assert_eq!(generated, expected);
    }
}
