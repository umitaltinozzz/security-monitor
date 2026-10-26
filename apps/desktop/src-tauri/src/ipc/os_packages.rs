use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use chrono::{Duration, Utc};
use security_monitor_advisory_providers::{
    FindingReason, OsvDatabase, ecosystem_slug, evaluate_inventory,
};
use security_monitor_agent_protocol::{
    AgentInventory, CheckKind, CheckStatus, OperatingSystem, PackageSource,
    osv_os_package_ecosystems,
};
use security_monitor_core::{FindingStatus, Severity};
use security_monitor_inventory::{Inventory, InventoryComponent};

use crate::ipc_types::{OsPackageEvaluationStatus, ServerOsPackageFinding};

const OSV_CACHE_MAX_AGE: Duration = Duration::hours(1);

#[derive(Debug)]
pub(super) struct OsPackageEvaluation {
    pub(super) status: OsPackageEvaluationStatus,
    pub(super) findings: Vec<ServerOsPackageFinding>,
}

pub(super) fn evaluate_os_packages(
    cache_root: &Path,
    inventory: &AgentInventory,
) -> OsPackageEvaluation {
    let Some(os) = inventory.operating_system.as_ref() else {
        return OsPackageEvaluation {
            status: OsPackageEvaluationStatus::Unverified,
            findings: Vec::new(),
        };
    };
    if is_oracle_linux(os) {
        return OsPackageEvaluation {
            status: OsPackageEvaluationStatus::NoDataSource,
            findings: Vec::new(),
        };
    }
    let Some(ecosystems) = osv_os_package_ecosystems(os) else {
        return OsPackageEvaluation {
            status: OsPackageEvaluationStatus::Unverified,
            findings: Vec::new(),
        };
    };
    let Some(package_check) = inventory
        .checks
        .iter()
        .find(|check| check.kind == CheckKind::PackageInventory)
    else {
        return OsPackageEvaluation {
            status: OsPackageEvaluationStatus::Unverified,
            findings: Vec::new(),
        };
    };
    let package_inventory_complete = package_check.status == CheckStatus::Complete;
    let Some(source) = package_source_for_os(os) else {
        return OsPackageEvaluation {
            status: OsPackageEvaluationStatus::Unverified,
            findings: Vec::new(),
        };
    };
    let packages = inventory
        .packages
        .iter()
        .filter(|package| package.source == source)
        .collect::<Vec<_>>();
    let Some(slug) = ecosystems
        .first()
        .and_then(|ecosystem| ecosystem_slug(ecosystem))
    else {
        return OsPackageEvaluation {
            status: OsPackageEvaluationStatus::NoDataSource,
            findings: Vec::new(),
        };
    };
    let Ok(database) = OsvDatabase::open(cache_root.join(slug)) else {
        return OsPackageEvaluation {
            status: OsPackageEvaluationStatus::Unverified,
            findings: Vec::new(),
        };
    };
    let cache_is_fresh = !database.status().stale
        && database.status().updated_at.is_some_and(|updated| {
            let now = Utc::now();
            updated <= now && now.signed_duration_since(updated) <= OSV_CACHE_MAX_AGE
        });
    let verified = package_inventory_complete && cache_is_fresh && !is_red_hat(os);

    let mut advisory_by_scope = BTreeMap::new();
    let mut component_keys = BTreeMap::new();
    let mut components = Vec::new();
    for (package_index, package) in packages.iter().enumerate() {
        for (scope_index, ecosystem) in ecosystems.iter().enumerate() {
            for advisory in database.query(ecosystem, &package.name) {
                advisory_by_scope
                    .entry((advisory.canonical_id.clone(), ecosystem.clone()))
                    .or_insert(advisory);
            }
            let purl =
                format!("pkg:generic/security-monitor-os-package/{package_index}/{scope_index}");
            component_keys.insert(purl.clone(), (package_index, scope_index));
            components.push(InventoryComponent {
                purl,
                ecosystem: ecosystem.clone(),
                name: package.name.clone(),
                version: package.version.clone(),
                source_type: "agent_os_package".to_owned(),
                evidence_paths: Vec::new(),
            });
        }
    }
    let inventory = Inventory {
        components,
        project_roots: Vec::new(),
        detected_files: Vec::new(),
        diagnostics: Vec::new(),
        complete: package_inventory_complete,
    };
    let advisories = advisory_by_scope.into_values().collect::<Vec<_>>();
    let mut emitted = BTreeSet::new();
    let findings = evaluate_inventory(&advisories, &inventory)
        .into_iter()
        .filter_map(|finding| {
            let (package_index, scope_index) = *component_keys.get(&finding.component_purl)?;
            let package = packages.get(package_index)?;
            let ecosystem = ecosystems.get(scope_index)?;
            let advisory = advisories.iter().find(|advisory| {
                advisory.canonical_id == finding.advisory_id
                    && advisory
                        .affected_ranges
                        .iter()
                        .any(|range| range.ecosystem.eq_ignore_ascii_case(ecosystem))
            })?;
            if !emitted.insert((finding.advisory_id.clone(), package.name.clone())) {
                return None;
            }
            let status = if verified && finding.reason == FindingReason::AffectedVersion {
                FindingStatus::New
            } else {
                FindingStatus::NeedsReview
            };
            Some(ServerOsPackageFinding {
                advisory_id: finding.advisory_id,
                package_name: package.name.clone(),
                installed_version: package.version.clone().unwrap_or_default(),
                severity: advisory.severity.clone().unwrap_or(Severity::Unknown),
                status,
                fix_version: finding.fix_version,
            })
        })
        .collect();

    OsPackageEvaluation {
        status: if is_red_hat(os) {
            OsPackageEvaluationStatus::UnverifiedScope
        } else if verified {
            OsPackageEvaluationStatus::Evaluated
        } else {
            OsPackageEvaluationStatus::Unverified
        },
        findings,
    }
}

fn package_source_for_os(os: &OperatingSystem) -> Option<PackageSource> {
    match os.id.as_deref()?.to_ascii_lowercase().as_str() {
        "debian" | "ubuntu" => Some(PackageSource::Dpkg),
        "almalinux" | "rocky" | "rhel" | "redhat" => Some(PackageSource::Rpm),
        "alpine" => Some(PackageSource::Apk),
        _ => None,
    }
}

fn is_oracle_linux(os: &OperatingSystem) -> bool {
    os.id.as_deref().is_some_and(|id| {
        matches!(
            id.to_ascii_lowercase().as_str(),
            "ol" | "oracle" | "oraclelinux"
        )
    })
}

fn is_red_hat(os: &OperatingSystem) -> bool {
    os.id
        .as_deref()
        .is_some_and(|id| matches!(id.to_ascii_lowercase().as_str(), "rhel" | "redhat"))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use chrono::{Duration, Utc};
    use security_monitor_advisory_providers::OsvUpdateStatus;
    use security_monitor_agent_protocol::{
        AgentInventory, CheckKind, CheckStatus, PackageRecord, PackageSource, parse_package_output,
    };
    use security_monitor_core::FindingStatus;

    use super::{OsPackageEvaluationStatus, evaluate_os_packages};

    fn inventory_with_package(
        distro: &str,
        version_id: &str,
        package_name: &str,
        package_version: &str,
    ) -> AgentInventory {
        let mut inventory: AgentInventory = serde_json::from_str(include_str!(
            "../../../../../tests/fixtures/agent/realistic-complete.json"
        ))
        .expect("complete agent fixture is valid");
        let os = inventory.operating_system.as_mut().expect("fixture OS");
        os.id = Some(distro.to_owned());
        os.version_id = Some(version_id.to_owned());
        inventory.packages.push(PackageRecord {
            name: package_name.to_owned(),
            version: Some(package_version.to_owned()),
            architecture: Some("amd64".to_owned()),
            ecosystem: "deb".to_owned(),
            purl: None,
            source: PackageSource::Dpkg,
            evidence_path: None,
        });
        inventory
    }

    fn inventory_from_package_fixture(
        distro: &str,
        version_id: &str,
        fixture: &str,
        ecosystem: &str,
        source: PackageSource,
    ) -> AgentInventory {
        let mut inventory: AgentInventory = serde_json::from_str(include_str!(
            "../../../../../tests/fixtures/agent/realistic-complete.json"
        ))
        .expect("complete agent fixture is valid");
        let os = inventory.operating_system.as_mut().expect("fixture OS");
        os.id = Some(distro.to_owned());
        os.version_id = Some(version_id.to_owned());
        let parsed = parse_package_output(fixture.as_bytes(), ecosystem, source);
        assert!(!parsed.partial, "package fixture parses completely");
        inventory.packages = parsed.records;
        inventory
    }

    fn install_cache(root: &Path, distro_slug: &str, fixture_name: &str, stale_by: Duration) {
        let cache = root.join(distro_slug);
        fs::create_dir_all(&cache).expect("create test OSV cache");
        let fixture = match fixture_name {
            "debian" => include_bytes!(
                "../../../../../tests/fixtures/advisory-db/Debian/CVE-2026-9001.json"
            )
            .as_slice(),
            "ubuntu" => include_bytes!(
                "../../../../../tests/fixtures/advisory-db/Ubuntu/CVE-2026-9002.json"
            )
            .as_slice(),
            "almalinux" => include_bytes!(
                "../../../../../tests/fixtures/advisory-db/AlmaLinux/CVE-2026-9101.json"
            )
            .as_slice(),
            "rocky" => include_bytes!(
                "../../../../../tests/fixtures/advisory-db/Rocky Linux/CVE-2026-9102.json"
            )
            .as_slice(),
            "alpine" => include_bytes!(
                "../../../../../tests/fixtures/advisory-db/Alpine/CVE-2026-9103.json"
            )
            .as_slice(),
            "redhat" => include_bytes!(
                "../../../../../tests/fixtures/advisory-db/Red Hat/CVE-2026-9104.json"
            )
            .as_slice(),
            _ => unreachable!("test helper only supports known fixture names"),
        };
        let advisory_id = match fixture_name {
            "debian" => "CVE-2026-9001",
            "ubuntu" => "CVE-2026-9002",
            "almalinux" => "CVE-2026-9101",
            "rocky" => "CVE-2026-9102",
            "alpine" => "CVE-2026-9103",
            "redhat" => "CVE-2026-9104",
            _ => unreachable!("test helper only supports known fixture names"),
        };
        fs::write(cache.join(format!("{advisory_id}.json")), fixture)
            .expect("write test advisory fixture");
        let status = OsvUpdateStatus {
            ecosystem: fixture_name.to_owned(),
            updated_at: Some(Utc::now() - stale_by),
            stale: false,
            error: None,
            ..OsvUpdateStatus::default()
        };
        fs::write(
            cache.join(".secmon-cache.json"),
            serde_json::to_vec(&status).expect("serialize test cache status"),
        )
        .expect("write test cache status");
    }

    #[test]
    fn complete_fresh_debian_inventory_is_evaluated_and_fixed_versions_are_clear() {
        let temp = tempfile::tempdir().expect("temporary cache");
        install_cache(temp.path(), "Debian", "debian", Duration::zero());

        let affected = inventory_with_package("debian", "12", "openssl", "3.0.14-1~deb12u0");
        let result = evaluate_os_packages(temp.path(), &affected);
        assert_eq!(result.status, OsPackageEvaluationStatus::Evaluated);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].advisory_id, "CVE-2026-9001");
        assert_eq!(result.findings[0].status, FindingStatus::New);
        assert_eq!(
            result.findings[0].fix_version.as_deref(),
            Some("3.0.14-1~deb12u1")
        );

        let fixed = inventory_with_package("debian", "12", "openssl", "3.0.14-1~deb12u1");
        let result = evaluate_os_packages(temp.path(), &fixed);
        assert_eq!(result.status, OsPackageEvaluationStatus::Evaluated);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn ubuntu_evaluation_uses_the_ubuntu_osv_ecosystem() {
        let temp = tempfile::tempdir().expect("temporary cache");
        install_cache(temp.path(), "Ubuntu", "ubuntu", Duration::zero());
        let inventory = inventory_with_package("ubuntu", "22.04.5", "curl", "7.81.0-1ubuntu1.19");

        let result = evaluate_os_packages(temp.path(), &inventory);
        assert_eq!(result.status, OsPackageEvaluationStatus::Evaluated);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].advisory_id, "CVE-2026-9002");
        assert_eq!(result.findings[0].status, FindingStatus::New);
    }

    #[test]
    fn stale_cache_and_partial_package_inventory_are_never_marked_evaluated() {
        let stale_temp = tempfile::tempdir().expect("temporary stale cache");
        install_cache(stale_temp.path(), "Debian", "debian", Duration::hours(25));
        let inventory = inventory_with_package("debian", "12", "openssl", "3.0.14-1~deb12u0");
        let result = evaluate_os_packages(stale_temp.path(), &inventory);
        assert_eq!(result.status, OsPackageEvaluationStatus::Unverified);
        assert_eq!(result.findings[0].status, FindingStatus::NeedsReview);

        let fresh_temp = tempfile::tempdir().expect("temporary fresh cache");
        install_cache(fresh_temp.path(), "Debian", "debian", Duration::zero());
        let mut partial = inventory;
        partial.complete = false;
        partial
            .checks
            .iter_mut()
            .find(|check| check.kind == CheckKind::PackageInventory)
            .expect("package inventory check")
            .status = CheckStatus::Partial;
        let result = evaluate_os_packages(fresh_temp.path(), &partial);
        assert_eq!(result.status, OsPackageEvaluationStatus::Unverified);
        assert_eq!(result.findings[0].status, FindingStatus::NeedsReview);
    }

    #[test]
    fn alma_rocky_and_alpine_package_fixtures_are_evaluated_from_their_own_osv_scopes() {
        let cases = [
            (
                "almalinux",
                "9.5",
                include_str!("../../../../../tests/fixtures/agent/almalinux-9-packages.txt"),
                "AlmaLinux:9",
                PackageSource::Rpm,
                "AlmaLinux",
                "CVE-2026-9101",
            ),
            (
                "rocky",
                "9.5",
                include_str!("../../../../../tests/fixtures/agent/rocky-9-packages.txt"),
                "Rocky Linux:9",
                PackageSource::Rpm,
                "Rocky Linux",
                "CVE-2026-9102",
            ),
            (
                "alpine",
                "3.20.3",
                include_str!("../../../../../tests/fixtures/agent/alpine-3.20-packages.txt"),
                "Alpine:v3.20",
                PackageSource::Apk,
                "Alpine",
                "CVE-2026-9103",
            ),
        ];
        for (distro, release, package_fixture, ecosystem, source, slug, advisory_id) in cases {
            let temp = tempfile::tempdir().expect("temporary cache");
            install_cache(temp.path(), slug, distro, Duration::zero());
            let inventory =
                inventory_from_package_fixture(distro, release, package_fixture, ecosystem, source);
            let result = evaluate_os_packages(temp.path(), &inventory);
            assert_eq!(
                result.status,
                OsPackageEvaluationStatus::Evaluated,
                "{distro}"
            );
            assert_eq!(result.findings.len(), 1, "{distro}");
            assert_eq!(result.findings[0].advisory_id, advisory_id);
            assert_eq!(result.findings[0].status, FindingStatus::New);
        }
    }

    #[test]
    fn red_hat_repository_matches_require_review_and_oracle_linux_has_no_source() {
        let temp = tempfile::tempdir().expect("temporary cache");
        install_cache(temp.path(), "Red Hat", "redhat", Duration::zero());
        let inventory = inventory_with_package("rhel", "9.5", "openssl-libs", "3.0.7-28.el9_4");
        let mut inventory = inventory;
        inventory.packages.last_mut().expect("inserted RPM").source = PackageSource::Rpm;

        let result = evaluate_os_packages(temp.path(), &inventory);
        assert_eq!(result.status, OsPackageEvaluationStatus::UnverifiedScope);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].advisory_id, "CVE-2026-9104");
        assert_eq!(result.findings[0].status, FindingStatus::NeedsReview);

        let oracle = inventory_with_package("ol", "9.5", "openssl-libs", "3.0.7-28.el9_4");
        let result = evaluate_os_packages(temp.path(), &oracle);
        assert_eq!(result.status, OsPackageEvaluationStatus::NoDataSource);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn unknown_distribution_is_unverified_without_reusing_another_os_ecosystem() {
        let temp = tempfile::tempdir().expect("temporary cache");
        let inventory = inventory_with_package("unknown-linux", "9.5", "openssl", "3.0.7-28.el9");

        let result = evaluate_os_packages(temp.path(), &inventory);
        assert_eq!(result.status, OsPackageEvaluationStatus::Unverified);
        assert!(result.findings.is_empty());
    }
}
