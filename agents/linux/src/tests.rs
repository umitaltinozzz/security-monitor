use std::path::PathBuf;

use super::{
    collect_dependency_inventory, is_well_formed_version_id, kernel_restart_required,
    manual_product_name, newest_installed_kernel, os_collection_is_complete,
    package_command_for_os, parse_docker_inspect, parse_os_release, parse_package_output,
};
use security_monitor_agent_protocol::{CheckKind, CheckStatus, DiagnosticCode, PackageSource};

#[test]
fn system_metadata_parsers_return_only_allowlisted_fields() {
    let os = parse_os_release("ID=debian\nNAME=Debian\nVERSION_ID=12\nSECRET=value\n").expect("OS");
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

    let collection = super::collect_manual_binaries_at([opt_root.as_path(), local_root.as_path()]);
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
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/agent/project");
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
