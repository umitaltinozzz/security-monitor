use std::{fs, path::Path};

use security_monitor_advisory_providers::{HttpPolicy, PublicDataHttp};
use tempfile::tempdir;

use crate::{
    EngineDetection, EngineKind, EngineStatus, FindingKind, NormalizedScan, ScanMode, ScanRequest,
    normalize_osv_scanner, normalize_semgrep, normalize_trivy,
    runner::args_for_test,
    runner::contains_semgrepignore,
    runner::select_detection,
    version::{detect_in_paths, minimum_supported_version, parse_version_for_test},
};

fn fixture(name: &str) -> &'static [u8] {
    match name {
        "osv-output" => include_bytes!("../../../tests/fixtures/scanner-adapters/osv/output.json"),
        "osv-expected" => {
            include_bytes!("../../../tests/fixtures/scanner-adapters/osv/expected.json")
        }
        "trivy-output" => {
            include_bytes!("../../../tests/fixtures/scanner-adapters/trivy/output.json")
        }
        "trivy-expected" => {
            include_bytes!("../../../tests/fixtures/scanner-adapters/trivy/expected.json")
        }
        "semgrep-output" => {
            include_bytes!("../../../tests/fixtures/scanner-adapters/semgrep/output.json")
        }
        "semgrep-expected" => {
            include_bytes!("../../../tests/fixtures/scanner-adapters/semgrep/expected.json")
        }
        _ => panic!("fixture key is defined in the test"),
    }
}

fn create_project_files(root: &Path) {
    fs::write(root.join("package-lock.json"), "{}\n").unwrap();
    fs::write(root.join("Dockerfile"), "FROM alpine:3.20\n").unwrap();
    fs::write(root.join("app.py"), "print('fixture')\n").unwrap();
}

fn expected(name: &str) -> NormalizedScan {
    serde_json::from_slice(fixture(name)).unwrap()
}

#[test]
fn recorded_osv_scanner_json_normalizes_to_the_golden_model() {
    let project = tempdir().unwrap();
    create_project_files(project.path());

    let normalized = normalize_osv_scanner(fixture("osv-output"), project.path()).unwrap();

    assert_eq!(normalized, expected("osv-expected"));
}

#[test]
fn recorded_trivy_json_normalizes_findings_without_secret_values() {
    let project = tempdir().unwrap();
    create_project_files(project.path());

    let normalized = normalize_trivy(fixture("trivy-output"), Some(project.path())).unwrap();

    assert_eq!(normalized, expected("trivy-expected"));
    let serialized = serde_json::to_string(&normalized).unwrap();
    assert!(!serialized.contains("AKIAIOSFODNN7EXAMPLE"));
    assert_eq!(normalized.findings.len(), 3);
    assert_eq!(normalized.findings[1].kind, FindingKind::Secret);
}

#[test]
fn recorded_semgrep_json_normalizes_without_rendering_match_data() {
    let project = tempdir().unwrap();
    create_project_files(project.path());

    let normalized = normalize_semgrep(fixture("semgrep-output"), project.path()).unwrap();

    assert_eq!(normalized, expected("semgrep-expected"));
    let serialized = serde_json::to_string(&normalized).unwrap();
    assert!(!serialized.contains("sk_fixture_do_not_store"));
    assert!(!serialized.contains("eval(input"));
}

#[test]
fn output_paths_outside_the_project_make_the_scan_incomplete_and_are_omitted() {
    let project = tempdir().unwrap();
    let outside = tempdir().unwrap();
    create_project_files(project.path());
    let outside_path = outside.path().join("private-lockfile.json");
    fs::write(&outside_path, "{}\n").unwrap();
    let input = serde_json::json!({
        "results": [{
            "source": {"path": outside_path.to_string_lossy()},
            "packages": []
        }]
    });

    let normalized =
        normalize_osv_scanner(&serde_json::to_vec(&input).unwrap(), project.path()).unwrap();

    assert!(!normalized.complete);
    assert!(normalized.findings.is_empty());
    assert!(normalized.diagnostics.iter().any(|diagnostic| {
        diagnostic.kind == crate::ScanDiagnosticKind::PathOutsideProject
            && diagnostic.path.is_none()
    }));
    assert!(
        !serde_json::to_string(&normalized)
            .unwrap()
            .contains("private-lockfile")
    );
}

#[test]
fn malformed_or_partial_scanner_documents_do_not_become_complete_empty_results() {
    let project = tempdir().unwrap();

    assert!(normalize_osv_scanner(b"not json", project.path()).is_err());
    assert!(normalize_trivy(br#"{"SchemaVersion":2}"#, Some(project.path())).is_err());
    assert!(normalize_semgrep(br#"{"results":null}"#, project.path()).is_err());
}

#[tokio::test]
async fn missing_scanner_has_an_explicit_missing_state() {
    let directory = tempdir().unwrap();

    let detection = detect_in_paths(EngineKind::Trivy, [directory.path().to_path_buf()]).await;

    assert_eq!(detection.status, EngineStatus::Missing);
    assert_eq!(detection.engine, EngineKind::Trivy);
    assert!(detection.version.is_none());
    assert!(detection.executable.is_none());
}

#[test]
fn minimum_engine_versions_are_read_from_the_pinned_data_file() {
    assert_eq!(
        minimum_supported_version(EngineKind::OsvScanner)
            .unwrap()
            .to_string(),
        "2.0.0"
    );
    assert_eq!(
        minimum_supported_version(EngineKind::Trivy)
            .unwrap()
            .to_string(),
        "0.70.0"
    );
}

#[test]
fn available_managed_scanner_is_preferred_over_a_system_installation() {
    let system = EngineDetection {
        engine: EngineKind::Trivy,
        status: EngineStatus::Available,
        version: Some("0.76.1".to_owned()),
        executable: Some("system/trivy".into()),
    };
    let managed = EngineDetection {
        engine: EngineKind::Trivy,
        status: EngineStatus::Available,
        version: Some("0.76.1".to_owned()),
        executable: Some("app-data/scanners/trivy/0.76.1/trivy".into()),
    };

    assert_eq!(
        select_detection(EngineKind::Trivy, system, Some(managed.clone())),
        managed
    );
}

#[test]
fn installed_versions_are_parsed_from_scanner_version_text() {
    assert_eq!(
        parse_version_for_test("OSV-Scanner version: v2.7.0 (commit fixture)"),
        Some(semver::Version::new(2, 7, 0))
    );
    assert_eq!(
        parse_version_for_test("Version: 0.76.1"),
        Some(semver::Version::new(0, 76, 1))
    );
}

#[test]
fn scanner_arguments_are_fixed_and_disable_scanner_network_features() {
    let project = tempdir().unwrap();
    let cache = project.path().join("cache with spaces");
    let trusted_config = tempfile::NamedTempFile::new_in(project.path()).unwrap();
    let request = ScanRequest::new(
        EngineKind::OsvScanner,
        ScanMode::Dependencies,
        project.path(),
    );
    let args = args_for_test(
        &request,
        project.path(),
        &cache,
        Some(trusted_config.path()),
    )
    .unwrap();
    let args = args
        .iter()
        .map(|argument| argument.to_string_lossy())
        .collect::<Vec<_>>();

    assert!(args.iter().any(|argument| argument == "--offline"));
    assert!(
        args.iter()
            .any(|argument| argument == "--offline-vulnerabilities")
    );
    assert_eq!(args.last().unwrap(), &project.path().to_string_lossy());
    let config_flag = args
        .iter()
        .position(|argument| argument == "--config")
        .unwrap();
    assert_eq!(
        args[config_flag + 1],
        trusted_config.path().to_string_lossy()
    );
    assert!(
        !args
            .iter()
            .any(|argument| argument == "-c" || argument == "/c")
    );

    let trivy = ScanRequest::new(EngineKind::Trivy, ScanMode::Filesystem, project.path());
    let trivy_args = args_for_test(&trivy, project.path(), &cache, None).unwrap();
    let trivy_args = trivy_args
        .iter()
        .map(|argument| argument.to_string_lossy())
        .collect::<Vec<_>>();
    for flag in [
        "--skip-db-update",
        "--skip-java-db-update",
        "--skip-check-update",
        "--offline-scan",
        "--disable-telemetry",
        "--config=",
        "--ignorefile=",
        "--secret-config=",
    ] {
        assert!(trivy_args.iter().any(|argument| argument == flag));
    }
}

#[test]
fn semgrep_repository_ignore_files_block_unapproved_configuration() {
    let project = tempdir().unwrap();
    let nested = project.path().join("src").join("module");
    fs::create_dir_all(&nested).unwrap();
    assert!(!contains_semgrepignore(project.path()).unwrap());

    fs::write(nested.join(".semgrepignore"), "secret/**\n").unwrap();

    assert!(contains_semgrepignore(project.path()).unwrap());
}

#[test]
fn semgrep_requires_an_explicit_local_rules_file_inside_the_project() {
    let project = tempdir().unwrap();
    let outside = tempdir().unwrap();
    create_project_files(project.path());
    let rules = project.path().join("rules.yml");
    fs::write(&rules, "rules: []\n").unwrap();
    let outside_rules = outside.path().join("rules.yml");
    fs::write(&outside_rules, "rules: []\n").unwrap();

    let accepted = ScanRequest::new(EngineKind::Semgrep, ScanMode::Code, project.path())
        .with_local_rules(&rules);
    assert!(crate::commands::validate_request(&accepted).is_ok());
    let arguments = args_for_test(&accepted, project.path(), project.path(), Some(&rules)).unwrap();
    assert!(
        arguments
            .iter()
            .any(|argument| argument == "--no-git-ignore")
    );
    assert!(
        arguments
            .iter()
            .any(|argument| argument == "--disable-nosem")
    );

    let rejected = ScanRequest::new(EngineKind::Semgrep, ScanMode::Code, project.path())
        .with_local_rules(&outside_rules);
    assert!(crate::commands::validate_request(&rejected).is_err());
}

#[tokio::test]
async fn semgrep_does_not_load_repository_ignore_configuration_without_approval() {
    let project = tempdir().unwrap();
    let app_data = tempdir().unwrap();
    create_project_files(project.path());
    let rules = project.path().join("rules.yml");
    fs::write(&rules, "rules: []\n").unwrap();
    fs::write(project.path().join(".semgrepignore"), "src/**\n").unwrap();
    let http = PublicDataHttp::new(HttpPolicy {
        public_downloads_enabled: false,
    })
    .unwrap();
    let adapters = crate::ScannerAdapters::new(http, app_data.path());
    let request = ScanRequest::new(EngineKind::Semgrep, ScanMode::Code, project.path())
        .with_local_rules(&rules);

    let error = adapters.scan(request).await.unwrap_err();

    assert!(matches!(
        error,
        crate::ScannerError::RepositoryConfigurationRequiresApproval
    ));
}

#[test]
fn installation_path_helpers_do_not_accept_outside_roots() {
    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let link = root.path().join("scanner-link");
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), &link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(outside.path(), &link).unwrap();
    let resolved = link.canonicalize().unwrap();
    assert!(!resolved.starts_with(root.path().canonicalize().unwrap()));
}
