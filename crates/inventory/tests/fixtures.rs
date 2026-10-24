use security_monitor_inventory::{DetectedFileKind, DiagnosticKind, scan_repository};
use std::{
    fs,
    path::{Path, PathBuf},
};

const FIXTURES: &[&str] = &[
    "npm",
    "pnpm",
    "yarn-v1",
    "yarn-berry",
    "bun",
    "requirements",
    "poetry",
    "uv",
    "pipfile",
    "composer",
    "go",
    "cargo",
    "monorepo",
];

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/inventory")
}

#[test]
fn supported_lockfile_fixtures_match_the_expected_package_url_lists() {
    for fixture in FIXTURES {
        let root = fixtures_root().join(fixture);
        let inventory = scan_repository(&root).expect("fixture root is a directory");
        assert!(
            inventory.complete,
            "{fixture} should be fully parsed: {:?}",
            inventory.diagnostics
        );
        let expected: Vec<String> = serde_json::from_slice(
            &fs::read(root.join("expected.json")).expect("expected list exists"),
        )
        .expect("expected list is valid JSON");
        let actual = inventory
            .components
            .iter()
            .map(|component| component.purl.clone())
            .collect::<Vec<_>>();
        assert_eq!(actual, expected, "fixture {fixture}");
    }
}

#[test]
fn monorepo_discovery_finds_nested_roots_dockerfiles_and_workflows() {
    let inventory = scan_repository(fixtures_root().join("monorepo"))
        .expect("monorepo fixture root is a directory");

    assert_eq!(inventory.project_roots, ["", "apps/api"]);
    assert!(inventory.detected_files.iter().any(|file| {
        file.path == "services/api/Dockerfile" && file.kind == DetectedFileKind::Dockerfile
    }));
    assert!(inventory.detected_files.iter().any(|file| {
        file.path == ".github/workflows/checks.yaml"
            && file.kind == DetectedFileKind::GithubWorkflow
    }));
}

#[test]
fn generated_dependency_directories_are_not_scanned() {
    let root = temporary_directory("generated");
    fs::create_dir_all(root.join("node_modules/nested")).expect("create fixture directories");
    fs::write(
        root.join("node_modules/nested/package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"node_modules/hidden":{"version":"1.0.0"}}}"#,
    )
    .expect("write generated lockfile");

    let inventory = scan_repository(&root).expect("temporary root is a directory");
    assert!(inventory.complete);
    assert!(inventory.components.is_empty());
    fs::remove_dir_all(root).expect("remove temporary fixture");
}

#[test]
fn malformed_lockfiles_make_inventory_incomplete_without_echoing_contents() {
    let root = temporary_directory("malformed");
    let secret_like_input =
        r#"{"privateRegistry":"https://user:password@example.invalid","packages": [}"#;
    fs::write(root.join("package-lock.json"), secret_like_input).expect("write malformed lockfile");

    let inventory = scan_repository(&root).expect("temporary root is a directory");
    assert!(!inventory.complete);
    assert_eq!(
        inventory.diagnostics[0].kind,
        DiagnosticKind::MalformedLockfile
    );
    assert!(!format!("{:?}", inventory.diagnostics).contains("password"));
    fs::remove_dir_all(root).expect("remove temporary fixture");
}

#[cfg(unix)]
#[test]
fn symlinks_outside_the_selected_root_make_inventory_incomplete() {
    use std::os::unix::fs::symlink;

    let parent = temporary_directory("symlink");
    let root = parent.join("repo");
    let outside = parent.join("outside");
    fs::create_dir_all(&root).expect("create repository root");
    fs::create_dir_all(&outside).expect("create outside directory");
    fs::write(
        outside.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"node_modules/hidden":{"version":"1.0.0"}}}"#,
    )
    .expect("write outside lockfile");
    symlink(&outside, root.join("external")).expect("create directory symlink");

    let inventory = scan_repository(&root).expect("repository root is a directory");
    assert!(!inventory.complete);
    assert_eq!(
        inventory.diagnostics[0].kind,
        DiagnosticKind::SymlinkOutsideRoot
    );
    assert!(inventory.components.is_empty());
    fs::remove_dir_all(parent).expect("remove temporary fixture");
}

fn temporary_directory(label: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("secmon-inventory-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("create temporary directory");
    path
}
