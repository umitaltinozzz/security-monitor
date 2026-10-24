use std::process::{Command, Stdio};

use chrono::Utc;
use security_monitor_core::{Advisory, AffectedRange, RangeEvent, Severity};
use security_monitor_database::Database;

#[tokio::test]
async fn scan_fail_on_uses_local_vulnerable_fixture_and_review_exit_codes() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(
        project.join("package-lock.json"),
        include_bytes!("../../../tests/fixtures/orchestration/package-lock.json"),
    )
    .unwrap();
    let database_path = temp.path().join("security-monitor.sqlite3");

    let initial = scan(&project, &database_path, "high");
    assert_eq!(initial.status.code(), Some(3));

    let database = Database::open(&database_path).await.unwrap();
    let now = Utc::now();
    database
        .repository::<Advisory>()
        .create(&Advisory {
            canonical_id: "GHSA-fixture-0000-0000".into(),
            title: "Fixture vulnerable package".into(),
            summary: None,
            summary_model: None,
            description: None,
            source_attributions: vec![],
            aliases: vec!["CVE-2026-7001".into()],
            affected_ranges: vec![AffectedRange {
                ecosystem: "npm".into(),
                package: Some("left-pad".into()),
                source: None,
                range_type: Some("SEMVER".into()),
                events: vec![
                    RangeEvent {
                        introduced: Some("0".into()),
                        fixed: None,
                        last_affected: None,
                        limit: None,
                    },
                    RangeEvent {
                        introduced: None,
                        fixed: Some("1.3.1".into()),
                        last_affected: None,
                        limit: None,
                    },
                ],
            }],
            fixed_versions: vec!["1.3.1".into()],
            cvss: Some(8.0),
            severity: Some(Severity::High),
            kev: false,
            epss: None,
            epss_date: None,
            source_urls: vec!["https://github.com/advisories/GHSA-fixture-0000-0000".into()],
            source_updated_at: Some(now),
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();
    database.close().await;

    let threshold = scan(&project, &database_path, "high");
    assert_eq!(threshold.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&threshold.stdout).contains("GHSA-fixture-0000-0000"));

    let review = scan(&project, &database_path, "critical");
    assert_eq!(review.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&review.stdout).contains("needs_review"));
}

fn scan(
    project: &std::path::Path,
    database: &std::path::Path,
    fail_on: &str,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_secmon"))
        .args(["scan"])
        .arg(project)
        .args([
            "--offline",
            "--format",
            "json",
            "--fail-on",
            fail_on,
            "--database",
        ])
        .arg(database)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}
