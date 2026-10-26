use std::{fs, io::Write, path::Path};

use chrono::{DateTime, Utc};
use flate2::{Compression, write::GzEncoder};
use security_monitor_core::{Advisory, FindingStatus};
use security_monitor_database::Database;
use security_monitor_inventory::{Inventory, InventoryComponent};
use serde_json::Value;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::{
    AdvisoryCache, AdvisoryMerger, AdvisoryService, CveNowCursor, CveNowProvider,
    CveNowSourceStatus, DEFAULT_CVE_POLL_INTERVAL_SECONDS, EpssProvider, FindingReason,
    GhsaProvider, HttpPolicy, KevProvider, MAX_CVE_POLL_INTERVAL_SECONDS,
    MIN_CVE_POLL_INTERVAL_SECONDS, OsvDatabase, OsvDatabaseUpdater, OsvUpdateStatus,
    ProviderFreshness, PublicDataHttp, apply_epss, apply_kev, evaluate_inventory, parse_epss_csv,
    parse_ghsa_advisory, parse_kev_catalog,
};

fn fixture(path: &str) -> &'static [u8] {
    match path {
        "cve-status" => {
            include_bytes!("../../../tests/fixtures/advisory-providers/cve-now/status.json")
        }
        "cve-entries" => {
            include_bytes!("../../../tests/fixtures/advisory-providers/cve-now/entries.json")
        }
        "cve-entry" => {
            include_bytes!("../../../tests/fixtures/advisory-providers/cve-now/entry.json")
        }
        "cve-entry-no-package" => include_bytes!(
            "../../../tests/fixtures/advisory-providers/cve-now/entry-without-package.json"
        ),
        "ghsa" => include_bytes!("../../../tests/fixtures/advisory-providers/ghsa/advisory.json"),
        "kev" => include_bytes!("../../../tests/fixtures/advisory-providers/kev/catalog.json"),
        "epss" => include_bytes!("../../../tests/fixtures/advisory-providers/epss/scores.csv"),
        _ => panic!("fixture key is defined in the test"),
    }
}

#[tokio::test]
async fn failed_advisory_refresh_marks_previous_provider_status_stale() {
    let temp = tempfile::tempdir().unwrap();
    let cache_root = temp.path().join("advisories");
    fs::create_dir_all(&cache_root).unwrap();
    let statuses = vec![ProviderFreshness {
        provider: "OSV".to_owned(),
        updated_at: Some(Utc::now()),
        stale: false,
        error: None,
    }];
    fs::write(
        cache_root.join("provider-status.json"),
        serde_json::to_vec(&statuses).unwrap(),
    )
    .unwrap();
    let service = AdvisoryService::new(
        HttpPolicy {
            public_downloads_enabled: false,
        },
        Database::in_memory().await.unwrap(),
        &cache_root,
    )
    .unwrap();
    service.mark_provider_statuses_stale().unwrap();

    let cached: Vec<ProviderFreshness> =
        serde_json::from_slice(&fs::read(cache_root.join("provider-status.json")).unwrap())
            .unwrap();
    assert_eq!(cached.len(), 1);
    assert!(cached[0].stale);
    assert_eq!(cached[0].error.as_deref(), Some("latest refresh failed"));
}

#[tokio::test]
async fn persisted_alias_merge_rekeys_findings_and_removes_old_advisory_id() {
    let database = Database::in_memory().await.unwrap();
    let mut canonical = parse_fixture_entry("cve-entry");
    canonical.canonical_id = "CVE-2026-7001".to_owned();
    canonical.aliases.push("GHSA-abcd-efgh-ijkl".to_owned());
    let mut old = canonical.clone();
    old.canonical_id = "GHSA-abcd-efgh-ijkl".to_owned();
    old.aliases.push(canonical.canonical_id.clone());
    database
        .repository::<Advisory>()
        .create(&old)
        .await
        .unwrap();

    let persisted = AdvisoryMerger::new([canonical.clone()])
        .persist(&database)
        .await
        .unwrap();
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].canonical_id, "CVE-2026-7001");
    let repository = database.repository::<Advisory>();
    assert!(repository.get(&old.canonical_id).await.unwrap().is_none());
    assert!(
        repository
            .get(&canonical.canonical_id)
            .await
            .unwrap()
            .is_some()
    );
}

fn component(name: &str, version: Option<&str>, ecosystem: &str) -> InventoryComponent {
    InventoryComponent {
        purl: version
            .map(|version| format!("pkg:{ecosystem}/{name}@{version}"))
            .unwrap_or_else(|| format!("pkg:{ecosystem}/{name}")),
        ecosystem: ecosystem.to_owned(),
        name: name.to_owned(),
        version: version.map(str::to_owned),
        source_type: "lockfile".to_owned(),
        evidence_paths: vec!["package-lock.json".to_owned()],
    }
}

fn inventory(component: InventoryComponent) -> Inventory {
    Inventory {
        components: vec![component],
        project_roots: vec![".".to_owned()],
        detected_files: Vec::new(),
        diagnostics: Vec::new(),
        complete: true,
    }
}

fn parse_fixture_entry(key: &str) -> Advisory {
    let value: Value = serde_json::from_slice(fixture(key)).expect("fixture JSON is valid");
    super::normalize::cve_now_advisory(&value).expect("fixture advisory is valid")
}

#[tokio::test]
async fn cve_now_incremental_record_matches_inventory_and_produces_a_finding() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/status"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(fixture("cve-status")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/entries"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(fixture("cve-entries")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/entries/CVE-2026-7001"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(fixture("cve-entry")))
        .mount(&server)
        .await;

    let provider = CveNowProvider::with_base_url(PublicDataHttp::for_tests(), server.uri());
    let mut cursor = CveNowCursor::default();
    let sync = provider.sync(&mut cursor).await.expect("fixture feed sync");
    let findings = evaluate_inventory(
        &sync.advisories,
        &inventory(component("fixture-package", Some("1.0.2"), "npm")),
    );

    assert!(sync.cursor_advanced);
    assert!(sync.entries_requested);
    assert_eq!(sync.source_statuses.len(), 3);
    let osv_status = sync
        .source_statuses
        .iter()
        .find(|status| status.name == "osv")
        .unwrap();
    assert!(osv_status.healthy);
    assert_eq!(
        osv_status.updated_at.unwrap().to_rfc3339(),
        "2026-10-24T09:59:00+00:00"
    );
    let vendor_status = sync
        .source_statuses
        .iter()
        .find(|status| status.name == "vendor-feed")
        .unwrap();
    assert!(!vendor_status.healthy);
    assert!(
        sync.source_statuses
            .iter()
            .any(|status| status.name == "package data (npm)")
    );
    assert_eq!(
        cursor.polling_cursor.as_deref(),
        Some("2026-10-24T10:00:00Z")
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].advisory_id, "CVE-2026-7001");
    assert_eq!(findings[0].status, FindingStatus::New);
    assert_eq!(findings[0].reason, FindingReason::AffectedVersion);
    assert_eq!(
        sync.advisories[0].summary_model.as_deref(),
        Some("test/model")
    );
    assert!(sync.advisories[0].source_attributions.iter().any(|source| {
        source.name == "cve.now" && source.license.as_deref() == Some("CC-BY 4.0")
    }));
}

#[tokio::test]
async fn unchanged_status_cursor_does_not_call_entries_endpoint() {
    let server = MockServer::start().await;
    let mut status: Value = serde_json::from_slice(fixture("cve-status")).unwrap();
    status["polling"]["cursor"] = Value::String("already-seen".to_owned());
    Mock::given(method("GET"))
        .and(path("/api/v1/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(status))
        .mount(&server)
        .await;
    let provider = CveNowProvider::with_base_url(PublicDataHttp::for_tests(), server.uri());
    let mut cursor = CveNowCursor {
        polling_cursor: Some("already-seen".to_owned()),
        last_seen_id: Some("CVE-2026-6000".to_owned()),
        ..CveNowCursor::default()
    };
    let sync = provider
        .sync(&mut cursor)
        .await
        .expect("status cursor is unchanged");
    assert!(!sync.cursor_advanced);
    assert!(!sync.entries_requested);
    assert!(sync.advisories.is_empty());
    let requests = server
        .received_requests()
        .await
        .expect("mock server records requests");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), "/api/v1/status");
}

#[tokio::test]
async fn cve_now_follows_opaque_page_cursor_until_previous_entry() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/status"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(fixture("cve-status")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/entries"))
        .and(wiremock::matchers::query_param_is_missing("cursor"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "entries": [{"id": "CVE-2026-7001"}],
            "nextCursor": "opaque-page-token"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/entries"))
        .and(wiremock::matchers::query_param(
            "cursor",
            "opaque-page-token",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "entries": [{"id": "CVE-2026-6000"}],
            "nextCursor": null
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/entries/CVE-2026-7001"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(fixture("cve-entry")))
        .mount(&server)
        .await;

    let provider = CveNowProvider::with_base_url(PublicDataHttp::for_tests(), server.uri());
    let mut cursor = CveNowCursor {
        last_seen_id: Some("CVE-2026-6000".to_owned()),
        ..CveNowCursor::default()
    };
    let sync = provider
        .sync(&mut cursor)
        .await
        .expect("paginated feed sync");
    assert_eq!(sync.advisories.len(), 1);
    assert_eq!(sync.advisories[0].canonical_id, "CVE-2026-7001");
    let requests = server.received_requests().await.expect("request log");
    assert_eq!(requests.len(), 4);
    assert!(
        requests
            .iter()
            .any(|request| request.url.query() == Some("cursor=opaque-page-token"))
    );
}

#[tokio::test]
async fn cve_now_does_not_advance_the_feed_when_the_prior_entry_is_unreachable() {
    let server = MockServer::start().await;
    let mut status: Value = serde_json::from_slice(fixture("cve-status")).unwrap();
    status["polling"]["cursor"] = Value::String("new-polling-cursor".to_owned());
    Mock::given(method("GET"))
        .and(path("/api/v1/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(status))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/entries"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "entries": [{"id": "CVE-2026-7001"}],
            "nextCursor": null
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/entries/CVE-2026-7001"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(fixture("cve-entry")))
        .mount(&server)
        .await;

    let provider = CveNowProvider::with_base_url(PublicDataHttp::for_tests(), server.uri());
    let mut cursor = CveNowCursor {
        polling_cursor: Some("previous-polling-cursor".to_owned()),
        last_seen_id: Some("CVE-2026-6000".to_owned()),
        ..CveNowCursor::default()
    };
    let result = provider.sync(&mut cursor).await;
    assert!(result.is_err());
    assert_eq!(
        cursor.polling_cursor.as_deref(),
        Some("previous-polling-cursor")
    );
}

#[tokio::test]
async fn cached_cve_now_advisories_remain_available_and_turn_stale_offline() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/status"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(fixture("cve-status")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/entries"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(fixture("cve-entries")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/entries/CVE-2026-7001"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(fixture("cve-entry")))
        .mount(&server)
        .await;
    let temp = tempfile::tempdir().unwrap();
    let cache = AdvisoryCache::new(temp.path().join("cve-cache.json"));
    let cursor_file = temp.path().join("cursor.json");
    let provider = CveNowProvider::with_base_url(PublicDataHttp::for_tests(), server.uri());
    let initial = provider
        .sync_cached(&cache, &cursor_file)
        .await
        .expect("cache the fixture feed");
    assert!(!initial.stale);
    assert_eq!(initial.advisories.len(), 1);
    let mut saved_cursor: CveNowCursor =
        serde_json::from_slice(&fs::read(&cursor_file).unwrap()).unwrap();
    saved_cursor.last_checked_at = Some(DateTime::<Utc>::UNIX_EPOCH);
    fs::write(&cursor_file, serde_json::to_vec(&saved_cursor).unwrap()).unwrap();

    let offline = CveNowProvider::with_base_url(
        PublicDataHttp::for_tests_with_policy(HttpPolicy {
            public_downloads_enabled: false,
        }),
        server.uri(),
    );
    let cached = offline
        .sync_cached(&cache, cursor_file.clone())
        .await
        .expect("reuse the local cache");
    assert!(cached.stale);
    assert_eq!(cached.advisories.len(), 1);
    let saved_cursor: CveNowCursor =
        serde_json::from_slice(&fs::read(cursor_file).unwrap()).unwrap();
    assert_eq!(saved_cursor.consecutive_failures, 1);
    assert!(saved_cursor.backoff_until.is_some());
    let still_cached = offline
        .sync_cached(&cache, temp.path().join("cursor.json"))
        .await
        .expect("backoff keeps the last cache available");
    assert!(still_cached.stale);
    let saved_cursor: CveNowCursor =
        serde_json::from_slice(&fs::read(temp.path().join("cursor.json")).unwrap()).unwrap();
    assert_eq!(saved_cursor.consecutive_failures, 1);
}

#[test]
fn pinned_osv_fixture_queries_are_deterministic_and_package_scoped() {
    let directory =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/advisory-db/npm");
    let database = OsvDatabase::open(directory).expect("pinned fixture database");
    let advisories = database.query("npm", "fixture-package");
    assert_eq!(advisories.len(), 1);
    assert_eq!(advisories[0].canonical_id, "GHSA-abcd-efgh-ijkl");
    assert!(database.query("npm", "another-package").is_empty());
    assert!(!database.status().stale);
}

#[test]
fn debian_and_ubuntu_osv_fixtures_use_the_distro_ecosystem_and_dpkg_ordering() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/advisory-db");
    for (slug, ecosystem, package, affected, fixed, advisory_id) in [
        (
            "Debian",
            "Debian:12",
            "openssl",
            "3.0.14-1~deb12u0",
            "3.0.14-1~deb12u1",
            "CVE-2026-9001",
        ),
        (
            "Ubuntu",
            "Ubuntu:22.04:LTS",
            "curl",
            "7.81.0-1ubuntu1.19",
            "7.81.0-1ubuntu1.20",
            "CVE-2026-9002",
        ),
    ] {
        let database = OsvDatabase::open(root.join(slug)).expect("OSV distro fixture opens");
        let advisories = database.query(ecosystem, package);
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].canonical_id, advisory_id);
        let affected_findings = evaluate_inventory(
            &advisories,
            &inventory(component(package, Some(affected), ecosystem)),
        );
        assert_eq!(affected_findings.len(), 1);
        assert_eq!(affected_findings[0].reason, FindingReason::AffectedVersion);
        assert!(
            evaluate_inventory(
                &advisories,
                &inventory(component(package, Some(fixed), ecosystem)),
            )
            .is_empty()
        );
    }
    assert_eq!(crate::ecosystem_slug("Debian:12"), Some("Debian"));
    assert_eq!(crate::ecosystem_slug("Ubuntu:22.04:LTS"), Some("Ubuntu"));
    assert_eq!(crate::ecosystem_slug("AlmaLinux:9"), Some("AlmaLinux"));
    assert_eq!(crate::ecosystem_slug("Rocky Linux:9"), Some("Rocky Linux"));
    assert_eq!(
        crate::ecosystem_slug("Red Hat:enterprise_linux:9::appstream"),
        Some("Red Hat")
    );
    assert_eq!(crate::ecosystem_slug("Alpine:v3.20"), Some("Alpine"));
    assert_eq!(crate::ecosystem_slug("rpm"), None);
    assert_eq!(crate::ecosystem_slug("apk"), None);
}

#[tokio::test]
async fn stale_osv_cache_remains_queryable_when_refresh_is_disabled() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("osv");
    let target = root.join("npm");
    copy_directory(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/advisory-db/npm"),
        &target,
    );
    let scanner_cache = root.join("scanner-db/osv-scanner/npm");
    fs::create_dir_all(&scanner_cache).unwrap();
    fs::write(scanner_cache.join("all.zip"), b"previous local database").unwrap();
    fs::write(
        scanner_cache.join(".secmon-cache.json"),
        serde_json::to_vec(&OsvUpdateStatus {
            ecosystem: "npm".to_owned(),
            updated_at: Some(Utc::now()),
            stale: false,
            error: None,
            ..OsvUpdateStatus::default()
        })
        .unwrap(),
    )
    .unwrap();
    let updater = OsvDatabaseUpdater::new(
        PublicDataHttp::new(HttpPolicy {
            public_downloads_enabled: false,
        })
        .unwrap(),
    );
    let statuses = updater
        .update_ecosystems(&root, ["npm".to_owned()])
        .await
        .expect("stale cache should not fail the update batch");
    assert!(statuses[0].stale);
    let scanner_status: OsvUpdateStatus =
        serde_json::from_slice(&fs::read(scanner_cache.join(".secmon-cache.json")).unwrap())
            .unwrap();
    assert!(scanner_status.stale);
    let database = OsvDatabase::open(target).expect("open the cached database offline");
    assert!(database.status().stale);
    assert_eq!(database.query("npm", "fixture-package").len(), 1);
}

#[tokio::test]
async fn osv_updater_installs_a_downloaded_ecosystem_archive_atomically() {
    let server = MockServer::start().await;
    let mut writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    writer
        .start_file(
            "GHSA-abcd-efgh-ijkl.json",
            SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
        )
        .unwrap();
    writer
        .write_all(include_bytes!(
            "../../../tests/fixtures/advisory-db/npm/GHSA-abcd-efgh-ijkl.json"
        ))
        .unwrap();
    let archive = writer.finish().unwrap().into_inner();
    let scanner_archive = archive.clone();
    Mock::given(method("GET"))
        .and(path("/npm/all.zip"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(archive))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let updater = OsvDatabaseUpdater::with_base_url(PublicDataHttp::for_tests(), server.uri());
    let statuses = updater
        .update_ecosystems(temp.path(), ["npm".to_owned()])
        .await
        .expect("download and install the fixture dump");
    assert_eq!(statuses.len(), 1);
    assert!(!statuses[0].stale);
    let database = OsvDatabase::open(temp.path().join("npm")).expect("installed dump");
    assert_eq!(database.query("npm", "fixture-package").len(), 1);
    assert!(!temp.path().join(".npm-staging").exists());
    assert_eq!(
        fs::read(temp.path().join("scanner-db/osv-scanner/npm/all.zip")).unwrap(),
        scanner_archive
    );
    let scanner_status: OsvUpdateStatus = serde_json::from_slice(
        &fs::read(
            temp.path()
                .join("scanner-db/osv-scanner/npm/.secmon-cache.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(!scanner_status.stale);
}

#[tokio::test]
async fn versioned_distro_ecosystems_share_one_offline_fixture_dump_per_distro() {
    let server = MockServer::start().await;
    let mut distro_archives = Vec::new();
    for (slug, file_name, bytes) in [
        (
            "Debian",
            "CVE-2026-9001.json",
            include_bytes!("../../../tests/fixtures/advisory-db/Debian/CVE-2026-9001.json")
                .as_slice(),
        ),
        (
            "Ubuntu",
            "CVE-2026-9002.json",
            include_bytes!("../../../tests/fixtures/advisory-db/Ubuntu/CVE-2026-9002.json")
                .as_slice(),
        ),
    ] {
        let mut writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        writer
            .start_file(
                file_name,
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
            )
            .unwrap();
        writer.write_all(bytes).unwrap();
        distro_archives.push((slug, writer.finish().unwrap().into_inner()));
    }
    for (slug, archive) in &distro_archives {
        Mock::given(method("GET"))
            .and(path(format!("/{slug}/all.zip")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(archive.clone()))
            .expect(1)
            .mount(&server)
            .await;
    }

    let temp = tempfile::tempdir().unwrap();
    let updater = OsvDatabaseUpdater::with_base_url(PublicDataHttp::for_tests(), server.uri());
    let statuses = updater
        .update_ecosystems(
            temp.path(),
            [
                "Debian:12".to_owned(),
                "Debian:13".to_owned(),
                "Ubuntu:22.04:LTS".to_owned(),
                "Ubuntu:24.04:LTS".to_owned(),
            ],
        )
        .await
        .expect("one dump serves all releases of each distro");
    assert_eq!(statuses.len(), 2);
    assert_eq!(statuses[0].ecosystem, "debian:12");
    assert_eq!(statuses[1].ecosystem, "ubuntu:22.04:lts");
    let database = OsvDatabase::open(temp.path().join("Debian")).unwrap();
    assert_eq!(database.query("Debian:12", "openssl").len(), 1);
    let database = OsvDatabase::open(temp.path().join("Ubuntu")).unwrap();
    assert_eq!(database.query("Ubuntu:22.04:LTS", "curl").len(), 1);
}

#[tokio::test]
async fn osv_updater_rejects_archive_paths_that_escape_the_cache_root() {
    let server = MockServer::start().await;
    let mut writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    writer
        .start_file(
            "../../escape.json",
            SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
        )
        .unwrap();
    writer.write_all(b"{}").unwrap();
    let archive = writer.finish().unwrap().into_inner();
    Mock::given(method("GET"))
        .and(path("/npm/all.zip"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(archive))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let cache_root = temp.path().join("cache");
    let updater = OsvDatabaseUpdater::with_base_url(PublicDataHttp::for_tests(), server.uri());
    let result = updater
        .update_ecosystems(&cache_root, ["npm".to_owned()])
        .await;
    assert!(result.is_err());
    assert!(!temp.path().join("escape.json").exists());
    assert!(!cache_root.join("npm").exists());
}

#[tokio::test]
async fn osv_updater_rejects_duplicate_archive_paths() {
    let server = MockServer::start().await;
    let mut writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, payload) in [
        ("duplicate.json", b"{}".as_slice()),
        ("DUPLICATE.JSON", b"{\"id\":\"CVE-2026-7001\"}".as_slice()),
    ] {
        writer
            .start_file(
                name,
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
            )
            .unwrap();
        writer.write_all(payload).unwrap();
    }
    let archive = writer.finish().unwrap().into_inner();
    Mock::given(method("GET"))
        .and(path("/npm/all.zip"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(archive))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let updater = OsvDatabaseUpdater::with_base_url(PublicDataHttp::for_tests(), server.uri());
    let result = updater
        .update_ecosystems(temp.path(), ["npm".to_owned()])
        .await;
    assert!(result.is_err());
    assert!(!temp.path().join("npm").exists());
}

#[test]
fn later_osv_record_merges_into_one_canonical_advisory() {
    let cve_now = parse_fixture_entry("cve-entry");
    let osv = super::osv::parse_osv_advisory(include_bytes!(
        "../../../tests/fixtures/advisory-db/npm/GHSA-abcd-efgh-ijkl.json"
    ))
    .expect("OSV fixture is valid");
    let merger = AdvisoryMerger::new([cve_now, osv]);
    assert_eq!(merger.records().len(), 1);
    let merged = &merger.records()[0];
    assert_eq!(merged.canonical_id, "CVE-2026-7001");
    assert!(merged.aliases.contains(&"GHSA-ABCD-EFGH-IJKL".to_owned()));
    assert!(merged.source_attributions.iter().any(|source| {
        source.name == "OSV.dev"
            && source.url == "https://osv.dev/vulnerability/GHSA-abcd-efgh-ijkl"
    }));
    assert!(merged.source_attributions.iter().any(|source| {
        source.name == "OSV upstream source"
            && source.url == "https://github.com/advisories/GHSA-abcd-efgh-ijkl"
    }));
    assert!(
        merged
            .affected_ranges
            .iter()
            .any(|range| range.source.as_deref() == Some("cve.now"))
    );
    assert!(
        merged
            .affected_ranges
            .iter()
            .any(|range| range.source.as_deref() == Some("OSV"))
    );
}

#[test]
fn conflicting_source_ranges_create_a_needs_review_finding_with_both_sources() {
    let cve_now = parse_fixture_entry("cve-entry");
    let mut osv = super::osv::parse_osv_advisory(include_bytes!(
        "../../../tests/fixtures/advisory-db/npm/GHSA-abcd-efgh-ijkl.json"
    ))
    .expect("OSV fixture is valid");
    osv.affected_ranges[0].events[1].fixed = Some("1.0.1".to_owned());
    let advisories = AdvisoryMerger::new([cve_now, osv]).into_records();
    let findings = evaluate_inventory(
        &advisories,
        &inventory(component("fixture-package", Some("1.0.2"), "npm")),
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].status, FindingStatus::NeedsReview);
    assert_eq!(findings[0].reason, FindingReason::SourceDisagreement);
    assert!(findings[0].evidence_sources.contains(&"cve.now".to_owned()));
    assert!(findings[0].evidence_sources.contains(&"OSV".to_owned()));
}

#[test]
fn package_data_re_evaluates_a_deferred_product_match() {
    let pending = parse_fixture_entry("cve-entry-no-package");
    let no_version_inventory = inventory(component("fixture-lib", None, "npm"));
    let findings = evaluate_inventory(std::slice::from_ref(&pending), &no_version_inventory);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].status, FindingStatus::NeedsReview);
    assert_eq!(findings[0].reason, FindingReason::VersionDataPending);

    let mut package_advisory = super::osv::parse_osv_advisory(include_bytes!(
        "../../../tests/fixtures/advisory-providers/osv/deferred.json"
    ))
    .expect("deferred OSV fixture is valid");
    package_advisory.aliases.push(pending.canonical_id.clone());
    let merged = AdvisoryMerger::new([pending, package_advisory]).into_records();
    let findings = evaluate_inventory(
        &merged,
        &inventory(component("fixture-lib", Some("1.0.5"), "npm")),
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].status, FindingStatus::New);
    assert_eq!(findings[0].reason, FindingReason::AffectedVersion);
}

#[test]
fn ghsa_kev_and_epss_records_normalize_and_enrich_advisories() {
    let ghsa = parse_ghsa_advisory(fixture("ghsa")).expect("GHSA fixture is valid");
    assert_eq!(ghsa.canonical_id, "GHSA-abcd-efgh-ijkl");
    assert_eq!(
        ghsa.affected_ranges[0].package.as_deref(),
        Some("fixture-package")
    );

    let catalog = parse_kev_catalog(fixture("kev")).expect("KEV fixture is valid");
    let scores = parse_epss_csv(fixture("epss")).expect("EPSS fixture is valid");
    let mut advisories = vec![ghsa];
    let snapshot = crate::EpssSnapshot {
        scores,
        fetched_at: DateTime::<Utc>::UNIX_EPOCH,
        stale: false,
    };
    apply_kev(
        &mut advisories,
        &crate::CachedKevCatalog {
            cve_ids: catalog,
            fetched_at: DateTime::<Utc>::UNIX_EPOCH,
            stale: false,
        },
    );
    apply_epss(&mut advisories, &snapshot);
    assert!(advisories[0].kev);
    assert_eq!(advisories[0].epss, Some(0.42));
    assert_eq!(
        advisories[0].epss_date.unwrap().to_rfc3339(),
        "2026-10-24T00:00:00+00:00"
    );
}

#[test]
fn missing_package_ranges_stay_needs_review_and_reference_urls_drop_credentials() {
    let mut value: Value = serde_json::from_slice(fixture("cve-entry")).unwrap();
    value["affected"][0]["ranges"] = Value::Array(Vec::new());
    value["affected"][0]
        .as_object_mut()
        .unwrap()
        .remove("versions");
    value["sources"][0]["url"] = Value::String(
        "https://user:token@example.invalid/path?access_token=secret#fragment".to_owned(),
    );
    value["references"] = serde_json::json!([
        {"url": "https://example.invalid/advisory?token=private"}
    ]);
    let advisory = super::normalize::cve_now_advisory(&value).unwrap();
    let findings = evaluate_inventory(
        std::slice::from_ref(&advisory),
        &inventory(component("fixture-package", Some("1.0.2"), "npm")),
    );
    assert_eq!(findings[0].status, FindingStatus::NeedsReview);
    assert_eq!(findings[0].reason, FindingReason::VersionDataPending);
    let encoded = serde_json::to_string(&advisory).unwrap();
    assert!(!encoded.contains("token"));
    assert!(!encoded.contains("secret"));
    assert!(!encoded.contains("private"));
}

#[test]
fn ecosystem_versions_use_supported_comparators_or_stay_reviewable() {
    let mut advisory = parse_fixture_entry("cve-entry");
    advisory.affected_ranges[0].ecosystem = "pypi".to_owned();
    advisory.affected_ranges[0].range_type = Some("ECOSYSTEM".to_owned());
    advisory.affected_ranges[0].events = vec![security_monitor_core::RangeEvent {
        introduced: Some("1.0".to_owned()),
        fixed: Some("2.0".to_owned()),
        last_affected: None,
        limit: None,
    }];
    let pep440_post = evaluate_inventory(
        std::slice::from_ref(&advisory),
        &inventory(component("fixture-package", Some("1.0.post1"), "pypi")),
    );
    assert_eq!(pep440_post[0].status, FindingStatus::New);
    assert_eq!(pep440_post[0].reason, FindingReason::AffectedVersion);

    advisory.affected_ranges[0].ecosystem = "Debian:12".to_owned();
    advisory.affected_ranges[0].events = vec![security_monitor_core::RangeEvent {
        introduced: Some("1:9.2p1-1".to_owned()),
        fixed: Some("1:9.2p1-3".to_owned()),
        last_affected: None,
        limit: None,
    }];
    let debian_epoch = evaluate_inventory(
        std::slice::from_ref(&advisory),
        &inventory(component("fixture-package", Some("1:9.2p1-2"), "Debian:12")),
    );
    assert_eq!(debian_epoch[0].status, FindingStatus::New);

    advisory.affected_ranges[0].ecosystem = "Ubuntu:22.04:LTS".to_owned();
    advisory.affected_ranges[0].events = vec![security_monitor_core::RangeEvent {
        introduced: Some("1:9.2p1-1ubuntu1".to_owned()),
        fixed: Some("1:9.2p1-3ubuntu1".to_owned()),
        last_affected: None,
        limit: None,
    }];
    let ubuntu_epoch = evaluate_inventory(
        std::slice::from_ref(&advisory),
        &inventory(component(
            "fixture-package",
            Some("1:9.2p1-2ubuntu1"),
            "Ubuntu:22.04:LTS",
        )),
    );
    assert_eq!(ubuntu_epoch.len(), 1);
    assert_eq!(ubuntu_epoch[0].status, FindingStatus::New);
    assert_eq!(ubuntu_epoch[0].reason, FindingReason::AffectedVersion);
    assert!(
        evaluate_inventory(
            std::slice::from_ref(&advisory),
            &inventory(component(
                "fixture-package",
                Some("1:9.2p1-10"),
                "Debian:12"
            )),
        )
        .is_empty()
    );
    assert!(
        evaluate_inventory(
            std::slice::from_ref(&advisory),
            &inventory(component("fixture-package", Some("0:9.2p1-2"), "Debian:12")),
        )
        .is_empty()
    );

    advisory.affected_ranges[0].ecosystem = "golang".to_owned();
    advisory.affected_ranges[0].events = vec![security_monitor_core::RangeEvent {
        introduced: Some("v0.0.0".to_owned()),
        fixed: Some("v0.0.0-20250320123456-abcdef123456".to_owned()),
        last_affected: None,
        limit: None,
    }];
    let go_pseudo = evaluate_inventory(
        std::slice::from_ref(&advisory),
        &inventory(component(
            "fixture-package",
            Some("v1.2.3-0.20250319123456-123456abcdef"),
            "golang",
        )),
    );
    assert_eq!(go_pseudo[0].status, FindingStatus::NeedsReview);
    assert_eq!(go_pseudo[0].reason, FindingReason::VersionRangeUnverified);

    advisory.affected_ranges[0].ecosystem = "rubygems".to_owned();
    advisory.affected_ranges[0].range_type = Some("SEMVER".to_owned());
    advisory.affected_ranges[0].events = vec![security_monitor_core::RangeEvent {
        introduced: Some("0".to_owned()),
        fixed: Some("2.0.0".to_owned()),
        last_affected: None,
        limit: None,
    }];
    let ruby_platform = evaluate_inventory(
        std::slice::from_ref(&advisory),
        &inventory(component(
            "fixture-package",
            Some("1.0.0-x86_64-linux"),
            "rubygems",
        )),
    );
    assert_eq!(ruby_platform[0].status, FindingStatus::NeedsReview);
    assert_eq!(
        ruby_platform[0].reason,
        FindingReason::VersionRangeUnverified
    );

    advisory.affected_ranges[0].range_type = Some("ECOSYSTEM".to_owned());
    for ecosystem in ["composer", "maven", "nuget"] {
        advisory.affected_ranges[0].ecosystem = ecosystem.to_owned();
        let unsupported = evaluate_inventory(
            std::slice::from_ref(&advisory),
            &inventory(component("fixture-package", Some("1.0"), ecosystem)),
        );
        assert_eq!(unsupported[0].status, FindingStatus::NeedsReview);
        assert_eq!(unsupported[0].reason, FindingReason::VersionRangeUnverified);
    }

    advisory.affected_ranges[0].ecosystem = "pypi".to_owned();
    advisory.affected_ranges[0].range_type = Some("EXACT".to_owned());
    advisory.affected_ranges[0].events = vec![security_monitor_core::RangeEvent {
        introduced: Some("1.0rc1".to_owned()),
        fixed: None,
        last_affected: Some("1.0rc1".to_owned()),
        limit: None,
    }];
    let matching = evaluate_inventory(
        &[advisory.clone()],
        &inventory(component("fixture-package", Some("1.0rc1"), "pypi")),
    );
    assert_eq!(matching[0].status, FindingStatus::New);
    assert_eq!(matching[0].reason, FindingReason::AffectedVersion);
    assert!(
        evaluate_inventory(
            &[advisory],
            &inventory(component("fixture-package", Some("1.0"), "pypi")),
        )
        .is_empty()
    );
}

#[test]
fn cve_provider_source_status_requires_a_recent_verified_timestamp() {
    let now = DateTime::parse_from_rfc3339("2026-10-24T12:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let current = CveNowSourceStatus {
        name: "osv".to_owned(),
        updated_at: Some(now - chrono::Duration::hours(23)),
        healthy: true,
    };
    assert!(!super::service::cve_source_status_is_stale(
        &current, false, now
    ));

    let old = CveNowSourceStatus {
        updated_at: Some(now - chrono::Duration::hours(25)),
        ..current.clone()
    };
    assert!(super::service::cve_source_status_is_stale(&old, false, now));

    let future = CveNowSourceStatus {
        updated_at: Some(now + chrono::Duration::seconds(1)),
        ..current.clone()
    };
    assert!(super::service::cve_source_status_is_stale(
        &future, false, now
    ));
    assert!(super::service::cve_source_status_is_stale(
        &current, true, now
    ));
}

#[test]
fn epss_daily_comment_supplies_score_date_when_rows_omit_it() {
    let scores = parse_epss_csv(
        b"# model_version: current, score_date: 2026-10-24\ncve,epss,percentile\nCVE-2026-7001,0.42,0.91\n",
    )
    .expect("daily EPSS CSV");
    assert_eq!(
        scores["CVE-2026-7001"].date.unwrap().to_string(),
        "2026-10-24"
    );
}

#[test]
fn incomplete_kev_and_epss_documents_are_rejected() {
    assert!(parse_kev_catalog(br#"{"vulnerabilities":[{}]}"#).is_err());
    assert!(parse_kev_catalog(br#"{"vulnerabilities":[]}"#).is_err());
    assert!(parse_epss_csv(b"cve,epss,percentile\n").is_err());
    assert!(parse_epss_csv(b"cve,epss,percentile\nCVE-2026-7001,0.4,0.8\n").is_err());
}

#[test]
fn cve_now_poll_interval_is_bounded_to_the_documented_range() {
    let provider = CveNowProvider::new(PublicDataHttp::for_tests());
    assert_eq!(DEFAULT_CVE_POLL_INTERVAL_SECONDS, 600);
    assert!(
        provider
            .clone()
            .with_poll_interval_seconds(MIN_CVE_POLL_INTERVAL_SECONDS)
            .is_ok()
    );
    assert!(
        provider
            .clone()
            .with_poll_interval_seconds(MAX_CVE_POLL_INTERVAL_SECONDS)
            .is_ok()
    );
    assert!(
        provider
            .clone()
            .with_poll_interval_seconds(MIN_CVE_POLL_INTERVAL_SECONDS - 1)
            .is_err()
    );
    assert!(
        provider
            .with_poll_interval_seconds(MAX_CVE_POLL_INTERVAL_SECONDS + 1)
            .is_err()
    );
}

#[tokio::test]
async fn service_uses_local_caches_and_persists_one_enriched_finding_offline() {
    let temp = tempfile::tempdir().unwrap();
    let cache_root = temp.path().join("cache");
    let now = Utc::now();

    let cve_dir = cache_root.join("cve-now");
    let cve_cache = AdvisoryCache::new(cve_dir.join("advisories.json"));
    cve_cache
        .save([parse_fixture_entry("cve-entry")], false)
        .unwrap();
    fs::create_dir_all(&cve_dir).unwrap();
    fs::write(
        cve_dir.join("cursor.json"),
        serde_json::to_vec(&CveNowCursor {
            polling_cursor: Some("fixture-cursor".to_owned()),
            last_seen_id: Some("CVE-2026-7001".to_owned()),
            last_checked_at: Some(now),
            ..CveNowCursor::default()
        })
        .unwrap(),
    )
    .unwrap();

    let osv_root = cache_root.join("osv");
    let osv_directory = osv_root.join("npm");
    copy_directory(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/advisory-db/npm"),
        &osv_directory,
    );
    fs::write(
        osv_directory.join(".secmon-cache.json"),
        serde_json::to_vec(&crate::OsvUpdateStatus {
            ecosystem: "npm".to_owned(),
            updated_at: Some(now),
            stale: false,
            error: None,
            ..crate::OsvUpdateStatus::default()
        })
        .unwrap(),
    )
    .unwrap();

    let kev_path = cache_root.join("kev/catalog.json");
    fs::create_dir_all(kev_path.parent().unwrap()).unwrap();
    fs::write(
        &kev_path,
        serde_json::to_vec(&crate::CachedKevCatalog {
            cve_ids: parse_kev_catalog(fixture("kev")).unwrap(),
            fetched_at: now,
            stale: false,
        })
        .unwrap(),
    )
    .unwrap();

    let epss_path = cache_root.join("epss/scores.csv.gz");
    fs::create_dir_all(epss_path.parent().unwrap()).unwrap();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(fixture("epss")).unwrap();
    fs::write(&epss_path, encoder.finish().unwrap()).unwrap();
    let mut epss_metadata_path = epss_path.as_os_str().to_owned();
    epss_metadata_path.push(".meta.json");
    fs::write(
        epss_metadata_path,
        serde_json::to_vec(&serde_json::json!({"fetched_at": now, "stale": false})).unwrap(),
    )
    .unwrap();

    let database = Database::in_memory().await.unwrap();
    let service = AdvisoryService::new(
        HttpPolicy {
            public_downloads_enabled: false,
        },
        database.clone(),
        &cache_root,
    )
    .unwrap();
    let report = service
        .refresh_and_match(&inventory(component(
            "fixture-package",
            Some("1.0.2"),
            "npm",
        )))
        .await
        .expect("offline cached provider run");

    assert_eq!(report.advisories.len(), 1);
    assert_eq!(report.advisories[0].canonical_id, "CVE-2026-7001");
    assert!(report.advisories[0].kev);
    assert_eq!(report.advisories[0].epss, Some(0.42));
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].status, FindingStatus::New);
    assert!(report.inventory_complete);
    assert_eq!(
        database
            .repository::<Advisory>()
            .list()
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        report
            .provider_freshness
            .iter()
            .any(|provider| provider.provider == "cve.now" && !provider.stale)
    );
    assert!(
        !report
            .provider_freshness
            .iter()
            .any(|provider| provider.provider == "GitHub Advisory Database")
    );
}

#[tokio::test]
async fn direct_ghsa_lookup_uses_the_shared_public_http_boundary() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/advisories/GHSA-abcd-efgh-ijkl"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(fixture("ghsa")))
        .mount(&server)
        .await;
    let provider = GhsaProvider::with_base_url(
        PublicDataHttp::for_tests(),
        format!("{}/advisories", server.uri()),
    );
    let advisory = provider
        .fetch_by_id("GHSA-abcd-efgh-ijkl")
        .await
        .expect("GHSA lookup");
    assert_eq!(advisory.aliases, vec!["CVE-2026-7001"]);
}

#[tokio::test]
async fn shared_http_boundary_rejects_unlisted_destinations() {
    let http = PublicDataHttp::new(HttpPolicy {
        public_downloads_enabled: true,
    })
    .unwrap();
    let error = http
        .get("https://unlisted.example.invalid/advisory")
        .await
        .expect_err("unlisted destination is rejected before networking");
    assert!(matches!(error, crate::ProviderError::DestinationNotAllowed));
}

#[tokio::test]
async fn kev_and_epss_caches_are_used_when_network_is_disabled() {
    let temp = tempfile::tempdir().unwrap();
    let disabled_http = PublicDataHttp::new(HttpPolicy {
        public_downloads_enabled: false,
    })
    .unwrap();
    let kev_path = temp.path().join("kev.json");
    let cached_kev = crate::CachedKevCatalog {
        cve_ids: parse_kev_catalog(fixture("kev")).unwrap(),
        fetched_at: DateTime::<Utc>::UNIX_EPOCH,
        stale: false,
    };
    fs::write(&kev_path, serde_json::to_vec(&cached_kev).unwrap()).unwrap();
    let kev = KevProvider::new(disabled_http.clone())
        .fetch_cached(&kev_path)
        .await
        .expect("offline KEV cache");
    assert!(kev.stale);
    assert!(kev.cve_ids.contains("CVE-2026-7001"));

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(fixture("epss")).unwrap();
    let epss_path = temp.path().join("epss.csv.gz");
    fs::write(&epss_path, encoder.finish().unwrap()).unwrap();
    let epss = EpssProvider::new(disabled_http)
        .fetch_cached(&epss_path)
        .await
        .expect("offline EPSS cache");
    assert!(epss.stale);
    assert_eq!(epss.scores["CVE-2026-7001"].epss, 0.42);
}

#[tokio::test]
async fn malformed_epss_download_keeps_the_last_valid_snapshot_and_marks_it_stale() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/scores.csv.gz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"not a gzip file"))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("scores.csv.gz");
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(fixture("epss")).unwrap();
    let valid_bytes = encoder.finish().unwrap();
    fs::write(&path, &valid_bytes).unwrap();
    let metadata_path = path.with_file_name("scores.csv.gz.meta.json");
    fs::write(
        &metadata_path,
        serde_json::to_vec(&serde_json::json!({
            "fetched_at": DateTime::<Utc>::UNIX_EPOCH,
            "stale": false
        }))
        .unwrap(),
    )
    .unwrap();

    let provider = EpssProvider::with_url(
        PublicDataHttp::for_tests(),
        format!("{}/scores.csv.gz", server.uri()),
    );
    let snapshot = provider
        .fetch_cached(&path)
        .await
        .expect("last valid snapshot remains usable");

    assert!(snapshot.stale);
    assert_eq!(snapshot.scores["CVE-2026-7001"].epss, 0.42);
    assert_eq!(fs::read(path).unwrap(), valid_bytes);
}

fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let source_path = entry.path();
        let target_path = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_directory(&source_path, &target_path);
        } else {
            fs::copy(source_path, target_path).unwrap();
        }
    }
}
