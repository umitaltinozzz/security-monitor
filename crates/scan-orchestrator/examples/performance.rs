use std::{fs, path::Path, sync::Arc, time::Instant};

use chrono::Utc;
use security_monitor_advisory_providers::HttpPolicy;
use security_monitor_core::Project;
use security_monitor_database::Database;
use security_monitor_scan_orchestrator::{
    LocalProjectScanner, LocalScanSettings, ScanLimits, ScanProfile, ScanReason, ScanRequest,
};
use serde_json::{Map, Value, json};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dependency_count = std::env::args()
        .nth(1)
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(50_000);
    if dependency_count == 0 || dependency_count > 100_000 {
        return Err("dependency count must be between 1 and 100000".into());
    }

    let workspace = tempfile::tempdir()?;
    let project_root = workspace.path().join("project");
    let app_data = workspace.path().join("app-data");
    fs::create_dir_all(&project_root)?;
    fs::create_dir_all(&app_data)?;
    write_package_lock(&project_root, dependency_count)?;

    let database_path = app_data.join("security-monitor.sqlite3");
    let database = Database::open(&database_path).await?;
    let now = Utc::now();
    let project = Project {
        id: "performance-fixture".to_owned(),
        name: "Synthetic npm monorepo".to_owned(),
        root_path: project_root.canonicalize()?.to_string_lossy().into_owned(),
        git_remote: None,
        reference_branch: None,
        allowed_ai_providers: Vec::new(),
        last_scan_at: None,
        created_at: now,
        updated_at: now,
    };
    database.repository::<Project>().create(&project).await?;

    let scanner = Arc::new(LocalProjectScanner::new(
        database.clone(),
        &app_data,
        HttpPolicy {
            public_downloads_enabled: false,
        },
        LocalScanSettings::default(),
    )?);
    let queue = scanner.queue(ScanLimits::default())?;
    let full_scan_started = Instant::now();
    let scan = queue
        .enqueue(ScanRequest {
            project_id: project.id.clone(),
            root: project_root.clone(),
            profile: ScanProfile::Quick,
            reason: ScanReason::Manual,
        })
        .await?
        .wait()
        .await?;
    let full_scan_ms = full_scan_started.elapsed().as_millis();

    let incremental_started = Instant::now();
    let startup = scanner
        .startup_check(std::slice::from_ref(&project), &queue)
        .await?;
    let incremental_scan_ms = incremental_started.elapsed().as_millis();
    if !startup.scanned_project_ids.is_empty()
        || startup.unchanged_project_ids.len() != 1
        || startup.unchanged_project_ids.first() != Some(&project.id)
    {
        return Err("unchanged project did not use the incremental startup path".into());
    }
    if scan.component_count != dependency_count {
        return Err(format!(
            "inventory count mismatch: expected {dependency_count}, got {}",
            scan.component_count
        )
        .into());
    }

    database.close().await;
    let database_bytes = sqlite_file_bytes(&database_path)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "dependency_count": dependency_count,
            "full_scan_ms": full_scan_ms,
            "incremental_scan_ms": incremental_scan_ms,
            "sqlite_bytes": database_bytes,
            "inventory_complete": scan.inventory_complete,
            "outcome": scan.outcome,
            "network_enabled": false,
        }))?
    );
    Ok(())
}

fn write_package_lock(root: &Path, dependency_count: usize) -> std::io::Result<()> {
    let mut packages = Map::<String, Value>::new();
    packages.insert(String::new(), json!({ "name": "synthetic-perf" }));
    for index in 0..dependency_count {
        let name = format!("node_modules/perf-package-{index:05}");
        packages.insert(name, json!({ "version": "1.2.3" }));
    }
    let package_lock = json!({
        "name": "synthetic-perf",
        "lockfileVersion": 3,
        "packages": packages,
    });
    fs::write(
        root.join("package-lock.json"),
        serde_json::to_vec(&package_lock).map_err(std::io::Error::other)?,
    )
}

fn sqlite_file_bytes(path: &Path) -> std::io::Result<u64> {
    let mut bytes = 0;
    for suffix in ["", "-wal", "-shm"] {
        let file = path.with_file_name(format!(
            "{}{}",
            path.file_name().unwrap_or_default().to_string_lossy(),
            suffix
        ));
        if file.exists() {
            bytes += fs::metadata(file)?.len();
        }
    }
    Ok(bytes)
}
