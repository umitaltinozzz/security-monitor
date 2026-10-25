use std::path::{Path, PathBuf};

use security_monitor_agent_protocol::AgentInventory;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppDataPlatform {
    Windows,
    MacOs,
    Xdg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerSnapshotError {
    InvalidAssetId,
    Serialization,
    Storage,
}

pub fn resolve_app_data_dir(
    platform: AppDataPlatform,
    app_data: Option<&Path>,
    xdg_data_home: Option<&Path>,
    home: Option<&Path>,
    temporary: &Path,
) -> PathBuf {
    match platform {
        AppDataPlatform::Windows => app_data
            .unwrap_or(temporary)
            .join("org.securitymonitor.desktop"),
        AppDataPlatform::MacOs => home
            .unwrap_or(temporary)
            .join("Library")
            .join("Application Support")
            .join("org.securitymonitor.desktop"),
        AppDataPlatform::Xdg => xdg_data_home
            .map(Path::to_path_buf)
            .unwrap_or_else(|| home.unwrap_or(temporary).join(".local").join("share"))
            .join("org.securitymonitor.desktop"),
    }
}

pub fn default_app_data_dir() -> PathBuf {
    let temporary = std::env::temp_dir();
    #[cfg(target_os = "windows")]
    let platform = AppDataPlatform::Windows;
    #[cfg(target_os = "macos")]
    let platform = AppDataPlatform::MacOs;
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let platform = AppDataPlatform::Xdg;

    resolve_app_data_dir(
        platform,
        std::env::var_os("APPDATA").as_deref().map(Path::new),
        std::env::var_os("XDG_DATA_HOME").as_deref().map(Path::new),
        std::env::var_os("HOME").as_deref().map(Path::new),
        &temporary,
    )
}

pub fn default_database_path() -> PathBuf {
    default_app_data_dir().join("security-monitor.sqlite3")
}

pub fn database_locations(database_path: Option<PathBuf>) -> (PathBuf, PathBuf) {
    let database_path = database_path.unwrap_or_else(default_database_path);
    let app_data = database_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(default_app_data_dir);
    (database_path, app_data)
}

pub fn app_data_dir_for_build(app_data_dir: &Path, debug_build: bool) -> PathBuf {
    if debug_build {
        app_data_dir.join("development")
    } else {
        app_data_dir.to_path_buf()
    }
}

pub fn persist_server_snapshot(
    app_data_dir: &Path,
    asset_id: &str,
    inventory: &AgentInventory,
) -> Result<(), ServerSnapshotError> {
    let asset_id = Uuid::parse_str(asset_id).map_err(|_| ServerSnapshotError::InvalidAssetId)?;
    std::fs::create_dir_all(app_data_dir).map_err(|_| ServerSnapshotError::Storage)?;
    let canonical_app_data = app_data_dir
        .canonicalize()
        .map_err(|_| ServerSnapshotError::Storage)?;
    let directory = canonical_app_data.join("server-inventory");
    std::fs::create_dir_all(&directory).map_err(|_| ServerSnapshotError::Storage)?;
    let canonical_directory = directory
        .canonicalize()
        .map_err(|_| ServerSnapshotError::Storage)?;
    if !canonical_directory.starts_with(&canonical_app_data) {
        return Err(ServerSnapshotError::Storage);
    }

    let destination = canonical_directory.join(format!("{asset_id}.json"));
    let temporary = canonical_directory.join(format!(".{asset_id}-{}.tmp", Uuid::new_v4()));
    let bytes = serde_json::to_vec(inventory).map_err(|_| ServerSnapshotError::Serialization)?;
    std::fs::write(&temporary, bytes).map_err(|_| ServerSnapshotError::Storage)?;
    std::fs::rename(&temporary, &destination).map_err(|_| {
        let _ = std::fs::remove_file(&temporary);
        ServerSnapshotError::Storage
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_data_paths_preserve_platform_layout_and_build_isolation() {
        assert_eq!(
            resolve_app_data_dir(
                AppDataPlatform::Windows,
                Some(Path::new("appdata")),
                None,
                None,
                Path::new("temp"),
            ),
            Path::new("appdata/org.securitymonitor.desktop")
        );
        assert_eq!(
            resolve_app_data_dir(
                AppDataPlatform::MacOs,
                None,
                None,
                Some(Path::new("home")),
                Path::new("temp"),
            ),
            Path::new("home/Library/Application Support/org.securitymonitor.desktop")
        );
        assert_eq!(
            resolve_app_data_dir(
                AppDataPlatform::Xdg,
                None,
                None,
                Some(Path::new("home")),
                Path::new("temp"),
            ),
            Path::new("home/.local/share/org.securitymonitor.desktop")
        );
        assert_eq!(
            app_data_dir_for_build(Path::new("app-data"), true),
            Path::new("app-data/development")
        );
        assert_eq!(
            app_data_dir_for_build(Path::new("app-data"), false),
            Path::new("app-data")
        );
    }

    #[test]
    fn snapshot_writer_canonicalizes_the_store_and_writes_atomic_inventory_json() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let inventory = security_monitor_agent_protocol::decode_inventory(include_bytes!(
            "../../../tests/fixtures/agent/stale-inventory.json"
        ))
        .expect("valid inventory fixture");
        let asset_id = Uuid::new_v4();

        persist_server_snapshot(temp.path(), &asset_id.to_string(), &inventory)
            .expect("snapshot should persist");

        let path = temp
            .path()
            .join("server-inventory")
            .join(format!("{asset_id}.json"));
        let stored = std::fs::read(path).expect("snapshot should exist");
        assert_eq!(
            security_monitor_agent_protocol::decode_inventory(&stored).expect("valid snapshot"),
            inventory
        );
    }

    #[test]
    fn snapshot_writer_rejects_invalid_asset_ids() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let inventory = security_monitor_agent_protocol::decode_inventory(include_bytes!(
            "../../../tests/fixtures/agent/stale-inventory.json"
        ))
        .expect("valid inventory fixture");

        assert_eq!(
            persist_server_snapshot(temp.path(), "../outside", &inventory),
            Err(ServerSnapshotError::InvalidAssetId)
        );
    }
}
