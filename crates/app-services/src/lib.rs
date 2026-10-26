use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

use security_monitor_agent_protocol::AgentInventory;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppDataPlatform {
    Windows,
    MacOs,
    Xdg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppDataDirError;

impl fmt::Display for AppDataDirError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("application data directory is unavailable")
    }
}

impl Error for AppDataDirError {}

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
) -> Result<PathBuf, AppDataDirError> {
    let app_data = app_data.filter(|path| path.is_absolute());
    let xdg_data_home = xdg_data_home.filter(|path| path.is_absolute());
    let home = home.filter(|path| path.is_absolute());
    match platform {
        AppDataPlatform::Windows => app_data
            .map(Path::to_path_buf)
            .or_else(|| home.map(|path| path.join("AppData").join("Roaming")))
            .map(|path| path.join("org.securitymonitor.desktop"))
            .ok_or(AppDataDirError),
        AppDataPlatform::MacOs => home
            .map(|path| {
                path.join("Library")
                    .join("Application Support")
                    .join("org.securitymonitor.desktop")
            })
            .ok_or(AppDataDirError),
        AppDataPlatform::Xdg => xdg_data_home
            .map(Path::to_path_buf)
            .or_else(|| home.map(|path| path.join(".local").join("share")))
            .map(|path| path.join("org.securitymonitor.desktop"))
            .ok_or(AppDataDirError),
    }
}

pub fn default_app_data_dir() -> Result<PathBuf, AppDataDirError> {
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
        #[cfg(target_os = "windows")]
        std::env::var_os("USERPROFILE").as_deref().map(Path::new),
        #[cfg(not(target_os = "windows"))]
        std::env::var_os("HOME").as_deref().map(Path::new),
    )
}

pub fn default_database_path() -> Result<PathBuf, AppDataDirError> {
    Ok(default_app_data_dir()?.join("security-monitor.sqlite3"))
}

pub fn database_locations(
    database_path: Option<PathBuf>,
) -> Result<(PathBuf, PathBuf), AppDataDirError> {
    match database_path {
        Some(database_path) => {
            let app_data = database_path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .map(Path::to_path_buf)
                .map(Ok)
                .unwrap_or_else(|| std::env::current_dir().map_err(|_| AppDataDirError))?;
            Ok((database_path, app_data))
        }
        None => {
            let app_data = default_app_data_dir()?;
            Ok((app_data.join("security-monitor.sqlite3"), app_data))
        }
    }
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

pub fn remove_server_snapshot(
    app_data_dir: &Path,
    asset_id: &str,
) -> Result<bool, ServerSnapshotError> {
    let asset_id = Uuid::parse_str(asset_id).map_err(|_| ServerSnapshotError::InvalidAssetId)?;
    let canonical_app_data = match app_data_dir.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(ServerSnapshotError::Storage),
    };
    let directory = canonical_app_data.join("server-inventory");
    let canonical_directory = match directory.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(ServerSnapshotError::Storage),
    };
    if !canonical_directory.starts_with(&canonical_app_data) {
        return Err(ServerSnapshotError::Storage);
    }
    let path = canonical_directory.join(format!("{asset_id}.json"));
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(ServerSnapshotError::Storage),
    };
    if !metadata.file_type().is_file() {
        return Err(ServerSnapshotError::Storage);
    }
    let canonical_path = path
        .canonicalize()
        .map_err(|_| ServerSnapshotError::Storage)?;
    if !canonical_path.starts_with(&canonical_directory) {
        return Err(ServerSnapshotError::Storage);
    }
    std::fs::remove_file(canonical_path).map_err(|_| ServerSnapshotError::Storage)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_data_paths_preserve_platform_layout_and_build_isolation() {
        let root = std::env::current_dir().unwrap();
        let app_data = root.join("appdata");
        let home = root.join("home");
        assert_eq!(
            resolve_app_data_dir(AppDataPlatform::Windows, Some(&app_data), None, None,),
            Ok(app_data.join("org.securitymonitor.desktop"))
        );
        assert_eq!(
            resolve_app_data_dir(AppDataPlatform::MacOs, None, None, Some(&home),),
            Ok(home.join("Library/Application Support/org.securitymonitor.desktop"))
        );
        assert_eq!(
            resolve_app_data_dir(AppDataPlatform::Xdg, None, None, Some(&home),),
            Ok(home.join(".local/share/org.securitymonitor.desktop"))
        );
        assert_eq!(
            resolve_app_data_dir(AppDataPlatform::Windows, None, None, Some(&home)),
            Ok(home.join("AppData/Roaming/org.securitymonitor.desktop"))
        );
        assert_eq!(
            resolve_app_data_dir(AppDataPlatform::Xdg, None, Some(&app_data), Some(&home)),
            Ok(app_data.join("org.securitymonitor.desktop"))
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
    fn missing_or_relative_platform_directories_never_fall_back_to_temporary_storage() {
        assert_eq!(
            resolve_app_data_dir(AppDataPlatform::Windows, None, None, None),
            Err(AppDataDirError)
        );
        assert_eq!(
            resolve_app_data_dir(AppDataPlatform::MacOs, None, None, None),
            Err(AppDataDirError)
        );
        assert_eq!(
            resolve_app_data_dir(AppDataPlatform::Xdg, None, None, None),
            Err(AppDataDirError)
        );
        assert_eq!(
            resolve_app_data_dir(
                AppDataPlatform::Xdg,
                None,
                Some(Path::new("relative-xdg")),
                Some(Path::new("relative-home")),
            ),
            Err(AppDataDirError)
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

    #[test]
    fn snapshot_removal_deletes_only_the_server_inventory_file() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let inventory = security_monitor_agent_protocol::decode_inventory(include_bytes!(
            "../../../tests/fixtures/agent/stale-inventory.json"
        ))
        .expect("valid inventory fixture");
        let asset_id = Uuid::new_v4();
        persist_server_snapshot(temp.path(), &asset_id.to_string(), &inventory)
            .expect("snapshot should persist");

        assert!(remove_server_snapshot(temp.path(), &asset_id.to_string()).unwrap());
        assert!(!remove_server_snapshot(temp.path(), &asset_id.to_string()).unwrap());
        assert!(
            !temp
                .path()
                .join("server-inventory")
                .join(format!("{asset_id}.json"))
                .exists()
        );
    }
}
