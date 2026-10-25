use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use security_monitor_advisory_providers::HttpPolicy;
use security_monitor_ai::AiSettings;
use security_monitor_database::Database;
use security_monitor_scan_orchestrator::{
    LocalProjectScanner, LocalScanSettings, ScanLimits, ScanQueue,
};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use crate::ipc_types::{AppSettings, ScanResult};

const MAX_RETAINED_SCAN_RESULTS: usize = 128;

pub fn retain_scan_result(results: &mut HashMap<String, ScanResult>, result: ScanResult) {
    if results.len() >= MAX_RETAINED_SCAN_RESULTS
        && !results.contains_key(&result.scan_id)
        && let Some(evicted) = results.keys().next().cloned()
    {
        results.remove(&evicted);
    }
    results.insert(result.scan_id.clone(), result);
}

pub fn take_scan_result(
    results: &mut HashMap<String, ScanResult>,
    scan_id: &str,
) -> Option<ScanResult> {
    results.remove(scan_id)
}

pub struct ScanServices {
    pub scanner: Arc<LocalProjectScanner>,
    pub queue: Arc<ScanQueue>,
}

impl ScanServices {
    fn new(
        database: &Database,
        app_data_dir: &PathBuf,
        settings: &AppSettings,
    ) -> Result<Self, String> {
        let scanner = Arc::new(
            LocalProjectScanner::new(
                database.clone(),
                app_data_dir,
                HttpPolicy {
                    public_downloads_enabled: settings.public_downloads_enabled,
                },
                LocalScanSettings::default(),
            )
            .map_err(|_| "storage_unavailable".to_owned())?,
        );
        let queue = Arc::new(
            scanner
                .queue(ScanLimits::default())
                .map_err(|_| "storage_unavailable".to_owned())?,
        );
        Ok(Self { scanner, queue })
    }
}

pub struct AppState {
    pub database: Database,
    pub app_data_dir: PathBuf,
    settings_path: PathBuf,
    ai_settings_path: PathBuf,
    pub settings: RwLock<AppSettings>,
    pub ai_settings: RwLock<AiSettings>,
    pub ai_run_guard: Mutex<()>,
    pub update_run_guard: Mutex<()>,
    pub scans: RwLock<ScanServices>,
    pub scan_results: Arc<Mutex<HashMap<String, ScanResult>>>,
}

impl AppState {
    pub fn new(
        database: Database,
        app_data_dir: PathBuf,
        settings: AppSettings,
    ) -> Result<Self, String> {
        let scans = ScanServices::new(&database, &app_data_dir, &settings)?;
        let ai_settings = load_ai_settings(&app_data_dir);
        Ok(Self {
            database,
            settings_path: app_data_dir.join("settings.json"),
            ai_settings_path: app_data_dir.join("ai-settings.json"),
            app_data_dir,
            settings: RwLock::new(settings),
            ai_settings: RwLock::new(ai_settings),
            ai_run_guard: Mutex::new(()),
            update_run_guard: Mutex::new(()),
            scans: RwLock::new(scans),
            scan_results: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn save_settings(&self, settings: AppSettings) -> Result<(), String> {
        if !(1..=168).contains(&settings.scan_interval_hours) {
            return Err("invalid_input".to_owned());
        }
        let next_scans = ScanServices::new(&self.database, &self.app_data_dir, &settings)?;
        let bytes = serde_json::to_vec(&settings).map_err(|_| "storage_unavailable".to_owned())?;
        write_settings_atomically(&self.settings_path, &bytes)
            .map_err(|_| "storage_unavailable".to_owned())?;
        *self.settings.write().await = settings;
        *self.scans.write().await = next_scans;
        Ok(())
    }

    pub async fn save_ai_settings(&self, settings: AiSettings) -> Result<(), String> {
        settings
            .validate()
            .map_err(|_| "invalid_input".to_owned())?;
        let bytes =
            serde_json::to_vec_pretty(&settings).map_err(|_| "storage_unavailable".to_owned())?;
        write_settings_atomically(&self.ai_settings_path, &bytes)
            .map_err(|_| "storage_unavailable".to_owned())?;
        *self.ai_settings.write().await = settings;
        Ok(())
    }
}

pub fn load_settings(app_data_dir: &Path) -> AppSettings {
    let path = app_data_dir.join("settings.json");
    match fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(settings) => settings,
            Err(_) => {
                warn_corrupt_settings(&path, "settings");
                AppSettings::default()
            }
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => AppSettings::default(),
        Err(_) => {
            tracing::warn!(
                setting = "settings",
                reason = "read_failed",
                "Settings could not be loaded"
            );
            AppSettings::default()
        }
    }
}

fn load_ai_settings(app_data_dir: &Path) -> AiSettings {
    let path = app_data_dir.join("ai-settings.json");
    match fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice::<AiSettings>(&bytes) {
            Ok(settings) if settings.validate().is_ok() => settings,
            _ => {
                warn_corrupt_settings(&path, "ai-settings");
                AiSettings::default()
            }
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => AiSettings::default(),
        Err(_) => {
            tracing::warn!(
                setting = "ai-settings",
                reason = "read_failed",
                "Settings could not be loaded"
            );
            AiSettings::default()
        }
    }
}

fn warn_corrupt_settings(path: &Path, setting: &'static str) {
    let Some(parent) = path.parent() else {
        tracing::warn!(
            setting,
            reason = "invalid_file",
            "Settings could not be loaded"
        );
        return;
    };
    let quarantined_path = parent.join(format!("{setting}.corrupt-{}.json", Uuid::new_v4()));
    match fs::rename(path, quarantined_path) {
        Ok(()) => {
            tracing::warn!(
                setting,
                reason = "invalid_file_quarantined",
                "Settings could not be loaded; a copy was preserved"
            );
        }
        Err(_) => {
            tracing::warn!(
                setting,
                reason = "invalid_file_quarantine_failed",
                "Settings could not be loaded or preserved"
            );
        }
    }
}

fn write_settings_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "settings path has no parent")
        })?;
    fs::create_dir_all(parent)?;
    let filename = path
        .file_name()
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "settings path has no filename")
        })?
        .to_string_lossy();
    let temporary = parent.join(format!(".{filename}.{}.tmp", Uuid::new_v4()));
    let mut created = false;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        created = true;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        replace_file(&temporary, path)
    })();
    if result.is_err() && created {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(not(windows))]
fn replace_file(temporary: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(temporary, destination)
}

#[cfg(windows)]
fn replace_file(temporary: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let temporary = temporary
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    let result = unsafe { MoveFileExW(temporary.as_ptr(), destination.as_ptr(), flags) };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AiSettings, AppSettings, MAX_RETAINED_SCAN_RESULTS, load_ai_settings, load_settings,
        retain_scan_result, take_scan_result, write_settings_atomically,
    };
    use crate::ipc_types::ScanResult;
    use security_monitor_core::ScanOutcome;
    use std::{collections::HashMap, fs};

    #[test]
    fn saved_settings_ignore_the_removed_notification_toggle() {
        let settings: AppSettings =
            serde_json::from_str(r#"{"notifications_enabled":true,"scan_interval_hours":12}"#)
                .expect("older settings remain readable");

        assert_eq!(settings.scan_interval_hours, 12);
        assert_eq!(settings.ecosystems, AppSettings::default().ecosystems);
    }

    #[test]
    fn scan_results_are_bounded_and_consumed_once() {
        let mut results = HashMap::new();
        for index in 0..MAX_RETAINED_SCAN_RESULTS + 1 {
            let result = ScanResult {
                scan_id: format!("scan-{index}"),
                outcome: ScanOutcome::Succeeded,
                inventory_complete: true,
                component_count: 0,
                finding_count: 0,
                scanner_finding_count: 0,
                diagnostics: Vec::new(),
            };
            retain_scan_result(&mut results, result);
        }
        assert_eq!(results.len(), MAX_RETAINED_SCAN_RESULTS);
        let scan_id = results.keys().next().cloned().unwrap();
        assert!(take_scan_result(&mut results, &scan_id).is_some());
        assert!(take_scan_result(&mut results, &scan_id).is_none());
    }

    #[test]
    fn corrupt_settings_are_quarantined_and_replaced_with_defaults() {
        let directory = tempfile::tempdir().unwrap();
        let settings_path = directory.path().join("settings.json");
        let ai_settings_path = directory.path().join("ai-settings.json");
        fs::write(&settings_path, b"not json").unwrap();
        fs::write(&ai_settings_path, b"not json").unwrap();

        assert_eq!(load_settings(directory.path()), AppSettings::default());
        assert_eq!(load_ai_settings(directory.path()), AiSettings::default());
        assert!(!settings_path.exists());
        assert!(!ai_settings_path.exists());

        let quarantined = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert!(quarantined.iter().any(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("settings.corrupt-"))
        }));
        assert!(quarantined.iter().any(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("ai-settings.corrupt-"))
        }));
    }

    #[test]
    fn settings_are_replaced_atomically_without_leaving_temporary_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        fs::write(&path, b"old settings").unwrap();

        write_settings_atomically(&path, b"new settings").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"new settings");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
