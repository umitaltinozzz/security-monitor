use std::{
    collections::HashMap,
    fs,
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
        fs::write(&self.settings_path, bytes).map_err(|_| "storage_unavailable".to_owned())?;
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
        fs::write(&self.ai_settings_path, bytes).map_err(|_| "storage_unavailable".to_owned())?;
        *self.ai_settings.write().await = settings;
        Ok(())
    }
}

pub fn load_settings(app_data_dir: &Path) -> AppSettings {
    let path = app_data_dir.join("settings.json");
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn load_ai_settings(app_data_dir: &Path) -> AiSettings {
    let path = app_data_dir.join("ai-settings.json");
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<AiSettings>(&bytes).ok())
        .filter(|settings| settings.validate().is_ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{AppSettings, MAX_RETAINED_SCAN_RESULTS, retain_scan_result, take_scan_result};
    use crate::ipc_types::ScanResult;
    use security_monitor_core::ScanOutcome;
    use std::collections::HashMap;

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
}
