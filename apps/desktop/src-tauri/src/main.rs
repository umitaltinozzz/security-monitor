#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app_state;
mod ipc;
mod ipc_types;

use std::{fs, path::PathBuf};

use app_state::{AppState, load_settings};
use security_monitor_database::Database;
use tauri::{
    Manager,
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
};

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let app_data_dir = app.path().app_data_dir()?;
            fs::create_dir_all(&app_data_dir)?;
            let settings = load_settings(&app_data_dir);
            let database_path: PathBuf = app_data_dir.join("security-monitor.sqlite3");
            let database = tauri::async_runtime::block_on(Database::open(database_path))?;
            let state = tauri::async_runtime::block_on(async {
                AppState::new(database, app_data_dir, settings.clone())
            })
            .map_err(std::io::Error::other)?;
            app.manage(state);

            let locale_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../src/locales")
                .join(format!("{}.json", settings.language.as_str()));
            let locale_bytes = fs::read(locale_path)?;
            let locale: serde_json::Value = serde_json::from_slice(&locale_bytes)?;
            let show_label = locale["tray"]["show"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("tray locale is unavailable"))?;
            let quit_label = locale["tray"]["quit"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("tray locale is unavailable"))?;
            let show = MenuItem::with_id(app, "show", show_label, true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", quit_label, true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            TrayIconBuilder::new()
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            ipc::get_app_settings,
            ipc::save_app_settings,
            ipc::list_projects,
            ipc::add_project,
            ipc::discover_local_projects,
            ipc::start_project_scan,
            ipc::cancel_project_scan,
            ipc::get_scan_result,
            ipc::list_findings,
            ipc::list_advisories,
            ipc::list_components,
            ipc::list_component_instances,
            ipc::list_finding_evidence,
            ipc::list_scan_runs,
            ipc::list_audit_events,
            ipc::set_finding_status,
            ipc::list_server_assets,
            ipc::detect_scanners,
            ipc::install_scanner,
            ipc::update_advisory_data,
            ipc::list_ssh_config_hosts,
            ipc::inspect_server_host_key,
            ipc::pair_server,
            ipc::collect_server_inventory,
            ipc::get_server_inventory_summary,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Security Monitor");
}
