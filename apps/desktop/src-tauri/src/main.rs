#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app_state;
mod drift_sync;
mod ipc;
mod ipc_types;

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use app_state::{AppState, load_settings};
use security_monitor_database::Database;
use tauri::{
    Manager,
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
};

fn show_main_window(app: &tauri::AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let window = match app.get_webview_window("main") {
        Some(window) => window,
        None => {
            let config = app
                .config()
                .app
                .windows
                .iter()
                .find(|window| window.label == "main")
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "main_window_config_missing")
                })?;
            tauri::WebviewWindowBuilder::from_config(app, config)?.build()?
        }
    };
    window.show()?;
    window.set_focus()?;
    Ok(())
}

fn destroy_main_window(window: &tauri::Window) {
    let window = window.clone();
    let app = window.app_handle().clone();
    if let Err(error) = app.run_on_main_thread(move || {
        if let Err(error) = window.destroy() {
            tracing::error!(%error, "failed to destroy the main webview for tray mode");
        }
    }) {
        tracing::error!(%error, "failed to schedule main webview destruction");
    }
}

fn should_keep_tray_process_alive(exit_code: Option<i32>) -> bool {
    exit_code.is_none()
}

fn app_data_dir_for_build(app_data_dir: &Path, debug_build: bool) -> PathBuf {
    if debug_build {
        app_data_dir.join("development")
    } else {
        app_data_dir.to_path_buf()
    }
}

fn main() {
    let builder = tauri::Builder::default();
    let builder = if let Some(public_key) =
        option_env!("SECMON_UPDATE_PUBLIC_KEY").filter(|key| !key.trim().is_empty())
    {
        builder.plugin(
            tauri_plugin_updater::Builder::new()
                .pubkey(public_key)
                .build(),
        )
    } else {
        builder
    };
    let app = builder
        .setup(|app| {
            let app_data_dir = app_data_dir_for_build(
                &app.path().app_data_dir()?,
                cfg!(debug_assertions),
            );
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
                        let window_app = app.clone();
                        if let Err(error) = app.run_on_main_thread(move || {
                            if let Err(error) = show_main_window(&window_app) {
                                tracing::error!(%error, "failed to show the main window from the tray");
                            }
                        }) {
                            tracing::error!(%error, "failed to schedule showing the main window");
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
                destroy_main_window(window);
            }
        })
        .invoke_handler(tauri::generate_handler![
            ipc::get_app_settings,
            ipc::save_app_settings,
            ipc::get_ai_configuration,
            ipc::save_ai_settings,
            ipc::save_ai_provider,
            ipc::set_project_ai_providers,
            ipc::estimate_ai_request,
            ipc::run_ai_request,
            ipc::list_projects,
            ipc::add_project,
            ipc::discover_local_projects,
            ipc::start_project_scan,
            ipc::cancel_project_scan,
            ipc::get_scan_result,
            ipc::list_findings,
            ipc::list_memories,
            ipc::create_memory,
            ipc::update_memory,
            ipc::delete_memory,
            ipc::export_memories,
            ipc::import_memories,
            ipc::delete_all_memories,
            ipc::list_advisories,
            ipc::list_news_signals,
            ipc::refresh_news_signals,
            ipc::list_components,
            ipc::list_component_instances,
            ipc::list_finding_evidence,
            ipc::list_scan_runs,
            ipc::list_audit_events,
            ipc::list_remediations,
            ipc::remediation_sandbox_status,
            ipc::list_mcp_remediation_requests,
            ipc::dismiss_mcp_remediation_request,
            ipc::request_remediation,
            ipc::approve_remediation,
            ipc::reject_remediation,
            ipc::run_safe_tests,
            ipc::set_finding_status,
            ipc::list_server_assets,
            ipc::detect_scanners,
            ipc::install_scanner,
            ipc::update_advisory_data,
            ipc::check_for_updates,
            ipc::install_update,
            ipc::list_ssh_config_hosts,
            ipc::inspect_server_host_key,
            ipc::pair_server,
            ipc::collect_server_inventory,
            ipc::get_server_inventory_summary,
            ipc::list_project_server_links,
            ipc::link_project_server,
            ipc::unlink_project_server,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build Security Monitor");
    app.run(|_, event| {
        if let tauri::RunEvent::ExitRequested { code, api, .. } = event
            && should_keep_tray_process_alive(code)
        {
            api.prevent_exit();
        }
    });
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{app_data_dir_for_build, should_keep_tray_process_alive};

    #[test]
    fn tray_close_keeps_process_alive_but_explicit_exit_does_not() {
        assert!(should_keep_tray_process_alive(None));
        assert!(!should_keep_tray_process_alive(Some(0)));
    }

    #[test]
    fn debug_build_uses_separate_app_data_without_moving_release_data() {
        let app_data = Path::new("app-data");

        assert_eq!(
            app_data_dir_for_build(app_data, true),
            Path::new("app-data/development")
        );
        assert_eq!(app_data_dir_for_build(app_data, false), app_data);
    }
}
