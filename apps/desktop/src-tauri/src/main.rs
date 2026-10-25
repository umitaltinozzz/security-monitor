#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app_state;
mod background;
mod drift_sync;
mod ipc;
mod ipc_types;
mod logging;

use std::{fs, io, path::PathBuf};

use app_state::{AppState, load_settings};
use security_monitor_app_services::app_data_dir_for_build;
use security_monitor_database::Database;
use tauri::{
    Manager,
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
};
use tokio_util::sync::CancellationToken;

const EN_TRAY_LOCALE: &str = include_str!("../../src/locales/en.json");
const TR_TRAY_LOCALE: &str = include_str!("../../src/locales/tr.json");

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

fn main() {
    let smoke_test = std::env::args_os().any(|argument| argument == "--smoke-test");
    let background_cancellation = CancellationToken::new();
    let setup_background_cancellation = background_cancellation.clone();
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
        .setup(move |app| {
            let app_data_dir = app_data_dir_for_build(
                &app.path().app_data_dir()?,
                cfg!(debug_assertions),
            );
            fs::create_dir_all(&app_data_dir)?;
            logging::initialize(&app_data_dir.join("logs"))?;
            let settings = load_settings(&app_data_dir);
            let database_path: PathBuf = app_data_dir.join("security-monitor.sqlite3");
            let database = tauri::async_runtime::block_on(Database::open(database_path))?;
            let state = tauri::async_runtime::block_on(async {
                AppState::new(database, app_data_dir, settings.clone())
            })
            .map_err(std::io::Error::other)?;
            app.manage(state);

            if smoke_test {
                app.handle().exit(0);
                return Ok(());
            }

            let locale_source = match settings.language.as_str() {
                "tr" => TR_TRAY_LOCALE,
                _ => EN_TRAY_LOCALE,
            };
            let locale: serde_json::Value = serde_json::from_str(locale_source)?;
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
            background::start(app.handle().clone(), setup_background_cancellation.clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                destroy_main_window(window);
            }
        })
        .invoke_handler(tauri::generate_handler![
            ipc::settings::get_app_settings,
            ipc::settings::save_app_settings,
            ipc::settings::get_ai_configuration,
            ipc::settings::save_ai_settings,
            ipc::ai::save_ai_provider,
            ipc::ai::set_project_ai_providers,
            ipc::ai::estimate_ai_request,
            ipc::ai::run_ai_request,
            ipc::projects::list_projects,
            ipc::projects::add_project,
            ipc::projects::discover_local_projects,
            ipc::scan::start_project_scan,
            ipc::scan::cancel_project_scan,
            ipc::scan::get_scan_result,
            ipc::findings::list_findings,
            ipc::findings::list_findings_page,
            ipc::memory::list_memories,
            ipc::memory::create_memory,
            ipc::memory::update_memory,
            ipc::memory::delete_memory,
            ipc::memory::export_memories,
            ipc::memory::import_memories,
            ipc::memory::delete_all_memories,
            ipc::findings::list_advisories,
            ipc::news::list_news_signals,
            ipc::news::refresh_news_signals,
            ipc::findings::list_components,
            ipc::findings::list_component_instances,
            ipc::findings::list_finding_evidence,
            ipc::findings::list_scan_runs,
            ipc::findings::list_audit_events,
            ipc::remediation::list_remediations,
            ipc::remediation::remediation_sandbox_status,
            ipc::remediation::list_mcp_remediation_requests,
            ipc::remediation::dismiss_mcp_remediation_request,
            ipc::remediation::request_remediation,
            ipc::remediation::approve_remediation,
            ipc::remediation::reject_remediation,
            ipc::remediation::run_safe_tests,
            ipc::findings::set_finding_status,
            ipc::servers::list_server_assets,
            ipc::scan::detect_scanners,
            ipc::scan::install_scanner,
            ipc::scan::update_advisory_data,
            ipc::update::check_for_updates,
            ipc::update::install_update,
            ipc::servers::list_ssh_config_hosts,
            ipc::servers::inspect_server_host_key,
            ipc::servers::pair_server,
            ipc::servers::collect_server_inventory,
            ipc::drift::get_server_inventory_summary,
            ipc::drift::list_project_server_links,
            ipc::drift::link_project_server,
            ipc::drift::unlink_project_server,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build Security Monitor");
    app.run(move |_, event| match event {
        tauri::RunEvent::Exit => background_cancellation.cancel(),
        tauri::RunEvent::ExitRequested { code, api, .. }
            if should_keep_tray_process_alive(code) =>
        {
            api.prevent_exit();
        }
        _ => {}
    });
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        EN_TRAY_LOCALE, TR_TRAY_LOCALE, app_data_dir_for_build, should_keep_tray_process_alive,
    };
    use crate::ipc_types::AppSettings;

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

    #[test]
    fn tray_locales_are_embedded_and_contain_both_menu_labels() {
        for source in [EN_TRAY_LOCALE, TR_TRAY_LOCALE] {
            let locale: serde_json::Value =
                serde_json::from_str(source).expect("embedded tray locale should be valid JSON");

            assert!(locale["tray"]["show"].as_str().is_some());
            assert!(locale["tray"]["quit"].as_str().is_some());
        }
    }

    #[tokio::test]
    async fn registered_settings_command_responds_through_tauri_ipc() {
        let directory = tempfile::tempdir().unwrap();
        let database = crate::Database::open(directory.path().join("test.sqlite3"))
            .await
            .unwrap();
        let state = crate::app_state::AppState::new(
            database,
            directory.path().to_owned(),
            AppSettings::default(),
        )
        .unwrap();
        let app = tauri::test::mock_builder()
            .manage(state)
            .invoke_handler(tauri::generate_handler![
                crate::ipc::settings::get_app_settings
            ])
            .build(tauri::generate_context!())
            .unwrap();
        let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .unwrap();
        let response = tauri::test::get_ipc_response(
            &window,
            tauri::webview::InvokeRequest {
                cmd: "get_app_settings".into(),
                callback: tauri::ipc::CallbackFn(0),
                error: tauri::ipc::CallbackFn(1),
                url: "http://tauri.localhost".parse().unwrap(),
                body: tauri::ipc::InvokeBody::default(),
                headers: Default::default(),
                invoke_key: tauri::test::INVOKE_KEY.to_owned(),
            },
        )
        .unwrap()
        .deserialize::<AppSettings>()
        .unwrap();

        assert_eq!(response, AppSettings::default());
    }
}
