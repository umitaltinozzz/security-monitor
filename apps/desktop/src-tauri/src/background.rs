use std::{collections::HashMap, path::PathBuf, time::Duration};

use security_monitor_core::Project;
use security_monitor_scan_orchestrator::{
    ProjectWatcher, ScanProfile, ScanReason, ScanRequest, ScheduleAction, SchedulePlan, Scheduler,
    watch_project,
};
use tauri::{AppHandle, Manager};
use tokio::{sync::mpsc, time::Instant};
use tokio_util::sync::CancellationToken;

use crate::app_state::AppState;

struct ActiveProjectWatcher {
    root: PathBuf,
    cancellation: CancellationToken,
}

pub fn start(app: AppHandle, cancellation: CancellationToken) {
    tauri::async_runtime::spawn(async move {
        run(app, cancellation).await;
    });
}

async fn run(app: AppHandle, cancellation: CancellationToken) {
    let (sender, mut receiver) = mpsc::channel(16);
    let scheduler_cancellation = cancellation.child_token();
    tauri::async_runtime::spawn(async move {
        let scheduler = match Scheduler::new(SchedulePlan::default(), Instant::now()) {
            Ok(scheduler) => scheduler,
            Err(_) => {
                tracing::error!("background scheduler configuration is invalid");
                return;
            }
        };
        if scheduler.run(sender, scheduler_cancellation).await.is_err() {
            tracing::warn!("background scheduler stopped before application shutdown");
        }
    });

    let mut watchers = HashMap::new();
    reconcile_watchers(&app, &cancellation, &mut watchers).await;
    run_startup_check(&app).await;
    let mut last_full_scan = Instant::now();

    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            action = receiver.recv() => {
                let Some(action) = action else { break };
                match action {
                    ScheduleAction::CheckProjects => {
                        reconcile_watchers(&app, &cancellation, &mut watchers).await;
                        run_startup_check(&app).await;
                        let interval = configured_scan_interval(&app).await;
                        if last_full_scan.elapsed() >= interval {
                            run_scheduled_full_scans(&app).await;
                            last_full_scan = Instant::now();
                        }
                    }
                    ScheduleAction::RefreshAdvisories => refresh_advisories(&app).await,
                    ScheduleAction::FullScanProjects => {
                        let interval = configured_scan_interval(&app).await;
                        if last_full_scan.elapsed() >= interval {
                            run_scheduled_full_scans(&app).await;
                            last_full_scan = Instant::now();
                        }
                    }
                }
            }
        }
    }

    for watcher in watchers.values() {
        watcher.cancellation.cancel();
    }
}

async fn configured_scan_interval(app: &AppHandle) -> Duration {
    let Some(state) = app.try_state::<AppState>() else {
        return Duration::from_secs(24 * 60 * 60);
    };
    let hours = state
        .settings
        .read()
        .await
        .scan_interval_hours
        .clamp(1, 168);
    Duration::from_secs(u64::from(hours) * 60 * 60)
}

async fn projects(app: &AppHandle) -> Result<Vec<Project>, ()> {
    let Some(state) = app.try_state::<AppState>() else {
        return Err(());
    };
    let database = state.database.clone();
    database
        .repository::<Project>()
        .list()
        .await
        .map_err(|_| ())
}

async fn run_startup_check(app: &AppHandle) {
    let Ok(projects) = projects(app).await else {
        tracing::warn!("scheduled project list could not be loaded");
        return;
    };
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let (scanner, queue) = {
        let services = state.scans.read().await;
        (services.scanner.clone(), services.queue.clone())
    };
    match scanner.startup_check(&projects, &queue).await {
        Ok(report) => {
            tracing::info!(
                scanned = report.scanned_project_ids.len(),
                unchanged = report.unchanged_project_ids.len(),
                unverified = report.unverified_project_ids.len(),
                "scheduled project check completed"
            );
            let database = state.database.clone();
            let app_data_dir = state.app_data_dir.clone();
            for project_id in report.scanned_project_ids {
                if crate::drift_sync::refresh_project_drift(
                    &database,
                    &app_data_dir,
                    &project_id,
                    chrono::Utc::now(),
                )
                .await
                .is_err()
                {
                    tracing::warn!("scheduled project drift refresh failed");
                }
            }
        }
        Err(_) => tracing::warn!("scheduled project check did not complete"),
    }
}

async fn refresh_advisories(app: &AppHandle) {
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let queue = state.scans.read().await.queue.clone();
    if queue.refresh_advisories().await.is_err() {
        tracing::warn!("scheduled advisory refresh did not complete");
    }
}

async fn run_scheduled_full_scans(app: &AppHandle) {
    let Ok(projects) = projects(app).await else {
        tracing::warn!("scheduled project list could not be loaded");
        return;
    };
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let queue = state.scans.read().await.queue.clone();
    let database = state.database.clone();
    let app_data_dir = state.app_data_dir.clone();

    let mut handles = Vec::new();
    for project in projects {
        let Ok(root) = PathBuf::from(&project.root_path).canonicalize() else {
            continue;
        };
        if !root.is_dir() {
            continue;
        }
        match queue
            .enqueue(ScanRequest {
                project_id: project.id.clone(),
                root,
                profile: ScanProfile::Full,
                reason: ScanReason::Scheduled,
            })
            .await
        {
            Ok(handle) => handles.push((project.id, handle)),
            Err(_) => tracing::warn!("scheduled full scan could not be queued"),
        }
    }
    for (project_id, handle) in handles {
        if handle.wait().await.is_err() {
            tracing::warn!("scheduled full scan did not complete");
            continue;
        }
        if crate::drift_sync::refresh_project_drift(
            &database,
            &app_data_dir,
            &project_id,
            chrono::Utc::now(),
        )
        .await
        .is_err()
        {
            tracing::warn!("scheduled project drift refresh failed");
        }
    }
}

async fn reconcile_watchers(
    app: &AppHandle,
    cancellation: &CancellationToken,
    active: &mut HashMap<String, ActiveProjectWatcher>,
) {
    let Ok(projects) = projects(app).await else {
        tracing::warn!("project watchers could not be synchronized");
        return;
    };
    let roots = projects
        .into_iter()
        .filter_map(|project| {
            let root = PathBuf::from(&project.root_path).canonicalize().ok()?;
            root.is_dir().then_some((project.id, root))
        })
        .collect::<HashMap<_, _>>();

    active.retain(|project_id, watcher| {
        let keep = roots.get(project_id) == Some(&watcher.root);
        if !keep {
            watcher.cancellation.cancel();
        }
        keep
    });

    for (project_id, root) in roots {
        if active.contains_key(&project_id) {
            continue;
        }
        let watcher_root = root.clone();
        let watcher = tokio::task::spawn_blocking(move || watch_project(watcher_root)).await;
        let Ok(Ok(watcher)) = watcher else {
            tracing::warn!("project file watcher could not be started");
            continue;
        };
        let watcher_cancellation = cancellation.child_token();
        let task_cancellation = watcher_cancellation.clone();
        let task_app = app.clone();
        let task_project_id = project_id.clone();
        tokio::spawn(async move {
            watch_project_changes(task_app, task_project_id, watcher, task_cancellation).await;
        });
        active.insert(
            project_id,
            ActiveProjectWatcher {
                root,
                cancellation: watcher_cancellation,
            },
        );
    }
}

async fn watch_project_changes(
    app: AppHandle,
    project_id: String,
    mut watcher: ProjectWatcher,
    cancellation: CancellationToken,
) {
    let root = watcher.root().to_path_buf();
    loop {
        let change = tokio::select! {
            _ = cancellation.cancelled() => return,
            change = watcher.next_change() => match change {
                Some(change) => change,
                None => return,
            },
        };
        let Some(state) = app.try_state::<AppState>() else {
            return;
        };
        let queue = state.scans.read().await.queue.clone();
        let handle = queue
            .enqueue(ScanRequest {
                project_id: project_id.clone(),
                root: root.clone(),
                profile: change.profile,
                reason: ScanReason::FileChange,
            })
            .await;
        let Ok(handle) = handle else {
            tracing::warn!("file-change scan could not be queued");
            continue;
        };
        if handle.wait().await.is_err() {
            tracing::warn!("file-change scan did not complete");
            continue;
        }
        let database = state.database.clone();
        let app_data_dir = state.app_data_dir.clone();
        if crate::drift_sync::refresh_project_drift(
            &database,
            &app_data_dir,
            &project_id,
            chrono::Utc::now(),
        )
        .await
        .is_err()
        {
            tracing::warn!("file-change drift refresh failed");
        }
    }
}
