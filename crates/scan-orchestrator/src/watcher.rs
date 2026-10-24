use std::{
    path::{Component, Path, PathBuf},
    sync::mpsc as std_mpsc,
    time::Duration,
};

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep_until};

use crate::{DebouncedChanges, FileChange, FileChangeKind, hash::is_dependency_input};

const FILE_CHANGE_DEBOUNCE: Duration = Duration::from_secs(3);

#[derive(Debug, Error)]
pub enum WatchError {
    #[error("project watcher could not be started")]
    Start(#[source] notify::Error),
    #[error("selected project root cannot be accessed")]
    InvalidRoot,
}

pub struct ProjectWatcher {
    _watcher: RecommendedWatcher,
    receiver: mpsc::UnboundedReceiver<(PathBuf, FileChangeKind)>,
    root: PathBuf,
}

impl ProjectWatcher {
    /// Waits until three seconds have passed since the last relevant file event.
    pub async fn next_change(&mut self) -> Option<FileChange> {
        let (first_path, first_kind) = self.receiver.recv().await?;
        let mut changes = DebouncedChanges::new(FILE_CHANGE_DEBOUNCE);
        changes.push(first_path, first_kind, Instant::now());
        loop {
            let deadline = changes.deadline()?;
            tokio::select! {
                event = self.receiver.recv() => match event {
                    Some((path, kind)) => changes.push(path, kind, Instant::now()),
                    None => return changes.take_if_ready(Instant::now()),
                },
                _ = sleep_until(deadline) => {
                    if let Some(batch) = changes.take_if_ready(Instant::now()) {
                        return Some(batch);
                    }
                }
            }
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

pub fn watch_project(root: impl AsRef<Path>) -> Result<ProjectWatcher, WatchError> {
    let root = root
        .as_ref()
        .canonicalize()
        .map_err(|_| WatchError::InvalidRoot)?;
    if !root.is_dir() {
        return Err(WatchError::InvalidRoot);
    }
    let callback_root = root.clone();
    let (sender, receiver) = mpsc::unbounded_channel();
    let (ready_sender, ready_receiver) = std_mpsc::sync_channel(1);
    let mut watcher =
        notify::recommended_watcher(move |result: Result<notify::Event, notify::Error>| {
            let Ok(event) = result else { return };
            if !matches!(
                event.kind,
                EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
            ) {
                return;
            }
            for path in event.paths {
                if let Some((relative, kind)) = classify_event_path(&callback_root, &path)
                    && sender.send((relative, kind)).is_err()
                {
                    return;
                }
            }
        })
        .map_err(WatchError::Start)?;
    watcher
        .watch(&root, RecursiveMode::Recursive)
        .map_err(WatchError::Start)?;
    let _ = ready_sender.send(());
    let _ = ready_receiver.recv();
    Ok(ProjectWatcher {
        _watcher: watcher,
        receiver,
        root,
    })
}

fn classify_event_path(root: &Path, path: &Path) -> Option<(PathBuf, FileChangeKind)> {
    let canonical = match path.canonicalize() {
        Ok(canonical) => canonical,
        Err(_) => {
            let parent = path.parent()?.canonicalize().ok()?;
            let name = path.file_name()?;
            parent.join(name)
        }
    };
    if !canonical.starts_with(root) {
        return None;
    }
    let relative = canonical.strip_prefix(root).ok()?;
    if relative.components().any(|component| {
        matches!(component, Component::Normal(name) if is_pruned(name.to_str().unwrap_or_default()))
    }) {
        return None;
    }
    if is_dependency_input(&canonical, root) {
        return Some((relative.to_path_buf(), FileChangeKind::DependencyInput));
    }
    let name = canonical.file_name()?.to_str()?;
    let extension = canonical
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let is_source = matches!(
        extension.to_ascii_lowercase().as_str(),
        "rs" | "js"
            | "jsx"
            | "ts"
            | "tsx"
            | "py"
            | "php"
            | "go"
            | "java"
            | "kt"
            | "c"
            | "cc"
            | "cpp"
            | "h"
            | "hpp"
            | "rb"
            | "swift"
            | "cs"
    );
    let is_security_config = name == "Dockerfile"
        || name.starts_with("Dockerfile.")
        || name == ".semgrepignore"
        || name.ends_with(".yaml")
        || name.ends_with(".yml");
    (is_source || is_security_config).then_some((
        relative.to_path_buf(),
        FileChangeKind::SourceOrConfiguration,
    ))
}

fn is_pruned(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | "node_modules"
            | "vendor"
            | "target"
            | "dist"
            | "build"
            | "coverage"
            | ".next"
            | ".turbo"
            | ".venv"
            | "venv"
            | ".pnpm-store"
            | "Pods"
    )
}
