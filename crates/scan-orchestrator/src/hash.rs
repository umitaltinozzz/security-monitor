use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy)]
pub struct InputHashLimits {
    pub max_files: usize,
    pub max_bytes: u64,
}

impl Default for InputHashLimits {
    fn default() -> Self {
        Self {
            max_files: 20_000,
            max_bytes: 128 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputHash {
    pub sha256: Option<String>,
    pub complete: bool,
    pub files: usize,
    pub bytes: u64,
}

pub fn hash_dependency_inputs(root: impl AsRef<Path>, limits: InputHashLimits) -> InputHash {
    let root = match fs::canonicalize(root.as_ref()) {
        Ok(root) if root.is_dir() => root,
        _ => return incomplete(0, 0),
    };
    let mut files = Vec::new();
    let mut visited = BTreeSet::new();
    let mut diagnostics = false;
    if collect_files(&root, &root, &mut visited, &mut files, &mut diagnostics).is_err() {
        return incomplete(files.len(), 0);
    }
    files.sort();
    files.dedup();
    if diagnostics || files.is_empty() || files.len() > limits.max_files {
        return incomplete(files.len(), 0);
    }

    let mut digest = Sha256::new();
    let mut bytes_seen = 0_u64;
    for path in &files {
        let canonical = match path.canonicalize() {
            Ok(canonical) if canonical.starts_with(&root) => canonical,
            _ => return incomplete(files.len(), bytes_seen),
        };
        let relative = match canonical.strip_prefix(&root) {
            Ok(relative) => relative,
            Err(_) => return incomplete(files.len(), bytes_seen),
        };
        let relative = match relative.to_str() {
            Some(relative) => relative.replace('\\', "/"),
            None => return incomplete(files.len(), bytes_seen),
        };
        let contents = match fs::read(&canonical) {
            Ok(contents) => contents,
            Err(_) => return incomplete(files.len(), bytes_seen),
        };
        bytes_seen = match bytes_seen.checked_add(contents.len() as u64) {
            Some(bytes) if bytes <= limits.max_bytes => bytes,
            _ => return incomplete(files.len(), bytes_seen),
        };
        digest.update((relative.len() as u64).to_be_bytes());
        digest.update(relative.as_bytes());
        digest.update((contents.len() as u64).to_be_bytes());
        digest.update(contents);
    }
    InputHash {
        sha256: Some(hex::encode(digest.finalize())),
        complete: true,
        files: files.len(),
        bytes: bytes_seen,
    }
}

fn collect_files(
    root: &Path,
    directory: &Path,
    visited: &mut BTreeSet<PathBuf>,
    files: &mut Vec<PathBuf>,
    diagnostics: &mut bool,
) -> Result<(), ()> {
    let canonical_directory = directory.canonicalize().map_err(|_| ())?;
    if !canonical_directory.starts_with(root) {
        *diagnostics = true;
        return Ok(());
    }
    if !visited.insert(canonical_directory.clone()) {
        return Ok(());
    }
    let entries = match fs::read_dir(&canonical_directory) {
        Ok(entries) => entries,
        Err(_) => {
            *diagnostics = true;
            return Ok(());
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                *diagnostics = true;
                continue;
            }
        };
        let name = entry.file_name();
        if name.to_str().is_some_and(is_pruned_directory) {
            continue;
        }
        let path = entry.path();
        let canonical = match path.canonicalize() {
            Ok(canonical) if canonical.starts_with(root) => canonical,
            Ok(_) | Err(_) => {
                *diagnostics = true;
                continue;
            }
        };
        let metadata = match fs::metadata(&canonical) {
            Ok(metadata) => metadata,
            Err(_) => {
                *diagnostics = true;
                continue;
            }
        };
        if metadata.is_dir() {
            collect_files(root, &canonical, visited, files, diagnostics)?;
        } else if metadata.is_file() && is_dependency_input(&canonical, root) {
            files.push(canonical);
        }
    }
    Ok(())
}

pub(crate) fn is_dependency_input(path: &Path, root: &Path) -> bool {
    path.strip_prefix(root)
        .is_ok_and(security_monitor_inventory::is_dependency_file)
}

fn is_pruned_directory(name: &str) -> bool {
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

fn incomplete(files: usize, bytes: u64) -> InputHash {
    InputHash {
        sha256: None,
        complete: false,
        files,
        bytes,
    }
}
