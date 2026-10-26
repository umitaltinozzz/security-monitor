use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy)]
pub struct InputHashLimits {
    pub max_files: usize,
    pub max_bytes: u64,
    pub max_entries: usize,
    pub max_depth: usize,
}

impl Default for InputHashLimits {
    fn default() -> Self {
        Self {
            max_files: 20_000,
            max_bytes: 128 * 1024 * 1024,
            max_entries: 250_000,
            max_depth: 64,
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
    let mut traversal = HashTraversal::new(root.clone(), limits);
    if traversal.collect_files(&root, 0).is_err() {
        return incomplete(traversal.files.len(), 0);
    }
    let mut files = traversal.files;
    files.sort();
    files.dedup();
    if traversal.diagnostics || files.is_empty() || files.len() > limits.max_files {
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
        let mut file = match fs::File::open(&canonical) {
            Ok(file) => file,
            Err(_) => return incomplete(files.len(), bytes_seen),
        };
        let metadata = match file.metadata() {
            Ok(metadata) if metadata.is_file() => metadata,
            _ => return incomplete(files.len(), bytes_seen),
        };
        let expected_bytes = metadata.len();
        let remaining_bytes = limits.max_bytes.saturating_sub(bytes_seen);
        if expected_bytes > remaining_bytes {
            return incomplete(files.len(), bytes_seen);
        }
        digest.update((relative.len() as u64).to_be_bytes());
        digest.update(relative.as_bytes());
        digest.update(expected_bytes.to_be_bytes());
        let mut contents_read = 0_u64;
        let mut buffer = [0_u8; 8192];
        loop {
            let count = match file.read(&mut buffer) {
                Ok(count) => count,
                Err(_) => return incomplete(files.len(), bytes_seen),
            };
            if count == 0 {
                break;
            }
            contents_read = match contents_read.checked_add(count as u64) {
                Some(total) if total <= expected_bytes && total <= remaining_bytes => total,
                _ => return incomplete(files.len(), bytes_seen),
            };
            digest.update(&buffer[..count]);
        }
        if contents_read != expected_bytes {
            return incomplete(files.len(), bytes_seen);
        }
        bytes_seen += contents_read;
    }
    InputHash {
        sha256: Some(hex::encode(digest.finalize())),
        complete: true,
        files: files.len(),
        bytes: bytes_seen,
    }
}

struct HashTraversal {
    root: PathBuf,
    visited: BTreeSet<PathBuf>,
    files: Vec<PathBuf>,
    diagnostics: bool,
    entries_seen: usize,
    limits: InputHashLimits,
}

impl HashTraversal {
    fn new(root: PathBuf, limits: InputHashLimits) -> Self {
        Self {
            root,
            visited: BTreeSet::new(),
            files: Vec::new(),
            diagnostics: false,
            entries_seen: 0,
            limits,
        }
    }

    fn collect_files(&mut self, directory: &Path, depth: usize) -> Result<(), ()> {
        if depth > self.limits.max_depth {
            self.diagnostics = true;
            return Err(());
        }
        let canonical_directory = directory.canonicalize().map_err(|_| ())?;
        if !canonical_directory.starts_with(&self.root) {
            self.diagnostics = true;
            return Ok(());
        }
        if !self.visited.insert(canonical_directory.clone()) {
            return Ok(());
        }
        let entries = match fs::read_dir(&canonical_directory) {
            Ok(entries) => entries,
            Err(_) => {
                self.diagnostics = true;
                return Ok(());
            }
        };
        for entry in entries {
            self.entries_seen = self.entries_seen.saturating_add(1);
            if self.entries_seen > self.limits.max_entries {
                self.diagnostics = true;
                return Err(());
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    self.diagnostics = true;
                    continue;
                }
            };
            let name = entry.file_name();
            if name.to_str().is_some_and(is_pruned_directory) {
                continue;
            }
            let path = entry.path();
            let canonical = match path.canonicalize() {
                Ok(canonical) if canonical.starts_with(&self.root) => canonical,
                Ok(_) | Err(_) => {
                    self.diagnostics = true;
                    continue;
                }
            };
            let metadata = match fs::metadata(&canonical) {
                Ok(metadata) => metadata,
                Err(_) => {
                    self.diagnostics = true;
                    continue;
                }
            };
            if metadata.is_dir() {
                self.collect_files(&canonical, depth + 1)?;
            } else if metadata.is_file() && is_dependency_input(&canonical, &self.root) {
                if self.files.len() >= self.limits.max_files {
                    self.diagnostics = true;
                    return Err(());
                }
                self.files.push(canonical);
            }
        }
        Ok(())
    }
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
