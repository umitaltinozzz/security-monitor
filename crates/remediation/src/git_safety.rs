use super::*;

/// Neutralizes configuration a repository could use to run programs when Git touches it:
/// hooks, fsmonitor, system/global config and attribute files, and inherited Git environment.
/// Repository-local filters still exist, so callers must avoid commands that apply them
/// (for example `status` or `diff`) on untrusted repositories.
pub struct GitCommandSafety {
    directory: PathBuf,
    hooks_directory: PathBuf,
    empty_file: PathBuf,
}

const GIT_ENVIRONMENT_REMOVED: [&str; 9] = [
    "GIT_CONFIG_PARAMETERS",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_PREFIX",
    "GIT_EXTERNAL_DIFF",
];

impl GitCommandSafety {
    pub fn create() -> Result<Self, RemediationError> {
        let directory =
            std::env::temp_dir().join(format!("secmon-git-safe-{}", Uuid::new_v4().simple()));
        fs::create_dir(&directory).map_err(|_| RemediationError::FilesystemFailed)?;
        let hooks_directory = directory.join("hooks");
        let empty_file = directory.join("empty");
        if fs::create_dir(&hooks_directory).is_err()
            || OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&empty_file)
                .is_err()
        {
            let _ = fs::remove_dir_all(&directory);
            return Err(RemediationError::FilesystemFailed);
        }
        Ok(Self {
            directory,
            hooks_directory,
            empty_file,
        })
    }

    fn environment(&self) -> [(&'static str, &std::ffi::OsStr); 11] {
        [
            ("GIT_CONFIG_NOSYSTEM", "1".as_ref()),
            ("GIT_CONFIG_GLOBAL", self.empty_file.as_os_str()),
            ("GIT_ATTR_NOSYSTEM", "1".as_ref()),
            ("GIT_CONFIG_COUNT", "3".as_ref()),
            ("GIT_CONFIG_KEY_0", "core.hooksPath".as_ref()),
            ("GIT_CONFIG_VALUE_0", self.hooks_directory.as_os_str()),
            ("GIT_CONFIG_KEY_1", "core.fsmonitor".as_ref()),
            ("GIT_CONFIG_VALUE_1", "false".as_ref()),
            ("GIT_CONFIG_KEY_2", "core.attributesFile".as_ref()),
            ("GIT_CONFIG_VALUE_2", self.empty_file.as_os_str()),
            ("GIT_TERMINAL_PROMPT", "0".as_ref()),
        ]
    }

    pub(super) fn configure(&self, command: &mut Command) {
        command.envs(self.environment());
        for name in GIT_ENVIRONMENT_REMOVED {
            command.env_remove(name);
        }
    }

    pub fn configure_std(&self, command: &mut std::process::Command) {
        command.envs(self.environment());
        for name in GIT_ENVIRONMENT_REMOVED {
            command.env_remove(name);
        }
    }
}

impl Drop for GitCommandSafety {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

pub fn validate_worktree_under(
    app_data_dir: &Path,
    worktree_path: &Path,
) -> Result<PathBuf, RemediationError> {
    let canonical_root = canonical_worktrees_directory(app_data_dir)?;
    let canonical_worktree =
        fs::canonicalize(worktree_path).map_err(|_| RemediationError::WorktreePathInvalid)?;
    if !canonical_worktree.starts_with(&canonical_root)
        || !canonical_worktree.is_dir()
        || contains_symlink(&canonical_worktree)?
    {
        return Err(RemediationError::WorktreePathInvalid);
    }
    Ok(canonical_worktree)
}

pub(super) fn contains_symlink(root: &Path) -> Result<bool, RemediationError> {
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0usize;
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(directory).map_err(|_| RemediationError::FilesystemFailed)?;
        for entry in entries {
            visited = visited.saturating_add(1);
            if visited > MAX_WORKTREE_ENTRIES {
                return Err(RemediationError::WorktreePathInvalid);
            }
            let entry = entry.map_err(|_| RemediationError::FilesystemFailed)?;
            let file_type = entry
                .file_type()
                .map_err(|_| RemediationError::FilesystemFailed)?;
            if file_type.is_symlink() {
                return Ok(true);
            }
            if file_type.is_dir() && entry.file_name() != ".git" {
                pending.push(entry.path());
            }
        }
    }
    Ok(false)
}
