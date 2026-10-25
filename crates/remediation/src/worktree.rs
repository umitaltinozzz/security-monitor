use super::*;

pub fn worktrees_directory(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("worktrees")
}

pub async fn create_worktree(
    repository_path: &Path,
    app_data_dir: &Path,
) -> Result<PreparedWorktree, RemediationError> {
    create_worktree_with_id(repository_path, app_data_dir, &Uuid::new_v4().to_string()).await
}

pub async fn create_worktree_with_id(
    repository_path: &Path,
    app_data_dir: &Path,
    id: &str,
) -> Result<PreparedWorktree, RemediationError> {
    Uuid::parse_str(id).map_err(|_| RemediationError::WorktreePathInvalid)?;
    let repository =
        fs::canonicalize(repository_path).map_err(|_| RemediationError::InvalidRepository)?;
    if !repository.is_dir() {
        return Err(RemediationError::InvalidRepository);
    }
    let top_level = run_git_command(
        &["-C", path_arg(&repository)?, "rev-parse", "--show-toplevel"],
        Duration::from_secs(15),
        MAX_TEST_OUTPUT_BYTES,
    )
    .await?;
    let root = PathBuf::from(String::from_utf8_lossy(&top_level.0).trim());
    let root = fs::canonicalize(root).map_err(|_| RemediationError::InvalidRepository)?;
    if contains_symlink(&root)? {
        return Err(RemediationError::WorktreePathInvalid);
    }
    let git_dir_output = run_git_command(
        &["-C", path_arg(&root)?, "rev-parse", "--absolute-git-dir"],
        Duration::from_secs(15),
        MAX_TEST_OUTPUT_BYTES,
    )
    .await?;
    let git_dir = fs::canonicalize(String::from_utf8_lossy(&git_dir_output.0).trim())
        .map_err(|_| RemediationError::InvalidRepository)?;
    if has_git_filter_attributes(&root, &git_dir)? {
        return Err(RemediationError::GitFiltersNotAllowed);
    }
    let status = run_git_command(
        &[
            "-C",
            path_arg(&root)?,
            "status",
            "--porcelain",
            "--untracked-files=all",
        ],
        Duration::from_secs(15),
        MAX_TEST_OUTPUT_BYTES,
    )
    .await?;
    if !status.0.is_empty() {
        return Err(RemediationError::RepositoryNotClean);
    }

    let canonical_directory = canonical_worktrees_directory(app_data_dir)?;
    let branch = format!("{WORKTREE_BRANCH_PREFIX}{id}");
    let path = canonical_directory.join(id);
    if !path.starts_with(&canonical_directory) {
        return Err(RemediationError::WorktreePathInvalid);
    }
    run_git_command(
        &[
            "-C",
            path_arg(&root)?,
            "worktree",
            "add",
            "-b",
            &branch,
            path_arg(&path)?,
            "HEAD",
        ],
        Duration::from_secs(60),
        MAX_TEST_OUTPUT_BYTES,
    )
    .await?;
    let canonical_worktree =
        fs::canonicalize(&path).map_err(|_| RemediationError::WorktreeFailed)?;
    if !canonical_worktree.starts_with(&canonical_directory)
        || contains_symlink(&canonical_worktree)?
    {
        let _ = remove_worktree(&root, &canonical_worktree).await;
        return Err(RemediationError::WorktreePathInvalid);
    }
    Ok(PreparedWorktree {
        id: id.to_owned(),
        repository_root: root,
        worktree_path: canonical_worktree,
        branch,
    })
}

pub async fn remove_worktree(
    repository_root: &Path,
    worktree_path: &Path,
) -> Result<(), RemediationError> {
    let root =
        fs::canonicalize(repository_root).map_err(|_| RemediationError::InvalidRepository)?;
    let worktree =
        fs::canonicalize(worktree_path).map_err(|_| RemediationError::WorktreePathInvalid)?;
    run_git_command(
        &[
            "-C",
            path_arg(&root)?,
            "worktree",
            "remove",
            "--force",
            path_arg(&worktree)?,
        ],
        Duration::from_secs(60),
        MAX_TEST_OUTPUT_BYTES,
    )
    .await?;
    Ok(())
}

pub async fn worktree_diff(worktree_path: &Path) -> Result<WorktreeDiff, RemediationError> {
    let worktree =
        fs::canonicalize(worktree_path).map_err(|_| RemediationError::WorktreePathInvalid)?;
    if !worktree.is_dir() || contains_symlink(&worktree)? {
        return Err(RemediationError::WorktreePathInvalid);
    }
    let git_dir_output = run_git_command(
        &[
            "-C",
            path_arg(&worktree)?,
            "rev-parse",
            "--absolute-git-dir",
        ],
        Duration::from_secs(15),
        MAX_TEST_OUTPUT_BYTES,
    )
    .await?;
    let git_dir = fs::canonicalize(String::from_utf8_lossy(&git_dir_output.0).trim())
        .map_err(|_| RemediationError::WorktreePathInvalid)?;
    if has_git_filter_attributes(&worktree, &git_dir)? {
        return Err(RemediationError::GitFiltersNotAllowed);
    }
    let diff = run_git_command(
        &[
            "-C",
            path_arg(&worktree)?,
            "diff",
            "--binary",
            "--no-ext-diff",
            "--no-textconv",
            "HEAD",
        ],
        Duration::from_secs(30),
        MAX_AGENT_OUTPUT_BYTES,
    )
    .await?;
    if diff.1 {
        return Err(RemediationError::WorktreePathInvalid);
    }
    let untracked = run_git_command(
        &["-C", path_arg(&worktree)?, "ls-files", "--others", "-z"],
        Duration::from_secs(30),
        MAX_AGENT_OUTPUT_BYTES,
    )
    .await?;
    if untracked.1 {
        return Err(RemediationError::WorktreePathInvalid);
    }
    let mut hash = Sha256::new();
    hash.update(&diff.0);
    let mut untracked_count = 0usize;
    let mut untracked_bytes = 0usize;
    for path_bytes in untracked
        .0
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let relative = path_from_git_bytes(path_bytes)?;
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(RemediationError::WorktreePathInvalid);
        }
        let file_path = worktree.join(&relative);
        let metadata =
            fs::symlink_metadata(&file_path).map_err(|_| RemediationError::FilesystemFailed)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(RemediationError::WorktreePathInvalid);
        }
        let canonical =
            fs::canonicalize(&file_path).map_err(|_| RemediationError::WorktreePathInvalid)?;
        if !canonical.starts_with(&worktree) {
            return Err(RemediationError::WorktreePathInvalid);
        }
        untracked_bytes = untracked_bytes.saturating_add(metadata.len() as usize);
        if untracked_bytes > MAX_AGENT_OUTPUT_BYTES {
            return Err(RemediationError::WorktreePathInvalid);
        }
        let contents = fs::read(&canonical).map_err(|_| RemediationError::FilesystemFailed)?;
        hash.update((path_bytes.len() as u64).to_le_bytes());
        hash.update(path_bytes);
        hash.update((contents.len() as u64).to_le_bytes());
        hash.update(contents);
        untracked_count = untracked_count.saturating_add(1);
        if untracked_count > MAX_WORKTREE_ENTRIES {
            return Err(RemediationError::WorktreePathInvalid);
        }
    }
    Ok(WorktreeDiff {
        sha256: format!("{:x}", hash.finalize()),
        has_changes: !diff.0.is_empty() || untracked_count > 0,
    })
}

fn path_from_git_bytes(bytes: &[u8]) -> Result<PathBuf, RemediationError> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
    }
    #[cfg(windows)]
    {
        let path = std::str::from_utf8(bytes).map_err(|_| RemediationError::WorktreePathInvalid)?;
        Ok(PathBuf::from(path))
    }
}

fn has_git_filter_attributes(root: &Path, git_dir: &Path) -> Result<bool, RemediationError> {
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).map_err(|_| RemediationError::FilesystemFailed)? {
            visited = visited.saturating_add(1);
            if visited > MAX_WORKTREE_ENTRIES {
                return Err(RemediationError::WorktreePathInvalid);
            }
            let entry = entry.map_err(|_| RemediationError::FilesystemFailed)?;
            let file_type = entry
                .file_type()
                .map_err(|_| RemediationError::FilesystemFailed)?;
            if file_type.is_symlink() {
                return Err(RemediationError::WorktreePathInvalid);
            }
            if file_type.is_dir() {
                if entry.file_name() != ".git" {
                    pending.push(entry.path());
                }
            } else if entry.file_name() == ".gitattributes"
                && file_has_filter_attribute(&entry.path())?
            {
                return Ok(true);
            }
        }
    }
    let info_attributes = git_dir.join("info").join("attributes");
    if info_attributes.exists() && file_has_filter_attribute(&info_attributes)? {
        return Ok(true);
    }
    Ok(false)
}

fn file_has_filter_attribute(path: &Path) -> Result<bool, RemediationError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RemediationError::FilesystemFailed)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 1024 * 1024 {
        return Err(RemediationError::GitFiltersNotAllowed);
    }
    let contents = fs::read(path).map_err(|_| RemediationError::FilesystemFailed)?;
    for line in contents.split(|byte| *byte == b'\n') {
        let line = line.trim_ascii();
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        let mut fields = line
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty());
        let _pattern = fields.next();
        if fields.any(|field| {
            let field = field
                .strip_prefix(b"!")
                .or_else(|| field.strip_prefix(b"-"))
                .unwrap_or(field);
            field.split(|byte| *byte == b'=').next() == Some(b"filter".as_slice())
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn canonical_worktrees_directory(
    app_data_dir: &Path,
) -> Result<PathBuf, RemediationError> {
    fs::create_dir_all(app_data_dir).map_err(|_| RemediationError::FilesystemFailed)?;
    let canonical_data =
        fs::canonicalize(app_data_dir).map_err(|_| RemediationError::FilesystemFailed)?;
    let directory = canonical_data.join("worktrees");
    fs::create_dir_all(&directory).map_err(|_| RemediationError::FilesystemFailed)?;
    let canonical_directory =
        fs::canonicalize(directory).map_err(|_| RemediationError::FilesystemFailed)?;
    if !canonical_directory.starts_with(&canonical_data) {
        return Err(RemediationError::WorktreePathInvalid);
    }
    Ok(canonical_directory)
}
