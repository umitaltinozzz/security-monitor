use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedPath(String);

impl RedactedPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

#[derive(Debug, Error)]
pub enum PathRedactionError {
    #[error("the project root could not be resolved")]
    ProjectRoot(#[source] std::io::Error),
    #[error("the observed path could not be resolved")]
    ObservedPath(#[source] std::io::Error),
    #[error("the observed path is outside the project")]
    OutsideProject,
}

pub fn redact_project_path(
    project_root: &Path,
    observed_path: &Path,
) -> Result<RedactedPath, PathRedactionError> {
    let canonical_root = canonicalize(project_root).map_err(PathRedactionError::ProjectRoot)?;
    let canonical_path = canonicalize(observed_path).map_err(PathRedactionError::ObservedPath)?;
    let relative = canonical_path
        .strip_prefix(&canonical_root)
        .map_err(|_| PathRedactionError::OutsideProject)?;

    if relative.as_os_str().is_empty() {
        return Ok(RedactedPath("<project>".to_owned()));
    }

    let relative = relative.to_string_lossy().replace('\\', "/");
    Ok(RedactedPath(format!("<project>/{relative}")))
}

fn canonicalize(path: &Path) -> std::io::Result<PathBuf> {
    path.canonicalize()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{PathRedactionError, redact_project_path};

    #[test]
    fn redacts_paths_inside_project_after_canonicalization() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}").unwrap();

        let redacted = redact_project_path(&root, &root.join("src/main.rs")).unwrap();

        assert_eq!(redacted.as_str(), "<project>/src/main.rs");
    }

    #[test]
    fn rejects_paths_outside_project() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        let outside = temp.path().join("outside.txt");
        fs::create_dir_all(&root).unwrap();
        fs::write(&outside, "private").unwrap();

        let error = redact_project_path(&root, &outside).unwrap_err();

        assert!(matches!(error, PathRedactionError::OutsideProject));
        assert_eq!(
            error.to_string(),
            "the observed path is outside the project"
        );
    }
}
