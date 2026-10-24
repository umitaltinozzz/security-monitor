use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use security_monitor_inventory::{InventoryError, scan_repository};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectCandidate {
    pub name: String,
    pub root_path: PathBuf,
    pub component_count: usize,
    pub inventory_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectDiscovery {
    pub parent: PathBuf,
    pub candidates: Vec<ProjectCandidate>,
    pub diagnostics: usize,
    pub complete: bool,
}

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("selected directory cannot be accessed")]
    InvalidRoot,
    #[error("project discovery failed")]
    Inventory(#[from] InventoryError),
}

/// Returns project roots for review. Discovery never writes projects to the database.
pub fn discover_projects(parent: impl AsRef<Path>) -> Result<ProjectDiscovery, DiscoveryError> {
    let parent = fs::canonicalize(parent.as_ref()).map_err(|_| DiscoveryError::InvalidRoot)?;
    if !parent.is_dir() {
        return Err(DiscoveryError::InvalidRoot);
    }
    let inventory = scan_repository(&parent)?;
    let relative_roots = inventory
        .project_roots
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut candidates = Vec::new();
    for relative in relative_roots {
        let candidate_path = if relative.is_empty() {
            parent.clone()
        } else {
            parent.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR))
        };
        let canonical = candidate_path
            .canonicalize()
            .map_err(|_| DiscoveryError::InvalidRoot)?;
        if !canonical.starts_with(&parent) || !canonical.is_dir() {
            return Err(DiscoveryError::InvalidRoot);
        }
        let name = canonical
            .file_name()
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty())
            .unwrap_or("project")
            .to_owned();
        let relative_component_prefix = relative.trim_end_matches('/');
        let component_count = inventory
            .components
            .iter()
            .filter(|component| {
                component.evidence_paths.iter().any(|path| {
                    path == relative_component_prefix
                        || (relative_component_prefix.is_empty() && !path.contains('/'))
                        || path.starts_with(&format!("{relative_component_prefix}/"))
                })
            })
            .count();
        candidates.push(ProjectCandidate {
            name,
            root_path: canonical,
            component_count,
            inventory_complete: inventory.complete,
        });
    }
    candidates.sort_by(|left, right| left.root_path.cmp(&right.root_path));
    Ok(ProjectDiscovery {
        parent,
        candidates,
        diagnostics: inventory.diagnostics.len(),
        complete: inventory.complete,
    })
}
