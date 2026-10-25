use super::*;

pub(crate) fn collect_dependency_inventory(
    allowed_roots: &[PathBuf],
    configuration_unavailable: bool,
) -> impl std::future::Future<Output = DependencyCollection> {
    let roots = allowed_roots.to_vec();
    async move {
        if roots.is_empty() {
            return DependencyCollection {
                records: Vec::new(),
                check: check(
                    CheckKind::DependencyFiles,
                    CheckStatus::Partial,
                    if configuration_unavailable {
                        DiagnosticCode::ConfigurationUnavailable
                    } else {
                        DiagnosticCode::NoAllowlistedPaths
                    },
                    0,
                ),
            };
        }
        let mut records = Vec::new();
        let mut partial = false;
        for root in roots {
            if !preflight_root(&root) {
                partial = true;
                continue;
            }
            let scan_root = root.clone();
            let inventory = task::spawn_blocking(move || scan_repository(scan_root)).await;
            let Ok(Ok(inventory)) = inventory else {
                partial = true;
                continue;
            };
            partial |= !inventory.complete;
            for component in inventory
                .components
                .into_iter()
                .take(MAX_PACKAGE_RECORDS.saturating_sub(records.len()))
            {
                let evidence_path = component
                    .evidence_paths
                    .iter()
                    .find(|path| safe_relative_evidence(path))
                    .cloned();
                records.push(PackageRecord {
                    name: component.name,
                    version: component.version,
                    architecture: None,
                    ecosystem: component.ecosystem,
                    purl: Some(component.purl),
                    source: PackageSource::Lockfile,
                    evidence_path,
                });
            }
            if records.len() >= MAX_PACKAGE_RECORDS {
                partial = true;
                break;
            }
        }
        let count = records.len();
        DependencyCollection {
            records,
            check: check(
                CheckKind::DependencyFiles,
                if partial {
                    CheckStatus::Partial
                } else {
                    CheckStatus::Complete
                },
                if partial {
                    DiagnosticCode::LimitReached
                } else {
                    DiagnosticCode::NoAllowlistedPaths
                },
                count,
            ),
        }
    }
}

pub(super) struct DependencyCollection {
    pub(super) records: Vec<PackageRecord>,
    pub(super) check: CollectionCheck,
}

fn preflight_root(root: &Path) -> bool {
    let Ok(canonical_root) = root.canonicalize() else {
        return false;
    };
    let mut stack = vec![(canonical_root.clone(), 0usize)];
    let mut file_count = 0usize;
    let mut total_bytes = 0u64;
    while let Some((directory, depth)) = stack.pop() {
        if depth > MAX_ROOT_SCAN_DEPTH {
            return false;
        }
        let Ok(entries) = fs::read_dir(directory) else {
            return false;
        };
        for entry in entries {
            file_count += 1;
            if file_count > MAX_ROOT_SCAN_FILES {
                return false;
            }
            let Ok(entry) = entry else { return false };
            let Ok(metadata) = fs::symlink_metadata(entry.path()) else {
                return false;
            };
            if metadata.file_type().is_symlink() {
                return false;
            }
            if metadata.is_dir() {
                if matches!(
                    entry.file_name().to_str(),
                    Some(".git" | "node_modules" | "vendor" | "target" | "dist")
                ) {
                    continue;
                }
                stack.push((entry.path(), depth + 1));
            } else if metadata.is_file() {
                total_bytes = total_bytes.saturating_add(metadata.len());
                if total_bytes > MAX_ROOT_SCAN_BYTES {
                    return false;
                }
            }
        }
    }
    canonical_root.is_dir()
}

fn safe_relative_evidence(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}
