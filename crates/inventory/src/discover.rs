use crate::{
    model::{
        DetectedFile, DetectedFileKind, Diagnostic, DiagnosticKind, Inventory, InventoryComponent,
    },
    parsers::{
        ParsedPackage, parse_editable_requirement, parse_lockfile, parse_requirement_line,
        requirement_include, requirement_is_ignored_option,
    },
    purl::package_url,
};
use security_monitor_bounded_reader::read_bounded_text;
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    path::{Component, Path, PathBuf},
};
use thiserror::Error;

const MAX_INVENTORY_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("repository root cannot be accessed")]
    RootUnavailable,
    #[error("repository root is not a directory")]
    RootNotDirectory,
}

#[derive(Default)]
struct ScanState {
    files: Vec<(PathBuf, PathBuf)>,
    diagnostics: Vec<Diagnostic>,
}

pub fn scan_repository(root: impl AsRef<Path>) -> Result<Inventory, InventoryError> {
    let root = fs::canonicalize(root.as_ref()).map_err(|_| InventoryError::RootUnavailable)?;
    if !root.is_dir() {
        return Err(InventoryError::RootNotDirectory);
    }

    let mut state = ScanState::default();
    discover_files(&root, &mut state);
    state.files.sort_by(|left, right| left.1.cmp(&right.1));

    let mut components = BTreeMap::<String, InventoryComponent>::new();
    let mut roots = BTreeMap::<String, ()>::new();
    let mut detected = Vec::new();
    let mut visited_requirements = HashSet::new();

    for (path, relative) in &state.files {
        let relative_text = display_relative(relative);
        if let Some(kind) = detected_file_kind(relative) {
            detected.push(DetectedFile {
                path: relative_text.clone(),
                kind,
            });
        }

        let Some(filename) = relative.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if is_requirements_filename(filename) {
            let canonical = match path.canonicalize() {
                Ok(path) if path.starts_with(&root) => path,
                Ok(_) => {
                    state.diagnostics.push(Diagnostic {
                        path: relative_text,
                        kind: DiagnosticKind::SymlinkOutsideRoot,
                    });
                    continue;
                }
                Err(_) => {
                    state.diagnostics.push(Diagnostic {
                        path: relative_text,
                        kind: DiagnosticKind::InvalidPath,
                    });
                    continue;
                }
            };
            roots.insert(
                display_relative(relative.parent().unwrap_or_else(|| Path::new(""))),
                (),
            );
            parse_requirements_file(
                &root,
                &canonical,
                relative,
                &mut visited_requirements,
                &mut components,
                &mut state.diagnostics,
            );
            continue;
        }

        let Some(file_format) = lockfile_format(filename) else {
            continue;
        };
        roots.insert(
            display_relative(relative.parent().unwrap_or_else(|| Path::new(""))),
            (),
        );
        let canonical = match path.canonicalize() {
            Ok(path) if path.starts_with(&root) => path,
            Ok(_) => {
                state.diagnostics.push(Diagnostic {
                    path: relative_text,
                    kind: DiagnosticKind::SymlinkOutsideRoot,
                });
                continue;
            }
            Err(_) => {
                state.diagnostics.push(Diagnostic {
                    path: relative_text,
                    kind: DiagnosticKind::InvalidPath,
                });
                continue;
            }
        };
        let contents = match read_bounded_text(&canonical, MAX_INVENTORY_FILE_BYTES) {
            Ok(contents) => contents,
            Err(_) => {
                state.diagnostics.push(Diagnostic {
                    path: relative_text,
                    kind: DiagnosticKind::UnreadableFile,
                });
                continue;
            }
        };
        match parse_lockfile(file_format, &contents) {
            Ok(packages) => add_packages(
                packages,
                &relative_text,
                &mut components,
                &mut state.diagnostics,
            ),
            Err(_) => state.diagnostics.push(Diagnostic {
                path: relative_text,
                kind: DiagnosticKind::MalformedLockfile,
            }),
        }
    }

    let mut components = components.into_values().collect::<Vec<_>>();
    components.sort_by(|left, right| left.purl.cmp(&right.purl));
    for component in &mut components {
        component.evidence_paths.sort();
        component.evidence_paths.dedup();
    }
    detected.sort_by(|left, right| left.path.cmp(&right.path));
    state
        .diagnostics
        .sort_by_key(|diagnostic| (diagnostic.path.clone(), format!("{:?}", diagnostic.kind)));
    state.diagnostics.dedup();

    Ok(Inventory {
        components,
        project_roots: roots.into_keys().collect(),
        detected_files: detected,
        complete: state.diagnostics.is_empty(),
        diagnostics: state.diagnostics,
    })
}

fn discover_files(root: &Path, state: &mut ScanState) {
    let mut pending = vec![(root.to_owned(), PathBuf::new())];
    let mut visited_directories = HashSet::from([root.to_owned()]);

    while let Some((directory, relative_directory)) = pending.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(_) => {
                state.diagnostics.push(Diagnostic {
                    path: display_relative(&relative_directory),
                    kind: DiagnosticKind::UnreadableDirectory,
                });
                continue;
            }
        };
        let mut directory_entries = Vec::new();
        for result in entries {
            match result {
                Ok(entry) => directory_entries.push(entry),
                Err(_) => state.diagnostics.push(Diagnostic {
                    path: display_relative(&relative_directory),
                    kind: DiagnosticKind::UnreadableDirectory,
                }),
            }
        }
        let mut entries = directory_entries;
        entries.sort_by_key(|entry| entry.file_name());

        for entry in entries {
            let name = entry.file_name();
            let relative = relative_directory.join(&name);
            if is_pruned_directory_name(&name) {
                continue;
            }
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => {
                    state.diagnostics.push(Diagnostic {
                        path: display_relative(&relative),
                        kind: DiagnosticKind::InvalidPath,
                    });
                    continue;
                }
            };
            let candidate = if file_type.is_symlink() {
                match entry.path().canonicalize() {
                    Ok(canonical) if canonical.starts_with(root) => canonical,
                    Ok(_) => {
                        state.diagnostics.push(Diagnostic {
                            path: display_relative(&relative),
                            kind: DiagnosticKind::SymlinkOutsideRoot,
                        });
                        continue;
                    }
                    Err(_) => {
                        state.diagnostics.push(Diagnostic {
                            path: display_relative(&relative),
                            kind: DiagnosticKind::InvalidPath,
                        });
                        continue;
                    }
                }
            } else {
                entry.path()
            };

            let metadata = match fs::metadata(&candidate) {
                Ok(metadata) => metadata,
                Err(_) => {
                    state.diagnostics.push(Diagnostic {
                        path: display_relative(&relative),
                        kind: DiagnosticKind::InvalidPath,
                    });
                    continue;
                }
            };
            if metadata.is_dir() {
                let canonical = match candidate.canonicalize() {
                    Ok(canonical) if canonical.starts_with(root) => canonical,
                    Ok(_) => {
                        state.diagnostics.push(Diagnostic {
                            path: display_relative(&relative),
                            kind: DiagnosticKind::SymlinkOutsideRoot,
                        });
                        continue;
                    }
                    Err(_) => {
                        state.diagnostics.push(Diagnostic {
                            path: display_relative(&relative),
                            kind: DiagnosticKind::InvalidPath,
                        });
                        continue;
                    }
                };
                if visited_directories.insert(canonical.clone()) {
                    pending.push((canonical, relative));
                }
            } else if metadata.is_file() {
                state.files.push((candidate, relative));
            }
        }
    }
}

fn parse_requirements_file(
    root: &Path,
    canonical_file: &Path,
    relative_file: &Path,
    visited: &mut HashSet<PathBuf>,
    components: &mut BTreeMap<String, InventoryComponent>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !visited.insert(canonical_file.to_owned()) {
        return;
    }
    if !canonical_file.starts_with(root) {
        diagnostics.push(Diagnostic {
            path: display_relative(relative_file),
            kind: DiagnosticKind::SymlinkOutsideRoot,
        });
        return;
    }
    let contents = match read_bounded_text(canonical_file, MAX_INVENTORY_FILE_BYTES) {
        Ok(contents) => contents,
        Err(_) => {
            diagnostics.push(Diagnostic {
                path: display_relative(relative_file),
                kind: DiagnosticKind::UnreadableFile,
            });
            return;
        }
    };

    for line in logical_requirement_lines(&contents) {
        if let Some((target, is_constraint)) = requirement_include(&line) {
            if is_constraint {
                continue;
            }
            if target.starts_with("https://") || target.starts_with("http://") {
                diagnostics.push(Diagnostic {
                    path: display_relative(relative_file),
                    kind: DiagnosticKind::UnsupportedRequirement,
                });
                continue;
            }
            let target = target.trim_matches(['\'', '"']);
            let candidate = canonical_file.parent().unwrap_or(root).join(target);
            match candidate.canonicalize() {
                Ok(included) if included.starts_with(root) && included.is_file() => {
                    let relative = included
                        .strip_prefix(root)
                        .map(Path::to_owned)
                        .unwrap_or_else(|_| relative_file.to_owned());
                    parse_requirements_file(
                        root,
                        &included,
                        &relative,
                        visited,
                        components,
                        diagnostics,
                    );
                }
                Ok(_) => diagnostics.push(Diagnostic {
                    path: display_relative(relative_file),
                    kind: DiagnosticKind::SymlinkOutsideRoot,
                }),
                Err(_) => diagnostics.push(Diagnostic {
                    path: display_relative(relative_file),
                    kind: DiagnosticKind::InvalidPath,
                }),
            }
            continue;
        }
        if requirement_is_ignored_option(&line) {
            continue;
        }
        if line.trim_start().starts_with('-') {
            if let Some(package) = parse_editable_requirement(&line) {
                add_packages(
                    vec![package],
                    &display_relative(relative_file),
                    components,
                    diagnostics,
                );
            } else {
                diagnostics.push(Diagnostic {
                    path: display_relative(relative_file),
                    kind: DiagnosticKind::UnsupportedRequirement,
                });
            }
            continue;
        }
        match parse_requirement_line(&line) {
            Ok(Some(package)) => add_packages(
                vec![package],
                &display_relative(relative_file),
                components,
                diagnostics,
            ),
            Ok(None) => {}
            Err(_) => diagnostics.push(Diagnostic {
                path: display_relative(relative_file),
                kind: DiagnosticKind::UnsupportedRequirement,
            }),
        }
    }
}

fn logical_requirement_lines(contents: &str) -> Vec<String> {
    let mut logical = Vec::new();
    let mut current = String::new();
    for line in contents.lines() {
        let line = line.trim_end();
        if let Some(without_slash) = line.strip_suffix('\\') {
            current.push_str(without_slash.trim_end());
            current.push(' ');
        } else if current.is_empty() {
            logical.push(line.to_owned());
        } else {
            current.push_str(line.trim_start());
            logical.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        current.push('\\');
        logical.push(current);
    }
    logical
}

fn add_packages(
    packages: Vec<ParsedPackage>,
    relative_path: &str,
    components: &mut BTreeMap<String, InventoryComponent>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for package in packages {
        let purl = match package_url(package.ecosystem, &package.name, package.version.as_deref()) {
            Ok(purl) => purl,
            Err(_) => {
                diagnostics.push(Diagnostic {
                    path: relative_path.to_owned(),
                    kind: DiagnosticKind::InvalidPackageIdentifier,
                });
                continue;
            }
        };
        components
            .entry(purl.clone())
            .and_modify(|component| {
                component.evidence_paths.push(relative_path.to_owned());
                if package.source_type == "lockfile" {
                    component.source_type = "lockfile".to_owned();
                }
            })
            .or_insert_with(|| InventoryComponent {
                purl,
                ecosystem: package.ecosystem.as_str().to_owned(),
                name: package.name,
                version: package.version,
                source_type: package.source_type.to_owned(),
                evidence_paths: vec![relative_path.to_owned()],
            });
    }
}

fn lockfile_format(filename: &str) -> Option<&'static str> {
    match filename {
        "package-lock.json" => Some("package-lock.json"),
        "pnpm-lock.yaml" => Some("pnpm-lock.yaml"),
        "yarn.lock" => Some("yarn.lock"),
        "bun.lock" => Some("bun.lock"),
        "poetry.lock" => Some("poetry.lock"),
        "uv.lock" => Some("uv.lock"),
        "Pipfile.lock" => Some("Pipfile.lock"),
        "composer.lock" => Some("composer.lock"),
        "go.sum" => Some("go.sum"),
        "go.mod" => Some("go.mod"),
        "Cargo.lock" => Some("Cargo.lock"),
        _ => None,
    }
}

fn is_requirements_filename(filename: &str) -> bool {
    filename.starts_with("requirements")
        && Path::new(filename)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("txt"))
}

fn detected_file_kind(relative: &Path) -> Option<DetectedFileKind> {
    let name = relative.file_name()?.to_str()?;
    if name == "Dockerfile" || name.starts_with("Dockerfile.") {
        return Some(DetectedFileKind::Dockerfile);
    }
    let components = relative.components().collect::<Vec<_>>();
    let workflow_directory = components.windows(2).any(|pair| {
        pair[0] == Component::Normal(".github".as_ref())
            && pair[1] == Component::Normal("workflows".as_ref())
    });
    if workflow_directory
        && Path::new(name)
            .extension()
            .is_some_and(|extension| extension == "yml" || extension == "yaml")
    {
        Some(DetectedFileKind::GithubWorkflow)
    } else {
        None
    }
}

fn is_pruned_directory_name(name: &std::ffi::OsStr) -> bool {
    matches!(
        name.to_str(),
        Some(
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
    )
}

fn display_relative(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}
