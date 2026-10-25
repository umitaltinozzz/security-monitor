use super::*;

pub(super) struct PackageCollection {
    pub(super) records: Vec<PackageRecord>,
    pub(super) check: CollectionCheck,
}

pub(super) async fn collect_os_packages(os: Option<&OperatingSystem>) -> PackageCollection {
    let Some((command, ecosystem, source)) = package_command_for_os(os) else {
        return PackageCollection {
            records: Vec::new(),
            check: check(
                CheckKind::PackageInventory,
                CheckStatus::Unavailable,
                DiagnosticCode::UnsupportedPlatform,
                0,
            ),
        };
    };
    match run_allowlisted(&command).await {
        Ok(output) => {
            let ecosystem = package_ecosystem(os, ecosystem);
            let parsed = parse_package_output(&output.stdout, &ecosystem, source);
            let status = if parsed.partial {
                CheckStatus::Partial
            } else {
                CheckStatus::Complete
            };
            PackageCollection {
                check: check(
                    CheckKind::PackageInventory,
                    status,
                    parsed.diagnostic,
                    parsed.records.len(),
                ),
                records: parsed.records,
            }
        }
        Err(error) => PackageCollection {
            records: Vec::new(),
            check: check(
                CheckKind::PackageInventory,
                CheckStatus::Unavailable,
                command_diagnostic(error),
                0,
            ),
        },
    }
}

pub(super) fn package_ecosystem(os: Option<&OperatingSystem>, fallback: &str) -> String {
    os.and_then(osv_os_package_ecosystem)
        .unwrap_or_else(|| fallback.to_owned())
}

pub(super) fn package_command_for_os(
    os: Option<&OperatingSystem>,
) -> Option<(HostCommand, &'static str, PackageSource)> {
    match os.and_then(|os| os.id.as_deref()) {
        Some("debian" | "ubuntu" | "linuxmint" | "raspbian") => {
            Some((HostCommand::DpkgPackages, "deb", PackageSource::Dpkg))
        }
        Some("alpine") => Some((HostCommand::ApkPackages, "apk", PackageSource::Apk)),
        Some("fedora" | "rhel" | "centos" | "rocky" | "almalinux" | "ol") => {
            Some((HostCommand::RpmPackages, "rpm", PackageSource::Rpm))
        }
        _ => None,
    }
}

pub(super) struct ManualCollection {
    pub(super) records: Vec<PackageRecord>,
    pub(super) partial: bool,
}

#[cfg(target_os = "linux")]
pub(super) fn collect_manual_binaries() -> ManualCollection {
    collect_manual_binaries_at([Path::new("/opt"), Path::new("/usr/local")])
}

#[cfg(target_os = "linux")]
pub(super) fn collect_manual_binaries_at(roots: [&Path; 2]) -> ManualCollection {
    use std::os::unix::fs::PermissionsExt;

    const MAX_ENTRIES: usize = 50_000;
    const MAX_DEPTH: usize = 16;
    let allowed_roots = roots
        .into_iter()
        .filter_map(|root| root.canonicalize().ok())
        .collect::<Vec<_>>();
    let mut records = BTreeMap::<String, PackageRecord>::new();
    let mut partial = allowed_roots.len() != 2;
    let mut visited = 0usize;
    for canonical_root in allowed_roots {
        let mut stack = vec![(canonical_root.clone(), 0usize)];
        while let Some((directory, depth)) = stack.pop() {
            if depth > MAX_DEPTH {
                partial = true;
                continue;
            }
            let entries = match fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(_) => {
                    partial = true;
                    continue;
                }
            };
            for entry in entries {
                visited += 1;
                if visited > MAX_ENTRIES {
                    partial = true;
                    break;
                }
                let Ok(entry) = entry else {
                    partial = true;
                    continue;
                };
                let Ok(file_type) = entry.file_type() else {
                    partial = true;
                    continue;
                };
                if file_type.is_symlink() {
                    continue;
                }
                let path = entry.path();
                let Ok(canonical_path) = path.canonicalize() else {
                    partial = true;
                    continue;
                };
                if !canonical_path.starts_with(&canonical_root) {
                    partial = true;
                    continue;
                }
                if file_type.is_dir() {
                    if matches!(entry.file_name().to_str(), Some(".git" | "cache" | "share")) {
                        continue;
                    }
                    stack.push((canonical_path, depth + 1));
                    continue;
                }
                if !file_type.is_file() {
                    continue;
                }
                let Ok(metadata) = fs::metadata(&canonical_path) else {
                    partial = true;
                    continue;
                };
                if metadata.permissions().mode() & 0o111 == 0 {
                    continue;
                }
                let Some(filename) = canonical_path.file_name().and_then(|name| name.to_str())
                else {
                    continue;
                };
                let Some(product) = manual_product_name(filename) else {
                    continue;
                };
                records
                    .entry(product.to_owned())
                    .or_insert_with(|| PackageRecord {
                        name: product.to_owned(),
                        version: None,
                        architecture: None,
                        ecosystem: "unknown".to_owned(),
                        purl: None,
                        source: PackageSource::Manual,
                        evidence_path: None,
                    });
            }
            if visited > MAX_ENTRIES {
                break;
            }
        }
        if visited > MAX_ENTRIES {
            break;
        }
    }
    ManualCollection {
        records: records.into_values().collect(),
        partial,
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn collect_manual_binaries() -> ManualCollection {
    ManualCollection {
        records: Vec::new(),
        partial: false,
    }
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn manual_product_name(filename: &str) -> Option<&'static str> {
    match filename {
        "nginx" => Some("nginx"),
        "node" => Some("nodejs"),
        "php" => Some("php"),
        "python" | "python3" => Some("python"),
        "redis-server" => Some("redis"),
        "postgres" => Some("postgresql"),
        "mysqld" => Some("mysql"),
        "openssl" => Some("openssl"),
        _ => None,
    }
}

pub(super) fn newest_installed_kernel(packages: &[PackageRecord]) -> Option<String> {
    let mut candidates = BTreeMap::<Vec<u64>, BTreeSet<String>>::new();
    for package in packages {
        let Some(candidate) = (if let Some(release) = package.name.strip_prefix("linux-image-") {
            Some(release)
        } else if matches!(
            package.name.as_str(),
            "kernel-core" | "kernel" | "linux-lts"
        ) {
            package.version.as_deref()
        } else {
            None
        }) else {
            continue;
        };
        if let Some(key) = numeric_release_key(candidate) {
            candidates
                .entry(key)
                .or_default()
                .insert(candidate.to_owned());
        }
    }
    let (_, releases) = candidates.last_key_value()?;
    if releases.len() == 1 {
        releases.first().cloned()
    } else {
        None
    }
}

pub(super) fn kernel_restart_required(running: &str, installed: &str) -> Option<bool> {
    let running_key = numeric_release_key(running)?;
    let installed_key = numeric_release_key(installed)?;
    match installed_key.cmp(&running_key) {
        std::cmp::Ordering::Greater => Some(true),
        std::cmp::Ordering::Less => Some(false),
        std::cmp::Ordering::Equal if installed == running => Some(false),
        std::cmp::Ordering::Equal => None,
    }
}

fn numeric_release_key(value: &str) -> Option<Vec<u64>> {
    if value
        .as_bytes()
        .first()
        .is_none_or(|byte| !byte.is_ascii_digit())
    {
        return None;
    }
    let mut numbers = Vec::new();
    let mut current = String::new();
    for character in value.chars() {
        if character.is_ascii_digit() {
            current.push(character);
        } else if !current.is_empty() {
            numbers.push(current.parse().ok()?);
            current.clear();
        }
    }
    if !current.is_empty() {
        numbers.push(current.parse().ok()?);
    }
    (!numbers.is_empty()).then_some(numbers)
}
