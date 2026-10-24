use crate::purl::PackageEcosystem;
use cargo_lock::Lockfile as CargoLockfile;
use pep508_rs::{Requirement, VerbatimUrl, VersionOrUrl};
use serde_json::Value as JsonValue;
use serde_yaml_ng::Value as YamlValue;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedPackage {
    pub(crate) ecosystem: PackageEcosystem,
    pub(crate) name: String,
    pub(crate) version: Option<String>,
    pub(crate) source_type: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ParseFailure;

pub(crate) fn parse_lockfile(
    filename: &str,
    contents: &str,
) -> Result<Vec<ParsedPackage>, ParseFailure> {
    match filename {
        "package-lock.json" => parse_package_lock(contents),
        "pnpm-lock.yaml" => parse_pnpm_lock(contents),
        "yarn.lock" => parse_yarn_lock(contents),
        "bun.lock" => parse_bun_lock(contents),
        "poetry.lock" => parse_poetry_lock(contents),
        "uv.lock" => parse_uv_lock(contents),
        "Pipfile.lock" => parse_pipfile_lock(contents),
        "composer.lock" => parse_composer_lock(contents),
        "go.sum" => parse_go_sum(contents),
        "go.mod" => parse_go_mod(contents),
        "Cargo.lock" => parse_cargo_lock(contents),
        _ => Err(ParseFailure),
    }
}

pub(crate) fn parse_requirement_line(line: &str) -> Result<Option<ParsedPackage>, ParseFailure> {
    let line = strip_requirement_comment(line).trim();
    if line.is_empty() || line.starts_with('-') {
        return Ok(None);
    }
    let line = strip_hash_options(line);
    if line.is_empty() {
        return Ok(None);
    }
    let requirement = Requirement::<VerbatimUrl>::from_str(line).map_err(|_| ParseFailure)?;
    let version = requirement
        .version_or_url
        .as_ref()
        .and_then(|specifier| match specifier {
            VersionOrUrl::VersionSpecifier(specifiers) => {
                exact_python_version(&specifiers.to_string())
            }
            VersionOrUrl::Url(_) => None,
        });
    Ok(Some(ParsedPackage {
        ecosystem: PackageEcosystem::Pypi,
        name: requirement.name.to_string(),
        version,
        source_type: "manifest",
    }))
}

pub(crate) fn parse_editable_requirement(line: &str) -> Option<ParsedPackage> {
    let line = line.trim();
    let value = line
        .strip_prefix("--editable")
        .or_else(|| line.strip_prefix("-e"))?
        .trim_start_matches(['=', ' ']);
    let egg = value.split_once("#egg=")?.1;
    let name = egg.split(['&', '#']).next()?.trim();
    (!name.is_empty()).then(|| ParsedPackage {
        ecosystem: PackageEcosystem::Pypi,
        name: name.to_owned(),
        version: None,
        source_type: "manifest",
    })
}

pub(crate) fn requirement_include(line: &str) -> Option<(&str, bool)> {
    let line = strip_requirement_comment(line).trim();
    for (prefix, is_constraint) in [
        ("-r", false),
        ("--requirement", false),
        ("-c", true),
        ("--constraint", true),
    ] {
        if let Some(value) = line.strip_prefix(prefix)
            && (value.is_empty() || value.chars().next().is_some_and(char::is_whitespace))
            && !value.trim().is_empty()
        {
            return Some((value.trim(), is_constraint));
        }
    }
    None
}

pub(crate) fn requirement_is_ignored_option(line: &str) -> bool {
    let trimmed = strip_requirement_comment(line).trim();
    trimmed.is_empty()
        || [
            "--index-url",
            "--extra-index-url",
            "--trusted-host",
            "--find-links",
            "--no-index",
            "--require-hashes",
            "--only-binary",
            "--no-binary",
        ]
        .iter()
        .any(|option| is_option(trimmed, option))
}

fn is_option(value: &str, option: &str) -> bool {
    value == option
        || value
            .strip_prefix(option)
            .is_some_and(|suffix| suffix.starts_with([' ', '=']))
}

fn parse_package_lock(contents: &str) -> Result<Vec<ParsedPackage>, ParseFailure> {
    let value: JsonValue = serde_json::from_str(contents).map_err(|_| ParseFailure)?;
    let root = value.as_object().ok_or(ParseFailure)?;
    let mut packages = Vec::new();
    if let Some(locked) = root.get("packages") {
        let entries = locked.as_object().ok_or(ParseFailure)?;
        for (path, item) in entries {
            if path.is_empty() || item.get("link").and_then(JsonValue::as_bool) == Some(true) {
                continue;
            }
            let Some(name) = item
                .get("name")
                .and_then(JsonValue::as_str)
                .or_else(|| npm_name_from_node_modules_path(path))
            else {
                continue;
            };
            let Some(version) = item.get("version").and_then(JsonValue::as_str) else {
                continue;
            };
            push_package(
                &mut packages,
                PackageEcosystem::Npm,
                name,
                Some(version),
                "lockfile",
            );
        }
    } else if let Some(dependencies) = root.get("dependencies") {
        parse_npm_v1_dependencies(dependencies, &mut packages)?;
    } else {
        return Err(ParseFailure);
    }
    Ok(packages)
}

fn parse_npm_v1_dependencies(
    value: &JsonValue,
    packages: &mut Vec<ParsedPackage>,
) -> Result<(), ParseFailure> {
    let dependencies = value.as_object().ok_or(ParseFailure)?;
    for (key, dependency) in dependencies {
        let item = dependency.as_object().ok_or(ParseFailure)?;
        if let Some(version) = item.get("version").and_then(JsonValue::as_str) {
            let name = item.get("name").and_then(JsonValue::as_str).unwrap_or(key);
            push_package(
                packages,
                PackageEcosystem::Npm,
                name,
                Some(version),
                "lockfile",
            );
        }
        if let Some(children) = item.get("dependencies") {
            parse_npm_v1_dependencies(children, packages)?;
        }
    }
    Ok(())
}

fn npm_name_from_node_modules_path(path: &str) -> Option<&str> {
    let suffix = path.rsplit_once("node_modules/")?.1;
    (!suffix.is_empty() && !suffix.contains("/node_modules/")).then_some(suffix)
}

fn parse_pnpm_lock(contents: &str) -> Result<Vec<ParsedPackage>, ParseFailure> {
    let value: YamlValue = serde_yaml_ng::from_str(contents).map_err(|_| ParseFailure)?;
    let mapping = value.as_mapping().ok_or(ParseFailure)?;
    let packages_key = YamlValue::String("packages".to_owned());
    let entries = mapping.get(&packages_key).and_then(YamlValue::as_mapping);
    let mut packages = Vec::new();
    if let Some(entries) = entries {
        for (key, item) in entries {
            let Some(locator) = key.as_str() else {
                continue;
            };
            let parsed = parse_pnpm_locator(locator).or_else(|| {
                let name = item.get("name")?.as_str()?;
                let version = item.get("version")?.as_str()?;
                Some((name.to_owned(), version.to_owned()))
            });
            if let Some((name, version)) = parsed {
                push_package(
                    &mut packages,
                    PackageEcosystem::Npm,
                    &name,
                    Some(&version),
                    "lockfile",
                );
            }
        }
    } else if mapping.contains_key(YamlValue::String("importers".to_owned())) {
        // Empty importers are valid for a workspace with no external packages.
    } else {
        return Err(ParseFailure);
    }
    Ok(packages)
}

fn parse_pnpm_locator(locator: &str) -> Option<(String, String)> {
    let locator = locator
        .trim_start_matches('/')
        .split('(')
        .next()
        .unwrap_or_default();
    let package_separator = if locator.starts_with('@') {
        locator.find('/').and_then(|slash| {
            locator[slash + 1..]
                .find('@')
                .map(|separator| slash + 1 + separator)
        })
    } else {
        locator.find('@')
    };
    if let Some(package_separator) = package_separator.filter(|separator| *separator > 0) {
        let name = &locator[..package_separator];
        let version = locator[package_separator + 1..]
            .split(['(', '_'])
            .next()
            .unwrap_or_default();
        if !name.is_empty() && !version.is_empty() {
            return Some((name.to_owned(), version.to_owned()));
        }
    }
    if locator.starts_with('@') {
        let mut parts = locator.splitn(3, '/');
        let scope = parts.next()?;
        let package = parts.next()?;
        let version = parts.next()?.split(['(', '_']).next()?;
        if !package.is_empty() && !version.is_empty() {
            return Some((format!("{scope}/{package}"), version.to_owned()));
        }
    } else {
        let (name, version) = locator.split_once('/')?;
        let version = version.split(['(', '_']).next()?;
        if !name.is_empty() && !version.is_empty() {
            return Some((name.to_owned(), version.to_owned()));
        }
    }
    None
}

fn parse_yarn_lock(contents: &str) -> Result<Vec<ParsedPackage>, ParseFailure> {
    let lockfile = yarn_lock_parser::parse_str(contents).map_err(|_| ParseFailure)?;
    Ok(lockfile
        .entries
        .into_iter()
        .filter(|entry| {
            !entry.name.is_empty() && !entry.version.is_empty() && !is_workspace_entry(entry)
        })
        .map(|entry| {
            let name = resolved_npm_name(entry.resolved).unwrap_or(entry.name);
            ParsedPackage {
                ecosystem: PackageEcosystem::Npm,
                name: name.to_owned(),
                version: Some(entry.version.to_owned()),
                source_type: "lockfile",
            }
        })
        .collect())
}

fn parse_bun_lock(contents: &str) -> Result<Vec<ParsedPackage>, ParseFailure> {
    if contents.trim_start().starts_with('{') {
        let value: JsonValue = serde_json::from_str(contents).map_err(|_| ParseFailure)?;
        let root = value.as_object().ok_or(ParseFailure)?;
        let workspace_key = if root.contains_key("workspaces") {
            "workspaces"
        } else if root.contains_key("packages") {
            "packages"
        } else {
            return Err(ParseFailure);
        };
        let entries = root
            .get(workspace_key)
            .and_then(JsonValue::as_object)
            .ok_or(ParseFailure)?;
        let mut packages = Vec::new();
        for (path, item) in entries {
            if !path.contains("node_modules/") {
                continue;
            }
            let Some(version) = item.get("version").and_then(JsonValue::as_str) else {
                continue;
            };
            let name = item
                .get("name")
                .and_then(JsonValue::as_str)
                .or_else(|| npm_name_from_node_modules_path(path));
            if let Some(name) = name {
                push_package(
                    &mut packages,
                    PackageEcosystem::Npm,
                    name,
                    Some(version),
                    "lockfile",
                );
            }
        }
        return Ok(packages);
    }
    let lockfile = yarn_lock_parser::parse_str(contents).map_err(|_| ParseFailure)?;
    if lockfile.generator != yarn_lock_parser::Generator::Bun {
        return Err(ParseFailure);
    }
    Ok(lockfile
        .entries
        .into_iter()
        .filter(|entry| {
            !entry.name.is_empty() && !entry.version.is_empty() && !is_workspace_entry(entry)
        })
        .map(|entry| {
            let name = resolved_npm_name(entry.resolved).unwrap_or(entry.name);
            ParsedPackage {
                ecosystem: PackageEcosystem::Npm,
                name: name.to_owned(),
                version: Some(entry.version.to_owned()),
                source_type: "lockfile",
            }
        })
        .collect())
}

fn is_workspace_entry(entry: &yarn_lock_parser::Entry<'_>) -> bool {
    entry.resolved.contains("workspace:")
        || entry.resolved.contains("portal:")
        || entry.resolved.contains("link:")
        || entry.descriptors.iter().any(|(_, selector)| {
            selector.starts_with("workspace:")
                || selector.starts_with("portal:")
                || selector.starts_with("link:")
        })
}

fn resolved_npm_name(resolved: &str) -> Option<&str> {
    let (name, _) = resolved.split_once("@npm:")?;
    (!name.is_empty()).then_some(name)
}

fn parse_poetry_lock(contents: &str) -> Result<Vec<ParsedPackage>, ParseFailure> {
    let value: toml::Value = toml::from_str(contents).map_err(|_| ParseFailure)?;
    let entries = value
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or(ParseFailure)?;
    let mut packages = Vec::new();
    for item in entries {
        let Some(name) = item.get("name").and_then(toml::Value::as_str) else {
            continue;
        };
        let Some(version) = item.get("version").and_then(toml::Value::as_str) else {
            continue;
        };
        push_package(
            &mut packages,
            PackageEcosystem::Pypi,
            name,
            Some(version),
            "lockfile",
        );
    }
    Ok(packages)
}

fn parse_uv_lock(contents: &str) -> Result<Vec<ParsedPackage>, ParseFailure> {
    let value: toml::Value = toml::from_str(contents).map_err(|_| ParseFailure)?;
    let entries = value
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or(ParseFailure)?;
    let mut packages = Vec::new();
    for item in entries {
        let Some(name) = item.get("name").and_then(toml::Value::as_str) else {
            continue;
        };
        let Some(version) = item.get("version").and_then(toml::Value::as_str) else {
            continue;
        };
        let local = item
            .get("source")
            .and_then(toml::Value::as_table)
            .is_some_and(|source| {
                source.contains_key("editable")
                    || source.contains_key("directory")
                    || source.get("virtual").and_then(toml::Value::as_bool) == Some(true)
            });
        if !local {
            push_package(
                &mut packages,
                PackageEcosystem::Pypi,
                name,
                Some(version),
                "lockfile",
            );
        }
    }
    Ok(packages)
}

fn parse_pipfile_lock(contents: &str) -> Result<Vec<ParsedPackage>, ParseFailure> {
    let value: JsonValue = serde_json::from_str(contents).map_err(|_| ParseFailure)?;
    let root = value.as_object().ok_or(ParseFailure)?;
    let mut packages = Vec::new();
    for section in ["default", "develop"] {
        let Some(entries) = root.get(section) else {
            continue;
        };
        let entries = entries.as_object().ok_or(ParseFailure)?;
        for (name, item) in entries {
            let Some(item) = item.as_object() else {
                return Err(ParseFailure);
            };
            let version = item
                .get("version")
                .and_then(JsonValue::as_str)
                .map(|version| {
                    version
                        .strip_prefix("===")
                        .or_else(|| version.strip_prefix("=="))
                        .unwrap_or(version)
                });
            push_package(
                &mut packages,
                PackageEcosystem::Pypi,
                name,
                version,
                "lockfile",
            );
        }
    }
    if !root.contains_key("default") && !root.contains_key("develop") {
        return Err(ParseFailure);
    }
    Ok(packages)
}

fn parse_composer_lock(contents: &str) -> Result<Vec<ParsedPackage>, ParseFailure> {
    let value: JsonValue = serde_json::from_str(contents).map_err(|_| ParseFailure)?;
    let root = value.as_object().ok_or(ParseFailure)?;
    let mut packages = Vec::new();
    for section in ["packages", "packages-dev"] {
        let Some(entries) = root.get(section) else {
            continue;
        };
        let entries = entries.as_array().ok_or(ParseFailure)?;
        for item in entries {
            let Some(name) = item.get("name").and_then(JsonValue::as_str) else {
                continue;
            };
            let Some(version) = item.get("version").and_then(JsonValue::as_str) else {
                continue;
            };
            push_package(
                &mut packages,
                PackageEcosystem::Composer,
                name,
                Some(version),
                "lockfile",
            );
        }
    }
    if !root.contains_key("packages") && !root.contains_key("packages-dev") {
        return Err(ParseFailure);
    }
    Ok(packages)
}

fn parse_go_sum(contents: &str) -> Result<Vec<ParsedPackage>, ParseFailure> {
    let mut packages = Vec::new();
    for line in contents.lines().filter(|line| !line.trim().is_empty()) {
        let mut columns = line.split_whitespace();
        let Some(module) = columns.next() else {
            return Err(ParseFailure);
        };
        let Some(version) = columns.next() else {
            return Err(ParseFailure);
        };
        let Some(checksum) = columns.next() else {
            return Err(ParseFailure);
        };
        if columns.next().is_some() || !checksum.starts_with("h1:") {
            return Err(ParseFailure);
        }
        if version.ends_with("/go.mod") {
            continue;
        }
        push_package(
            &mut packages,
            PackageEcosystem::Golang,
            module,
            Some(version),
            "lockfile",
        );
    }
    Ok(packages)
}

fn parse_go_mod(contents: &str) -> Result<Vec<ParsedPackage>, ParseFailure> {
    let parsed = gomod_parser::GoMod::from_str(contents).map_err(|_| ParseFailure)?;
    let mut packages = Vec::new();
    for dependency in parsed.require {
        push_package(
            &mut packages,
            PackageEcosystem::Golang,
            &dependency.module.module_path,
            Some(&dependency.module.version),
            "manifest",
        );
    }
    Ok(packages)
}

fn parse_cargo_lock(contents: &str) -> Result<Vec<ParsedPackage>, ParseFailure> {
    let lockfile = CargoLockfile::from_str(contents).map_err(|_| ParseFailure)?;
    Ok(lockfile
        .packages
        .into_iter()
        .filter(|package| package.source.is_some())
        .map(|package| ParsedPackage {
            ecosystem: PackageEcosystem::Cargo,
            name: package.name.to_string(),
            version: Some(package.version.to_string()),
            source_type: "lockfile",
        })
        .collect())
}

fn exact_python_version(specifiers: &str) -> Option<String> {
    let version = specifiers
        .strip_prefix("===")
        .or_else(|| specifiers.strip_prefix("=="))?;
    if version.is_empty() || version.contains(['*', ',']) {
        None
    } else {
        Some(version.to_owned())
    }
}

fn strip_requirement_comment(line: &str) -> &str {
    line.char_indices()
        .find(|(index, character)| {
            *character == '#' && (*index == 0 || line.as_bytes()[index - 1].is_ascii_whitespace())
        })
        .map_or(line, |(index, _)| &line[..index])
}

fn strip_hash_options(line: &str) -> &str {
    line.find(" --hash")
        .map_or(line, |index| line[..index].trim_end())
}

fn push_package(
    packages: &mut Vec<ParsedPackage>,
    ecosystem: PackageEcosystem,
    name: &str,
    version: Option<&str>,
    source_type: &'static str,
) {
    if name.trim().is_empty() {
        return;
    }
    packages.push(ParsedPackage {
        ecosystem,
        name: name.to_owned(),
        version: version.map(str::to_owned),
        source_type,
    });
}

#[cfg(test)]
mod tests {
    use super::{parse_package_lock, parse_pnpm_lock, parse_requirement_line};

    #[test]
    fn parses_npm_lockfile_v1_nested_dependencies() {
        let fixture = r#"{
            "lockfileVersion": 1,
            "dependencies": {
                "parent": {
                    "version": "1.0.0",
                    "dependencies": {
                        "child": { "version": "2.0.0" }
                    }
                }
            }
        }"#;
        let packages = parse_package_lock(fixture).expect("valid npm v1 lockfile");
        let mut purls = packages
            .iter()
            .map(|package| {
                crate::purl::package_url(
                    package.ecosystem,
                    &package.name,
                    package.version.as_deref(),
                )
                .expect("valid package URL")
            })
            .collect::<Vec<_>>();
        purls.sort();
        assert_eq!(purls, ["pkg:npm/child@2.0.0", "pkg:npm/parent@1.0.0"]);
    }

    #[test]
    fn parses_scoped_pnpm_lock_locators_from_both_lockfile_generations() {
        let v6 = "lockfileVersion: '6.0'\npackages:\n  /@scope/pkg/2.3.4:\n    resolution: {integrity: sha512-test}\n";
        let v9 = "lockfileVersion: '9.0'\nimporters:\n  .: {}\npackages:\n  '@scope/pkg@2.3.4(peer@1.0.0)':\n    resolution: {integrity: sha512-test}\nsnapshots:\n  '@scope/pkg@2.3.4(peer@1.0.0)': {}\n";
        let v6_peer = "lockfileVersion: '6.0'\npackages:\n  /@scope/pkg@2.3.4_react@18.0.0:\n    resolution: {integrity: sha512-test}\n";

        for fixture in [v6, v9, v6_peer] {
            let packages = parse_pnpm_lock(fixture).expect("valid pnpm lockfile");
            assert_eq!(packages.len(), 1, "{fixture}");
            assert_eq!(packages[0].name, "@scope/pkg");
            assert_eq!(packages[0].version.as_deref(), Some("2.3.4"));
        }
    }

    #[test]
    fn requirements_only_claim_versions_for_exact_pins() {
        let pinned = parse_requirement_line("Requests[security]==2.31.0 ; python_version >= '3.9'")
            .expect("valid requirement")
            .expect("package");
        let ranged = parse_requirement_line("urllib3>=1.26,<3")
            .expect("valid requirement")
            .expect("package");
        assert_eq!(pinned.name, "requests");
        assert_eq!(pinned.version.as_deref(), Some("2.31.0"));
        assert_eq!(ranged.version, None);
    }
}
