use std::borrow::Cow;

use super::{DiagnosticCode, OperatingSystem, PackageRecord, PackageSource};

const MAX_PACKAGE_RECORDS: usize = 100_000;

#[derive(Debug, PartialEq, Eq)]
pub struct ParsedPackages {
    pub records: Vec<PackageRecord>,
    pub partial: bool,
    pub diagnostic: DiagnosticCode,
}

pub fn valid_container_id(value: &str) -> bool {
    (12..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn normalize_commit(value: &str) -> Option<String> {
    if (7..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(value.to_ascii_lowercase())
    } else {
        None
    }
}

pub fn parse_os_release(contents: &str) -> Option<OperatingSystem> {
    parse_os_release_with_architecture(contents, "unknown")
}

pub fn parse_os_release_with_architecture(
    contents: &str,
    architecture: &str,
) -> Option<OperatingSystem> {
    let mut values = std::collections::BTreeMap::new();
    for line in contents.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if !matches!(key, "ID" | "NAME" | "VERSION_ID" | "PRETTY_NAME") {
            continue;
        }
        let value = value.trim().trim_matches('"').trim_matches('\'');
        if !value.is_empty()
            && value.len() <= 512
            && !value.bytes().any(|byte| byte.is_ascii_control())
        {
            values.insert(key, value.to_owned());
        }
    }
    let id = values.get("ID").cloned();
    let name = values.get("NAME").cloned();
    if id.is_none() && name.is_none() {
        return None;
    }
    Some(OperatingSystem {
        id,
        name,
        version_id: values.get("VERSION_ID").cloned(),
        pretty_name: values.get("PRETTY_NAME").cloned(),
        kernel_release: None,
        installed_kernel_release: None,
        kernel_restart_required: None,
        architecture: architecture.to_owned(),
    })
}

pub fn parse_package_output(
    output: &[u8],
    ecosystem: &str,
    source: PackageSource,
) -> ParsedPackages {
    let output = match std::str::from_utf8(output) {
        Ok(output) => Cow::Borrowed(output),
        Err(_) => {
            return ParsedPackages {
                records: Vec::new(),
                partial: true,
                diagnostic: DiagnosticCode::InvalidOutput,
            };
        }
    };
    let mut records = Vec::new();
    let mut partial = false;
    let mut diagnostic = DiagnosticCode::InvalidOutput;
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let record = if source == PackageSource::Dpkg {
            match parse_strict_tabbed_package(line, ecosystem, source) {
                Ok(Some(record)) => Some(record),
                Ok(None) => continue,
                Err(()) => {
                    partial = true;
                    continue;
                }
            }
        } else if source == PackageSource::Apk {
            parse_apk_package(line, ecosystem)
        } else {
            parse_strict_tabbed_package(line, ecosystem, source)
                .ok()
                .flatten()
        };
        let Some(record) = record else {
            partial = true;
            continue;
        };
        if records.len() == MAX_PACKAGE_RECORDS {
            partial = true;
            diagnostic = DiagnosticCode::LimitReached;
            break;
        }
        records.push(record);
    }
    ParsedPackages {
        records,
        partial,
        diagnostic,
    }
}

fn parse_strict_tabbed_package(
    line: &str,
    ecosystem: &str,
    source: PackageSource,
) -> Result<Option<PackageRecord>, ()> {
    let mut fields = line.split('\t');
    let name = fields.next().ok_or(())?.trim();
    let version = fields.next().ok_or(())?.trim();
    let architecture = fields
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let status = if source == PackageSource::Dpkg {
        Some(fields.next().ok_or(())?.trim())
    } else {
        None
    };
    if fields.next().is_some()
        || name.is_empty()
        || version.is_empty()
        || [name, version]
            .into_iter()
            .chain(architecture)
            .any(|value| value.bytes().any(|byte| byte.is_ascii_control()))
    {
        return Err(());
    }
    if let Some(status) = status {
        match dpkg_current_state(status).ok_or(())? {
            "installed" => {}
            "config-files" | "not-installed" => return Ok(None),
            _ => return Err(()),
        }
    }
    Ok(Some(package_record(
        name,
        version,
        architecture,
        ecosystem,
        source,
    )))
}

fn dpkg_current_state(status: &str) -> Option<&str> {
    let mut fields = status.split_ascii_whitespace();
    let _desired = fields.next()?;
    let _error = fields.next()?;
    let current = fields.next()?;
    fields.next().is_none().then_some(current)
}

fn package_record(
    name: &str,
    version: &str,
    architecture: Option<&str>,
    ecosystem: &str,
    source: PackageSource,
) -> PackageRecord {
    PackageRecord {
        name: name.to_owned(),
        version: Some(version.to_owned()),
        architecture: architecture.map(str::to_owned),
        ecosystem: ecosystem.to_owned(),
        purl: None,
        source,
        evidence_path: None,
    }
}

fn parse_apk_package(line: &str, ecosystem: &str) -> Option<PackageRecord> {
    let (name, version) = line
        .match_indices('-')
        .rev()
        .map(|(index, _)| (&line[..index], &line[index + 1..]))
        .find(|(name, version)| {
            !name.is_empty()
                && version.as_bytes().first().is_some_and(u8::is_ascii_digit)
                && !name
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        })?;
    if version
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return None;
    }
    Some(package_record(
        name,
        version,
        None,
        ecosystem,
        PackageSource::Apk,
    ))
}
