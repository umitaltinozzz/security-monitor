use std::{
    collections::BTreeSet,
    path::{Component, Path, PathBuf},
};

use serde_json::Value;

use crate::types::{
    EngineKind, FindingKind, NormalizedFinding, NormalizedScan, NormalizedSeverity,
    PackageEvidence, ScanDiagnostic, ScanDiagnosticKind, ScannerError,
};

pub fn normalize_osv_scanner(
    input: &[u8],
    project_root: &Path,
) -> Result<NormalizedScan, ScannerError> {
    let value = serde_json::from_slice::<Value>(input).map_err(|_| ScannerError::InvalidOutput)?;
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or(ScannerError::InvalidOutput)?;
    let mut output = NormalizedScan {
        engine: EngineKind::OsvScanner,
        complete: true,
        findings: Vec::new(),
        diagnostics: Vec::new(),
    };
    if value
        .get("errors")
        .and_then(Value::as_array)
        .is_some_and(|errors| !errors.is_empty())
    {
        add_diagnostic(&mut output, ScanDiagnosticKind::ScannerReportedError, None);
    }

    for result in results {
        let source_path = result
            .get("source")
            .and_then(|source| source.get("path"))
            .and_then(Value::as_str);
        let path = match source_path {
            Some(path) => normalized_path(project_root, path, &mut output),
            None => {
                add_diagnostic(&mut output, ScanDiagnosticKind::MalformedRecord, None);
                None
            }
        };
        let Some(packages) = result.get("packages").and_then(Value::as_array) else {
            add_diagnostic(&mut output, ScanDiagnosticKind::MalformedRecord, None);
            continue;
        };
        for package_record in packages {
            let Some(package) = package_record.get("package") else {
                add_diagnostic(
                    &mut output,
                    ScanDiagnosticKind::MalformedRecord,
                    path.clone(),
                );
                continue;
            };
            let name = package
                .get("name")
                .and_then(Value::as_str)
                .and_then(bounded_text);
            let Some(name) = name else {
                add_diagnostic(
                    &mut output,
                    ScanDiagnosticKind::MalformedRecord,
                    path.clone(),
                );
                continue;
            };
            let package_evidence = PackageEvidence {
                name,
                ecosystem: package
                    .get("ecosystem")
                    .and_then(Value::as_str)
                    .and_then(bounded_text),
                version: package
                    .get("version")
                    .and_then(Value::as_str)
                    .and_then(bounded_text),
            };
            let Some(vulnerabilities) = package_record
                .get("vulnerabilities")
                .and_then(Value::as_array)
            else {
                add_diagnostic(
                    &mut output,
                    ScanDiagnosticKind::MalformedRecord,
                    path.clone(),
                );
                continue;
            };
            for vulnerability in vulnerabilities {
                let Some(identifier) = vulnerability
                    .get("id")
                    .and_then(Value::as_str)
                    .and_then(bounded_text)
                else {
                    add_diagnostic(
                        &mut output,
                        ScanDiagnosticKind::MalformedRecord,
                        path.clone(),
                    );
                    continue;
                };
                let aliases = string_set(vulnerability.get("aliases"));
                let title = vulnerability
                    .get("summary")
                    .and_then(Value::as_str)
                    .and_then(bounded_text);
                let fixed_version = find_fixed_version(vulnerability);
                output.findings.push(NormalizedFinding {
                    kind: FindingKind::Vulnerability,
                    rule_id: Some(identifier),
                    aliases,
                    package: Some(package_evidence.clone()),
                    severity: NormalizedSeverity::Unknown,
                    title,
                    fixed_version,
                    path: path.clone(),
                    line_start: None,
                    line_end: None,
                });
            }
        }
    }
    sort_findings(&mut output.findings);
    Ok(output)
}

pub fn normalize_trivy(
    input: &[u8],
    project_root: Option<&Path>,
) -> Result<NormalizedScan, ScannerError> {
    let value = serde_json::from_slice::<Value>(input).map_err(|_| ScannerError::InvalidOutput)?;
    if value.get("SchemaVersion").and_then(Value::as_u64).is_none() {
        return Err(ScannerError::InvalidOutput);
    }
    let results = value
        .get("Results")
        .and_then(Value::as_array)
        .ok_or(ScannerError::InvalidOutput)?;
    let mut output = NormalizedScan {
        engine: EngineKind::Trivy,
        complete: true,
        findings: Vec::new(),
        diagnostics: Vec::new(),
    };
    for result in results {
        let target = result.get("Target").and_then(Value::as_str);
        let path = match (project_root, target) {
            (Some(root), Some(target)) if !target.is_empty() => {
                normalized_path(root, target, &mut output)
            }
            (Some(_), None) => {
                add_diagnostic(&mut output, ScanDiagnosticKind::MalformedRecord, None);
                None
            }
            _ => None,
        };
        append_trivy_vulnerabilities(result, path.as_deref(), &mut output);
        append_trivy_secrets(result, path.as_deref(), &mut output);
        append_trivy_misconfigurations(result, path.as_deref(), &mut output);
    }
    sort_findings(&mut output.findings);
    Ok(output)
}

pub fn normalize_semgrep(
    input: &[u8],
    project_root: &Path,
) -> Result<NormalizedScan, ScannerError> {
    let value = serde_json::from_slice::<Value>(input).map_err(|_| ScannerError::InvalidOutput)?;
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or(ScannerError::InvalidOutput)?;
    let mut output = NormalizedScan {
        engine: EngineKind::Semgrep,
        complete: true,
        findings: Vec::new(),
        diagnostics: Vec::new(),
    };
    if value
        .get("errors")
        .and_then(Value::as_array)
        .is_some_and(|errors| !errors.is_empty())
    {
        add_diagnostic(&mut output, ScanDiagnosticKind::ScannerReportedError, None);
    }
    for result in results {
        let Some(rule_id) = result
            .get("check_id")
            .and_then(Value::as_str)
            .and_then(bounded_text)
        else {
            add_diagnostic(&mut output, ScanDiagnosticKind::MalformedRecord, None);
            continue;
        };
        let path = result
            .get("path")
            .and_then(Value::as_str)
            .map(|path| normalized_path(project_root, path, &mut output))
            .unwrap_or_else(|| {
                add_diagnostic(&mut output, ScanDiagnosticKind::MalformedRecord, None);
                None
            });
        let start = result.get("start");
        let end = result.get("end");
        output.findings.push(NormalizedFinding {
            kind: FindingKind::Code,
            rule_id: Some(rule_id),
            aliases: Vec::new(),
            package: None,
            severity: severity(result.get("extra").and_then(|extra| extra.get("severity"))),
            title: None,
            fixed_version: None,
            path,
            line_start: start
                .and_then(|position| position.get("line"))
                .and_then(Value::as_u64)
                .and_then(|line| u32::try_from(line).ok()),
            line_end: end
                .and_then(|position| position.get("line"))
                .and_then(Value::as_u64)
                .and_then(|line| u32::try_from(line).ok()),
        });
    }
    sort_findings(&mut output.findings);
    Ok(output)
}

fn append_trivy_vulnerabilities(result: &Value, path: Option<&str>, output: &mut NormalizedScan) {
    let Some(vulnerabilities) = result.get("Vulnerabilities").and_then(Value::as_array) else {
        return;
    };
    for vulnerability in vulnerabilities {
        let Some(identifier) = vulnerability
            .get("VulnerabilityID")
            .and_then(Value::as_str)
            .and_then(bounded_text)
        else {
            add_diagnostic(
                output,
                ScanDiagnosticKind::MalformedRecord,
                path.map(str::to_owned),
            );
            continue;
        };
        let package_name = vulnerability
            .get("PkgName")
            .and_then(Value::as_str)
            .and_then(bounded_text);
        output.findings.push(NormalizedFinding {
            kind: FindingKind::Vulnerability,
            rule_id: Some(identifier),
            aliases: Vec::new(),
            package: package_name.map(|name| PackageEvidence {
                name,
                ecosystem: vulnerability
                    .get("PkgType")
                    .and_then(Value::as_str)
                    .and_then(bounded_text),
                version: vulnerability
                    .get("InstalledVersion")
                    .and_then(Value::as_str)
                    .and_then(bounded_text),
            }),
            severity: severity(vulnerability.get("Severity")),
            title: vulnerability
                .get("Title")
                .and_then(Value::as_str)
                .and_then(bounded_text),
            fixed_version: vulnerability
                .get("FixedVersion")
                .and_then(Value::as_str)
                .and_then(bounded_text),
            path: path.map(str::to_owned),
            line_start: None,
            line_end: None,
        });
    }
}

fn append_trivy_secrets(result: &Value, path: Option<&str>, output: &mut NormalizedScan) {
    let Some(secrets) = result.get("Secrets").and_then(Value::as_array) else {
        return;
    };
    for secret in secrets {
        let Some(rule_id) = secret
            .get("RuleID")
            .and_then(Value::as_str)
            .and_then(bounded_text)
        else {
            add_diagnostic(
                output,
                ScanDiagnosticKind::MalformedRecord,
                path.map(str::to_owned),
            );
            continue;
        };
        let code = secret.get("Code");
        output.findings.push(NormalizedFinding {
            kind: FindingKind::Secret,
            rule_id: Some(rule_id),
            aliases: Vec::new(),
            package: None,
            severity: severity(secret.get("Severity")),
            title: None,
            fixed_version: None,
            path: path.map(str::to_owned),
            line_start: secret
                .get("StartLine")
                .or_else(|| code.and_then(|code| code.get("StartLine")))
                .and_then(Value::as_u64)
                .and_then(|line| u32::try_from(line).ok()),
            line_end: secret
                .get("EndLine")
                .or_else(|| code.and_then(|code| code.get("EndLine")))
                .and_then(Value::as_u64)
                .and_then(|line| u32::try_from(line).ok()),
        });
    }
}

fn append_trivy_misconfigurations(result: &Value, path: Option<&str>, output: &mut NormalizedScan) {
    let Some(misconfigurations) = result.get("Misconfigurations").and_then(Value::as_array) else {
        return;
    };
    for misconfiguration in misconfigurations {
        let status = misconfiguration
            .get("Status")
            .and_then(Value::as_str)
            .unwrap_or("FAIL");
        if status.eq_ignore_ascii_case("PASS") {
            continue;
        }
        let Some(rule_id) = misconfiguration
            .get("ID")
            .and_then(Value::as_str)
            .and_then(bounded_text)
        else {
            add_diagnostic(
                output,
                ScanDiagnosticKind::MalformedRecord,
                path.map(str::to_owned),
            );
            continue;
        };
        let code = misconfiguration
            .get("CauseMetadata")
            .and_then(|metadata| metadata.get("Code"));
        output.findings.push(NormalizedFinding {
            kind: FindingKind::Misconfiguration,
            rule_id: Some(rule_id),
            aliases: Vec::new(),
            package: None,
            severity: severity(misconfiguration.get("Severity")),
            title: None,
            fixed_version: None,
            path: path.map(str::to_owned),
            line_start: code
                .and_then(|code| code.get("StartLine"))
                .and_then(Value::as_u64)
                .and_then(|line| u32::try_from(line).ok()),
            line_end: code
                .and_then(|code| code.get("EndLine"))
                .and_then(Value::as_u64)
                .and_then(|line| u32::try_from(line).ok()),
        });
    }
}

fn normalized_path(project_root: &Path, path: &str, output: &mut NormalizedScan) -> Option<String> {
    let candidate = PathBuf::from(path);
    let joined = if candidate.is_absolute() {
        candidate
    } else {
        project_root.join(candidate)
    };
    let Ok(root) = project_root.canonicalize() else {
        add_diagnostic(output, ScanDiagnosticKind::MalformedRecord, None);
        return None;
    };
    let Ok(canonical) = joined.canonicalize() else {
        add_diagnostic(output, ScanDiagnosticKind::MalformedRecord, None);
        return None;
    };
    if !canonical.starts_with(&root) {
        add_diagnostic(output, ScanDiagnosticKind::PathOutsideProject, None);
        return None;
    }
    let relative = canonical.strip_prefix(root).ok()?;
    Some(path_to_portable_string(relative))
}

fn path_to_portable_string(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn find_fixed_version(vulnerability: &Value) -> Option<String> {
    vulnerability
        .get("affected")
        .and_then(Value::as_array)?
        .iter()
        .flat_map(|affected| {
            affected
                .get("ranges")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .flat_map(|range| {
            range
                .get("events")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .find_map(|event| {
            event
                .get("fixed")
                .and_then(Value::as_str)
                .and_then(bounded_text)
        })
}

fn string_set(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(bounded_text)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn severity(value: Option<&Value>) -> NormalizedSeverity {
    match value
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_uppercase()
        .as_str()
    {
        "CRITICAL" => NormalizedSeverity::Critical,
        "HIGH" | "ERROR" => NormalizedSeverity::High,
        "MEDIUM" | "WARNING" => NormalizedSeverity::Medium,
        "LOW" | "INFO" => NormalizedSeverity::Low,
        _ => NormalizedSeverity::Unknown,
    }
}

fn bounded_text(value: &str) -> Option<String> {
    let value = value
        .chars()
        .filter(|character| !character.is_control())
        .take(512)
        .collect::<String>();
    (!value.trim().is_empty()).then_some(value)
}

fn add_diagnostic(output: &mut NormalizedScan, kind: ScanDiagnosticKind, path: Option<String>) {
    output.complete = false;
    output.diagnostics.push(ScanDiagnostic { kind, path });
}

fn sort_findings(findings: &mut [NormalizedFinding]) {
    findings.sort_by(|left, right| {
        (
            left.kind,
            left.path.as_deref(),
            left.line_start,
            left.rule_id.as_deref(),
            left.package.as_ref().map(|package| package.name.as_str()),
        )
            .cmp(&(
                right.kind,
                right.path.as_deref(),
                right.line_start,
                right.rule_id.as_deref(),
                right.package.as_ref().map(|package| package.name.as_str()),
            ))
    });
}
