use super::*;

pub(super) fn patch_oasis_sarif_language_pattern(value: &mut Value) {
    const INVALID: &str = "^[a-zA-Z]{2}|^[a-zA-Z]{2}-[a-zA-Z]{2}]?$";
    const CORRECTED: &str = "^[a-zA-Z]{2}(-[a-zA-Z]{2})?$";
    match value {
        Value::Object(properties) => {
            if properties.get("pattern").and_then(Value::as_str) == Some(INVALID) {
                properties.insert("pattern".to_owned(), json!(CORRECTED));
            }
            for nested in properties.values_mut() {
                patch_oasis_sarif_language_pattern(nested);
            }
        }
        Value::Array(values) => {
            for nested in values {
                patch_oasis_sarif_language_pattern(nested);
            }
        }
        _ => {}
    }
}

pub(super) fn sarif_report(snapshot: &ReportSnapshot) -> Value {
    let component_by_id = component_map(snapshot);
    let instance_by_id = instance_map(snapshot);
    let advisory_by_id = advisory_map(snapshot);
    let mut rule_data = BTreeMap::<String, (String, Option<String>)>::new();
    for finding in &snapshot.findings {
        let id = finding.advisory_id.clone();
        let advisory = advisory_by_id.get(id.as_str());
        let title = advisory.map_or_else(|| id.clone(), |item| item.title.clone());
        let help_uri = advisory
            .and_then(|item| item.source_urls.first())
            .and_then(|uri| safe_reference_uri(uri));
        rule_data.entry(id).or_insert((title, help_uri));
    }
    for finding in &snapshot.scanner_findings {
        rule_data
            .entry(scanner_rule_id(finding))
            .or_insert_with(|| {
                (
                    finding
                        .title
                        .clone()
                        .or_else(|| finding.rule_id.clone())
                        .unwrap_or_else(|| finding.kind.clone()),
                    None,
                )
            });
    }
    let rules = rule_data
        .iter()
        .map(|(id, (title, help_uri))| {
            let mut rule = json!({"id":id,"shortDescription":{"text":title}});
            if let Some(uri) = help_uri {
                rule["helpUri"] = json!(uri);
            }
            rule
        })
        .collect::<Vec<_>>();
    let rule_indexes = rules
        .iter()
        .enumerate()
        .filter_map(|(index, rule)| Some((rule.get("id")?.as_str()?, index)))
        .collect::<BTreeMap<_, _>>();
    let mut results = snapshot
        .findings
        .iter()
        .map(|finding| {
            let instance = instance_by_id.get(finding.component_instance_id.as_str());
            let component = instance.and_then(|instance| component_by_id.get(instance.component_id.as_str()));
            let advisory = advisory_by_id.get(finding.advisory_id.as_str());
            let locations = snapshot.evidence.iter().filter(|item| item.finding_id == finding.id)
                .filter_map(|item| item.file_path_redacted.as_deref().and_then(relative_evidence_path))
                .map(|path| json!({"physicalLocation":{"artifactLocation":{"uri":path}}})).collect::<Vec<_>>();
            let mut result = json!({"ruleId":finding.advisory_id,"ruleIndex":rule_indexes.get(finding.advisory_id.as_str()).copied().unwrap_or(0),
                "level":sarif_level(&finding.severity),
                "message":{"text":format!("{} affects {}@{}; verification: {}",
                    advisory.map_or(finding.advisory_id.as_str(), |item| item.title.as_str()),
                    component.map_or("unknown component", |item| item.name.as_str()),
                    component.and_then(|item| item.version.as_deref()).unwrap_or("unknown version"), verification_text(snapshot.verification))},
                "partialFingerprints":{"securityMonitorFindingId":finding.id},
                "properties":{"status":finding_status(&finding.status),"repo_status":finding.repo_status,"production_status":finding.production_status,
                    "verification":verification_text(snapshot.verification),"priority_score":finding.priority_score}});
            if !locations.is_empty() {
                result["locations"] = json!(locations);
            }
            result
        })
        .collect::<Vec<_>>();
    results.extend(snapshot.scanner_findings.iter().map(|finding| {
        let rule_id = scanner_rule_id(finding);
        let mut result = json!({
            "ruleId":rule_id,
            "ruleIndex":rule_indexes.get(rule_id.as_str()).copied().unwrap_or(0),
            "level":sarif_level(&finding.severity),
            "message":{"text":finding.title.as_deref()
                .or(finding.rule_id.as_deref()).unwrap_or(&finding.kind)},
            "partialFingerprints":{"securityMonitorFindingId":finding.id},
            "properties":{"scanner":finding.scanner,"mode":finding.mode,
                "kind":finding.kind,"last_seen_at":finding.last_seen_at}
        });
        if let Some(path) = finding.path.as_deref().and_then(relative_evidence_path) {
            let mut physical_location = json!({"artifactLocation":{"uri":path}});
            if let Some(start_line) = finding.line_start {
                let mut region = json!({"startLine":start_line});
                if let Some(end_line) = finding.line_end {
                    region["endLine"] = json!(end_line);
                }
                physical_location["region"] = region;
            }
            result["locations"] = json!([{"physicalLocation":physical_location}]);
        }
        result
    }));
    json!({"$schema":"https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json",
        "version":"2.1.0","runs":[{"tool":{"driver":{"name":"Security Monitor","informationUri":"https://github.com/umitaltinozzz/security-monitor",
            "rules":rules}},"results":results,"properties":{"verification":verification_text(snapshot.verification),
                "inventory_complete":snapshot.inventory_complete,"project":snapshot.project}}]})
}

fn scanner_rule_id(finding: &security_monitor_core::ScannerFinding) -> String {
    format!(
        "{}:{}:{}",
        finding.scanner,
        finding.mode,
        finding.rule_id.as_deref().unwrap_or(&finding.kind)
    )
}

fn sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium | Severity::Unknown => "warning",
        Severity::Low => "note",
    }
}
