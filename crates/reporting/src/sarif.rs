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
    let rules = snapshot
        .findings
        .iter()
        .map(|finding| finding.advisory_id.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|id| {
            let advisory = advisory_by_id.get(id);
            let mut rule = json!({"id":id,"shortDescription":{"text":advisory.map_or(id, |item| item.title.as_str())}});
            if let Some(uri) = advisory
                .and_then(|item| item.source_urls.first())
                .and_then(|uri| safe_reference_uri(uri))
            {
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
    let results = snapshot
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
                    component.map_or("unknown version", |item| item.version.as_str()), verification_text(snapshot.verification))},
                "partialFingerprints":{"securityMonitorFindingId":finding.id},
                "properties":{"status":finding_status(&finding.status),"repo_status":finding.repo_status,"production_status":finding.production_status,
                    "verification":verification_text(snapshot.verification),"priority_score":finding.priority_score}});
            if !locations.is_empty() {
                result["locations"] = json!(locations);
            }
            result
        })
        .collect::<Vec<_>>();
    json!({"$schema":"https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json",
        "version":"2.1.0","runs":[{"tool":{"driver":{"name":"Security Monitor","informationUri":"https://github.com/umitaltinozzz/security-monitor",
            "rules":rules}},"results":results,"properties":{"verification":verification_text(snapshot.verification),
                "inventory_complete":snapshot.inventory_complete,"project":snapshot.project}}]})
}

fn sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium | Severity::Unknown => "warning",
        Severity::Low => "note",
    }
}
