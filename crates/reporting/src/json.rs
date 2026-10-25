use super::*;

pub(super) fn validate_json_report(document: &Value) -> Result<(), String> {
    let valid = document.get("format").and_then(Value::as_str) == Some("security-monitor-json")
        && document
            .get("generated_at")
            .and_then(Value::as_str)
            .is_some()
        && document
            .get("verification")
            .and_then(Value::as_str)
            .is_some_and(|value| matches!(value, "verified" | "needs_review"))
        && document.get("findings").and_then(Value::as_array).is_some()
        && document
            .get("components")
            .and_then(Value::as_array)
            .is_some();
    if valid {
        Ok(())
    } else {
        Err("document does not match the Security Monitor JSON report shape".to_owned())
    }
}

pub(super) fn json_report(snapshot: &ReportSnapshot) -> Value {
    let component_by_id = component_map(snapshot);
    let instance_by_id = instance_map(snapshot);
    let advisory_by_id = advisory_map(snapshot);
    json!({
        "format":"security-monitor-json",
        "version":1,
        "generated_at":snapshot.generated_at,
        "project":snapshot.project,
        "inventory_complete":snapshot.inventory_complete,
        "verification":verification_text(snapshot.verification),
        "components":snapshot.instances.iter().filter_map(|instance| {
            let component = component_by_id.get(instance.component_id.as_str())?;
            Some(json!({"purl":component.purl,"name":component.name,"version":component.version,
                "ecosystem":component.ecosystem,"evidence":instance.evidence.iter().map(|item| json!({
                    "type":item.evidence_type,"path":item.file_path_redacted.as_deref().and_then(relative_evidence_path)
                })).collect::<Vec<_>>() }))
        }).collect::<Vec<_>>(),
        "findings":snapshot.findings.iter().filter_map(|finding| {
            let instance = instance_by_id.get(finding.component_instance_id.as_str())?;
            let component = component_by_id.get(instance.component_id.as_str())?;
            let advisory = advisory_by_id.get(finding.advisory_id.as_str());
            Some(json!({"id":finding.id,"advisory_id":finding.advisory_id,
                "title":advisory.map_or(finding.advisory_id.as_str(), |item| item.title.as_str()),
                "component":{"purl":component.purl,"name":component.name,"version":component.version},
                "severity":finding.severity,"status":finding.status,"repo_status":finding.repo_status,
                "production_status":finding.production_status,"priority_score":finding.priority_score,
                "priority_reasons":finding.priority_reasons,
                "evidence":snapshot.evidence.iter().filter(|item| item.finding_id == finding.id)
                    .map(|item| json!({"type":item.evidence_type,"path":item.file_path_redacted.as_deref().and_then(relative_evidence_path),"confidence":item.confidence})).collect::<Vec<_>>() }))
        }).collect::<Vec<_>>()
    })
}

pub(crate) fn relative_evidence_path(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let relative = normalized.strip_prefix("<project>/").unwrap_or(&normalized);
    if relative.is_empty()
        || relative.starts_with('/')
        || relative.contains(':')
        || relative
            .split('/')
            .any(|segment| segment == ".." || segment.is_empty())
    {
        return None;
    }
    Some(relative.to_owned())
}
