use super::*;

pub(super) fn openvex_report(snapshot: &ReportSnapshot) -> Value {
    let component_by_id = component_map(snapshot);
    let instance_by_id = instance_map(snapshot);
    let advisory_by_id = advisory_map(snapshot);
    let skipped = skipped_vex_finding_ids(snapshot);
    let statements = snapshot
        .findings
        .iter()
        .map(|finding| {
            let Some(instance) = instance_by_id.get(finding.component_instance_id.as_str()) else {
                return openvex_unscoped_finding(finding, snapshot.generated_at);
            };
            let Some(component) = component_by_id.get(instance.component_id.as_str()) else {
                return openvex_unscoped_finding(finding, snapshot.generated_at);
            };
            let advisory = advisory_by_id.get(finding.advisory_id.as_str());
            let status = openvex_status(finding, snapshot.verification);
            let mut statement = json!({"vulnerability":{"name":finding.advisory_id},
                "products":[{"@id":component.purl,"identifiers":{"purl":component.purl}}],
                "status":status,"timestamp":snapshot.generated_at,"last_updated":snapshot.generated_at,
                "status_notes":format!("Security Monitor finding status: {}; verification: {}.{}",
                    finding_status(&finding.status),verification_text(snapshot.verification),
                    if skipped.is_empty() { String::new() } else { format!(" Skipped finding IDs omitted because product scope could not be verified ({}): {}.", skipped.len(), skipped.join(", ")) })});
            if let Some(title) = advisory.map(|item| item.title.as_str()).filter(|title| !title.is_empty()) {
                statement["vulnerability"]["description"] = json!(title);
            }
            if let Some(justification) = openvex_justification(finding) {
                statement["justification"] = json!(justification);
            }
            if status == "affected" {
                statement["action_statement"] = json!("Review the advisory and apply a verified fixed version where available.");
            }
            if status == "not_affected" {
                statement["impact_statement"] = json!("A user-reviewed disposition records that the vulnerable code does not affect this product.");
            }
            statement
        })
        .collect::<Vec<_>>();
    let statements = unique_values(statements);
    let tooling = if skipped.is_empty() {
        format!("Security Monitor {}", env!("CARGO_PKG_VERSION"))
    } else {
        format!(
            "Security Monitor {}; skipped findings without verifiable product scope ({}): {}",
            env!("CARGO_PKG_VERSION"),
            skipped.len(),
            skipped.join(", ")
        )
    };
    json!({"@context":"https://openvex.dev/ns/v0.2.0","@id":format!("https://openvex.dev/docs/secmon/{}",deterministic_uuid(snapshot)),
        "author":"Security Monitor","role":"Document Creator","timestamp":snapshot.generated_at,"last_updated":snapshot.generated_at,"version":1,
        "tooling":tooling,"statements":statements})
}

fn openvex_unscoped_finding(finding: &Finding, timestamp: DateTime<Utc>) -> Value {
    json!({"vulnerability":{"name":finding.advisory_id},
        "status":"under_investigation","timestamp":timestamp,"last_updated":timestamp,
        "status_notes":format!("Finding {} is omitted from product-specific statements because its component scope could not be verified.", finding.id)})
}

pub(super) fn openvex_status(finding: &Finding, verification: VerificationState) -> &'static str {
    match &finding.status {
        FindingStatus::FixedInProduction if is_verified_fixed(finding, verification) => "fixed",
        FindingStatus::FixedInProduction => "under_investigation",
        FindingStatus::ConfirmedAffected | FindingStatus::AcceptedRisk => "affected",
        FindingStatus::NotReachable | FindingStatus::FalsePositive
            if openvex_justification(finding).is_some() =>
        {
            "not_affected"
        }
        _ => "under_investigation",
    }
}

pub(super) fn openvex_justification(finding: &Finding) -> Option<&'static str> {
    match finding.disposition.as_ref()?.reason {
        FindingDispositionReason::NoAffectedCodePath
        | FindingDispositionReason::ConfigurationPreventsReachability => {
            Some("vulnerable_code_not_in_execute_path")
        }
        FindingDispositionReason::UnaffectedVersion => Some("vulnerable_code_not_present"),
        FindingDispositionReason::IncorrectPackage => Some("component_not_present"),
        FindingDispositionReason::CompensatingControl => Some("inline_mitigations_already_exist"),
        _ => None,
    }
}
