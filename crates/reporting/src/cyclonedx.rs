use super::*;

pub(super) struct VendoredCycloneDxRetriever {
    pub(super) spdx_schema: Value,
    pub(super) jsf_schema: Value,
}

impl Retrieve for VendoredCycloneDxRetriever {
    fn retrieve(
        &self,
        uri: &Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        match uri.as_str().split('#').next().unwrap_or(uri.as_str()) {
            "http://cyclonedx.org/schema/spdx.schema.json"
            | "https://cyclonedx.org/schema/spdx.schema.json" => Ok(self.spdx_schema.clone()),
            "http://cyclonedx.org/schema/jsf-0.82.schema.json"
            | "https://cyclonedx.org/schema/jsf-0.82.schema.json" => Ok(self.jsf_schema.clone()),
            _ => Err(format!("schema is not vendored: {uri}").into()),
        }
    }
}

pub(super) fn cyclonedx_report(snapshot: &ReportSnapshot) -> Value {
    let component_by_id = component_map(snapshot);
    let instance_by_id = instance_map(snapshot);
    let advisory_by_id = advisory_map(snapshot);
    let components = snapshot
        .instances
        .iter()
        .filter_map(|instance| component_by_id.get(instance.component_id.as_str()))
        .map(|component| {
            let mut value = json!({"type":"library","bom-ref":component.purl,"name":component.name,
                "purl":component.purl,"properties":[{"name":"security-monitor:ecosystem","value":component.ecosystem}]});
            if let Some(version) = &component.version {
                value["version"] = json!(version);
            }
            value
        })
        .collect::<Vec<_>>();
    let components = unique_values(components);
    let vulnerabilities = snapshot
        .findings
        .iter()
        .filter_map(|finding| {
            let instance = instance_by_id.get(finding.component_instance_id.as_str())?;
            let component = component_by_id.get(instance.component_id.as_str())?;
            let advisory = advisory_by_id.get(finding.advisory_id.as_str());
            let affects = if let Some(version) = &component.version {
                json!([{"ref":component.purl,"versions":[{"version":version,"status":cyclonedx_version_status(finding, snapshot.verification)}]}])
            } else {
                json!([{"ref":component.purl}])
            };
            let mut vulnerability = json!({"id":finding.advisory_id,"source":{"name":"OSV"},
                "ratings":[{"severity":cyclonedx_severity(&finding.severity)}],
                "affects":affects,
                "analysis":{"state":cyclonedx_analysis_state(finding, snapshot.verification)},
                "properties":[{"name":"security-monitor:verification","value":verification_text(snapshot.verification)},
                    {"name":"security-monitor:finding-status","value":finding_status(&finding.status)}]});
            if let Some(justification) = cyclonedx_justification(finding) {
                vulnerability["analysis"]["justification"] = json!(justification);
            }
            if let Some(response) = cyclonedx_response(finding) {
                vulnerability["analysis"]["response"] = json!([response]);
            }
            if let Some(title) = advisory.map(|item| item.title.as_str()).filter(|title| !title.is_empty()) {
                vulnerability["description"] = json!(title);
            }
            let references = advisory
                .into_iter()
                .flat_map(|item| item.source_urls.iter())
                .filter_map(|uri| safe_reference_uri(uri))
                .map(|uri| json!({"title":"Advisory reference","url":uri}))
                .collect::<Vec<_>>();
            if !references.is_empty() {
                vulnerability["advisories"] = json!(references);
            }
            Some(vulnerability)
        })
        .collect::<Vec<_>>();
    let vulnerabilities = unique_values(vulnerabilities);
    let skipped = skipped_vex_finding_ids(snapshot);
    json!({"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":format!("urn:uuid:{}", deterministic_uuid(snapshot)),
        "version":1,"metadata":{"timestamp":snapshot.generated_at,"component":{"type":"application","bom-ref":"secmon-report",
            "name":snapshot.project.as_ref().map_or("Security Monitor workspace", |project| project.name.as_str()),"version":"0.1.0"},
            "properties":[{"name":"security-monitor:verification","value":verification_text(snapshot.verification)},
                {"name":"security-monitor:inventory-complete","value":snapshot.inventory_complete.to_string()},
                {"name":"security-monitor:skipped-finding-count","value":skipped.len().to_string()},
                {"name":"security-monitor:skipped-finding-ids","value":skipped.join(",")} ]},
        "components":components,"vulnerabilities":vulnerabilities})
}

pub(super) fn cyclonedx_severity(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Unknown => "unknown",
    }
}

pub(super) fn cyclonedx_version_status(
    finding: &Finding,
    verification: VerificationState,
) -> &'static str {
    match &finding.status {
        FindingStatus::FixedInProduction if is_verified_fixed(finding, verification) => {
            "unaffected"
        }
        FindingStatus::FixedInProduction => "unknown",
        FindingStatus::FalsePositive | FindingStatus::NotReachable
            if cyclonedx_justification(finding).is_some() =>
        {
            "unaffected"
        }
        FindingStatus::FalsePositive | FindingStatus::NotReachable => "unknown",
        _ => "affected",
    }
}

pub(super) fn cyclonedx_analysis_state(
    finding: &Finding,
    verification: VerificationState,
) -> &'static str {
    match &finding.status {
        FindingStatus::FixedInProduction if is_verified_fixed(finding, verification) => "resolved",
        FindingStatus::FixedInProduction => "in_triage",
        FindingStatus::FalsePositive if cyclonedx_justification(finding).is_some() => {
            "false_positive"
        }
        FindingStatus::NotReachable if cyclonedx_justification(finding).is_some() => "not_affected",
        FindingStatus::ConfirmedAffected | FindingStatus::AcceptedRisk => "exploitable",
        _ => "in_triage",
    }
}

pub(super) fn cyclonedx_justification(finding: &Finding) -> Option<CycloneDxJustification> {
    let reason = finding.disposition.as_ref()?.reason;
    match (&finding.status, reason) {
        (FindingStatus::NotReachable, FindingDispositionReason::NoAffectedCodePath)
        | (
            FindingStatus::NotReachable,
            FindingDispositionReason::ConfigurationPreventsReachability,
        ) => Some(CycloneDxJustification::CodeNotReachable),
        (FindingStatus::FalsePositive, FindingDispositionReason::IncorrectPackage)
        | (FindingStatus::FalsePositive, FindingDispositionReason::UnaffectedVersion) => {
            Some(CycloneDxJustification::CodeNotPresent)
        }
        (FindingStatus::FalsePositive, FindingDispositionReason::NoAffectedCodePath) => {
            Some(CycloneDxJustification::CodeNotReachable)
        }
        (
            FindingStatus::FalsePositive,
            FindingDispositionReason::ConfigurationPreventsReachability,
        ) => Some(CycloneDxJustification::RequiresConfiguration),
        (FindingStatus::FalsePositive, FindingDispositionReason::CompensatingControl) => {
            Some(CycloneDxJustification::ProtectedByMitigatingControl)
        }
        _ => None,
    }
}

pub(super) fn cyclonedx_response(finding: &Finding) -> Option<CycloneDxResponse> {
    finding.disposition.as_ref()?;
    match &finding.status {
        FindingStatus::FixedInRepo | FindingStatus::FixedInProduction => {
            Some(CycloneDxResponse::Update)
        }
        FindingStatus::AcceptedRisk => Some(CycloneDxResponse::WillNotFix),
        _ => None,
    }
}

pub(crate) fn is_verified_fixed(finding: &Finding, verification: VerificationState) -> bool {
    finding.status == FindingStatus::FixedInProduction
        && verification == VerificationState::Verified
        && finding.disposition.is_some()
}
