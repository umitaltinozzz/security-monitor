use super::*;

pub(super) fn component_map(snapshot: &ReportSnapshot) -> BTreeMap<&str, &Component> {
    snapshot
        .components
        .iter()
        .map(|component| (component.id.as_str(), component))
        .collect()
}

pub(super) fn instance_map(snapshot: &ReportSnapshot) -> BTreeMap<&str, &ComponentInstance> {
    snapshot
        .instances
        .iter()
        .map(|instance| (instance.id.as_str(), instance))
        .collect()
}

pub(super) fn advisory_map(snapshot: &ReportSnapshot) -> BTreeMap<&str, &Advisory> {
    snapshot
        .advisories
        .iter()
        .map(|advisory| (advisory.canonical_id.as_str(), advisory))
        .collect()
}

pub(super) fn unique_values(values: Vec<Value>) -> Vec<Value> {
    let mut unique = BTreeMap::new();
    for value in values {
        unique.entry(value.to_string()).or_insert(value);
    }
    unique.into_values().collect()
}

pub(super) fn skipped_vex_finding_ids(snapshot: &ReportSnapshot) -> Vec<String> {
    let components = component_map(snapshot);
    let instances = instance_map(snapshot);
    snapshot
        .findings
        .iter()
        .filter(|finding| {
            instances
                .get(finding.component_instance_id.as_str())
                .and_then(|instance| components.get(instance.component_id.as_str()))
                .is_none()
        })
        .map(|finding| format!("{}@{}", finding.advisory_id, finding.component_instance_id))
        .collect()
}

pub(super) fn safe_reference_uri(value: &str) -> Option<String> {
    let mut uri = Url::parse(value).ok()?;
    if uri.scheme() != "https"
        || uri.host_str().is_none()
        || !uri.username().is_empty()
        || uri.password().is_some()
    {
        return None;
    }
    uri.set_query(None);
    uri.set_fragment(None);
    Some(uri.to_string())
}

pub(super) fn deterministic_uuid(snapshot: &ReportSnapshot) -> String {
    let input = format!(
        "{}:{}",
        snapshot
            .project
            .as_ref()
            .map_or("workspace", |project| project.id.as_str()),
        snapshot.generated_at
    );
    let mut digest = Sha256::digest(input.as_bytes());
    digest[6] = (digest[6] & 0x0f) | 0x50;
    digest[8] = (digest[8] & 0x3f) | 0x80;
    let hex = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

pub(super) fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Unknown => 0,
    }
}

pub(super) fn is_closed(status: &FindingStatus) -> bool {
    matches!(
        status,
        FindingStatus::FixedInProduction
            | FindingStatus::AcceptedRisk
            | FindingStatus::FalsePositive
            | FindingStatus::NotReachable
    )
}

pub(super) fn verification_text(state: VerificationState) -> &'static str {
    match state {
        VerificationState::Verified => "verified",
        VerificationState::NeedsReview => "needs_review",
    }
}

pub(super) fn finding_status(status: &FindingStatus) -> &'static str {
    match status {
        FindingStatus::New => "new",
        FindingStatus::NeedsReview => "needs_review",
        FindingStatus::ConfirmedAffected => "confirmed_affected",
        FindingStatus::NotReachable => "not_reachable",
        FindingStatus::Mitigated => "mitigated",
        FindingStatus::FixProposed => "fix_proposed",
        FindingStatus::FixedInRepo => "fixed_in_repo",
        FindingStatus::FixedInProduction => "fixed_in_production",
        FindingStatus::AcceptedRisk => "accepted_risk",
        FindingStatus::FalsePositive => "false_positive",
    }
}
