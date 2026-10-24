use security_monitor_core::{Component, ComponentEvidence, ComponentInstance};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub struct FindingFingerprintInput<'a> {
    pub canonical_advisory_id: &'a str,
    pub component: &'a Component,
    pub instance: &'a ComponentInstance,
    pub evidence: Option<&'a ComponentEvidence>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FingerprintError {
    #[error("canonical advisory identifier is empty")]
    EmptyAdvisoryId,
    #[error("component instance identifier is empty")]
    EmptyInstanceId,
    #[error("package URL is empty")]
    EmptyPackageUrl,
}

pub fn finding_fingerprint(
    input: &FindingFingerprintInput<'_>,
) -> Result<String, FingerprintError> {
    let advisory_id = input.canonical_advisory_id.trim().to_ascii_uppercase();
    if advisory_id.is_empty() {
        return Err(FingerprintError::EmptyAdvisoryId);
    }
    if input.instance.id.trim().is_empty() {
        return Err(FingerprintError::EmptyInstanceId);
    }
    if input.component.purl.trim().is_empty() {
        return Err(FingerprintError::EmptyPackageUrl);
    }

    let mut digest = Sha256::new();
    field(&mut digest, "advisory", Some(&advisory_id));
    field(&mut digest, "project", input.instance.project_id.as_deref());
    field(&mut digest, "asset", input.instance.asset_id.as_deref());
    field(&mut digest, "service", input.instance.service_id.as_deref());
    field(
        &mut digest,
        "deployment",
        input.instance.deployment_id.as_deref(),
    );
    field(&mut digest, "purl", Some(input.component.purl.trim()));
    field(&mut digest, "version", Some(input.component.version.trim()));
    let location = input
        .evidence
        .and_then(|evidence| evidence.file_path_redacted.as_deref())
        .and_then(normalize_relative_location);
    field(&mut digest, "location", location.as_deref());
    let hex = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("sha256:{hex}"))
}

fn field(digest: &mut Sha256, name: &str, value: Option<&str>) {
    let name = name.as_bytes();
    digest.update((name.len() as u64).to_be_bytes());
    digest.update(name);
    match value {
        Some(value) => {
            digest.update([1]);
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        None => digest.update([0]),
    }
}

fn normalize_relative_location(path: &str) -> Option<String> {
    let path = path.trim().replace('\\', "/");
    if path.is_empty()
        || path.starts_with('/')
        || path.contains(':')
        || path.chars().any(char::is_control)
    {
        return None;
    }
    let mut segments = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => return None,
            segment => segments.push(segment),
        }
    }
    (!segments.is_empty()).then(|| segments.join("/"))
}
