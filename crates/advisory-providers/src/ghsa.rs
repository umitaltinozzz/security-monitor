use chrono::{DateTime, Utc};
use security_monitor_core::{Advisory, AdvisorySource, AffectedRange, RangeEvent};
use serde_json::Value;

use crate::{
    ProviderError,
    http::PublicDataHttp,
    normalize::{canonical_ecosystem, is_cve_id, parse_time, severity_from_label, string},
};

const GHSA_API: &str = "https://api.github.com/advisories";

#[derive(Clone)]
pub struct GhsaProvider {
    http: PublicDataHttp,
    base_url: String,
}

impl GhsaProvider {
    pub fn new(http: PublicDataHttp) -> Self {
        Self {
            http,
            base_url: GHSA_API.to_owned(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_base_url(http: PublicDataHttp, base_url: String) -> Self {
        Self { http, base_url }
    }

    pub async fn fetch_by_id(&self, ghsa_id: &str) -> Result<Advisory, ProviderError> {
        if !is_ghsa_id(ghsa_id) {
            return Err(ProviderError::InvalidData);
        }
        let url = format!("{}/{ghsa_id}", self.base_url.trim_end_matches('/'));
        let response = self.http.get(&url).await?;
        let advisory = parse_ghsa_advisory(&response.body)?;
        if !advisory.canonical_id.eq_ignore_ascii_case(ghsa_id) {
            return Err(ProviderError::InvalidData);
        }
        Ok(advisory)
    }
}

pub fn parse_ghsa_advisory(bytes: &[u8]) -> Result<Advisory, ProviderError> {
    let value: Value = serde_json::from_slice(bytes)?;
    let id = string(&value, "ghsa_id").ok_or(ProviderError::InvalidData)?;
    if !is_ghsa_id(&id) {
        return Err(ProviderError::InvalidData);
    }
    let cve_id = string(&value, "cve_id");
    let mut aliases = cve_id
        .filter(|value| is_cve_id(value))
        .into_iter()
        .collect::<Vec<_>>();
    let mut affected_ranges = Vec::new();
    let mut fixed_versions = Vec::new();
    if let Some(vulnerabilities) = value.get("vulnerabilities").and_then(Value::as_array) {
        for vulnerability in vulnerabilities {
            let Some(package) = vulnerability.get("package") else {
                continue;
            };
            let Some(name) = string(package, "name") else {
                continue;
            };
            let ecosystem = string(package, "ecosystem")
                .map(|value| canonical_ecosystem(&value))
                .unwrap_or_else(|| "unknown".to_owned());
            let range = string(vulnerability, "vulnerable_version_range");
            let fixed = vulnerability
                .pointer("/first_patched_version/identifier")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if let Some(version) = &fixed {
                fixed_versions.push(version.clone());
            }
            let events = range.as_deref().map(parse_ghsa_range).unwrap_or_else(|| {
                vec![RangeEvent {
                    introduced: None,
                    fixed: fixed.clone(),
                    last_affected: None,
                    limit: None,
                }]
            });
            affected_ranges.push(AffectedRange {
                range_type: Some(
                    if matches!(ecosystem.as_str(), "npm" | "cargo" | "golang") {
                        "SEMVER".to_owned()
                    } else {
                        "ECOSYSTEM".to_owned()
                    },
                ),
                ecosystem,
                package: Some(name),
                source: Some("GitHub Advisory Database".to_owned()),
                events,
            });
        }
    }
    aliases.sort();
    aliases.dedup();
    let now = DateTime::<Utc>::UNIX_EPOCH;
    let updated_at = string(&value, "updated_at")
        .and_then(|date| parse_time(&date))
        .unwrap_or(now);
    let published_at = string(&value, "published_at")
        .and_then(|date| parse_time(&date))
        .unwrap_or(now);
    let source_url = format!("https://github.com/advisories/{id}");
    Ok(Advisory {
        canonical_id: id.clone(),
        title: string(&value, "summary").unwrap_or_else(|| id.clone()),
        summary: string(&value, "summary"),
        summary_model: None,
        description: string(&value, "description"),
        source_attributions: vec![AdvisorySource {
            name: "GitHub Advisory Database".to_owned(),
            url: source_url.clone(),
            license: Some("CC-BY 4.0".to_owned()),
        }],
        aliases,
        affected_ranges,
        fixed_versions,
        cvss: value.pointer("/cvss/score").and_then(Value::as_f64),
        severity: string(&value, "severity").and_then(|severity| severity_from_label(&severity)),
        kev: false,
        epss: None,
        epss_date: None,
        source_urls: vec![source_url],
        source_updated_at: Some(updated_at),
        created_at: published_at,
        updated_at,
    })
}

fn is_ghsa_id(value: &str) -> bool {
    let mut parts = value.split('-');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(prefix), Some(first), Some(second), Some(third), None)
            if prefix.eq_ignore_ascii_case("GHSA")
                && [first, second, third].iter().all(|part| {
                    part.len() == 4
                        && part
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric())
                })
    )
}

fn parse_ghsa_range(expression: &str) -> Vec<RangeEvent> {
    let mut introduced = None;
    let mut fixed = None;
    let mut last_affected = None;
    for token in expression.split(',').map(str::trim) {
        let (operator, version) = if let Some(version) = token.strip_prefix(">=") {
            (">=", version.trim())
        } else if let Some(version) = token.strip_prefix("<=") {
            ("<=", version.trim())
        } else if let Some(version) = token.strip_prefix('<') {
            ("<", version.trim())
        } else if let Some(version) = token.strip_prefix('>') {
            (">", version.trim())
        } else {
            continue;
        };
        if version.is_empty() {
            continue;
        }
        match operator {
            ">=" => introduced = Some(version.to_owned()),
            ">" => introduced = Some(format!(">{version}")),
            "<" => fixed = Some(version.to_owned()),
            "<=" => last_affected = Some(version.to_owned()),
            _ => {}
        }
    }
    if introduced.is_none() && fixed.is_none() && last_affected.is_none() {
        return vec![RangeEvent {
            introduced: None,
            fixed: None,
            last_affected: None,
            limit: None,
        }];
    }
    vec![RangeEvent {
        introduced,
        fixed,
        last_affected,
        limit: None,
    }]
}
