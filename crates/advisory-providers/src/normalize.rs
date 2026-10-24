use chrono::{DateTime, Utc};
use security_monitor_core::{Advisory, AdvisorySource, AffectedRange, RangeEvent, Severity};
pub(crate) use security_monitor_correlation::{canonical_ecosystem, normalize_package_name};
use serde_json::Value;

pub(crate) fn cve_now_advisory(value: &Value) -> Result<Advisory, super::ProviderError> {
    let id = string(value, "id").ok_or(super::ProviderError::InvalidData)?;
    let aliases = strings(value.get("aliases"));
    let title = string(value, "title").unwrap_or_else(|| id.clone());
    let summary = value
        .get("summary")
        .and_then(|summary| summary.get("text"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let summary_model = value
        .get("summary")
        .and_then(|summary| summary.get("model"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let description = string(value, "originalDescription");
    let severity_object = value.get("severity");
    let cvss = severity_object
        .and_then(|severity| severity.get("cvss"))
        .and_then(Value::as_f64);
    let severity = value
        .get("statedSeverity")
        .and_then(Value::as_str)
        .and_then(severity_from_label)
        .or_else(|| cvss.and_then(severity_from_score));
    let kev = value
        .pointer("/exploitation/kev")
        .is_some_and(|value| !value.is_null() && value != false);

    let mut affected_ranges = Vec::new();
    let mut fixed_versions = Vec::new();
    if let Some(affected) = value.get("affected").and_then(Value::as_array) {
        for item in affected {
            let Some(package) = string(item, "package").or_else(|| string(item, "product")) else {
                continue;
            };
            let ecosystem = string(item, "ecosystem")
                .map(|ecosystem| canonical_ecosystem(&ecosystem))
                .unwrap_or_else(|| "unknown".to_owned());
            let mut events = Vec::new();
            let mut range_type = None;
            if let Some(ranges) = item.get("ranges").and_then(Value::as_array) {
                for range in ranges {
                    if let Some(value) = string(range, "type") {
                        if range_type
                            .as_deref()
                            .is_some_and(|current| current != value)
                        {
                            range_type = Some("MIXED".to_owned());
                        } else if range_type.is_none() {
                            range_type = Some(value);
                        }
                    }
                    let introduced = string(range, "introduced");
                    let fixed = string(range, "fixed");
                    if let Some(version) = fixed.as_ref() {
                        fixed_versions.push(version.clone());
                    }
                    events.push(RangeEvent {
                        introduced,
                        fixed,
                        last_affected: string(range, "lastAffected"),
                        limit: string(range, "limit"),
                    });
                }
            }
            if let Some(versions) = item.get("versions").and_then(Value::as_array) {
                if events.is_empty() {
                    range_type = Some("EXACT".to_owned());
                }
                for version in versions.iter().filter_map(Value::as_str) {
                    events.push(RangeEvent {
                        introduced: Some(version.to_owned()),
                        fixed: None,
                        last_affected: Some(version.to_owned()),
                        limit: None,
                    });
                }
            }
            affected_ranges.push(AffectedRange {
                ecosystem,
                package: Some(package),
                source: Some("cve.now".to_owned()),
                range_type,
                events,
            });
        }
    }

    let mut source_urls = Vec::new();
    let mut source_attributions = Vec::new();
    if let Some(sources) = value.get("sources").and_then(Value::as_array) {
        for source in sources {
            let Some(url) = string(source, "url").and_then(|url| sanitize_public_url(&url)) else {
                continue;
            };
            source_urls.push(url.clone());
            source_attributions.push(AdvisorySource {
                name: string(source, "name").unwrap_or_else(|| "cve.now source".to_owned()),
                url,
                license: string(source, "license"),
            });
        }
    }
    if let Some(references) = value.get("references").and_then(Value::as_array) {
        for reference in references {
            if let Some(url) = string(reference, "url").and_then(|url| sanitize_public_url(&url)) {
                source_urls.push(url);
            }
        }
    }
    let summary_url = format!("https://cve.now/{id}");
    if !source_urls.contains(&summary_url) {
        source_urls.push(summary_url.clone());
    }
    if !source_attributions
        .iter()
        .any(|source| source.name == "cve.now")
    {
        source_attributions.push(AdvisorySource {
            name: "cve.now".to_owned(),
            url: summary_url,
            license: Some("CC-BY 4.0".to_owned()),
        });
    }

    Ok(Advisory {
        canonical_id: id,
        title,
        summary,
        summary_model,
        description,
        source_attributions,
        aliases,
        affected_ranges,
        fixed_versions,
        cvss,
        severity,
        kev,
        epss: None,
        epss_date: None,
        source_urls,
        source_updated_at: string(value, "modifiedAt").and_then(|date| parse_time(&date)),
        created_at: string(value, "firstSeenAt")
            .and_then(|date| parse_time(&date))
            .unwrap_or(DateTime::<Utc>::UNIX_EPOCH),
        updated_at: string(value, "modifiedAt")
            .and_then(|date| parse_time(&date))
            .or_else(|| string(value, "publishedAt").and_then(|date| parse_time(&date)))
            .unwrap_or(DateTime::<Utc>::UNIX_EPOCH),
    })
}

pub(crate) fn severity_from_label(value: &str) -> Option<Severity> {
    match value.to_ascii_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" | "moderate" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "unknown" | "none" => Some(Severity::Unknown),
        _ => None,
    }
}

pub(crate) fn severity_from_score(score: f64) -> Option<Severity> {
    if !(0.0..=10.0).contains(&score) {
        return None;
    }
    Some(match score {
        9.0..=10.0 => Severity::Critical,
        7.0..9.0 => Severity::High,
        4.0..7.0 => Severity::Medium,
        0.1..4.0 => Severity::Low,
        _ => Severity::Unknown,
    })
}

pub(crate) fn parse_time(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

pub(crate) fn is_cve_id(value: &str) -> bool {
    let mut parts = value.split('-');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some("CVE"), Some(year), Some(number), None)
            if year.len() == 4
                && year.bytes().all(|byte| byte.is_ascii_digit())
                && number.len() >= 4
                && number.bytes().all(|byte| byte.is_ascii_digit())
    )
}

pub(crate) fn sanitize_public_url(value: &str) -> Option<String> {
    let mut url = url::Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return None;
    }
    url.set_username("").ok()?;
    url.set_password(None).ok()?;
    url.set_query(None);
    url.set_fragment(None);
    Some(url.to_string())
}

pub(crate) fn string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

pub(crate) fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}
