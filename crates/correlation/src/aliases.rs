use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use security_monitor_core::{Advisory, Severity};

#[derive(Debug, Clone, Default)]
pub struct AliasMerger {
    records: Vec<Advisory>,
}

impl AliasMerger {
    pub fn new(records: impl IntoIterator<Item = Advisory>) -> Self {
        let mut merger = Self::default();
        merger.extend(records);
        merger
    }

    pub fn merge(&mut self, incoming: Advisory) {
        let mut merged = incoming;
        let mut index = 0;
        while index < self.records.len() {
            if aliases_of(&self.records[index]).is_disjoint(&aliases_of(&merged)) {
                index += 1;
                continue;
            }
            let existing = self.records.remove(index);
            merged = merge_record(existing, merged);
            index = 0;
        }
        normalize_record(&mut merged);
        self.records.push(merged);
        self.records.sort_by(|left, right| {
            left.canonical_id
                .cmp(&right.canonical_id)
                .then_with(|| aliases_of(left).cmp(&aliases_of(right)))
        });
    }

    pub fn extend(&mut self, advisories: impl IntoIterator<Item = Advisory>) {
        let mut advisories = advisories.into_iter().collect::<Vec<_>>();
        advisories.sort_by(|left, right| {
            preferred_id(&left.canonical_id)
                .cmp(&preferred_id(&right.canonical_id))
                .then_with(|| {
                    left.canonical_id
                        .to_ascii_uppercase()
                        .cmp(&right.canonical_id.to_ascii_uppercase())
                })
        });
        for advisory in advisories {
            self.merge(advisory);
        }
    }

    pub fn records(&self) -> &[Advisory] {
        &self.records
    }

    pub fn into_records(self) -> Vec<Advisory> {
        self.records
    }
}

fn aliases_of(advisory: &Advisory) -> BTreeSet<String> {
    std::iter::once(advisory.canonical_id.as_str())
        .chain(advisory.aliases.iter().map(String::as_str))
        .map(|id| id.trim().to_ascii_uppercase())
        .filter(|id| !id.is_empty())
        .collect()
}

fn merge_record(mut existing: Advisory, incoming: Advisory) -> Advisory {
    let ids = aliases_of(&existing)
        .into_iter()
        .chain(aliases_of(&incoming))
        .collect::<BTreeSet<_>>();
    let canonical_id = [existing.canonical_id.trim(), incoming.canonical_id.trim()]
        .into_iter()
        .filter(|id| !id.is_empty())
        .min_by(|left, right| compare_canonical_ids(left, right))
        .map(str::to_owned)
        .or_else(|| {
            ids.iter()
                .min_by(|left, right| compare_canonical_ids(left, right))
                .cloned()
        })
        .unwrap_or_default();
    existing.canonical_id = canonical_id.clone();
    existing.aliases = ids
        .into_iter()
        .filter(|id| id != &canonical_id.to_ascii_uppercase())
        .collect();

    existing.title = choose_text(&existing.title, &incoming.title).unwrap_or_default();
    let summaries = [
        (
            existing.summary.as_deref(),
            existing.summary_model.as_deref(),
        ),
        (
            incoming.summary.as_deref(),
            incoming.summary_model.as_deref(),
        ),
    ];
    if let Some((summary, model)) = summaries
        .into_iter()
        .filter_map(|(summary, model)| summary.map(|summary| (summary, model)))
        .min_by(|left, right| left.cmp(right))
    {
        existing.summary = Some(summary.to_owned());
        existing.summary_model = model.map(str::to_owned);
    }
    existing.description = choose_optional_text(
        existing.description.as_deref(),
        incoming.description.as_deref(),
    );

    existing.affected_ranges.extend(incoming.affected_ranges);
    existing.affected_ranges.sort();
    existing.affected_ranges.dedup();
    existing.fixed_versions.extend(incoming.fixed_versions);
    existing.fixed_versions.sort();
    existing.fixed_versions.dedup();
    existing.source_urls.extend(incoming.source_urls);
    existing.source_urls.sort();
    existing.source_urls.dedup();
    existing
        .source_attributions
        .extend(incoming.source_attributions);
    existing.source_attributions.sort();
    existing.source_attributions.dedup();

    existing.cvss = [existing.cvss, incoming.cvss]
        .into_iter()
        .flatten()
        .filter(|score| score.is_finite() && (0.0..=10.0).contains(score))
        .max_by(f64::total_cmp);
    existing.severity = [existing.severity, incoming.severity]
        .into_iter()
        .flatten()
        .max_by_key(severity_rank);
    existing.kev |= incoming.kev;
    merge_epss(&mut existing, incoming.epss, incoming.epss_date);
    existing.source_updated_at = latest(existing.source_updated_at, incoming.source_updated_at);
    existing.created_at = existing.created_at.min(incoming.created_at);
    existing.updated_at = existing.updated_at.max(incoming.updated_at);
    existing
}

fn normalize_record(record: &mut Advisory) {
    record.canonical_id = record.canonical_id.trim().to_owned();
    let canonical = record.canonical_id.to_ascii_uppercase();
    record.aliases = aliases_of(record)
        .into_iter()
        .filter(|alias| alias != &canonical)
        .collect();
    record.affected_ranges.sort();
    record.affected_ranges.dedup();
    record.fixed_versions.sort();
    record.fixed_versions.dedup();
    record.source_urls.sort();
    record.source_urls.dedup();
    record.source_attributions.sort();
    record.source_attributions.dedup();
}

fn compare_canonical_ids(left: &str, right: &str) -> std::cmp::Ordering {
    preferred_id(left)
        .cmp(&preferred_id(right))
        .then_with(|| left.to_ascii_uppercase().cmp(&right.to_ascii_uppercase()))
        .then_with(|| left.cmp(right))
}

fn preferred_id(left: &str) -> u8 {
    let id = left.trim().to_ascii_uppercase();
    if id.starts_with("CVE-") {
        0
    } else if id.starts_with("GHSA-") {
        1
    } else if id.starts_with("OSV-") {
        2
    } else {
        3
    }
}

fn choose_text(left: &str, right: &str) -> Option<String> {
    choose_optional_text(
        (!left.trim().is_empty()).then_some(left),
        (!right.trim().is_empty()).then_some(right),
    )
}

fn choose_optional_text(left: Option<&str>, right: Option<&str>) -> Option<String> {
    [left, right]
        .into_iter()
        .flatten()
        .filter(|text| !text.trim().is_empty())
        .min()
        .map(str::to_owned)
}

fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Unknown => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn merge_epss(
    record: &mut Advisory,
    incoming_score: Option<f64>,
    incoming_date: Option<DateTime<Utc>>,
) {
    let current_date = record.epss_date;
    match (current_date, incoming_date) {
        (None, Some(date)) => {
            if let Some(score) = valid_epss(incoming_score) {
                record.epss = Some(score);
                record.epss_date = Some(date);
            }
        }
        (Some(current), Some(incoming)) if incoming > current => {
            if let Some(score) = valid_epss(incoming_score) {
                record.epss = Some(score);
                record.epss_date = Some(incoming);
            }
        }
        (Some(current), Some(incoming)) if incoming == current => {
            if let Some(score) = valid_epss(incoming_score) {
                record.epss = valid_epss(record.epss)
                    .into_iter()
                    .chain(Some(score))
                    .max_by(f64::total_cmp);
            }
        }
        (None, None) => {
            record.epss = valid_epss(record.epss)
                .into_iter()
                .chain(valid_epss(incoming_score))
                .max_by(f64::total_cmp);
        }
        _ => {}
    }
}

fn valid_epss(score: Option<f64>) -> Option<f64> {
    score.filter(|value| value.is_finite() && (0.0..=1.0).contains(value))
}

fn latest(left: Option<DateTime<Utc>>, right: Option<DateTime<Utc>>) -> Option<DateTime<Utc>> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}
