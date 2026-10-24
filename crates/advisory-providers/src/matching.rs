use std::collections::{BTreeMap, BTreeSet};

use security_monitor_core::{Advisory, FindingStatus};
use security_monitor_inventory::{Inventory, InventoryComponent};
use semver::Version;

use crate::normalize::{canonical_ecosystem, normalize_package_name};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingReason {
    AffectedVersion,
    VersionDataPending,
    SourceDisagreement,
    VersionRangeUnverified,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdvisoryFinding {
    pub advisory_id: String,
    pub component_purl: String,
    pub status: FindingStatus,
    pub reason: FindingReason,
    pub fix_version: Option<String>,
    pub evidence_sources: Vec<String>,
}

pub fn evaluate_inventory(advisories: &[Advisory], inventory: &Inventory) -> Vec<AdvisoryFinding> {
    let mut findings = Vec::new();
    for advisory in advisories {
        for component in &inventory.components {
            if let Some(finding) = evaluate_component(advisory, component) {
                findings.push(finding);
            }
        }
    }
    findings.sort_by(|left, right| {
        (&left.advisory_id, &left.component_purl).cmp(&(&right.advisory_id, &right.component_purl))
    });
    findings.dedup_by(|left, right| {
        left.advisory_id == right.advisory_id && left.component_purl == right.component_purl
    });
    findings
}

fn evaluate_component(
    advisory: &Advisory,
    component: &InventoryComponent,
) -> Option<AdvisoryFinding> {
    let mut matching = advisory
        .affected_ranges
        .iter()
        .filter(|range| {
            let Some(package) = range.package.as_deref() else {
                return false;
            };
            if range.ecosystem == "unknown" {
                return normalize_package_name("unknown", package)
                    == normalize_package_name("unknown", &component.name);
            }
            canonical_ecosystem(&range.ecosystem) == canonical_ecosystem(&component.ecosystem)
                && normalize_package_name(&range.ecosystem, package)
                    == normalize_package_name(&component.ecosystem, &component.name)
        })
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return None;
    }
    if matching.iter().any(|range| range.ecosystem != "unknown") {
        matching.retain(|range| range.ecosystem != "unknown");
    }
    let evidence_sources = matching
        .iter()
        .filter_map(|range| range.source.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if component.version.is_none() {
        return Some(candidate(
            advisory,
            component,
            FindingReason::VersionDataPending,
            None,
            evidence_sources,
        ));
    }
    if matching
        .iter()
        .any(|range| range.ecosystem == "unknown" || range.events.is_empty())
    {
        return Some(candidate(
            advisory,
            component,
            FindingReason::VersionDataPending,
            None,
            evidence_sources,
        ));
    }

    let version = component.version.as_deref()?;
    let mut source_results: BTreeMap<String, Option<bool>> = BTreeMap::new();
    for range in matching {
        let source = range
            .source
            .as_deref()
            .unwrap_or("unknown source")
            .to_owned();
        let result = match range.range_type.as_deref() {
            Some("EXACT") => Some(range.events.iter().any(|event| {
                event.introduced.as_deref() == Some(version)
                    || event.last_affected.as_deref() == Some(version)
            })),
            Some("SEMVER") => events_include_version(version, &range.events),
            Some("ECOSYSTEM")
                if matches!(
                    canonical_ecosystem(&range.ecosystem).as_str(),
                    "npm" | "cargo" | "golang"
                ) =>
            {
                events_include_version(version, &range.events)
            }
            None if source == "cve.now"
                && matches!(
                    canonical_ecosystem(&range.ecosystem).as_str(),
                    "npm" | "cargo" | "golang"
                ) =>
            {
                events_include_version(version, &range.events)
            }
            _ => None,
        };
        source_results
            .entry(source)
            .and_modify(|current| *current = union_result(*current, result))
            .or_insert(result);
    }
    let verified = source_results
        .values()
        .flatten()
        .copied()
        .collect::<BTreeSet<_>>();
    if verified.len() > 1 {
        return Some(candidate(
            advisory,
            component,
            FindingReason::SourceDisagreement,
            advisory.fixed_versions.first().cloned(),
            evidence_sources,
        ));
    }
    if source_results.values().any(Option::is_none) {
        return Some(candidate(
            advisory,
            component,
            FindingReason::VersionRangeUnverified,
            advisory.fixed_versions.first().cloned(),
            evidence_sources,
        ));
    }
    if verified.first().copied().unwrap_or(false) {
        Some(candidate(
            advisory,
            component,
            FindingReason::AffectedVersion,
            advisory.fixed_versions.first().cloned(),
            evidence_sources,
        ))
    } else {
        None
    }
}

fn union_result(current: Option<bool>, incoming: Option<bool>) -> Option<bool> {
    match (current, incoming) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), Some(false)) => Some(false),
        _ => None,
    }
}

fn events_include_version(
    version: &str,
    events: &[security_monitor_core::RangeEvent],
) -> Option<bool> {
    let version = parse_version(version)?;
    let mut lower: Option<(Version, bool)> = None;
    let mut included = false;
    let mut saw_introduced = false;
    for event in events {
        if let Some(introduced) = &event.introduced {
            saw_introduced = true;
            lower = Some(if introduced == "0" {
                (Version::new(0, 0, 0), false)
            } else if let Some(exclusive) = introduced.strip_prefix('>') {
                (parse_version(exclusive)?, true)
            } else {
                (parse_version(introduced)?, false)
            });
        }
        if let Some(fixed) = &event.fixed {
            lower.as_ref()?;
            let upper = parse_version(fixed)?;
            included |= lower.as_ref().is_some_and(|(start, exclusive)| {
                lower_includes(&version, start, *exclusive) && version < upper
            });
            lower = None;
        }
        if let Some(last_affected) = &event.last_affected {
            lower.as_ref()?;
            let upper = parse_version(last_affected)?;
            included |= lower.as_ref().is_some_and(|(start, exclusive)| {
                lower_includes(&version, start, *exclusive) && version <= upper
            });
            lower = None;
        }
        if let Some(limit) = &event.limit {
            lower.as_ref()?;
            let upper = parse_version(limit)?;
            included |= lower.as_ref().is_some_and(|(start, exclusive)| {
                lower_includes(&version, start, *exclusive) && version < upper
            });
            lower = None;
        }
    }
    if !saw_introduced {
        return None;
    }
    if let Some((start, exclusive)) = lower {
        included |= lower_includes(&version, &start, exclusive);
    }
    Some(included)
}

fn lower_includes(candidate: &Version, start: &Version, exclusive: bool) -> bool {
    if exclusive {
        candidate > start
    } else {
        candidate >= start
    }
}

fn parse_version(value: &str) -> Option<Version> {
    let value = value.trim().strip_prefix('v').unwrap_or(value.trim());
    Version::parse(value).ok()
}

fn candidate(
    advisory: &Advisory,
    component: &InventoryComponent,
    reason: FindingReason,
    fix_version: Option<String>,
    evidence_sources: Vec<String>,
) -> AdvisoryFinding {
    let status = if reason == FindingReason::AffectedVersion {
        FindingStatus::New
    } else {
        FindingStatus::NeedsReview
    };
    AdvisoryFinding {
        advisory_id: advisory.canonical_id.clone(),
        component_purl: component.purl.clone(),
        status,
        reason,
        fix_version,
        evidence_sources,
    }
}
