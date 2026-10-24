use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use pep440_rs::Version as Pep440Version;
use security_monitor_core::{Advisory, FindingStatus};
use security_monitor_inventory::{Inventory, InventoryComponent};
use semver::Version;

use crate::version::{canonical_ecosystem, normalize_package_name};

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
            Some("SEMVER") => {
                if (canonical_ecosystem(&range.ecosystem) == "golang"
                    && is_go_pseudo_version(version))
                    || (canonical_ecosystem(&range.ecosystem) == "rubygems"
                        && is_ruby_platform_version(version))
                {
                    None
                } else {
                    events_include_semver(version, &range.events)
                }
            }
            Some("ECOSYSTEM") if is_debian_ecosystem(&range.ecosystem) => {
                events_include_debian(version, &range.events)
            }
            Some("ECOSYSTEM") if canonical_ecosystem(&range.ecosystem) == "pypi" => {
                events_include_pep440(version, &range.events)
            }
            Some("ECOSYSTEM")
                if matches!(
                    canonical_ecosystem(&range.ecosystem).as_str(),
                    "npm" | "cargo"
                ) || (canonical_ecosystem(&range.ecosystem) == "golang"
                    && !is_go_pseudo_version(version)) =>
            {
                events_include_semver(version, &range.events)
            }
            None if source == "cve.now" && is_debian_ecosystem(&range.ecosystem) => {
                events_include_debian(version, &range.events)
            }
            None if source == "cve.now"
                && matches!(
                    canonical_ecosystem(&range.ecosystem).as_str(),
                    "npm" | "cargo"
                )
                || (source == "cve.now"
                    && canonical_ecosystem(&range.ecosystem) == "golang"
                    && !is_go_pseudo_version(version)) =>
            {
                events_include_semver(version, &range.events)
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

fn events_include_semver(
    version: &str,
    events: &[security_monitor_core::RangeEvent],
) -> Option<bool> {
    events_include_with(version, events, parse_semver_version)
}

fn events_include_pep440(
    version: &str,
    events: &[security_monitor_core::RangeEvent],
) -> Option<bool> {
    events_include_with(version, events, |value| value.parse::<Pep440Version>().ok())
}

fn events_include_debian(
    version: &str,
    events: &[security_monitor_core::RangeEvent],
) -> Option<bool> {
    events_include_with(version, events, parse_debian_version)
}

fn events_include_with<T: Ord>(
    version: &str,
    events: &[security_monitor_core::RangeEvent],
    parse: impl Fn(&str) -> Option<T>,
) -> Option<bool> {
    let version = parse(version)?;
    let mut lower: Option<(T, bool)> = None;
    let mut included = false;
    let mut saw_introduced = false;
    for event in events {
        if let Some(introduced) = &event.introduced {
            saw_introduced = true;
            lower = Some(if introduced == "0" {
                (parse("0")?, false)
            } else if let Some(exclusive) = introduced.strip_prefix('>') {
                (parse(exclusive)?, true)
            } else {
                (parse(introduced)?, false)
            });
        }
        if let Some(fixed) = &event.fixed {
            lower.as_ref()?;
            let upper = parse(fixed)?;
            included |= lower.as_ref().is_some_and(|(start, exclusive)| {
                lower_includes(&version, start, *exclusive) && version < upper
            });
            lower = None;
        }
        if let Some(last_affected) = &event.last_affected {
            lower.as_ref()?;
            let upper = parse(last_affected)?;
            included |= lower.as_ref().is_some_and(|(start, exclusive)| {
                lower_includes(&version, start, *exclusive) && version <= upper
            });
            lower = None;
        }
        if let Some(limit) = &event.limit {
            lower.as_ref()?;
            let upper = parse(limit)?;
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

fn lower_includes<T: Ord>(candidate: &T, start: &T, exclusive: bool) -> bool {
    if exclusive {
        candidate > start
    } else {
        candidate >= start
    }
}

fn parse_semver_version(value: &str) -> Option<Version> {
    let value = value.trim().strip_prefix('v').unwrap_or(value.trim());
    if value == "0" {
        return Some(Version::new(0, 0, 0));
    }
    Version::parse(value).ok()
}

#[derive(Debug, Clone)]
struct DebianVersion {
    epoch: u64,
    upstream: String,
    revision: String,
}

impl PartialEq for DebianVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for DebianVersion {}

impl PartialOrd for DebianVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DebianVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.epoch
            .cmp(&other.epoch)
            .then_with(|| debian_revision_cmp(&self.upstream, &other.upstream))
            .then_with(|| debian_revision_cmp(&self.revision, &other.revision))
    }
}

fn parse_debian_version(value: &str) -> Option<DebianVersion> {
    let value = value.trim();
    if value.is_empty() || !value.is_ascii() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return None;
    }
    let (epoch, value) = match value.split_once(':') {
        Some((epoch, value)) if !epoch.is_empty() => (epoch.parse().ok()?, value),
        Some(_) => return None,
        None => (0, value),
    };
    let (upstream, revision) = match value.rsplit_once('-') {
        Some((upstream, revision)) if !revision.is_empty() => (upstream, revision),
        Some(_) => return None,
        None => (value, "0"),
    };
    if upstream.is_empty()
        || !upstream.as_bytes()[0].is_ascii_digit()
        || !upstream
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".+~-".contains(&byte))
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".+~".contains(&byte))
    {
        return None;
    }
    Some(DebianVersion {
        epoch,
        upstream: upstream.to_owned(),
        revision: revision.to_owned(),
    })
}

fn debian_revision_cmp(left: &str, right: &str) -> Ordering {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let (mut left_index, mut right_index) = (0, 0);
    loop {
        while (left_index < left.len() && !left[left_index].is_ascii_digit())
            || (right_index < right.len() && !right[right_index].is_ascii_digit())
        {
            let left_byte = left.get(left_index).copied();
            let right_byte = right.get(right_index).copied();
            let order = debian_character_order(left_byte).cmp(&debian_character_order(right_byte));
            if order != Ordering::Equal {
                return order;
            }
            left_index += usize::from(left_byte.is_some());
            right_index += usize::from(right_byte.is_some());
        }

        while left.get(left_index) == Some(&b'0') {
            left_index += 1;
        }
        while right.get(right_index) == Some(&b'0') {
            right_index += 1;
        }
        let left_start = left_index;
        let right_start = right_index;
        while left.get(left_index).is_some_and(u8::is_ascii_digit) {
            left_index += 1;
        }
        while right.get(right_index).is_some_and(u8::is_ascii_digit) {
            right_index += 1;
        }
        let left_length = left_index - left_start;
        let right_length = right_index - right_start;
        match left_length.cmp(&right_length) {
            Ordering::Equal => {}
            ordering => return ordering,
        }
        match left[left_start..left_index].cmp(&right[right_start..right_index]) {
            Ordering::Equal => {}
            ordering => return ordering,
        }
        if left_index == left.len() && right_index == right.len() {
            return Ordering::Equal;
        }
    }
}

fn debian_character_order(value: Option<u8>) -> i32 {
    match value {
        Some(b'~') => -1,
        None => 0,
        Some(value) if value.is_ascii_alphabetic() => i32::from(value),
        Some(value) => i32::from(value) + 256,
    }
}

fn is_debian_ecosystem(ecosystem: &str) -> bool {
    let ecosystem = canonical_ecosystem(ecosystem);
    ecosystem == "debian" || ecosystem.starts_with("debian:")
}

fn is_go_pseudo_version(value: &str) -> bool {
    let value = value.trim().strip_prefix('v').unwrap_or(value.trim());
    let value = value.strip_suffix("+incompatible").unwrap_or(value);
    let mut suffix = value.rsplitn(3, '-');
    let Some(commit) = suffix.next() else {
        return false;
    };
    let Some(timestamp_segment) = suffix.next() else {
        return false;
    };
    let Some(timestamp) = timestamp_segment.rsplit('.').next() else {
        return false;
    };
    commit.len() == 12
        && commit.bytes().all(|byte| byte.is_ascii_hexdigit())
        && timestamp.len() == 14
        && timestamp.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_ruby_platform_version(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    [
        "-java",
        "-x86_64-linux",
        "-x86_64-linux-musl",
        "-x86_64-darwin",
        "-arm64-darwin",
        "-aarch64-linux",
        "-x64-mingw-ucrt",
        "-x64-mingw32",
        "-universal-java",
    ]
    .iter()
    .any(|platform| value.ends_with(platform))
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
