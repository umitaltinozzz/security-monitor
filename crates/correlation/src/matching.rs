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
                        && (version.contains('-') || version.contains('+')))
                {
                    None
                } else {
                    events_include_semver(version, &range.events)
                }
            }
            Some("ECOSYSTEM") if is_deb_compatible_ecosystem(&range.ecosystem) => {
                events_include_debian(version, &range.events)
            }
            Some("ECOSYSTEM") if is_rpm_ecosystem(&range.ecosystem) => {
                events_include_rpm(version, &range.events)
            }
            Some("ECOSYSTEM") if is_apk_ecosystem(&range.ecosystem) => {
                events_include_apk(version, &range.events)
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
            None if source == "cve.now" && is_deb_compatible_ecosystem(&range.ecosystem) => {
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

fn events_include_rpm(version: &str, events: &[security_monitor_core::RangeEvent]) -> Option<bool> {
    events_include_with(version, events, parse_rpm_evr)
}

fn events_include_apk(version: &str, events: &[security_monitor_core::RangeEvent]) -> Option<bool> {
    events_include_with(version, events, parse_apk_version)
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

fn is_deb_compatible_ecosystem(ecosystem: &str) -> bool {
    let ecosystem = canonical_ecosystem(ecosystem);
    ecosystem == "debian"
        || ecosystem.starts_with("debian:")
        || ecosystem == "ubuntu"
        || ecosystem.starts_with("ubuntu:")
}

fn is_rpm_ecosystem(ecosystem: &str) -> bool {
    let ecosystem = canonical_ecosystem(ecosystem);
    ecosystem.starts_with("almalinux:")
        || ecosystem.starts_with("rocky linux:")
        || ecosystem.starts_with("red hat:")
}

fn is_apk_ecosystem(ecosystem: &str) -> bool {
    canonical_ecosystem(ecosystem).starts_with("alpine:")
}

#[derive(Debug, Clone)]
struct RpmEvr {
    epoch: u64,
    version: String,
    release: String,
}

impl PartialEq for RpmEvr {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for RpmEvr {}

impl PartialOrd for RpmEvr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RpmEvr {
    fn cmp(&self, other: &Self) -> Ordering {
        self.epoch
            .cmp(&other.epoch)
            .then_with(|| rpmvercmp(&self.version, &other.version))
            .then_with(|| rpmvercmp(&self.release, &other.release))
    }
}

fn parse_rpm_evr(value: &str) -> Option<RpmEvr> {
    let value = value.trim();
    if value.is_empty() || !value.is_ascii() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return None;
    }
    let (epoch, value) = match value.split_once(':') {
        Some((epoch, value)) if !epoch.is_empty() && epoch.bytes().all(|b| b.is_ascii_digit()) => {
            (epoch.parse().ok()?, value)
        }
        Some(_) => return None,
        None => (0, value),
    };
    let (version, release) = match value.split_once('-') {
        Some((version, release)) => (version, release),
        None => (value, ""),
    };
    if version.is_empty()
        || version.contains(':')
        || version.bytes().any(|byte| byte.is_ascii_whitespace())
        || release.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return None;
    }
    Some(RpmEvr {
        epoch,
        version: version.to_owned(),
        release: release.to_owned(),
    })
}

/// RPM's segment comparator: tilde is older than everything, caret is newer than the
/// base version but older than the next regular segment, and numeric runs outrank alpha.
fn rpmvercmp(left: &str, right: &str) -> Ordering {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let (mut left_index, mut right_index) = (0, 0);
    loop {
        while left
            .get(left_index)
            .is_some_and(|byte| !byte.is_ascii_alphanumeric() && *byte != b'~' && *byte != b'^')
        {
            left_index += 1;
        }
        while right
            .get(right_index)
            .is_some_and(|byte| !byte.is_ascii_alphanumeric() && *byte != b'~' && *byte != b'^')
        {
            right_index += 1;
        }
        match (left.get(left_index), right.get(right_index)) {
            (Some(b'~'), Some(b'~')) => {
                left_index += 1;
                right_index += 1;
                continue;
            }
            (Some(b'~'), _) => return Ordering::Less,
            (_, Some(b'~')) => return Ordering::Greater,
            (Some(b'^'), None) => return Ordering::Greater,
            (None, Some(b'^')) => return Ordering::Less,
            (Some(b'^'), Some(b'^')) => {
                left_index += 1;
                right_index += 1;
                continue;
            }
            (Some(b'^'), _) => return Ordering::Less,
            (_, Some(b'^')) => return Ordering::Greater,
            (None, None) => return Ordering::Equal,
            (None, _) => return Ordering::Less,
            (_, None) => return Ordering::Greater,
            _ => {}
        }

        let numeric = left[left_index].is_ascii_digit();
        let left_start = left_index;
        let right_start = right_index;
        if numeric {
            while left.get(left_index).is_some_and(u8::is_ascii_digit) {
                left_index += 1;
            }
            while right.get(right_index).is_some_and(u8::is_ascii_digit) {
                right_index += 1;
            }
        } else {
            while left.get(left_index).is_some_and(u8::is_ascii_alphabetic) {
                left_index += 1;
            }
            while right.get(right_index).is_some_and(u8::is_ascii_alphabetic) {
                right_index += 1;
            }
        }
        if left_start == left_index {
            return Ordering::Less;
        }
        if right_start == right_index {
            return if numeric {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        let mut left_segment = &left[left_start..left_index];
        let mut right_segment = &right[right_start..right_index];
        if numeric {
            while left_segment.first() == Some(&b'0') {
                left_segment = &left_segment[1..];
            }
            while right_segment.first() == Some(&b'0') {
                right_segment = &right_segment[1..];
            }
            match left_segment.len().cmp(&right_segment.len()) {
                Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        match left_segment.cmp(right_segment) {
            Ordering::Equal => {}
            ordering => return ordering,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ApkVersion(Vec<ApkToken>);

#[derive(Debug, Clone, PartialEq, Eq)]
enum ApkToken {
    InitialNumber(String),
    Number(String),
    Letter(u8),
    Suffix(u8),
    SuffixNumber(String),
    CommitHash(String),
    Revision(String),
}

impl ApkToken {
    fn kind(&self) -> u8 {
        match self {
            Self::InitialNumber(_) => 0,
            Self::Number(_) => 1,
            Self::Letter(_) => 2,
            Self::Suffix(_) => 3,
            Self::SuffixNumber(_) => 4,
            Self::CommitHash(_) => 5,
            Self::Revision(_) => 6,
        }
    }
}

impl PartialOrd for ApkVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ApkVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        for (left, right) in self.0.iter().zip(&other.0) {
            if left.kind() != right.kind() {
                if let ApkToken::Suffix(suffix) = left
                    && *suffix < APK_SUFFIX_NONE
                {
                    return Ordering::Less;
                }
                if let ApkToken::Suffix(suffix) = right
                    && *suffix < APK_SUFFIX_NONE
                {
                    return Ordering::Greater;
                }
                return right.kind().cmp(&left.kind());
            }
            let ordering = match (left, right) {
                (ApkToken::InitialNumber(left), ApkToken::InitialNumber(right))
                | (ApkToken::SuffixNumber(left), ApkToken::SuffixNumber(right))
                | (ApkToken::Revision(left), ApkToken::Revision(right)) => {
                    numeric_string_cmp(left, right)
                }
                (ApkToken::Number(left), ApkToken::Number(right)) => {
                    if left.starts_with('0') || right.starts_with('0') {
                        left.cmp(right)
                    } else {
                        numeric_string_cmp(left, right)
                    }
                }
                (ApkToken::Letter(left), ApkToken::Letter(right)) => left.cmp(right),
                (ApkToken::Suffix(left), ApkToken::Suffix(right)) => left.cmp(right),
                (ApkToken::CommitHash(left), ApkToken::CommitHash(right)) => left.cmp(right),
                _ => Ordering::Equal,
            };
            if ordering != Ordering::Equal {
                return ordering;
            }
        }
        let left = self.0.get(self.0.len().min(other.0.len()));
        let right = other.0.get(self.0.len().min(other.0.len()));
        match (left, right) {
            (None, None) => Ordering::Equal,
            (None, Some(ApkToken::Suffix(suffix))) if *suffix < APK_SUFFIX_NONE => {
                Ordering::Greater
            }
            (Some(ApkToken::Suffix(suffix)), None) if *suffix < APK_SUFFIX_NONE => Ordering::Less,
            (None, Some(token)) => token.kind().cmp(&7),
            (Some(token), None) => 7_u8.cmp(&token.kind()),
            _ => Ordering::Equal,
        }
    }
}

const APK_SUFFIX_NONE: u8 = 4;

fn numeric_string_cmp(left: &str, right: &str) -> Ordering {
    let left = left.trim_start_matches('0');
    let right = right.trim_start_matches('0');
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn parse_apk_version(value: &str) -> Option<ApkVersion> {
    if value.is_empty()
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return None;
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    let initial_start = index;
    while bytes.get(index).is_some_and(u8::is_ascii_digit) {
        index += 1;
    }
    if index == initial_start {
        return None;
    }
    let mut tokens = vec![ApkToken::InitialNumber(
        value[initial_start..index].to_owned(),
    )];
    let mut previous_kind = 0_u8;
    while index < bytes.len() {
        match bytes[index] {
            b'a'..=b'z' if previous_kind <= 1 => {
                tokens.push(ApkToken::Letter(bytes[index]));
                index += 1;
                previous_kind = 2;
            }
            b'.' if previous_kind <= 1 => {
                index += 1;
                let start = index;
                while bytes.get(index).is_some_and(u8::is_ascii_digit) {
                    index += 1;
                }
                if start == index {
                    return None;
                }
                tokens.push(ApkToken::Number(value[start..index].to_owned()));
                previous_kind = 1;
            }
            b'0'..=b'9' if previous_kind == 0 || previous_kind == 1 || previous_kind == 3 => {
                let start = index;
                while bytes.get(index).is_some_and(u8::is_ascii_digit) {
                    index += 1;
                }
                let token = if previous_kind == 3 {
                    ApkToken::SuffixNumber(value[start..index].to_owned())
                } else {
                    ApkToken::Number(value[start..index].to_owned())
                };
                tokens.push(token);
                previous_kind = if previous_kind == 3 { 4 } else { 1 };
            }
            b'_' if previous_kind <= 4 => {
                index += 1;
                let start = index;
                while bytes.get(index).is_some_and(u8::is_ascii_lowercase) {
                    index += 1;
                }
                let suffix = match &value[start..index] {
                    "alpha" => 0,
                    "beta" => 1,
                    "pre" => 2,
                    "rc" => 3,
                    "cvs" => 5,
                    "svn" => 6,
                    "git" => 7,
                    "hg" => 8,
                    "p" => 9,
                    _ => return None,
                };
                tokens.push(ApkToken::Suffix(suffix));
                previous_kind = 3;
            }
            b'~' if previous_kind < 5 => {
                index += 1;
                let start = index;
                while bytes.get(index).is_some_and(u8::is_ascii_hexdigit) {
                    index += 1;
                }
                if start == index {
                    return None;
                }
                tokens.push(ApkToken::CommitHash(value[start..index].to_owned()));
                previous_kind = 5;
            }
            b'-' if previous_kind < 6 && bytes.get(index..index + 2) == Some(b"-r") => {
                index += 2;
                let start = index;
                while bytes.get(index).is_some_and(u8::is_ascii_digit) {
                    index += 1;
                }
                if start == index {
                    return None;
                }
                tokens.push(ApkToken::Revision(value[start..index].to_owned()));
                previous_kind = 6;
            }
            _ => return None,
        }
    }
    Some(ApkVersion(tokens))
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

#[cfg(test)]
mod debian_version_tests {
    use std::cmp::Ordering;

    use proptest::{prelude::*, test_runner::RngSeed};
    use serde::Deserialize;

    use super::parse_debian_version;

    #[derive(Deserialize)]
    struct ComparisonFixture {
        left: String,
        right: String,
        ordering: String,
    }

    fn generated_debian_version() -> impl Strategy<Value = String> {
        (
            0_u16..5,
            0_u16..100,
            0_u16..30,
            0_u16..8,
            prop_oneof![Just(""), Just("~rc1"), Just("~beta2"), Just("+deb1")],
        )
            .prop_map(|(epoch, major, patch, revision, suffix)| {
                format!("{epoch}:{major}.{patch}{suffix}-{revision}")
            })
    }

    #[test]
    fn comparator_matches_recorded_dpkg_compare_versions_results() {
        let fixtures: Vec<ComparisonFixture> = serde_json::from_str(include_str!(
            "../../../tests/fixtures/correlation/debian-version-order.json"
        ))
        .expect("dpkg comparison fixtures are valid JSON");
        for fixture in fixtures {
            let left = parse_debian_version(&fixture.left).expect("left Debian version parses");
            let right = parse_debian_version(&fixture.right).expect("right Debian version parses");
            let expected = match fixture.ordering.as_str() {
                "less" => Ordering::Less,
                "equal" => Ordering::Equal,
                "greater" => Ordering::Greater,
                _ => panic!("unknown comparison fixture result"),
            };
            assert_eq!(
                left.cmp(&right),
                expected,
                "{} vs {}",
                fixture.left,
                fixture.right
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 256,
            rng_seed: RngSeed::Fixed(0x5ec0_2026),
            ..ProptestConfig::default()
        })]

        #[test]
        fn generated_versions_obey_reflexivity_and_antisymmetry(
            left in generated_debian_version(),
            right in generated_debian_version(),
        ) {
            let left = parse_debian_version(&left).expect("generated left version parses");
            let right = parse_debian_version(&right).expect("generated right version parses");
            prop_assert_eq!(left.cmp(&left), Ordering::Equal);
            prop_assert_eq!(left.cmp(&right), right.cmp(&left).reverse());
        }

        #[test]
        fn generated_versions_obey_transitivity(
            first in generated_debian_version(),
            second in generated_debian_version(),
            third in generated_debian_version(),
        ) {
            let first = parse_debian_version(&first).expect("generated first version parses");
            let second = parse_debian_version(&second).expect("generated second version parses");
            let third = parse_debian_version(&third).expect("generated third version parses");
            if first <= second && second <= third {
                prop_assert!(first <= third);
            }
        }
    }
}

#[cfg(test)]
mod rpm_version_tests {
    use std::cmp::Ordering;

    use proptest::{prelude::*, test_runner::RngSeed};
    use serde::Deserialize;

    use super::parse_rpm_evr;

    #[derive(Deserialize)]
    struct ComparisonFixture {
        left: String,
        right: String,
        ordering: String,
    }

    fn generated_rpm_evr() -> impl Strategy<Value = String> {
        (
            0_u16..5,
            0_u16..100,
            0_u16..30,
            0_u16..12,
            prop_oneof![Just(""), Just("~rc1"), Just("^git1"), Just(".el9")],
        )
            .prop_map(|(epoch, major, minor, release, suffix)| {
                format!("{epoch}:{major}.{minor}{suffix}-{release}.el9")
            })
    }

    #[test]
    fn comparator_matches_recorded_rpm_ordering_results() {
        let fixtures: Vec<ComparisonFixture> = serde_json::from_str(include_str!(
            "../../../tests/fixtures/correlation/rpm-version-order.json"
        ))
        .expect("RPM comparison fixtures are valid JSON");
        for fixture in fixtures {
            let left = parse_rpm_evr(&fixture.left).expect("left RPM EVR parses");
            let right = parse_rpm_evr(&fixture.right).expect("right RPM EVR parses");
            let expected = match fixture.ordering.as_str() {
                "less" => Ordering::Less,
                "equal" => Ordering::Equal,
                "greater" => Ordering::Greater,
                _ => panic!("unknown comparison fixture result"),
            };
            assert_eq!(
                left.cmp(&right),
                expected,
                "{} vs {}",
                fixture.left,
                fixture.right
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 256,
            rng_seed: RngSeed::Fixed(0x5ec0_2027),
            ..ProptestConfig::default()
        })]

        #[test]
        fn generated_versions_obey_reflexivity_and_antisymmetry(
            left in generated_rpm_evr(),
            right in generated_rpm_evr(),
        ) {
            let left = parse_rpm_evr(&left).expect("generated left RPM EVR parses");
            let right = parse_rpm_evr(&right).expect("generated right RPM EVR parses");
            prop_assert_eq!(left.cmp(&left), Ordering::Equal);
            prop_assert_eq!(left.cmp(&right), right.cmp(&left).reverse());
        }

        #[test]
        fn generated_versions_obey_transitivity(
            first in generated_rpm_evr(),
            second in generated_rpm_evr(),
            third in generated_rpm_evr(),
        ) {
            let first = parse_rpm_evr(&first).expect("generated first RPM EVR parses");
            let second = parse_rpm_evr(&second).expect("generated second RPM EVR parses");
            let third = parse_rpm_evr(&third).expect("generated third RPM EVR parses");
            if first <= second && second <= third {
                prop_assert!(first <= third);
            }
        }
    }
}

#[cfg(test)]
mod apk_version_tests {
    use std::cmp::Ordering;

    use proptest::{prelude::*, test_runner::RngSeed};
    use serde::Deserialize;

    use super::parse_apk_version;

    #[derive(Deserialize)]
    struct ComparisonFixture {
        left: String,
        right: String,
        ordering: String,
    }

    fn generated_apk_version() -> impl Strategy<Value = String> {
        (
            0_u16..10,
            0_u16..40,
            0_u16..30,
            prop_oneof![
                Just(""),
                Just("_alpha1"),
                Just("_beta2"),
                Just("_rc1"),
                Just("_p1"),
                Just("~abcdef"),
                Just("-r1"),
                Just(".01"),
            ],
        )
            .prop_map(|(major, minor, patch, suffix)| format!("{major}.{minor}.{patch}{suffix}"))
    }

    #[test]
    fn comparator_matches_recorded_apk_ordering_results() {
        let fixtures: Vec<ComparisonFixture> = serde_json::from_str(include_str!(
            "../../../tests/fixtures/correlation/apk-version-order.json"
        ))
        .expect("APK comparison fixtures are valid JSON");
        for fixture in fixtures {
            let left = parse_apk_version(&fixture.left).expect("left APK version parses");
            let right = parse_apk_version(&fixture.right).expect("right APK version parses");
            let expected = match fixture.ordering.as_str() {
                "less" => Ordering::Less,
                "equal" => Ordering::Equal,
                "greater" => Ordering::Greater,
                _ => panic!("unknown comparison fixture result"),
            };
            assert_eq!(
                left.cmp(&right),
                expected,
                "{} vs {}",
                fixture.left,
                fixture.right
            );
        }
    }

    #[test]
    fn invalid_apk_versions_are_not_compared() {
        for value in [
            "",
            "v3.20",
            "3..20",
            "3.20_alpha0suffix",
            "3.20~",
            "3.20-rx",
        ] {
            assert!(parse_apk_version(value).is_none(), "{value}");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 256,
            rng_seed: RngSeed::Fixed(0x5ec0_2028),
            ..ProptestConfig::default()
        })]

        #[test]
        fn generated_versions_obey_reflexivity_and_antisymmetry(
            left in generated_apk_version(),
            right in generated_apk_version(),
        ) {
            let left = parse_apk_version(&left).expect("generated left APK version parses");
            let right = parse_apk_version(&right).expect("generated right APK version parses");
            prop_assert_eq!(left.cmp(&left), Ordering::Equal);
            prop_assert_eq!(left.cmp(&right), right.cmp(&left).reverse());
        }

        #[test]
        fn generated_versions_obey_transitivity(
            first in generated_apk_version(),
            second in generated_apk_version(),
            third in generated_apk_version(),
        ) {
            let first = parse_apk_version(&first).expect("generated first APK version parses");
            let second = parse_apk_version(&second).expect("generated second APK version parses");
            let third = parse_apk_version(&third).expect("generated third APK version parses");
            if first <= second && second <= third {
                prop_assert!(first <= third);
            }
        }
    }
}
