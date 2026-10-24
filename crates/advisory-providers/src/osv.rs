use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use security_monitor_core::{Advisory, AdvisorySource, AffectedRange, RangeEvent};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tempfile::NamedTempFile;
use zip::ZipArchive;

use crate::{
    ProviderError,
    cache::atomic_write,
    http::PublicDataHttp,
    normalize::{canonical_ecosystem, normalize_package_name, parse_time, severity_from_label},
};

const OSV_DUMP_BASE: &str = "https://osv-vulnerabilities.storage.googleapis.com";
const MAX_OSV_ARCHIVE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_OSV_EXPANDED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_OSV_ARCHIVE_ENTRIES: usize = 500_000;
const MAX_OSV_PATH_BYTES: usize = 1024;
const MAX_OSV_PATH_DEPTH: usize = 16;
static OSV_UPDATE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsvUpdateStatus {
    pub ecosystem: String,
    pub updated_at: Option<DateTime<Utc>>,
    pub stale: bool,
    pub error: Option<String>,
    #[serde(default)]
    pub consecutive_failures: u32,
    #[serde(default)]
    pub retry_after_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct OsvDatabaseUpdater {
    http: PublicDataHttp,
    base_url: String,
}

#[derive(Debug, Clone)]
pub struct OsvDatabase {
    by_package: HashMap<(String, String), Vec<Advisory>>,
    status: OsvUpdateStatus,
}

#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    summary: Option<String>,
    details: Option<String>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    references: Vec<OsvReference>,
    #[serde(default)]
    severity: Vec<Value>,
    #[serde(default)]
    database_specific: Value,
    modified: Option<String>,
    published: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    package: OsvPackage,
    #[serde(default)]
    ranges: Vec<OsvRange>,
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct OsvPackage {
    ecosystem: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    range_type: Option<String>,
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
    limit: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvReference {
    url: String,
}

impl OsvDatabaseUpdater {
    pub fn new(http: PublicDataHttp) -> Self {
        Self {
            http,
            base_url: OSV_DUMP_BASE.to_owned(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_base_url(http: PublicDataHttp, base_url: String) -> Self {
        Self { http, base_url }
    }

    pub async fn update_ecosystems(
        &self,
        cache_root: impl AsRef<Path>,
        ecosystems: impl IntoIterator<Item = String>,
    ) -> Result<Vec<OsvUpdateStatus>, ProviderError> {
        let cache_root = cache_root.as_ref().to_path_buf();
        fs::create_dir_all(&cache_root).map_err(ProviderError::Io)?;
        let _guard = OSV_UPDATE_LOCK.lock().await;
        let mut statuses = Vec::new();
        let mut seen = Vec::new();
        for ecosystem in ecosystems {
            let canonical = canonical_ecosystem(&ecosystem);
            if seen.contains(&canonical) {
                continue;
            }
            seen.push(canonical.clone());
            let Some(slug) = ecosystem_slug(&canonical) else {
                statuses.push(OsvUpdateStatus {
                    ecosystem: canonical,
                    updated_at: None,
                    stale: true,
                    error: Some("unsupported ecosystem".to_owned()),
                    ..OsvUpdateStatus::default()
                });
                continue;
            };
            statuses.push(self.update_one(&cache_root, &canonical, slug).await?);
        }
        Ok(statuses)
    }

    async fn update_one(
        &self,
        root: &Path,
        ecosystem: &str,
        slug: &str,
    ) -> Result<OsvUpdateStatus, ProviderError> {
        let target = root.join(slug);
        let archive = root.join(format!(".{slug}-download.zip"));
        let backup = root.join(format!(".{slug}-previous"));
        if !target.exists() && backup.exists() {
            fs::rename(&backup, &target).map_err(ProviderError::Io)?;
        }
        let previous = read_update_status(root, &target, slug)?;
        if let Some(status) = previous.as_ref().filter(|status| {
            status.stale
                && status
                    .retry_after_at
                    .is_some_and(|until| Utc::now() < until)
        }) {
            return Ok(status.clone());
        }
        let url = format!("{}/{slug}/all.zip", self.base_url.trim_end_matches('/'));
        let result = self
            .http
            .download_to(&url, &archive, MAX_OSV_ARCHIVE_BYTES)
            .await;
        if let Err(error) = result {
            let _ = fs::remove_file(&archive);
            let stale_status = failure_status(ecosystem, previous, &error);
            write_update_status(root, &target, slug, &stale_status)?;
            return Ok(stale_status);
        }

        let stage = root.join(format!(".{slug}-staging"));
        if stage.exists() {
            fs::remove_dir_all(&stage).map_err(ProviderError::Io)?;
        }
        fs::create_dir_all(&stage).map_err(ProviderError::Io)?;
        let archive_for_extract = archive.clone();
        let stage_for_extract = stage.clone();
        let extract_result = tokio::task::spawn_blocking(move || {
            extract_osv_archive(&archive_for_extract, &stage_for_extract)
        })
        .await
        .map_err(|_| ProviderError::InvalidData)?;
        if let Err(error) = extract_result {
            let _ = fs::remove_dir_all(&stage);
            let _ = fs::remove_file(&archive);
            let stale_status = failure_status(ecosystem, previous, &error);
            write_update_status(root, &target, slug, &stale_status)?;
            return if target.is_dir() {
                Ok(stale_status)
            } else {
                Err(error)
            };
        }
        if let Err(error) = install_scanner_archive(root, slug, &archive) {
            let _ = fs::remove_dir_all(&stage);
            let _ = fs::remove_file(&archive);
            let stale_status = failure_status(ecosystem, previous, &error);
            write_update_status(root, &target, slug, &stale_status)?;
            return Ok(stale_status);
        }
        let fetched_at = Utc::now();
        let metadata = OsvUpdateStatus {
            ecosystem: ecosystem.to_owned(),
            updated_at: Some(fetched_at),
            stale: false,
            error: None,
            consecutive_failures: 0,
            retry_after_at: None,
        };
        atomic_write(
            &stage.join(".secmon-cache.json"),
            &serde_json::to_vec(&metadata)?,
        )?;

        if backup.exists() {
            fs::remove_dir_all(&backup).map_err(ProviderError::Io)?;
        }
        let moved_old = target.exists();
        if moved_old {
            fs::rename(&target, &backup).map_err(ProviderError::Io)?;
        }
        if let Err(error) = fs::rename(&stage, &target) {
            if moved_old {
                let _ = fs::rename(&backup, &target);
            }
            let _ = fs::remove_dir_all(&stage);
            let _ = fs::remove_file(&archive);
            return Err(ProviderError::Io(error));
        }
        if moved_old {
            fs::remove_dir_all(&backup).map_err(ProviderError::Io)?;
        }
        fs::remove_file(&archive).map_err(ProviderError::Io)?;
        write_update_status(root, &target, slug, &metadata)?;
        Ok(metadata)
    }
}

fn install_scanner_archive(root: &Path, slug: &str, archive: &Path) -> Result<(), ProviderError> {
    let root = root.canonicalize().map_err(ProviderError::Io)?;
    let scanner_root = root.join("scanner-db");
    fs::create_dir_all(&scanner_root).map_err(ProviderError::Io)?;
    let scanner_root = scanner_root.canonicalize().map_err(ProviderError::Io)?;
    if !scanner_root.starts_with(&root) {
        return Err(ProviderError::InvalidData);
    }
    let engine_root = scanner_root.join("osv-scanner");
    fs::create_dir_all(&engine_root).map_err(ProviderError::Io)?;
    let engine_root = engine_root.canonicalize().map_err(ProviderError::Io)?;
    if !engine_root.starts_with(&scanner_root) {
        return Err(ProviderError::InvalidData);
    }
    let ecosystem_root = engine_root.join(slug);
    fs::create_dir_all(&ecosystem_root).map_err(ProviderError::Io)?;
    let ecosystem_root = ecosystem_root.canonicalize().map_err(ProviderError::Io)?;
    if !ecosystem_root.starts_with(&engine_root) {
        return Err(ProviderError::InvalidData);
    }

    let source = archive.canonicalize().map_err(ProviderError::Io)?;
    if !source.starts_with(&root) {
        return Err(ProviderError::InvalidData);
    }
    let mut input = File::open(source).map_err(ProviderError::Io)?;
    let mut temporary = NamedTempFile::new_in(&ecosystem_root).map_err(ProviderError::Io)?;
    std::io::copy(&mut input, temporary.as_file_mut()).map_err(ProviderError::Io)?;
    temporary.as_file().sync_all().map_err(ProviderError::Io)?;
    temporary
        .persist(ecosystem_root.join("all.zip"))
        .map_err(|error| ProviderError::Io(error.error))?;
    Ok(())
}

impl OsvDatabase {
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, ProviderError> {
        let directory = directory.as_ref();
        let status = read_cache_status(directory)?.unwrap_or(OsvUpdateStatus {
            ecosystem: directory
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("unknown")
                .to_owned(),
            updated_at: None,
            stale: true,
            error: Some("cache metadata missing".to_owned()),
            ..OsvUpdateStatus::default()
        });
        let mut database = Self {
            by_package: HashMap::new(),
            status,
        };
        let mut files = Vec::new();
        collect_json_files(directory, &mut files)?;
        files.sort();
        for path in files {
            let bytes = fs::read(path).map_err(ProviderError::Io)?;
            let value: Value = serde_json::from_slice(&bytes)?;
            if value.get("id").and_then(Value::as_str).is_none() {
                return Err(ProviderError::InvalidData);
            }
            let advisory = parse_osv_advisory(&bytes)?;
            for affected in &advisory.affected_ranges {
                if let Some(package) = &affected.package {
                    database
                        .by_package
                        .entry((
                            affected.ecosystem.clone(),
                            normalize_package_name(&affected.ecosystem, package),
                        ))
                        .or_default()
                        .push(advisory.clone());
                }
            }
        }
        for advisories in database.by_package.values_mut() {
            advisories.sort_by(|left, right| left.canonical_id.cmp(&right.canonical_id));
            advisories.dedup_by(|left, right| left.canonical_id == right.canonical_id);
        }
        Ok(database)
    }

    pub fn query(&self, ecosystem: &str, package: &str) -> Vec<Advisory> {
        self.by_package
            .get(&(
                canonical_ecosystem(ecosystem),
                normalize_package_name(ecosystem, package),
            ))
            .cloned()
            .unwrap_or_default()
    }

    pub fn status(&self) -> &OsvUpdateStatus {
        &self.status
    }

    pub fn package_count(&self) -> usize {
        self.by_package.len()
    }
}

pub fn ecosystem_slug(ecosystem: &str) -> Option<&'static str> {
    match canonical_ecosystem(ecosystem).as_str() {
        "npm" => Some("npm"),
        "pypi" => Some("PyPI"),
        "golang" => Some("Go"),
        "maven" => Some("Maven"),
        "cargo" => Some("crates.io"),
        "composer" => Some("Packagist"),
        "rubygems" => Some("RubyGems"),
        "nuget" => Some("NuGet"),
        _ => None,
    }
}

pub(super) fn parse_osv_advisory(bytes: &[u8]) -> Result<Advisory, ProviderError> {
    let record: OsvVulnerability = serde_json::from_slice(bytes)?;
    if record.id.is_empty()
        || record.id.len() > 256
        || !record
            .id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
    {
        return Err(ProviderError::InvalidData);
    }
    let mut aliases = record.aliases;
    let mut affected_ranges = Vec::new();
    let mut fixed_versions = Vec::new();
    for affected in record.affected {
        let ecosystem = canonical_ecosystem(&affected.package.ecosystem);
        for range in affected.ranges {
            let mut events = Vec::new();
            for event in range.events {
                if let Some(fixed) = &event.fixed {
                    fixed_versions.push(fixed.clone());
                }
                events.push(RangeEvent {
                    introduced: event.introduced,
                    fixed: event.fixed,
                    last_affected: event.last_affected,
                    limit: event.limit,
                });
            }
            affected_ranges.push(AffectedRange {
                ecosystem: ecosystem.clone(),
                package: Some(affected.package.name.clone()),
                source: Some("OSV".to_owned()),
                range_type: range.range_type,
                events,
            });
        }
        if !affected.versions.is_empty() {
            let events = affected
                .versions
                .into_iter()
                .map(|version| RangeEvent {
                    introduced: Some(version.clone()),
                    fixed: None,
                    last_affected: Some(version),
                    limit: None,
                })
                .collect();
            affected_ranges.push(AffectedRange {
                ecosystem,
                package: Some(affected.package.name),
                source: Some("OSV".to_owned()),
                range_type: Some("EXACT".to_owned()),
                events,
            });
        }
    }
    aliases.sort();
    aliases.dedup();
    let mut source_urls = record
        .references
        .into_iter()
        .filter_map(|reference| crate::normalize::sanitize_public_url(&reference.url))
        .collect::<Vec<_>>();
    let mut source_url =
        url::Url::parse("https://osv.dev/vulnerability/").map_err(|_| ProviderError::InvalidUrl)?;
    let mut path_segments = source_url
        .path_segments_mut()
        .map_err(|_| ProviderError::InvalidUrl)?;
    path_segments.pop_if_empty().push(&record.id);
    drop(path_segments);
    let source_url = source_url.to_string();
    if !source_urls.contains(&source_url) {
        source_urls.push(source_url.clone());
    }
    let upstream_source = record
        .database_specific
        .get("source")
        .and_then(Value::as_str)
        .and_then(crate::normalize::sanitize_public_url);
    if let Some(url) = &upstream_source
        && !source_urls.contains(url)
    {
        source_urls.push(url.clone());
    }
    let modified = record.modified.as_deref().and_then(parse_time);
    let published = record.published.as_deref().and_then(parse_time);
    let severity = record
        .database_specific
        .get("severity")
        .and_then(Value::as_str)
        .and_then(severity_from_label);
    let _cvss_vectors = record.severity;
    let now = DateTime::<Utc>::UNIX_EPOCH;
    Ok(Advisory {
        canonical_id: record.id.clone(),
        title: record.summary.clone().unwrap_or_else(|| record.id.clone()),
        summary: record.summary,
        summary_model: None,
        description: record.details,
        source_attributions: std::iter::once(AdvisorySource {
            name: "OSV.dev".to_owned(),
            url: source_url,
            license: None,
        })
        .chain(upstream_source.map(|url| AdvisorySource {
            name: "OSV upstream source".to_owned(),
            url,
            license: None,
        }))
        .collect(),
        aliases,
        affected_ranges,
        fixed_versions,
        cvss: None,
        severity,
        kev: false,
        epss: None,
        epss_date: None,
        source_urls,
        source_updated_at: modified,
        created_at: published.unwrap_or(now),
        updated_at: modified.or(published).unwrap_or(now),
    })
}

fn collect_json_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), ProviderError> {
    if !directory.exists() {
        return Err(ProviderError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "OSV cache directory is missing",
        )));
    }
    let mut entries = fs::read_dir(directory)
        .map_err(ProviderError::Io)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(ProviderError::Io)?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let file_type = entry.file_type().map_err(ProviderError::Io)?;
        if file_type.is_dir() {
            collect_json_files(&entry.path(), files)?;
        } else if file_type.is_file()
            && entry.path().extension().and_then(|ext| ext.to_str()) == Some("json")
            && entry.file_name() != ".secmon-cache.json"
        {
            files.push(entry.path());
        }
    }
    Ok(())
}

fn extract_osv_archive(archive_path: &Path, destination: &Path) -> Result<(), ProviderError> {
    let file = File::open(archive_path).map_err(ProviderError::Io)?;
    let mut archive = ZipArchive::new(file)?;
    if archive.len() > MAX_OSV_ARCHIVE_ENTRIES {
        return Err(ProviderError::DownloadTooLarge);
    }
    let mut expanded = 0_u64;
    let mut extracted_paths = HashSet::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let Some(relative_path) = entry.enclosed_name() else {
            return Err(ProviderError::InvalidData);
        };
        let normalized_path = relative_path
            .components()
            .map(|component| component.as_os_str().to_string_lossy().to_lowercase())
            .collect::<Vec<_>>()
            .join("/");
        if normalized_path.len() > MAX_OSV_PATH_BYTES
            || relative_path.components().count() > MAX_OSV_PATH_DEPTH
            || !extracted_paths.insert(normalized_path)
        {
            return Err(ProviderError::InvalidData);
        }
        if entry.is_dir() {
            fs::create_dir_all(destination.join(relative_path)).map_err(ProviderError::Io)?;
            continue;
        }
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            return Err(ProviderError::InvalidData);
        }
        if !relative_path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
        {
            continue;
        }
        let remaining = MAX_OSV_EXPANDED_BYTES.saturating_sub(expanded);
        let declared_size = entry.size();
        if declared_size > remaining {
            return Err(ProviderError::DownloadTooLarge);
        }
        let output_path = destination.join(relative_path);
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent).map_err(ProviderError::Io)?;
        }
        let mut output = File::create(output_path).map_err(ProviderError::Io)?;
        let written = {
            let mut limited = entry.by_ref().take(remaining + 1);
            std::io::copy(&mut limited, &mut output).map_err(ProviderError::Io)?
        };
        if written > remaining {
            return Err(ProviderError::DownloadTooLarge);
        }
        if written != declared_size {
            return Err(ProviderError::InvalidData);
        }
        expanded = expanded
            .checked_add(written)
            .ok_or(ProviderError::DownloadTooLarge)?;
        output.flush().map_err(ProviderError::Io)?;
    }
    Ok(())
}

fn read_cache_status(directory: &Path) -> Result<Option<OsvUpdateStatus>, ProviderError> {
    let path = directory.join(".secmon-cache.json");
    match fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ProviderError::Io(error)),
    }
}

fn read_update_status(
    root: &Path,
    target: &Path,
    slug: &str,
) -> Result<Option<OsvUpdateStatus>, ProviderError> {
    if let Some(status) = read_cache_status(target)? {
        return Ok(Some(status));
    }
    let path = root.join(format!(".{slug}-status.json"));
    match fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ProviderError::Io(error)),
    }
}

fn write_update_status(
    root: &Path,
    target: &Path,
    slug: &str,
    status: &OsvUpdateStatus,
) -> Result<(), ProviderError> {
    let encoded = serde_json::to_vec(status)?;
    atomic_write(&root.join(format!(".{slug}-status.json")), &encoded)?;
    if target.is_dir() {
        atomic_write(&target.join(".secmon-cache.json"), &encoded)?;
    }
    let scanner_status = root
        .join("scanner-db/osv-scanner")
        .join(slug)
        .join(".secmon-cache.json");
    if scanner_status.parent().is_some_and(Path::is_dir) {
        let canonical_root = root.canonicalize().map_err(ProviderError::Io)?;
        let canonical_parent = scanner_status
            .parent()
            .ok_or(ProviderError::InvalidData)?
            .canonicalize()
            .map_err(ProviderError::Io)?;
        if !canonical_parent.starts_with(&canonical_root) {
            return Err(ProviderError::InvalidData);
        }
        atomic_write(&scanner_status, &encoded)?;
    }
    Ok(())
}

fn failure_status(
    ecosystem: &str,
    previous: Option<OsvUpdateStatus>,
    error: &ProviderError,
) -> OsvUpdateStatus {
    let consecutive_failures = previous
        .as_ref()
        .map_or(1, |status| status.consecutive_failures.saturating_add(1));
    let delay = retry_delay_seconds(error, consecutive_failures);
    OsvUpdateStatus {
        ecosystem: ecosystem.to_owned(),
        updated_at: previous.and_then(|status| status.updated_at),
        stale: true,
        error: Some(error.to_string()),
        consecutive_failures,
        retry_after_at: Some(Utc::now() + chrono::Duration::seconds(delay as i64)),
    }
}

fn retry_delay_seconds(error: &ProviderError, consecutive_failures: u32) -> u64 {
    if let ProviderError::RateLimited {
        retry_after: Some(value),
        ..
    } = error
    {
        if let Ok(seconds) = value.parse::<u64>() {
            return seconds;
        }
        if let Ok(deadline) = httpdate::parse_http_date(value) {
            return deadline
                .duration_since(std::time::SystemTime::now())
                .map(|duration| duration.as_secs())
                .unwrap_or_default();
        }
    }
    60_u64
        .saturating_mul(2_u64.saturating_pow(consecutive_failures.saturating_sub(1).min(10)))
        .min(24 * 60 * 60)
}
