use std::{collections::HashSet, path::PathBuf};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::{
    AdvisoryCache, CachedAdvisories, ProviderError, http::PublicDataHttp,
    normalize::cve_now_advisory,
};
use security_monitor_core::Advisory;

const CVE_NOW_URL: &str = "https://cve.now";
pub const DEFAULT_CVE_POLL_INTERVAL_SECONDS: u64 = 10 * 60;
pub const MIN_CVE_POLL_INTERVAL_SECONDS: u64 = 5 * 60;
pub const MAX_CVE_POLL_INTERVAL_SECONDS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CveNowCursor {
    pub polling_cursor: Option<String>,
    pub last_seen_id: Option<String>,
    #[serde(default)]
    pub consecutive_failures: u32,
    #[serde(default)]
    pub backoff_until: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_checked_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub source_statuses: Vec<CveNowSourceStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CveNowSourceStatus {
    pub name: String,
    pub updated_at: Option<DateTime<Utc>>,
    pub healthy: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CveNowSync {
    pub advisories: Vec<Advisory>,
    pub source_statuses: Vec<CveNowSourceStatus>,
    pub cursor_advanced: bool,
    pub entries_requested: bool,
}

#[derive(Clone)]
pub struct CveNowProvider {
    http: PublicDataHttp,
    base_url: String,
    poll_interval_seconds: u64,
}

impl CveNowProvider {
    pub fn new(http: PublicDataHttp) -> Self {
        Self {
            http,
            base_url: CVE_NOW_URL.to_owned(),
            poll_interval_seconds: DEFAULT_CVE_POLL_INTERVAL_SECONDS,
        }
    }

    pub fn with_poll_interval_seconds(mut self, seconds: u64) -> Result<Self, ProviderError> {
        if !(MIN_CVE_POLL_INTERVAL_SECONDS..=MAX_CVE_POLL_INTERVAL_SECONDS).contains(&seconds) {
            return Err(ProviderError::InvalidPollInterval);
        }
        self.poll_interval_seconds = seconds;
        Ok(self)
    }

    #[cfg(test)]
    pub(crate) fn with_base_url(http: PublicDataHttp, base_url: String) -> Self {
        Self {
            http,
            base_url,
            poll_interval_seconds: DEFAULT_CVE_POLL_INTERVAL_SECONDS,
        }
    }

    pub async fn sync(&self, cursor: &mut CveNowCursor) -> Result<CveNowSync, ProviderError> {
        if cursor.backoff_until.is_some_and(|until| Utc::now() < until) {
            return Err(ProviderError::BackoffActive);
        }
        let status_url = format!("{}/api/v1/status", self.base_url.trim_end_matches('/'));
        let status: Value = serde_json::from_slice(&self.http.get(&status_url).await?.body)?;
        let polling_cursor = status
            .pointer("/polling/cursor")
            .and_then(Value::as_str)
            .filter(|cursor| !cursor.is_empty() && cursor.len() <= 4096)
            .ok_or(ProviderError::InvalidData)?
            .to_owned();
        let source_statuses = parse_source_statuses(&status);
        if cursor.polling_cursor.as_deref() == Some(&polling_cursor) {
            cursor.consecutive_failures = 0;
            cursor.backoff_until = None;
            cursor.last_checked_at = Some(Utc::now());
            cursor.source_statuses = source_statuses.clone();
            return Ok(CveNowSync {
                advisories: Vec::new(),
                source_statuses,
                cursor_advanced: false,
                entries_requested: false,
            });
        }

        let mut next = cursor.clone();
        let mut advisories = Vec::new();
        let mut first_seen_id = None;
        let mut page_cursor: Option<String> = None;
        let mut visited_page_cursors = HashSet::new();
        loop {
            let entries_url = self.entries_url(page_cursor.as_deref())?;
            let bytes = self.http.get(entries_url.as_str()).await?.body;
            let page: Value = serde_json::from_slice(&bytes)?;
            let entries = page
                .get("entries")
                .and_then(Value::as_array)
                .ok_or(ProviderError::InvalidData)?;
            let mut reached_seen = false;
            for entry in entries {
                let id = entry
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or(ProviderError::InvalidData)?;
                if id.len() > 256 {
                    return Err(ProviderError::InvalidData);
                }
                if first_seen_id.is_none() {
                    first_seen_id = Some(id.to_owned());
                }
                if next.last_seen_id.as_deref() == Some(id) {
                    reached_seen = true;
                    break;
                }
                let detail_url = self.entry_url(id)?;
                let detail: Value =
                    serde_json::from_slice(&self.http.get(&detail_url).await?.body)?;
                if detail.get("id").and_then(Value::as_str) != Some(id) {
                    return Err(ProviderError::InvalidData);
                }
                advisories.push(cve_now_advisory(&detail)?);
            }
            if reached_seen || next.last_seen_id.is_none() {
                break;
            }
            let next_cursor = page
                .get("nextCursor")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 4096)
                .ok_or(ProviderError::InvalidData)?;
            if !visited_page_cursors.insert(next_cursor.to_owned()) {
                return Err(ProviderError::InvalidData);
            }
            page_cursor = Some(next_cursor.to_owned());
        }
        next.polling_cursor = Some(polling_cursor);
        next.last_seen_id = first_seen_id.or(next.last_seen_id);
        next.consecutive_failures = 0;
        next.backoff_until = None;
        next.last_checked_at = Some(Utc::now());
        next.source_statuses = source_statuses.clone();
        *cursor = next;
        Ok(CveNowSync {
            advisories,
            source_statuses,
            cursor_advanced: true,
            entries_requested: true,
        })
    }

    pub async fn sync_cached(
        &self,
        cache: &AdvisoryCache,
        cursor_file: impl Into<PathBuf>,
    ) -> Result<CachedAdvisories, ProviderError> {
        let cursor_file = cursor_file.into();
        let mut cursor = match std::fs::read(&cursor_file) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => CveNowCursor::default(),
            Err(error) => return Err(ProviderError::Io(error)),
        };
        if let (Some(last_checked), Some(cached)) = (cursor.last_checked_at, cache.load()?) {
            let now = Utc::now();
            if now >= last_checked
                && now - last_checked < Duration::seconds(self.poll_interval_seconds as i64)
            {
                return Ok(cached);
            }
        }
        match self.sync(&mut cursor).await {
            Ok(sync) => {
                cursor.consecutive_failures = 0;
                cursor.backoff_until = None;
                let previous = cache
                    .load()?
                    .map(|cached| cached.advisories)
                    .unwrap_or_default();
                let mut merger = crate::AdvisoryMerger::new(previous);
                merger.extend(sync.advisories);
                let cached = cache.save_with_source_statuses(
                    merger.into_records(),
                    false,
                    sync.source_statuses,
                )?;
                if let Some(parent) = cursor_file.parent() {
                    std::fs::create_dir_all(parent).map_err(ProviderError::Io)?;
                }
                crate::cache::atomic_write(&cursor_file, &serde_json::to_vec(&cursor)?)?;
                Ok(cached)
            }
            Err(error) => {
                if !matches!(&error, ProviderError::BackoffActive) {
                    cursor.consecutive_failures = cursor.consecutive_failures.saturating_add(1);
                    let delay = retry_delay_seconds(&error, cursor.consecutive_failures);
                    cursor.backoff_until = Some(Utc::now() + Duration::seconds(delay as i64));
                    if let Some(parent) = cursor_file.parent() {
                        std::fs::create_dir_all(parent).map_err(ProviderError::Io)?;
                    }
                    crate::cache::atomic_write(&cursor_file, &serde_json::to_vec(&cursor)?)?;
                }
                match cache.mark_stale()? {
                    Some(cached) => Ok(cached),
                    None => Err(error),
                }
            }
        }
    }

    fn entries_url(&self, cursor: Option<&str>) -> Result<Url, ProviderError> {
        let base = Url::parse(&format!(
            "{}/api/v1/entries",
            self.base_url.trim_end_matches('/')
        ))
        .map_err(|_| ProviderError::InvalidUrl)?;
        let mut url = base;
        if let Some(cursor) = cursor {
            url.query_pairs_mut().append_pair("cursor", cursor);
        }
        Ok(url)
    }

    fn entry_url(&self, id: &str) -> Result<String, ProviderError> {
        if id.is_empty()
            || !id.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '_')
            })
        {
            return Err(ProviderError::InvalidData);
        }
        Ok(format!(
            "{}/api/v1/entries/{id}",
            self.base_url.trim_end_matches('/')
        ))
    }
}

fn parse_source_statuses(status: &Value) -> Vec<CveNowSourceStatus> {
    let polling_sources = status
        .pointer("/polling/sources")
        .and_then(Value::as_object)
        .filter(|sources| !sources.is_empty());
    let mut statuses = polling_sources
        .into_iter()
        .flat_map(|sources| sources.iter())
        .map(|(name, source)| CveNowSourceStatus {
            name: name.clone(),
            updated_at: source
                .get("at")
                .and_then(Value::as_str)
                .and_then(crate::normalize::parse_time),
            healthy: source.get("ok").and_then(Value::as_bool) == Some(true),
        })
        .collect::<Vec<_>>();
    if polling_sources.is_none() {
        statuses.push(CveNowSourceStatus {
            name: "polling source status".to_owned(),
            updated_at: None,
            healthy: false,
        });
    }

    let packages = status.pointer("/history/packages");
    let ecosystems = packages
        .and_then(|value| value.get("ecosystems"))
        .and_then(Value::as_array);
    let cutoffs = packages
        .and_then(|value| value.get("cutoffs"))
        .and_then(Value::as_object);
    if let Some(ecosystems) = ecosystems {
        for ecosystem in ecosystems.iter().filter_map(Value::as_str) {
            let updated_at = cutoffs
                .and_then(|values| values.get(ecosystem))
                .and_then(Value::as_str)
                .and_then(crate::normalize::parse_time);
            statuses.push(CveNowSourceStatus {
                name: format!("package data ({ecosystem})"),
                healthy: updated_at.is_some(),
                updated_at,
            });
        }
    }
    if ecosystems.is_none_or(|values| values.is_empty()) {
        statuses.push(CveNowSourceStatus {
            name: "package data coverage".to_owned(),
            updated_at: None,
            healthy: false,
        });
    }
    statuses.sort_by(|left, right| left.name.cmp(&right.name));
    statuses
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
