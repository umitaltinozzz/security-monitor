use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Duration, Utc};
use quick_xml::{escape::resolve_predefined_entity, events::Event, reader::Reader};
use security_monitor_core::{Advisory, Component, ComponentInstance, NewsSignal};
use security_monitor_database::Database;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ts_rs::TS;
use url::Url;

use crate::{ProviderError, PublicDataHttp, cache::atomic_write};

const POLL_INTERVAL: Duration = Duration::minutes(30);
const ARCHIVE_AGE: Duration = Duration::days(7);
const MAX_FEEDS: usize = 64;
const MAX_ITEMS_PER_FEED: usize = 500;
const MAX_XML_DEPTH: usize = 32;
const MAX_XML_EVENTS: usize = 500_000;
const MAX_FIELD_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewsFeed {
    pub id: String,
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct NewsSyncReport {
    pub updated_feeds: usize,
    pub not_modified_feeds: usize,
    pub skipped_feeds: usize,
    pub failed_feeds: usize,
    pub signals_updated: usize,
    pub signals_archived: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedNewsItem {
    external_id: String,
    title: String,
    summary: Option<String>,
    url: String,
    published_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
struct LocalProduct {
    name: String,
    project_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct FeedCache {
    etag: Option<String>,
    last_modified: Option<String>,
    last_checked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct NewsCache {
    feeds: BTreeMap<String, FeedCache>,
}

pub struct NewsSignalService {
    http: PublicDataHttp,
    database: Database,
    app_data_dir: PathBuf,
}

impl NewsSignalService {
    pub fn new(
        policy: crate::HttpPolicy,
        database: Database,
        app_data_dir: impl Into<PathBuf>,
    ) -> Result<Self, ProviderError> {
        Ok(Self {
            http: PublicDataHttp::new(policy)?,
            database,
            app_data_dir: app_data_dir.into(),
        })
    }

    pub async fn refresh(&self) -> Result<NewsSyncReport, ProviderError> {
        fs::create_dir_all(&self.app_data_dir)?;
        let feeds = self.load_feeds()?;
        let aliases = self.load_synonyms()?;
        let products = self.local_products().await?;
        let advisories = self.database.repository::<Advisory>().list().await?;
        let signals = self.database.repository::<NewsSignal>().list().await?;
        let existing_signal_ids = signals
            .iter()
            .map(|signal| signal.id.clone())
            .collect::<BTreeSet<_>>();
        let mut signal_by_id = signals
            .into_iter()
            .map(|signal| (signal.id.clone(), signal))
            .collect::<BTreeMap<_, _>>();
        let mut cache = self.load_cache()?;
        let now = Utc::now();
        let mut report = NewsSyncReport::default();

        for signal in signal_by_id.values_mut() {
            if archive_if_expired(signal, now) {
                report.signals_archived += 1;
            }
            if signal.advisory_id.is_none()
                && let Some(advisory_id) = find_advisory_id(
                    &signal.title,
                    signal.summary.as_deref(),
                    &[&signal.external_id, &signal.url],
                    &advisories,
                )
            {
                signal.advisory_id = Some(advisory_id);
                signal.archived_at.get_or_insert(now);
                report.signals_updated += 1;
            }
        }

        for feed in feeds {
            if cache
                .feeds
                .get(&feed.id)
                .and_then(|state| state.last_checked_at)
                .is_some_and(|last_checked| now - last_checked < POLL_INTERVAL)
            {
                report.skipped_feeds += 1;
                continue;
            }
            let old_state = cache.feeds.get(&feed.id).cloned().unwrap_or_default();
            let response = self
                .http
                .get_conditional_feed(
                    &feed.url,
                    old_state.etag.as_deref(),
                    old_state.last_modified.as_deref(),
                )
                .await;
            let Ok(response) = response else {
                report.failed_feeds += 1;
                continue;
            };
            let mut next_state = FeedCache {
                etag: response.etag.or(old_state.etag),
                last_modified: response.last_modified.or(old_state.last_modified),
                last_checked_at: Some(now),
            };
            if response.not_modified {
                report.not_modified_feeds += 1;
                cache.feeds.insert(feed.id.clone(), next_state);
                continue;
            }
            let items = match parse_feed(&response.body) {
                Ok(items) => items,
                Err(_) => {
                    report.failed_feeds += 1;
                    next_state.last_checked_at = old_state.last_checked_at;
                    continue;
                }
            };
            for item in items {
                let id = signal_id(&feed.id, &item.external_id);
                let signal = make_signal(
                    &feed,
                    item,
                    now,
                    &products,
                    &aliases,
                    &advisories,
                    signal_by_id.get(&id),
                );
                signal_by_id.insert(signal.id.clone(), signal);
                report.signals_updated += 1;
            }
            report.updated_feeds += 1;
            cache.feeds.insert(feed.id.clone(), next_state);
        }

        let repository = self.database.repository::<NewsSignal>();
        for signal in signal_by_id.values() {
            if existing_signal_ids.contains(&signal.id) {
                repository.update(signal).await?;
            } else {
                repository.create(signal).await?;
            }
        }
        atomic_write(
            &self.app_data_dir.join("news-feed-state.json"),
            &serde_json::to_vec(&cache)?,
        )?;
        Ok(report)
    }

    fn load_feeds(&self) -> Result<Vec<NewsFeed>, ProviderError> {
        let path = self.app_data_dir.join("news-sources.json");
        let bytes = read_or_install(&path, include_bytes!("../data/news-sources.json"))?;
        let feeds: Vec<NewsFeed> = serde_json::from_slice(&bytes)?;
        if feeds.len() > MAX_FEEDS {
            return Err(ProviderError::InvalidData);
        }
        let mut ids = BTreeSet::new();
        if feeds
            .iter()
            .any(|feed| !valid_feed(feed) || !ids.insert(feed.id.clone()))
        {
            return Err(ProviderError::InvalidData);
        }
        Ok(feeds)
    }

    fn load_synonyms(&self) -> Result<Vec<Vec<String>>, ProviderError> {
        let path = self.app_data_dir.join("news-synonyms.json");
        let bytes = read_or_install(&path, include_bytes!("../data/news-synonyms.json"))?;
        let aliases: Vec<Vec<String>> = serde_json::from_slice(&bytes)?;
        if aliases.len() > 256
            || aliases.iter().any(|group| {
                group.is_empty()
                    || group.len() > 32
                    || group
                        .iter()
                        .any(|term| term.trim().is_empty() || term.len() > 128)
            })
        {
            return Err(ProviderError::InvalidData);
        }
        Ok(aliases)
    }

    fn load_cache(&self) -> Result<NewsCache, ProviderError> {
        let path = self.app_data_dir.join("news-feed-state.json");
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(ProviderError::Json),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(NewsCache::default()),
            Err(error) => Err(ProviderError::Io(error)),
        }
    }

    async fn local_products(&self) -> Result<Vec<LocalProduct>, ProviderError> {
        let components = self.database.repository::<Component>().list().await?;
        let components = components
            .into_iter()
            .map(|component| (component.id.clone(), component))
            .collect::<BTreeMap<String, Component>>();
        let instances = self
            .database
            .repository::<ComponentInstance>()
            .list()
            .await?;
        Ok(instances
            .into_iter()
            .filter_map(|instance: ComponentInstance| {
                let project_id = instance.project_id?;
                let component = components.get(&instance.component_id)?;
                Some(LocalProduct {
                    name: component.name.clone(),
                    project_id,
                })
            })
            .collect())
    }
}

fn read_or_install(path: &Path, default: &[u8]) -> Result<Vec<u8>, ProviderError> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            atomic_write(path, default)?;
            Ok(default.to_vec())
        }
        Err(error) => Err(ProviderError::Io(error)),
    }
}

fn valid_feed(feed: &NewsFeed) -> bool {
    let Ok(url) = Url::parse(&feed.url) else {
        return false;
    };
    let loopback_fixture = cfg!(test)
        && url.scheme() == "http"
        && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    !feed.id.is_empty()
        && feed.id.len() <= 128
        && feed
            .id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        && !feed.name.trim().is_empty()
        && feed.name.len() <= 256
        && (url.scheme() == "https" || loopback_fixture)
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && feed.url.len() <= 4096
}

fn parse_feed(bytes: &[u8]) -> Result<Vec<ParsedNewsItem>, ProviderError> {
    if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 {
        return Err(ProviderError::InvalidData);
    }
    let xml = std::str::from_utf8(bytes).map_err(|_| ProviderError::InvalidData)?;
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut stack = Vec::<String>::new();
    let mut root = None;
    let mut entry: Option<EntryBuilder> = None;
    let mut items = Vec::new();
    let mut events = 0usize;
    loop {
        events += 1;
        if events > MAX_XML_EVENTS {
            return Err(ProviderError::InvalidData);
        }
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(element)) => {
                let name = local_name(element.name().as_ref());
                if stack.is_empty() {
                    if root.is_some() || !matches!(name.as_str(), "rss" | "feed" | "rdf") {
                        return Err(ProviderError::InvalidData);
                    }
                    root = Some(name.clone());
                }
                if stack.len() >= MAX_XML_DEPTH {
                    return Err(ProviderError::InvalidData);
                }
                if entry.is_none() && matches!(name.as_str(), "item" | "entry") {
                    entry = Some(EntryBuilder::new(stack.len()));
                } else if let Some(current) = entry.as_mut() {
                    if name == "link" {
                        set_link_attribute(current, &element)?;
                    }
                    if current.capture.is_none()
                        && stack.len() == current.depth + 1
                        && is_item_field(&name)
                    {
                        current.capture = Some(CapturedField {
                            name: name.clone(),
                            depth: stack.len(),
                            value: String::new(),
                        });
                    }
                }
                stack.push(name);
            }
            Ok(Event::Empty(element)) => {
                let name = local_name(element.name().as_ref());
                if stack.is_empty() {
                    if root.is_some() || !matches!(name.as_str(), "rss" | "feed" | "rdf") {
                        return Err(ProviderError::InvalidData);
                    }
                    root = Some(name.clone());
                }
                if let Some(current) = entry.as_mut()
                    && name == "link"
                {
                    set_link_attribute(current, &element)?;
                }
            }
            Ok(Event::Text(text)) => {
                if let Some(capture) = entry.as_mut().and_then(|entry| entry.capture.as_mut()) {
                    append_capture(capture, &text.xml10_content())?;
                }
            }
            Ok(Event::CData(text)) => {
                if let Some(capture) = entry.as_mut().and_then(|entry| entry.capture.as_mut()) {
                    append_capture(capture, &text.xml10_content())?;
                }
            }
            Ok(Event::GeneralRef(reference)) => {
                if let Some(capture) = entry.as_mut().and_then(|entry| entry.capture.as_mut()) {
                    let reference_name = reference.as_ref();
                    let resolved = match reference.resolve_char_ref() {
                        Ok(Some(character)) => character.to_string(),
                        Ok(None) => resolve_predefined_entity(reference_name)
                            .map(str::to_owned)
                            .ok_or(ProviderError::InvalidData)?,
                        Err(_) => return Err(ProviderError::InvalidData),
                    };
                    append_capture(capture, &resolved)?;
                }
            }
            Ok(Event::End(element)) => {
                let name = local_name(element.name().as_ref());
                let Some(depth) = stack.len().checked_sub(1) else {
                    return Err(ProviderError::InvalidData);
                };
                if let Some(current) = entry.as_mut()
                    && current
                        .capture
                        .as_ref()
                        .is_some_and(|capture| capture.depth == depth)
                    && let Some(capture) = current.capture.take()
                {
                    current.set_field(capture.name, capture.value);
                }
                if entry.as_ref().is_some_and(|current| current.depth == depth)
                    && matches!(name.as_str(), "item" | "entry")
                    && let Some(current) = entry.take()
                    && let Some(item) = current.finish()?
                {
                    items.push(item);
                    if items.len() > MAX_ITEMS_PER_FEED {
                        return Err(ProviderError::InvalidData);
                    }
                }
                stack.pop();
            }
            Ok(Event::DocType(_)) => return Err(ProviderError::InvalidData),
            Ok(Event::Eof) => break,
            Ok(Event::Decl(_) | Event::Comment(_) | Event::PI(_)) => {}
            Err(_) => return Err(ProviderError::InvalidData),
        }
        buffer.clear();
    }
    if root.is_none() || !stack.is_empty() || entry.is_some() {
        return Err(ProviderError::InvalidData);
    }
    Ok(items)
}

#[derive(Default)]
struct EntryBuilder {
    depth: usize,
    title: Option<String>,
    id: Option<String>,
    url: Option<String>,
    summary: Option<String>,
    published_at: Option<DateTime<Utc>>,
    capture: Option<CapturedField>,
}

struct CapturedField {
    name: String,
    depth: usize,
    value: String,
}

impl EntryBuilder {
    fn new(depth: usize) -> Self {
        Self {
            depth,
            ..Self::default()
        }
    }

    fn set_field(&mut self, name: String, value: String) {
        let value = clean_text(&value);
        if value.is_empty() {
            return;
        }
        match name.as_str() {
            "title" => {
                self.title.get_or_insert(value);
            }
            "guid" | "id" => {
                self.id.get_or_insert(value);
            }
            "description" | "summary" | "content" | "encoded" => {
                self.summary.get_or_insert(value);
            }
            "published" | "pubdate" | "updated" | "date" => {
                if self.published_at.is_none() {
                    self.published_at = parse_date(&value);
                }
            }
            "link" => {
                self.url.get_or_insert(value);
            }
            _ => {}
        }
    }

    fn finish(self) -> Result<Option<ParsedNewsItem>, ProviderError> {
        let Some(title) = self.title.map(|title| clean_text(&title)) else {
            return Ok(None);
        };
        let Some(url) = self.url.filter(|url| valid_article_url(url)) else {
            return Ok(None);
        };
        let summary = self
            .summary
            .map(|summary| clean_text(&summary))
            .filter(|s| !s.is_empty());
        let external_id = self
            .id
            .map(|id| clean_text(&id))
            .filter(|id| !id.is_empty())
            .unwrap_or_else(|| stable_id(&title, self.published_at.as_ref()));
        Ok(Some(ParsedNewsItem {
            external_id,
            title: truncate(&title, 512),
            summary: summary.map(|summary| truncate(&summary, 4096)),
            url,
            published_at: self.published_at,
        }))
    }
}

fn is_item_field(name: &str) -> bool {
    matches!(
        name,
        "title"
            | "guid"
            | "id"
            | "link"
            | "description"
            | "summary"
            | "content"
            | "encoded"
            | "published"
            | "pubdate"
            | "updated"
            | "date"
    )
}

fn local_name(name: &str) -> String {
    name.rsplit(':').next().unwrap_or(name).to_ascii_lowercase()
}

fn set_link_attribute(
    entry: &mut EntryBuilder,
    element: &quick_xml::events::BytesStart<'_>,
) -> Result<(), ProviderError> {
    let mut href = None;
    let mut relation = None;
    for attribute in element.attributes().with_checks(true) {
        let attribute = attribute.map_err(|_| ProviderError::InvalidData)?;
        match attribute.key.local_name().as_ref() {
            "href" => {
                href = Some(
                    attribute
                        .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                        .map_err(|_| ProviderError::InvalidData)?
                        .into_owned(),
                );
            }
            "rel" => {
                relation = Some(
                    attribute
                        .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                        .map_err(|_| ProviderError::InvalidData)?
                        .into_owned(),
                );
            }
            _ => {}
        }
    }
    if relation.as_deref().is_none_or(|value| value == "alternate")
        && let Some(href) = href
        && valid_article_url(&href)
    {
        entry.url.get_or_insert(href);
    }
    Ok(())
}

fn append_capture(capture: &mut CapturedField, text: &str) -> Result<(), ProviderError> {
    if capture.value.len().saturating_add(text.len()) > MAX_FIELD_BYTES {
        return Err(ProviderError::InvalidData);
    }
    capture.value.push_str(text);
    Ok(())
}

fn valid_article_url(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    matches!(url.scheme(), "https" | "http")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && value.len() <= 4096
}

fn clean_text(value: &str) -> String {
    let mut output = String::with_capacity(value.len().min(MAX_FIELD_BYTES));
    let mut inside_tag = false;
    let mut pending_space = false;
    for character in value.chars() {
        match character {
            '<' => inside_tag = true,
            '>' => {
                inside_tag = false;
                pending_space = true;
            }
            _ if inside_tag => {}
            character if character.is_control() => pending_space = true,
            character if character.is_whitespace() => pending_space = true,
            character => {
                if pending_space && !output.is_empty() {
                    output.push(' ');
                }
                pending_space = false;
                output.push(character);
            }
        }
        if output.len() >= MAX_FIELD_BYTES {
            break;
        }
    }
    output.trim().to_owned()
}

fn truncate(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn parse_date(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|date| date.with_timezone(&Utc))
        .or_else(|_| DateTime::parse_from_rfc2822(value).map(|date| date.with_timezone(&Utc)))
        .ok()
}

fn stable_id(title: &str, published_at: Option<&DateTime<Utc>>) -> String {
    let mut digest = Sha256::new();
    digest.update(title.as_bytes());
    digest.update([0]);
    if let Some(date) = published_at {
        digest.update(date.to_rfc3339().as_bytes());
    }
    hex::encode(digest.finalize())
}

fn signal_id(feed_id: &str, external_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(feed_id.as_bytes());
    digest.update([0]);
    digest.update(external_id.as_bytes());
    format!("news-{}", hex::encode(digest.finalize()))
}

fn archive_if_expired(signal: &mut NewsSignal, now: DateTime<Utc>) -> bool {
    if signal.archived_at.is_none() && now - signal.last_seen_at >= ARCHIVE_AGE {
        signal.archived_at = Some(now);
        true
    } else {
        false
    }
}

fn make_signal(
    feed: &NewsFeed,
    item: ParsedNewsItem,
    now: DateTime<Utc>,
    products: &[LocalProduct],
    aliases: &[Vec<String>],
    advisories: &[Advisory],
    existing: Option<&NewsSignal>,
) -> NewsSignal {
    let text = normalize_text(&format!(
        "{} {}",
        item.title,
        item.summary.as_deref().unwrap_or("")
    ));
    let mut matched_projects = BTreeSet::new();
    let mut matched_products = BTreeSet::new();
    for product in products {
        let mut terms = vec![product.name.as_str()];
        for group in aliases {
            if group
                .iter()
                .any(|term| normalize_text(term) == normalize_text(&product.name))
            {
                terms.extend(group.iter().map(String::as_str));
            }
        }
        if terms
            .iter()
            .any(|term| contains_phrase(&text, &normalize_text(term)))
        {
            matched_products.insert(product.name.clone());
            matched_projects.insert(product.project_id.clone());
        }
    }
    let exact_id = find_advisory_id(
        &item.title,
        item.summary.as_deref(),
        &[&item.external_id, &item.url],
        advisories,
    );
    let bound_now = exact_id.is_some().then_some(now);
    let id = signal_id(&feed.id, &item.external_id);
    NewsSignal {
        id,
        feed_id: feed.id.clone(),
        external_id: item.external_id,
        title: item.title,
        summary: item.summary,
        url: item.url,
        published_at: item.published_at,
        first_seen_at: existing.map_or(now, |signal| signal.first_seen_at),
        last_seen_at: now,
        matched_projects: matched_projects.into_iter().collect(),
        matched_products: matched_products.into_iter().collect(),
        advisory_id: exact_id.or_else(|| existing.and_then(|signal| signal.advisory_id.clone())),
        archived_at: bound_now.or_else(|| existing.and_then(|signal| signal.archived_at)),
    }
}

fn find_advisory_id(
    title: &str,
    summary: Option<&str>,
    additional_identifiers: &[&str],
    advisories: &[Advisory],
) -> Option<String> {
    let text = std::iter::once(title)
        .chain(summary)
        .chain(additional_identifiers.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    let ids = text
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '-')
        .map(str::to_ascii_uppercase)
        .filter(|token| valid_vulnerability_id(token))
        .collect::<BTreeSet<_>>();
    advisories.iter().find_map(|advisory| {
        std::iter::once(advisory.canonical_id.as_str())
            .chain(advisory.aliases.iter().map(String::as_str))
            .find(|alias| ids.contains(&alias.to_ascii_uppercase()))
            .map(|_| advisory.canonical_id.clone())
    })
}

fn valid_vulnerability_id(value: &str) -> bool {
    if let Some(number) = value.strip_prefix("CVE-") {
        let Some((year, sequence)) = number.split_once('-') else {
            return false;
        };
        year.len() == 4
            && year.bytes().all(|byte| byte.is_ascii_digit())
            && (4..=9).contains(&sequence.len())
            && sequence.bytes().all(|byte| byte.is_ascii_digit())
    } else if let Some(suffix) = value.strip_prefix("GHSA-") {
        let parts = suffix.split('-').collect::<Vec<_>>();
        parts.len() == 3
            && parts.iter().all(|part| {
                part.len() == 4 && part.bytes().all(|byte| byte.is_ascii_alphanumeric())
            })
    } else {
        false
    }
}

fn normalize_text(value: &str) -> String {
    let mut result = String::new();
    let mut space = true;
    for character in value.chars().flat_map(char::to_lowercase) {
        if character.is_alphanumeric() {
            result.push(character);
            space = false;
        } else if !space {
            result.push(' ');
            space = true;
        }
    }
    result.trim().to_owned()
}

fn contains_phrase(normalized_text: &str, normalized_term: &str) -> bool {
    if normalized_term
        .chars()
        .filter(|character| character.is_alphanumeric())
        .count()
        < 3
    {
        return false;
    }
    let words = normalized_text.split_whitespace().collect::<Vec<_>>();
    if normalized_term.contains(' ') {
        let haystack = format!(" {normalized_text} ");
        let needle = format!(" {normalized_term} ");
        if haystack.contains(&needle) {
            return true;
        }
    }
    let needle = normalized_term.replace(' ', "");
    (0..words.len()).any(|start| {
        let mut combined = String::new();
        (start..words.len().min(start + 4)).any(|end| {
            combined.push_str(words[end]);
            combined == needle
        })
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use chrono::{Duration, Utc};
    use security_monitor_core::{
        Advisory, Component, ComponentInstance, Finding, NewsSignal, Project,
    };
    use security_monitor_database::Database;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::{
        NewsFeed, NewsSignalService, archive_if_expired, contains_phrase, find_advisory_id,
        make_signal, normalize_text, parse_feed, valid_feed,
    };

    #[test]
    fn rss_and_atom_fixtures_parse_to_plain_bounded_items() {
        let rss = include_bytes!("../../../tests/fixtures/news/rss-nextjs.xml");
        let atom = include_bytes!("../../../tests/fixtures/news/atom-nextjs-cve.xml");
        let rss_items = parse_feed(rss).expect("RSS fixture parses");
        let atom_items = parse_feed(atom).expect("Atom fixture parses");
        assert_eq!(rss_items.len(), 1);
        assert_eq!(rss_items[0].title, "Next.js security update");
        assert!(
            rss_items[0]
                .summary
                .as_deref()
                .unwrap()
                .contains("middleware")
        );
        assert!(!rss_items[0].summary.as_deref().unwrap().contains('<'));
        assert_eq!(atom_items[0].external_id, "nextjs-security-1");
        assert!(atom_items[0].title.contains("CVE-2026-12345"));
    }

    #[test]
    fn feed_parser_rejects_doctypes_and_duplicate_link_attributes() {
        let doctype = br#"<!DOCTYPE rss [<!ENTITY item "expanded">]><rss><channel/></rss>"#;
        let duplicate_attribute = br#"<feed><entry><title>item</title><link href="https://example.org/a" href="https://example.org/b"/></entry></feed>"#;
        assert!(parse_feed(doctype).is_err());
        assert!(parse_feed(duplicate_attribute).is_err());
    }

    #[test]
    fn product_matching_uses_normalized_aliases_and_whole_phrases() {
        let text = normalize_text("Next.js middleware security issue");
        assert!(contains_phrase(&text, &normalize_text("nextjs")));
        assert!(contains_phrase(&text, &normalize_text("next.js")));
        assert!(!contains_phrase("node modules update", "nodejs"));
    }

    #[test]
    fn news_binds_only_when_an_exact_cve_or_ghsa_alias_is_present() {
        let mut advisory: Advisory =
            serde_json::from_str(include_str!("../../../tests/fixtures/drift/advisory.json"))
                .expect("advisory fixture parses");
        advisory.aliases = vec!["GHSA-35jh-r3h4-6jhm".to_owned()];
        assert_eq!(
            find_advisory_id(
                "Security update CVE-2021-23337",
                None,
                &[],
                std::slice::from_ref(&advisory)
            ),
            Some(advisory.canonical_id.clone())
        );
        assert_eq!(
            find_advisory_id(
                "Security update",
                None,
                &["https://example.org/GHSA-35jh-r3h4-6jhm"],
                std::slice::from_ref(&advisory)
            ),
            Some(advisory.canonical_id.clone())
        );
        assert_eq!(
            find_advisory_id("Security update CVE-2021-23338", None, &[], &[advisory]),
            None
        );
    }

    #[test]
    fn feed_configuration_rejects_non_https_and_credential_urls() {
        let mut feed = NewsFeed {
            id: "custom".to_owned(),
            name: "Custom feed".to_owned(),
            url: "https://example.org/rss.xml".to_owned(),
        };
        assert!(valid_feed(&feed));
        feed.url = "http://example.org/rss.xml".to_owned();
        assert!(!valid_feed(&feed));
        feed.url = "https://user:secret@example.org/rss.xml".to_owned();
        assert!(!valid_feed(&feed));
    }

    #[tokio::test]
    async fn product_news_stays_separate_then_binds_to_a_later_advisory() {
        let database = Database::in_memory()
            .await
            .expect("in-memory database opens");
        let root = tempfile::tempdir().expect("temporary directory is available");
        let now = Utc::now();
        let project = Project {
            id: "project-local".to_owned(),
            name: "Local Next.js app".to_owned(),
            root_path: root.path().to_string_lossy().into_owned(),
            git_remote: None,
            reference_branch: None,
            allowed_ai_providers: Vec::new(),
            last_scan_at: None,
            created_at: now,
            updated_at: now,
        };
        database
            .repository::<Project>()
            .create(&project)
            .await
            .expect("project persists locally");
        database
            .repository::<Component>()
            .create(&Component {
                id: "component-next".to_owned(),
                purl: "pkg:npm/next@14.2.1".to_owned(),
                ecosystem: "npm".to_owned(),
                name: "next".to_owned(),
                version: Some("14.2.1".to_owned()),
                source_type: "lockfile".to_owned(),
                created_at: now,
            })
            .await
            .expect("component persists locally");
        database
            .repository::<ComponentInstance>()
            .create(&ComponentInstance {
                id: "instance-next".to_owned(),
                component_id: "component-next".to_owned(),
                project_id: Some(project.id.clone()),
                asset_id: None,
                service_id: None,
                deployment_id: None,
                evidence: Vec::new(),
                created_at: now,
                last_seen_at: Some(now),
            })
            .await
            .expect("component instance persists locally");

        let service = NewsSignalService {
            http: crate::http::PublicDataHttp::for_tests(),
            database: database.clone(),
            app_data_dir: PathBuf::from(root.path()),
        };
        let products = service
            .local_products()
            .await
            .expect("local inventory loads");
        let aliases = service.load_synonyms().expect("local synonym table loads");
        let feed = NewsFeed {
            id: "fixture".to_owned(),
            name: "Fixture feed".to_owned(),
            url: "https://security.example.test/feed.xml".to_owned(),
        };
        let rss = parse_feed(include_bytes!(
            "../../../tests/fixtures/news/rss-nextjs.xml"
        ))
        .expect("initial RSS entry parses")
        .remove(0);
        let unverified = make_signal(&feed, rss, now, &products, &aliases, &[], None);
        assert_eq!(unverified.matched_projects, [project.id]);
        assert_eq!(unverified.matched_products, ["next"]);
        assert_eq!(unverified.advisory_id, None);
        assert_eq!(unverified.archived_at, None);
        database
            .repository::<NewsSignal>()
            .create(&unverified)
            .await
            .expect("news persists separately");
        assert!(
            database
                .repository::<Finding>()
                .list()
                .await
                .expect("findings remain readable")
                .is_empty()
        );

        let mut advisory: Advisory =
            serde_json::from_str(include_str!("../../../tests/fixtures/drift/advisory.json"))
                .expect("advisory fixture parses");
        advisory.canonical_id = "CVE-2026-12345".to_owned();
        advisory.aliases.clear();
        database
            .repository::<Advisory>()
            .create(&advisory)
            .await
            .expect("advisory is already in the local advisory store");
        let atom = parse_feed(include_bytes!(
            "../../../tests/fixtures/news/atom-nextjs-cve.xml"
        ))
        .expect("updated Atom entry parses")
        .remove(0);
        let existing = database
            .repository::<NewsSignal>()
            .get(&unverified.id)
            .await
            .expect("signal lookup succeeds")
            .expect("initial signal exists");
        let bound = make_signal(
            &feed,
            atom,
            now + Duration::minutes(30),
            &products,
            &aliases,
            std::slice::from_ref(&advisory),
            Some(&existing),
        );
        assert_eq!(bound.id, existing.id);
        assert_eq!(bound.first_seen_at, existing.first_seen_at);
        assert_eq!(bound.advisory_id.as_deref(), Some("CVE-2026-12345"));
        assert!(bound.archived_at.is_some());
        database
            .repository::<NewsSignal>()
            .update(&bound)
            .await
            .expect("existing signal is updated in place");
        assert!(
            database
                .repository::<Finding>()
                .list()
                .await
                .expect("findings remain readable")
                .is_empty()
        );

        let mut aged = bound;
        aged.archived_at = None;
        aged.last_seen_at = now - Duration::days(8);
        assert!(archive_if_expired(&mut aged, now));
        assert_eq!(aged.archived_at, Some(now));
    }

    #[tokio::test]
    async fn not_modified_feed_is_not_parsed_or_reprocessed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/feed.xml"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("ETag", "\"feed-v1\"")
                    .insert_header("Last-Modified", "Sat, 24 Oct 2026 12:00:00 GMT")
                    .set_body_bytes(include_bytes!(
                        "../../../tests/fixtures/news/rss-nextjs.xml"
                    )),
            )
            .expect(1)
            .mount(&server)
            .await;
        let database = Database::in_memory()
            .await
            .expect("in-memory database opens");
        let root = tempfile::tempdir().expect("temporary directory is available");
        let feed = NewsFeed {
            id: "fixture".to_owned(),
            name: "Fixture feed".to_owned(),
            url: format!("{}/feed.xml", server.uri()),
        };
        std::fs::write(
            root.path().join("news-sources.json"),
            serde_json::to_vec(&[&feed]).expect("feed config serializes"),
        )
        .expect("feed config writes locally");
        let service = NewsSignalService {
            http: crate::http::PublicDataHttp::for_tests(),
            database: database.clone(),
            app_data_dir: root.path().to_path_buf(),
        };
        let first = service.refresh().await.expect("first poll succeeds");
        assert_eq!(first.updated_feeds, 1);
        assert_eq!(first.signals_updated, 1);
        let signal = database
            .repository::<NewsSignal>()
            .list()
            .await
            .expect("signal list succeeds")
            .remove(0);
        let original_seen_at = signal.last_seen_at;

        let cache_path = root.path().join("news-feed-state.json");
        let mut cache: super::NewsCache =
            serde_json::from_slice(&std::fs::read(&cache_path).expect("feed cache exists"))
                .expect("feed cache parses");
        cache.feeds.get_mut("fixture").unwrap().last_checked_at =
            Some(Utc::now() - Duration::minutes(31));
        std::fs::write(
            &cache_path,
            serde_json::to_vec(&cache).expect("feed cache serializes"),
        )
        .expect("feed cache can be aged for the fixture");

        server.reset().await;
        Mock::given(method("GET"))
            .and(path("/feed.xml"))
            .respond_with(
                ResponseTemplate::new(304)
                    .insert_header("ETag", "\"feed-v1\"")
                    .insert_header("Last-Modified", "Sat, 24 Oct 2026 12:00:00 GMT"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let second = service.refresh().await.expect("conditional poll succeeds");
        assert_eq!(second.not_modified_feeds, 1);
        assert_eq!(second.signals_updated, 0);
        assert_eq!(second.failed_feeds, 0);
        let unchanged = database
            .repository::<NewsSignal>()
            .get(&signal.id)
            .await
            .expect("signal lookup succeeds")
            .expect("signal still exists");
        assert_eq!(unchanged.last_seen_at, original_seen_at);
        let requests = server
            .received_requests()
            .await
            .expect("wiremock records the conditional request");
        assert_eq!(
            requests[0].headers.get("if-none-match").unwrap(),
            "\"feed-v1\""
        );
    }
}
