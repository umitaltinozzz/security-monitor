use std::{
    collections::BTreeMap,
    ffi::OsString,
    io::Read,
    path::{Path, PathBuf},
};

use chrono::{DateTime, NaiveDate, Utc};
use flate2::read::GzDecoder;
use security_monitor_core::{Advisory, AdvisorySource};
use serde::{Deserialize, Serialize};

use crate::{ProviderError, cache::atomic_write, http::PublicDataHttp, normalize::is_cve_id};

const EPSS_URL: &str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
const MAX_EPSS_CSV_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EpssScore {
    pub cve: String,
    pub epss: f64,
    pub percentile: f64,
    pub date: Option<NaiveDate>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EpssSnapshot {
    pub scores: BTreeMap<String, EpssScore>,
    pub fetched_at: DateTime<Utc>,
    pub stale: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EpssCacheMetadata {
    fetched_at: DateTime<Utc>,
    stale: bool,
}

#[derive(Clone)]
pub struct EpssProvider {
    http: PublicDataHttp,
    url: String,
}

impl EpssProvider {
    pub fn new(http: PublicDataHttp) -> Self {
        Self {
            http,
            url: EPSS_URL.to_owned(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_url(http: PublicDataHttp, url: String) -> Self {
        Self { http, url }
    }

    pub async fn fetch_current(&self) -> Result<EpssSnapshot, ProviderError> {
        let response = self.http.get(&self.url).await?;
        snapshot_from_gzip(&response.body, Utc::now(), false)
    }

    pub async fn fetch_cached(
        &self,
        path: impl Into<PathBuf>,
    ) -> Result<EpssSnapshot, ProviderError> {
        let path = path.into();
        match self.http.get(&self.url).await {
            Ok(response) => {
                let fetched_at = Utc::now();
                let snapshot = match snapshot_from_gzip(&response.body, fetched_at, false) {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        return match load_stale_cache(&path)? {
                            Some(snapshot) => Ok(snapshot),
                            None => Err(error),
                        };
                    }
                };
                atomic_write(&path, &response.body)?;
                atomic_write(
                    &metadata_path(&path),
                    &serde_json::to_vec(&EpssCacheMetadata {
                        fetched_at,
                        stale: false,
                    })?,
                )?;
                Ok(snapshot)
            }
            Err(error) => match load_stale_cache(&path)? {
                Some(snapshot) => Ok(snapshot),
                None => Err(error),
            },
        }
    }

    pub fn load_cached(path: impl AsRef<Path>) -> Result<Option<EpssSnapshot>, ProviderError> {
        let path = path.as_ref();
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(ProviderError::Io(error)),
        };
        let metadata = read_metadata(path)?;
        let fetched_at = metadata
            .as_ref()
            .map(|metadata| metadata.fetched_at)
            .unwrap_or(DateTime::<Utc>::UNIX_EPOCH);
        let stale = metadata.is_some_and(|metadata| metadata.stale);
        snapshot_from_gzip(&bytes, fetched_at, stale).map(Some)
    }
}

fn load_stale_cache(path: &Path) -> Result<Option<EpssSnapshot>, ProviderError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(ProviderError::Io(error)),
    };
    let metadata = read_metadata(path)?;
    let fetched_at = metadata
        .as_ref()
        .map(|metadata| metadata.fetched_at)
        .unwrap_or(DateTime::<Utc>::UNIX_EPOCH);
    atomic_write(
        &metadata_path(path),
        &serde_json::to_vec(&EpssCacheMetadata {
            fetched_at,
            stale: true,
        })?,
    )?;
    snapshot_from_gzip(&bytes, fetched_at, true).map(Some)
}

fn metadata_path(path: &Path) -> PathBuf {
    let mut name: OsString = path.as_os_str().to_owned();
    name.push(".meta.json");
    PathBuf::from(name)
}

fn read_metadata(path: &Path) -> Result<Option<EpssCacheMetadata>, ProviderError> {
    match std::fs::read(metadata_path(path)) {
        Ok(bytes) => {
            let metadata: EpssCacheMetadata = serde_json::from_slice(&bytes)?;
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ProviderError::Io(error)),
    }
}

pub fn parse_epss_csv(csv_bytes: &[u8]) -> Result<BTreeMap<String, EpssScore>, ProviderError> {
    let publication_date = comment_date(csv_bytes);
    let mut reader = csv::ReaderBuilder::new()
        .comment(Some(b'#'))
        .flexible(true)
        .from_reader(csv_bytes);
    let headers = reader.headers()?.clone();
    let cve_index = headers
        .iter()
        .position(|header| header.eq_ignore_ascii_case("cve"))
        .ok_or(ProviderError::InvalidData)?;
    let epss_index = headers
        .iter()
        .position(|header| header.eq_ignore_ascii_case("epss"))
        .ok_or(ProviderError::InvalidData)?;
    let percentile_index = headers
        .iter()
        .position(|header| header.eq_ignore_ascii_case("percentile"))
        .ok_or(ProviderError::InvalidData)?;
    let date_index = headers
        .iter()
        .position(|header| header.eq_ignore_ascii_case("date"));
    let mut records = BTreeMap::new();
    for row in reader.records() {
        let row = row?;
        let cve = row
            .get(cve_index)
            .ok_or(ProviderError::InvalidData)?
            .to_ascii_uppercase();
        if !is_cve_id(&cve) {
            return Err(ProviderError::InvalidData);
        }
        let epss = parse_probability(row.get(epss_index))?;
        let percentile = parse_probability(row.get(percentile_index))?;
        let date = date_index
            .and_then(|index| row.get(index))
            .and_then(|value| NaiveDate::parse_from_str(value, "%Y-%m-%d").ok())
            .or(publication_date);
        if date.is_none() || records.contains_key(&cve) {
            return Err(ProviderError::InvalidData);
        }
        records.insert(
            cve.clone(),
            EpssScore {
                cve,
                epss,
                percentile,
                date,
            },
        );
    }
    if records.is_empty() {
        return Err(ProviderError::InvalidData);
    }
    Ok(records)
}

fn comment_date(bytes: &[u8]) -> Option<NaiveDate> {
    let contents = std::str::from_utf8(bytes).ok()?;
    for line in contents
        .lines()
        .filter(|line| line.trim_start().starts_with('#'))
    {
        for token in line.split(|character: char| !character.is_ascii_digit() && character != '-') {
            if token.len() == 10
                && let Ok(date) = NaiveDate::parse_from_str(token, "%Y-%m-%d")
            {
                return Some(date);
            }
        }
    }
    None
}

pub fn apply_epss(advisories: &mut [Advisory], snapshot: &EpssSnapshot) {
    for advisory in advisories {
        let score = std::iter::once(advisory.canonical_id.as_str())
            .chain(advisory.aliases.iter().map(String::as_str))
            .find_map(|id| snapshot.scores.get(&id.to_ascii_uppercase()));
        if let Some(score) = score {
            advisory.epss = Some(score.epss);
            advisory.epss_date = score
                .date
                .and_then(|date| date.and_hms_opt(0, 0, 0))
                .map(|date| DateTime::from_naive_utc_and_offset(date, Utc));
            let url = "https://www.first.org/epss".to_owned();
            if !advisory.source_urls.contains(&url) {
                advisory.source_urls.push(url.clone());
                advisory.source_attributions.push(AdvisorySource {
                    name: "FIRST EPSS".to_owned(),
                    url,
                    license: Some("Attribution requested by FIRST".to_owned()),
                });
            }
        }
    }
}

fn snapshot_from_gzip(
    bytes: &[u8],
    fetched_at: DateTime<Utc>,
    stale: bool,
) -> Result<EpssSnapshot, ProviderError> {
    let mut decoder = GzDecoder::new(bytes);
    let mut csv_bytes = Vec::new();
    decoder
        .by_ref()
        .take(MAX_EPSS_CSV_BYTES + 1)
        .read_to_end(&mut csv_bytes)
        .map_err(|_| ProviderError::InvalidData)?;
    if csv_bytes.len() as u64 > MAX_EPSS_CSV_BYTES {
        return Err(ProviderError::DownloadTooLarge);
    }
    Ok(EpssSnapshot {
        scores: parse_epss_csv(&csv_bytes)?,
        fetched_at,
        stale,
    })
}

fn parse_probability(value: Option<&str>) -> Result<f64, ProviderError> {
    let number = value
        .and_then(|value| value.parse::<f64>().ok())
        .ok_or(ProviderError::InvalidData)?;
    if !number.is_finite() || !(0.0..=1.0).contains(&number) {
        return Err(ProviderError::InvalidData);
    }
    Ok(number)
}
