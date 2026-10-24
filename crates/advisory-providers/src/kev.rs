use std::{collections::BTreeSet, path::PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{ProviderError, cache::atomic_write, http::PublicDataHttp, normalize::is_cve_id};
use security_monitor_core::{Advisory, AdvisorySource};

const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedKevCatalog {
    pub cve_ids: BTreeSet<String>,
    pub fetched_at: DateTime<Utc>,
    pub stale: bool,
}

#[derive(Clone)]
pub struct KevProvider {
    http: PublicDataHttp,
}

impl KevProvider {
    pub fn new(http: PublicDataHttp) -> Self {
        Self { http }
    }

    pub async fn fetch(&self) -> Result<CachedKevCatalog, ProviderError> {
        let response = self.http.get(KEV_URL).await?;
        Ok(CachedKevCatalog {
            cve_ids: parse_kev_catalog(&response.body)?,
            fetched_at: Utc::now(),
            stale: false,
        })
    }

    pub async fn fetch_cached(
        &self,
        path: impl Into<PathBuf>,
    ) -> Result<CachedKevCatalog, ProviderError> {
        let path = path.into();
        match self.fetch().await {
            Ok(catalog) => {
                atomic_write(&path, &serde_json::to_vec(&catalog)?)?;
                Ok(catalog)
            }
            Err(error) => {
                let bytes = match std::fs::read(&path) {
                    Ok(bytes) => bytes,
                    Err(read_error) if read_error.kind() == std::io::ErrorKind::NotFound => {
                        return Err(error);
                    }
                    Err(read_error) => return Err(ProviderError::Io(read_error)),
                };
                let mut cached: CachedKevCatalog = serde_json::from_slice(&bytes)?;
                cached.stale = true;
                atomic_write(&path, &serde_json::to_vec(&cached)?)?;
                Ok(cached)
            }
        }
    }
}

pub fn parse_kev_catalog(bytes: &[u8]) -> Result<BTreeSet<String>, ProviderError> {
    let value: Value = serde_json::from_slice(bytes)?;
    let vulnerabilities = value
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .ok_or(ProviderError::InvalidData)?;
    let mut cve_ids = BTreeSet::new();
    for vulnerability in vulnerabilities {
        let cve_id = vulnerability
            .get("cveID")
            .and_then(Value::as_str)
            .map(str::to_ascii_uppercase)
            .filter(|value| is_cve_id(value))
            .ok_or(ProviderError::InvalidData)?;
        cve_ids.insert(cve_id);
    }
    if cve_ids.is_empty() {
        return Err(ProviderError::InvalidData);
    }
    Ok(cve_ids)
}

pub fn apply_kev(advisories: &mut [Advisory], catalog: &CachedKevCatalog) {
    for advisory in advisories {
        if advisory_ids(advisory).any(|id| catalog.cve_ids.contains(&id.to_ascii_uppercase())) {
            advisory.kev = true;
            let url = KEV_URL.to_owned();
            if !advisory.source_urls.contains(&url) {
                advisory.source_urls.push(url.clone());
                advisory.source_attributions.push(AdvisorySource {
                    name: "CISA Known Exploited Vulnerabilities Catalog".to_owned(),
                    url,
                    license: None,
                });
            }
        }
    }
}

fn advisory_ids(advisory: &Advisory) -> impl Iterator<Item = &str> {
    std::iter::once(advisory.canonical_id.as_str())
        .chain(advisory.aliases.iter().map(String::as_str))
}
