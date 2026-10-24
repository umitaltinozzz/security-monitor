use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Duration, Utc};
use security_monitor_core::Advisory;
use security_monitor_database::Database;
use security_monitor_inventory::Inventory;
use serde::{Deserialize, Serialize};

use crate::{
    AdvisoryCache, AdvisoryFinding, AdvisoryMerger, CveNowProvider,
    DEFAULT_CVE_POLL_INTERVAL_SECONDS, EpssProvider, GhsaProvider, HttpPolicy, KevProvider,
    OsvDatabase, OsvDatabaseUpdater, ProviderError, PublicDataHttp, apply_epss, apply_kev,
    ecosystem_slug, evaluate_inventory,
};

const KEV_REFRESH_INTERVAL: Duration = Duration::hours(24);
const EPSS_REFRESH_INTERVAL: Duration = Duration::hours(24);
const OSV_REFRESH_INTERVAL: Duration = Duration::hours(1);
const CVE_SOURCE_MAX_AGE: Duration = Duration::hours(24);
const MAX_GHSA_CROSS_CHECKS: usize = 10;
static REFRESH_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderFreshness {
    pub provider: String,
    pub updated_at: Option<DateTime<Utc>>,
    pub stale: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdvisorySyncReport {
    pub advisories: Vec<Advisory>,
    pub findings: Vec<AdvisoryFinding>,
    pub provider_freshness: Vec<ProviderFreshness>,
    pub inventory_complete: bool,
}

pub struct AdvisoryService {
    http: PublicDataHttp,
    database: Database,
    cache_root: PathBuf,
    cve_poll_interval_seconds: u64,
}

impl AdvisoryService {
    pub fn new(
        policy: HttpPolicy,
        database: Database,
        cache_root: impl Into<PathBuf>,
    ) -> Result<Self, ProviderError> {
        Ok(Self {
            http: PublicDataHttp::new(policy)?,
            database,
            cache_root: cache_root.into(),
            cve_poll_interval_seconds: DEFAULT_CVE_POLL_INTERVAL_SECONDS,
        })
    }

    pub fn with_cve_poll_interval_seconds(mut self, seconds: u64) -> Result<Self, ProviderError> {
        CveNowProvider::new(self.http.clone()).with_poll_interval_seconds(seconds)?;
        self.cve_poll_interval_seconds = seconds;
        Ok(self)
    }

    pub async fn refresh_and_match(
        &self,
        inventory: &Inventory,
    ) -> Result<AdvisorySyncReport, ProviderError> {
        let _guard = REFRESH_LOCK.lock().await;
        fs::create_dir_all(&self.cache_root).map_err(ProviderError::Io)?;
        let now = Utc::now();
        let mut freshness = Vec::new();
        let mut discovered = Vec::new();

        let cve_dir = self.cache_root.join("cve-now");
        let cve_cache = AdvisoryCache::new(cve_dir.join("advisories.json"));
        let cve_provider = CveNowProvider::new(self.http.clone())
            .with_poll_interval_seconds(self.cve_poll_interval_seconds)?;
        match cve_provider
            .sync_cached(&cve_cache, cve_dir.join("cursor.json"))
            .await
        {
            Ok(cached) => {
                freshness.push(ProviderFreshness {
                    provider: "cve.now".to_owned(),
                    updated_at: Some(cached.fetched_at),
                    stale: cached.stale,
                    error: None,
                });
                if cached.source_statuses.is_empty() {
                    freshness.push(ProviderFreshness {
                        provider: "cve.now: upstream source status".to_owned(),
                        updated_at: None,
                        stale: true,
                        error: Some("upstream source status is missing".to_owned()),
                    });
                } else {
                    freshness.extend(cached.source_statuses.iter().map(|status| {
                        let stale = cve_source_status_is_stale(status, cached.stale, now);
                        ProviderFreshness {
                            provider: format!("cve.now: {}", status.name),
                            updated_at: status.updated_at,
                            stale,
                            error: stale.then(|| {
                                if cached.stale {
                                    "using cached data".to_owned()
                                } else if !status.healthy {
                                    "upstream source reported an unhealthy or missing status"
                                        .to_owned()
                                } else if status.updated_at.is_none() {
                                    "upstream source update time is missing".to_owned()
                                } else {
                                    "upstream source update is older than 24 hours".to_owned()
                                }
                            }),
                        }
                    }));
                }
                discovered.extend(cached.advisories);
            }
            Err(error) => freshness.push(ProviderFreshness {
                provider: "cve.now".to_owned(),
                updated_at: None,
                stale: true,
                error: Some(error.to_string()),
            }),
        }

        let database_records = self.database.repository::<Advisory>().list().await?;
        let existing_ids = database_records
            .iter()
            .map(|advisory| advisory.canonical_id.clone())
            .collect::<BTreeSet<_>>();
        let mut merger = AdvisoryMerger::new(database_records);
        merger.extend(discovered.iter().cloned());

        let osv_root = self.cache_root.join("osv");
        let updater = OsvDatabaseUpdater::new(self.http.clone());
        let mut ecosystems = inventory
            .components
            .iter()
            .map(|component| component.ecosystem.clone())
            .collect::<Vec<_>>();
        ecosystems.sort();
        ecosystems.dedup();
        let mut osv_statuses = Vec::new();
        let mut needs_refresh = Vec::new();
        for ecosystem in &ecosystems {
            let Some(slug) = ecosystem_slug(ecosystem) else {
                needs_refresh.push(ecosystem.clone());
                continue;
            };
            let directory = osv_root.join(slug);
            match OsvDatabase::open(&directory) {
                Ok(database)
                    if is_fresh(
                        database.status().updated_at,
                        database.status().stale,
                        now,
                        OSV_REFRESH_INTERVAL,
                    ) =>
                {
                    osv_statuses.push(database.status().clone());
                }
                _ => needs_refresh.push(ecosystem.clone()),
            }
        }
        if !needs_refresh.is_empty() {
            osv_statuses.extend(updater.update_ecosystems(&osv_root, needs_refresh).await?);
        }
        for status in &osv_statuses {
            freshness.push(ProviderFreshness {
                provider: format!("OSV ({})", status.ecosystem),
                updated_at: status.updated_at,
                stale: status.stale,
                error: status.error.clone(),
            });
        }
        for ecosystem in &ecosystems {
            let Some(slug) = ecosystem_slug(ecosystem) else {
                continue;
            };
            let directory = osv_root.join(slug);
            match OsvDatabase::open(&directory) {
                Ok(database) => {
                    for component in inventory
                        .components
                        .iter()
                        .filter(|component| component.ecosystem.eq_ignore_ascii_case(ecosystem))
                    {
                        discovered.extend(database.query(ecosystem, &component.name));
                    }
                }
                Err(error) => {
                    if let Some(status) = freshness
                        .iter_mut()
                        .find(|status| status.provider == format!("OSV ({ecosystem})"))
                    {
                        status.stale = true;
                        status.error = Some(error.to_string());
                    } else {
                        freshness.push(ProviderFreshness {
                            provider: format!("OSV ({ecosystem})"),
                            updated_at: None,
                            stale: true,
                            error: Some(error.to_string()),
                        });
                    }
                }
            }
        }

        let ghsa_provider = GhsaProvider::new(self.http.clone());
        let mut ghsa_checks = 0;
        let mut ghsa_succeeded = false;
        let mut ghsa_failed = false;
        let mut ghsa_pending = false;
        for advisory in &discovered {
            if existing_ids.contains(&advisory.canonical_id)
                || advisory
                    .source_urls
                    .iter()
                    .any(|url| url.contains("github.com/advisories/"))
            {
                continue;
            }
            for alias in &advisory.aliases {
                if alias.starts_with("GHSA-") && ghsa_checks >= MAX_GHSA_CROSS_CHECKS {
                    ghsa_pending = true;
                    continue;
                }
                if alias.starts_with("GHSA-") {
                    ghsa_checks += 1;
                    match ghsa_provider.fetch_by_id(alias).await {
                        Ok(ghsa) => {
                            ghsa_succeeded = true;
                            merger.merge(ghsa);
                        }
                        Err(_) => ghsa_failed = true,
                    }
                }
            }
        }
        if ghsa_checks > 0 || ghsa_pending {
            let incomplete = ghsa_failed || ghsa_pending;
            freshness.push(ProviderFreshness {
                provider: "GitHub Advisory Database".to_owned(),
                updated_at: ghsa_succeeded.then_some(now),
                stale: incomplete,
                error: if ghsa_failed {
                    Some("one or more GHSA cross-checks failed".to_owned())
                } else if ghsa_pending {
                    Some("GHSA cross-checks remain beyond the per-refresh request limit".to_owned())
                } else {
                    None
                },
            });
        }
        let kev_path = self.cache_root.join("kev/catalog.json");
        let kev_provider = KevProvider::new(self.http.clone());
        let kev = match load_fresh_kev(&kev_path, now) {
            Ok(Some(cached)) => Some(cached),
            Ok(None) => match kev_provider.fetch_cached(&kev_path).await {
                Ok(cached) => Some(cached),
                Err(error) => {
                    freshness.push(ProviderFreshness {
                        provider: "CISA KEV".to_owned(),
                        updated_at: None,
                        stale: true,
                        error: Some(error.to_string()),
                    });
                    None
                }
            },
            Err(error) => {
                freshness.push(ProviderFreshness {
                    provider: "CISA KEV".to_owned(),
                    updated_at: None,
                    stale: true,
                    error: Some(error.to_string()),
                });
                None
            }
        };
        if let Some(catalog) = &kev {
            if catalog.stale {
                freshness.push(ProviderFreshness {
                    provider: "CISA KEV".to_owned(),
                    updated_at: Some(catalog.fetched_at),
                    stale: true,
                    error: Some("using cached data".to_owned()),
                });
            } else {
                freshness.push(ProviderFreshness {
                    provider: "CISA KEV".to_owned(),
                    updated_at: Some(catalog.fetched_at),
                    stale: false,
                    error: None,
                });
            }
        }

        let epss_path = self.cache_root.join("epss/scores.csv.gz");
        let epss_provider = EpssProvider::new(self.http.clone());
        let epss = match EpssProvider::load_cached(&epss_path) {
            Ok(Some(cached))
                if is_fresh(
                    Some(cached.fetched_at),
                    cached.stale,
                    now,
                    EPSS_REFRESH_INTERVAL,
                ) =>
            {
                Some(cached)
            }
            Ok(_) => match epss_provider.fetch_cached(&epss_path).await {
                Ok(cached) => Some(cached),
                Err(error) => {
                    freshness.push(ProviderFreshness {
                        provider: "FIRST EPSS".to_owned(),
                        updated_at: None,
                        stale: true,
                        error: Some(error.to_string()),
                    });
                    None
                }
            },
            Err(error) => {
                freshness.push(ProviderFreshness {
                    provider: "FIRST EPSS".to_owned(),
                    updated_at: None,
                    stale: true,
                    error: Some(error.to_string()),
                });
                None
            }
        };
        if let Some(snapshot) = &epss {
            freshness.push(ProviderFreshness {
                provider: "FIRST EPSS".to_owned(),
                updated_at: Some(snapshot.fetched_at),
                stale: snapshot.stale,
                error: snapshot.stale.then(|| "using cached data".to_owned()),
            });
        }

        let mut merged = merger.into_records();
        if let Some(catalog) = &kev {
            apply_kev(&mut merged, catalog);
        }
        if let Some(snapshot) = &epss {
            apply_epss(&mut merged, snapshot);
        }
        let merger = AdvisoryMerger::new(merged);
        let advisories = merger.persist(&self.database).await?;
        let findings = evaluate_inventory(&advisories, inventory);
        let provider_freshness = self.persist_provider_statuses(freshness)?;
        Ok(AdvisorySyncReport {
            advisories,
            findings,
            provider_freshness,
            inventory_complete: inventory.complete,
        })
    }

    fn persist_provider_statuses(
        &self,
        current: Vec<ProviderFreshness>,
    ) -> Result<Vec<ProviderFreshness>, ProviderError> {
        let path = self.cache_root.join("provider-status.json");
        let mut statuses = match fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<Vec<ProviderFreshness>>(&bytes) {
                Ok(previous) => previous
                    .into_iter()
                    .map(|status| (status.provider.clone(), status))
                    .collect::<BTreeMap<_, _>>(),
                Err(_) => BTreeMap::from([(
                    "local provider status".to_owned(),
                    ProviderFreshness {
                        provider: "local provider status".to_owned(),
                        updated_at: None,
                        stale: true,
                        error: Some("cached provider status is invalid".to_owned()),
                    },
                )]),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(ProviderError::Io(error)),
        };
        for status in current {
            statuses.insert(status.provider.clone(), status);
        }
        let result = statuses.into_values().collect::<Vec<_>>();
        crate::cache::atomic_write(&path, &serde_json::to_vec(&result)?)?;
        Ok(result)
    }
}

fn is_fresh(
    updated_at: Option<DateTime<Utc>>,
    stale: bool,
    now: DateTime<Utc>,
    maximum_age: Duration,
) -> bool {
    if stale {
        return false;
    }
    updated_at
        .is_some_and(|updated| now >= updated && now.signed_duration_since(updated) < maximum_age)
}

pub(super) fn cve_source_status_is_stale(
    status: &crate::CveNowSourceStatus,
    cache_stale: bool,
    now: DateTime<Utc>,
) -> bool {
    if cache_stale || !status.healthy {
        return true;
    }
    status.updated_at.is_none_or(|updated| {
        updated > now || now.signed_duration_since(updated) > CVE_SOURCE_MAX_AGE
    })
}

fn load_fresh_kev(
    path: &Path,
    now: DateTime<Utc>,
) -> Result<Option<crate::CachedKevCatalog>, ProviderError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(ProviderError::Io(error)),
    };
    let cached: crate::CachedKevCatalog = serde_json::from_slice(&bytes)?;
    Ok(is_fresh(
        Some(cached.fetched_at),
        cached.stale,
        now,
        KEV_REFRESH_INTERVAL,
    )
    .then_some(cached))
}
