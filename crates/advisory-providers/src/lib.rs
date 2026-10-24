mod cache;
mod cve_now;
mod epss;
mod ghsa;
mod http;
mod kev;
mod matching;
mod merge;
mod news;
mod normalize;
mod osv;
mod service;

pub use cache::{AdvisoryCache, CachedAdvisories};
pub use cve_now::{
    CveNowCursor, CveNowProvider, CveNowSourceStatus, CveNowSync,
    DEFAULT_CVE_POLL_INTERVAL_SECONDS, MAX_CVE_POLL_INTERVAL_SECONDS,
    MIN_CVE_POLL_INTERVAL_SECONDS,
};
pub use epss::{EpssProvider, EpssScore, EpssSnapshot, apply_epss, parse_epss_csv};
pub use ghsa::{GhsaProvider, parse_ghsa_advisory};
pub use http::{
    ApprovedAiRequest, HttpPolicy, ProviderError, PublicDataHttp, authorize_updater_destination,
    configure_updater_client,
};
pub use kev::{CachedKevCatalog, KevProvider, apply_kev, parse_kev_catalog};
pub use matching::{AdvisoryFinding, FindingReason, evaluate_inventory};
pub use merge::{AdvisoryMerger, merge_and_persist};
pub use news::{NewsFeed, NewsSignalService, NewsSyncReport};
pub use osv::{OsvDatabase, OsvDatabaseUpdater, OsvUpdateStatus, ecosystem_slug};
pub use service::{AdvisoryService, AdvisorySyncReport, ProviderFreshness};

#[cfg(test)]
mod tests;
