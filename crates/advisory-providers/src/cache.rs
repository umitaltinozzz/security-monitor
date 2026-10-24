use std::{
    fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use security_monitor_core::Advisory;
use serde::{Deserialize, Serialize};

use crate::{AdvisoryMerger, CveNowSourceStatus, ProviderError};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CachedAdvisories {
    pub advisories: Vec<Advisory>,
    pub fetched_at: DateTime<Utc>,
    pub stale: bool,
    #[serde(default)]
    pub source_statuses: Vec<CveNowSourceStatus>,
}

#[derive(Debug, Clone)]
pub struct AdvisoryCache {
    path: PathBuf,
}

impl AdvisoryCache {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn load(&self) -> Result<Option<CachedAdvisories>, ProviderError> {
        match fs::read(&self.path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(ProviderError::Io(error)),
        }
    }

    pub fn save(
        &self,
        advisories: impl IntoIterator<Item = Advisory>,
        stale: bool,
    ) -> Result<CachedAdvisories, ProviderError> {
        self.save_with_source_statuses(advisories, stale, Vec::new())
    }

    pub(crate) fn save_with_source_statuses(
        &self,
        advisories: impl IntoIterator<Item = Advisory>,
        stale: bool,
        source_statuses: Vec<CveNowSourceStatus>,
    ) -> Result<CachedAdvisories, ProviderError> {
        let mut merger = AdvisoryMerger::default();
        merger.extend(advisories);
        let cached = CachedAdvisories {
            advisories: merger.into_records(),
            fetched_at: Utc::now(),
            stale,
            source_statuses,
        };
        self.write(&cached)?;
        Ok(cached)
    }

    pub fn mark_stale(&self) -> Result<Option<CachedAdvisories>, ProviderError> {
        let Some(mut cached) = self.load()? else {
            return Ok(None);
        };
        cached.stale = true;
        self.write(&cached)?;
        Ok(Some(cached))
    }

    fn write(&self, cached: &CachedAdvisories) -> Result<(), ProviderError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(ProviderError::Io)?;
        }
        let bytes = serde_json::to_vec(cached)?;
        atomic_write(&self.path, &bytes)
    }
}

pub(crate) fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), ProviderError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(ProviderError::Io)?;
    }
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    fs::write(&temporary, contents).map_err(ProviderError::Io)?;
    match fs::rename(&temporary, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(ProviderError::Io(error))
        }
    }
}
