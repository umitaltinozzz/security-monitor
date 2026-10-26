use std::collections::{BTreeSet, HashMap};

use security_monitor_core::Advisory;
use security_monitor_correlation::AliasMerger;
use security_monitor_database::Database;

use crate::ProviderError;

#[derive(Debug, Clone, Default)]
pub struct AdvisoryMerger {
    inner: AliasMerger,
}

impl AdvisoryMerger {
    pub fn new(records: impl IntoIterator<Item = Advisory>) -> Self {
        Self {
            inner: AliasMerger::new(records),
        }
    }

    pub fn merge(&mut self, incoming: Advisory) {
        self.inner.merge(incoming);
    }

    pub fn extend(&mut self, advisories: impl IntoIterator<Item = Advisory>) {
        self.inner.extend(advisories);
    }

    pub fn records(&self) -> Vec<Advisory> {
        self.inner.records()
    }

    pub fn into_records(self) -> Vec<Advisory> {
        self.inner.into_records()
    }

    pub async fn persist(self, database: &Database) -> Result<Vec<Advisory>, ProviderError> {
        let repository = database.repository::<Advisory>();
        let existing = repository.list().await?;
        let mut existing_by_alias = HashMap::<String, BTreeSet<String>>::new();
        for old in &existing {
            for alias in advisory_ids(old) {
                existing_by_alias
                    .entry(alias)
                    .or_default()
                    .insert(old.canonical_id.clone());
            }
        }
        let mut merger = AliasMerger::new(existing.clone());
        merger.extend(self.into_records());
        let records = merger.into_records();
        for record in &records {
            if repository.get(&record.canonical_id).await?.is_some() {
                repository.update(record).await?;
            } else {
                repository.create(record).await?;
            }
            let canonical_ids = advisory_ids(record);
            let obsolete_ids = canonical_ids
                .iter()
                .filter_map(|alias| existing_by_alias.get(alias))
                .flatten()
                .filter(|old_id| old_id.as_str() != record.canonical_id)
                .cloned()
                .collect::<BTreeSet<_>>();
            for old_id in obsolete_ids {
                database
                    .rekey_advisory_findings(&old_id, &record.canonical_id)
                    .await?;
            }
        }
        Ok(records)
    }
}

pub async fn merge_and_persist(
    database: &Database,
    incoming: impl IntoIterator<Item = Advisory>,
) -> Result<Vec<Advisory>, ProviderError> {
    let merger = AdvisoryMerger::new(incoming);
    merger.persist(database).await
}

fn advisory_ids(advisory: &Advisory) -> BTreeSet<String> {
    std::iter::once(advisory.canonical_id.as_str())
        .chain(advisory.aliases.iter().map(String::as_str))
        .map(|id| id.trim().to_ascii_uppercase())
        .filter(|id| !id.is_empty())
        .collect()
}
