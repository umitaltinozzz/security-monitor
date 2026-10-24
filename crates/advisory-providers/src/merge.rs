use std::collections::BTreeSet;

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

    pub fn records(&self) -> &[Advisory] {
        self.inner.records()
    }

    pub fn into_records(self) -> Vec<Advisory> {
        self.inner.into_records()
    }

    pub async fn persist(self, database: &Database) -> Result<Vec<Advisory>, ProviderError> {
        let repository = database.repository::<Advisory>();
        let existing = repository.list().await?;
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
            for old in &existing {
                if old.canonical_id != record.canonical_id
                    && !advisory_ids(old).is_disjoint(&canonical_ids)
                {
                    database
                        .rekey_advisory_findings(&old.canonical_id, &record.canonical_id)
                        .await?;
                }
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
