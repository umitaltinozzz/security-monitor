use std::collections::BTreeSet;

use security_monitor_core::{Advisory, AdvisorySource};
use security_monitor_database::Database;

use crate::ProviderError;

#[derive(Debug, Clone, Default)]
pub struct AdvisoryMerger {
    records: Vec<Advisory>,
}

impl AdvisoryMerger {
    pub fn new(records: impl IntoIterator<Item = Advisory>) -> Self {
        let mut merger = Self::default();
        merger.extend(records);
        merger
    }

    pub fn merge(&mut self, incoming: Advisory) {
        let mut merged = incoming;
        let mut index = 0;
        while index < self.records.len() {
            if !aliases_of(&self.records[index]).is_disjoint(&aliases_of(&merged)) {
                let mut existing = self.records.remove(index);
                merge_record(&mut existing, merged);
                merged = existing;
                index = 0;
            } else {
                index += 1;
            }
        }
        self.records.push(merged);
        self.records
            .sort_by(|left, right| left.canonical_id.cmp(&right.canonical_id));
    }

    pub fn extend(&mut self, advisories: impl IntoIterator<Item = Advisory>) {
        for advisory in advisories {
            self.merge(advisory);
        }
    }

    pub fn records(&self) -> &[Advisory] {
        &self.records
    }

    pub fn into_records(self) -> Vec<Advisory> {
        self.records
    }

    pub async fn persist(self, database: &Database) -> Result<Vec<Advisory>, ProviderError> {
        let repository = database.repository::<Advisory>();
        let records = self.into_records();
        for record in &records {
            if repository.get(&record.canonical_id).await?.is_some() {
                repository.update(record).await?;
            } else {
                repository.create(record).await?;
            }
        }
        Ok(records)
    }
}

pub async fn merge_and_persist(
    database: &Database,
    incoming: impl IntoIterator<Item = Advisory>,
) -> Result<Vec<Advisory>, ProviderError> {
    let existing = database.repository::<Advisory>().list().await?;
    let mut merger = AdvisoryMerger::new(existing);
    merger.extend(incoming);
    merger.persist(database).await
}

fn aliases_of(advisory: &Advisory) -> BTreeSet<String> {
    std::iter::once(advisory.canonical_id.as_str())
        .chain(advisory.aliases.iter().map(String::as_str))
        .map(|id| id.trim().to_ascii_uppercase())
        .filter(|id| !id.is_empty())
        .collect()
}

fn merge_record(existing: &mut Advisory, incoming: Advisory) {
    let mut aliases = aliases_of(existing);
    aliases.extend(aliases_of(&incoming));
    aliases.remove(&existing.canonical_id.to_ascii_uppercase());
    existing.aliases = aliases.into_iter().collect();

    if existing.title.is_empty() {
        existing.title = incoming.title;
    }
    if existing.summary.is_none() {
        existing.summary = incoming.summary;
        existing.summary_model = incoming.summary_model;
    } else if existing.summary_model.is_none() {
        existing.summary_model = incoming.summary_model;
    }
    if existing.description.is_none() {
        existing.description = incoming.description;
    }
    append_unique(&mut existing.affected_ranges, incoming.affected_ranges);
    append_unique(&mut existing.fixed_versions, incoming.fixed_versions);
    append_unique(&mut existing.source_urls, incoming.source_urls);
    append_sources(
        &mut existing.source_attributions,
        incoming.source_attributions,
    );
    existing.cvss = incoming.cvss.or(existing.cvss);
    existing.severity = incoming.severity.or(existing.severity.clone());
    existing.kev |= incoming.kev;
    match (existing.epss_date, incoming.epss_date) {
        (None, Some(next)) => {
            existing.epss = incoming.epss.or(existing.epss);
            existing.epss_date = Some(next);
        }
        (Some(previous), Some(next)) if next >= previous => {
            existing.epss = incoming.epss.or(existing.epss);
            existing.epss_date = Some(next);
        }
        (Some(_), Some(_)) => {}
        (Some(_), None) => {
            if existing.epss.is_none() {
                existing.epss = incoming.epss;
            }
        }
        (None, None) => existing.epss = incoming.epss.or(existing.epss),
    }
    if incoming.source_updated_at.is_some_and(|next| {
        existing
            .source_updated_at
            .is_none_or(|previous| next >= previous)
    }) {
        existing.source_updated_at = incoming.source_updated_at;
    }
    if existing.updated_at < incoming.updated_at {
        existing.updated_at = incoming.updated_at;
    }
}

fn append_unique<T: PartialEq>(target: &mut Vec<T>, incoming: Vec<T>) {
    for value in incoming {
        if !target.contains(&value) {
            target.push(value);
        }
    }
}

fn append_sources(target: &mut Vec<AdvisorySource>, incoming: Vec<AdvisorySource>) {
    for source in incoming {
        if !target.iter().any(|current| current.url == source.url) {
            target.push(source);
        }
    }
}
