use std::{collections::BTreeSet, path::PathBuf, time::Duration};

use tokio::time::Instant;

use crate::ScanProfile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileChangeKind {
    DependencyInput,
    SourceOrConfiguration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChange {
    pub paths: Vec<PathBuf>,
    pub profile: ScanProfile,
}

#[derive(Debug, Clone)]
pub struct DebouncedChanges {
    delay: Duration,
    deadline: Option<Instant>,
    profile: Option<ScanProfile>,
    paths: BTreeSet<PathBuf>,
}

impl DebouncedChanges {
    pub fn new(delay: Duration) -> Self {
        Self {
            delay,
            deadline: None,
            profile: None,
            paths: BTreeSet::new(),
        }
    }

    pub fn push(&mut self, path: PathBuf, kind: FileChangeKind, now: Instant) {
        self.deadline = Some(now + self.delay);
        self.paths.insert(path);
        let incoming = match kind {
            FileChangeKind::DependencyInput => ScanProfile::Quick,
            FileChangeKind::SourceOrConfiguration => ScanProfile::Full,
        };
        if incoming == ScanProfile::Full || self.profile.is_none() {
            self.profile = Some(incoming);
        }
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    pub fn take_if_ready(&mut self, now: Instant) -> Option<FileChange> {
        if !self.deadline.is_some_and(|deadline| now >= deadline) {
            return None;
        }
        self.deadline = None;
        Some(FileChange {
            paths: std::mem::take(&mut self.paths).into_iter().collect(),
            profile: self.profile.take().unwrap_or(ScanProfile::Quick),
        })
    }
}
