mod debounce;
mod discovery;
mod hash;
mod local;
mod queue;
mod scheduler;
mod watcher;

pub use debounce::{DebouncedChanges, FileChange, FileChangeKind};
pub use discovery::{ProjectCandidate, ProjectDiscovery, discover_projects};
pub use hash::{InputHash, InputHashLimits, hash_dependency_inputs};
pub use local::{LocalProjectScanner, LocalScanSettings};
pub use queue::{
    QueueError, QueueWaitError, ScanError, ScanExecutor, ScanHandle, ScanLimits, ScanProfile,
    ScanQueue, ScanReason, ScanRequest, ScanSummary,
};
pub use scheduler::{ScheduleAction, SchedulePlan, Scheduler};
pub use watcher::{ProjectWatcher, WatchError, watch_project};

#[cfg(test)]
mod tests;
