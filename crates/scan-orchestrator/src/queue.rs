use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use security_monitor_core::ScanOutcome;
use security_monitor_scanner_adapters::ScanExecution;
use thiserror::Error;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

static NEXT_JOB_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanProfile {
    Quick,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanReason {
    Manual,
    StartupChanged,
    FileChange,
    Scheduled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRequest {
    pub project_id: String,
    pub root: PathBuf,
    pub profile: ScanProfile,
    pub reason: ScanReason,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScanSummary {
    pub scan_id: String,
    pub outcome: ScanOutcome,
    pub input_hash: Option<String>,
    pub inventory_complete: bool,
    pub component_count: usize,
    pub correlated_finding_count: usize,
    pub scanner_findings: usize,
    pub diagnostics: Vec<String>,
    pub executions: Vec<ScanExecution>,
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("scan was cancelled")]
    Cancelled,
    #[error("scan exceeded its configured time limit")]
    TimedOut,
    #[error("project scan failed")]
    Failed,
    #[error("advisory refresh failed")]
    AdvisoryRefreshFailed,
}

#[async_trait]
pub trait ScanExecutor: Send + Sync + 'static {
    async fn scan(
        &self,
        request: ScanRequest,
        cancellation: CancellationToken,
    ) -> Result<ScanSummary, ScanError>;

    async fn refresh_advisories(&self, cancellation: CancellationToken)
    -> Result<usize, ScanError>;
}

#[derive(Debug, Clone, Copy)]
pub struct ScanLimits {
    pub max_parallel_scans: usize,
    pub queue_capacity: usize,
    pub max_scan_duration: Duration,
}

impl Default for ScanLimits {
    fn default() -> Self {
        let parallelism = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .clamp(1, 2);
        Self {
            max_parallel_scans: parallelism,
            queue_capacity: 64,
            max_scan_duration: Duration::from_secs(600),
        }
    }
}

#[derive(Debug, Error)]
pub enum QueueError {
    #[error("scan queue limits must be positive")]
    InvalidLimits,
    #[error("scan queue is closed")]
    Closed,
    #[error("scan worker stopped before returning a result")]
    WorkerStopped,
}

enum Job {
    Scan {
        id: String,
        request: ScanRequest,
        cancellation: CancellationToken,
        response: oneshot::Sender<Result<ScanSummary, ScanError>>,
    },
    Refresh {
        cancellation: CancellationToken,
        response: oneshot::Sender<Result<usize, ScanError>>,
    },
}

pub struct ScanQueue {
    sender: mpsc::Sender<Job>,
    active: Arc<Mutex<std::collections::HashMap<String, CancellationToken>>>,
}

pub struct ScanHandle {
    pub id: String,
    cancellation: CancellationToken,
    response: oneshot::Receiver<Result<ScanSummary, ScanError>>,
}

impl ScanHandle {
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub async fn wait(self) -> Result<ScanSummary, QueueWaitError> {
        self.response
            .await
            .map_err(|_| QueueWaitError::WorkerStopped)?
            .map_err(QueueWaitError::Scan)
    }
}

#[derive(Debug, Error)]
pub enum QueueWaitError {
    #[error("scan worker stopped before returning a result")]
    WorkerStopped,
    #[error(transparent)]
    Scan(#[from] ScanError),
}

impl ScanQueue {
    pub fn new(executor: Arc<dyn ScanExecutor>, limits: ScanLimits) -> Result<Self, QueueError> {
        if limits.max_parallel_scans == 0
            || limits.queue_capacity == 0
            || limits.max_scan_duration.is_zero()
        {
            return Err(QueueError::InvalidLimits);
        }
        let (sender, receiver) = mpsc::channel(limits.queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        let active = Arc::new(Mutex::new(std::collections::HashMap::new()));
        for _ in 0..limits.max_parallel_scans {
            let receiver = receiver.clone();
            let executor = executor.clone();
            let active = active.clone();
            tokio::spawn(async move {
                worker(receiver, executor, active, limits.max_scan_duration).await;
            });
        }
        Ok(Self { sender, active })
    }

    pub async fn enqueue(&self, request: ScanRequest) -> Result<ScanHandle, QueueError> {
        let id = format!("scan-job-{}", NEXT_JOB_ID.fetch_add(1, Ordering::Relaxed));
        let cancellation = CancellationToken::new();
        let (response, receiver) = oneshot::channel();
        self.active
            .lock()
            .await
            .insert(id.clone(), cancellation.clone());
        let job = Job::Scan {
            id: id.clone(),
            request,
            cancellation: cancellation.clone(),
            response,
        };
        if self.sender.send(job).await.is_err() {
            self.active.lock().await.remove(&id);
            return Err(QueueError::Closed);
        }
        Ok(ScanHandle {
            id,
            cancellation,
            response: receiver,
        })
    }

    pub async fn cancel(&self, id: &str) -> bool {
        let active = self.active.lock().await;
        if let Some(token) = active.get(id) {
            token.cancel();
            true
        } else {
            false
        }
    }

    pub async fn refresh_advisories(&self) -> Result<usize, QueueWaitError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Job::Refresh {
                cancellation: CancellationToken::new(),
                response,
            })
            .await
            .map_err(|_| QueueWaitError::WorkerStopped)?;
        receiver
            .await
            .map_err(|_| QueueWaitError::WorkerStopped)?
            .map_err(QueueWaitError::Scan)
    }
}

async fn worker(
    receiver: Arc<Mutex<mpsc::Receiver<Job>>>,
    executor: Arc<dyn ScanExecutor>,
    active: Arc<Mutex<std::collections::HashMap<String, CancellationToken>>>,
    max_duration: Duration,
) {
    loop {
        let job = receiver.lock().await.recv().await;
        let Some(job) = job else { return };
        match job {
            Job::Scan {
                id,
                request,
                cancellation,
                response,
            } => {
                let result = tokio::select! {
                    _ = cancellation.cancelled() => Err(ScanError::Cancelled),
                    result = tokio::time::timeout(max_duration, executor.scan(request, cancellation.clone())) => {
                        match result {
                            Ok(result) => result,
                            Err(_) => {
                                cancellation.cancel();
                                Err(ScanError::TimedOut)
                            }
                        }
                    }
                };
                let _ = response.send(result);
                active.lock().await.remove(&id);
            }
            Job::Refresh {
                cancellation,
                response,
            } => {
                let result = tokio::select! {
                    _ = cancellation.cancelled() => Err(ScanError::Cancelled),
                    result = tokio::time::timeout(max_duration, executor.refresh_advisories(cancellation.clone())) => {
                        match result {
                            Ok(result) => result,
                            Err(_) => {
                                cancellation.cancel();
                                Err(ScanError::TimedOut)
                            }
                        }
                    }
                };
                let _ = response.send(result);
            }
        }
    }
}
