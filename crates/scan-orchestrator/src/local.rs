use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use security_monitor_advisory_providers::{
    AdvisoryService, HttpPolicy, ProviderFreshness, PublicDataHttp,
};
use security_monitor_core::{
    Advisory, AuditScope, Component, ComponentEvidence, ComponentInstance, Project,
    ProjectScanCheckpoint, ScanOutcome, ScanRun,
};
use security_monitor_correlation::{
    CorrelationComponent, InventoryFreshness, PriorityContext, ScopeVerification,
    correlate_and_persist,
};
use security_monitor_database::Database;
use security_monitor_inventory::{Inventory, InventoryComponent, scan_repository};
use security_monitor_scanner_adapters::{
    EngineKind, EngineStatus, ScanExecution, ScanMode, ScanRequest as EngineScanRequest,
    ScannerAdapters,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use tracing::warn;
use uuid::Uuid;

use crate::{
    InputHash, InputHashLimits, QueueError, QueueWaitError, ScanError, ScanExecutor, ScanHandle,
    ScanLimits, ScanProfile, ScanQueue, ScanReason, ScanRequest, ScanSummary,
    hash_dependency_inputs,
};

#[derive(Debug, Clone, Default)]
pub struct LocalScanSettings {
    pub hash_limits: InputHashLimits,
    pub semgrep_rules_file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupCheckReport {
    pub scanned_project_ids: Vec<String>,
    pub unchanged_project_ids: Vec<String>,
    pub unverified_project_ids: Vec<String>,
    pub correlated_finding_count: usize,
}

#[derive(Debug, Error)]
pub enum StartupCheckError {
    #[error("project startup check failed")]
    Scan(#[from] ScanError),
    #[error("startup scan queue is unavailable")]
    Queue(#[from] QueueError),
    #[error("startup scan worker stopped")]
    QueueWait(#[from] QueueWaitError),
    #[error("startup check database operation failed")]
    Database(#[from] security_monitor_database::DatabaseError),
}

pub struct LocalProjectScanner {
    database: Database,
    app_data_dir: PathBuf,
    http_policy: HttpPolicy,
    scanners: ScannerAdapters,
    settings: LocalScanSettings,
    project_locks:
        tokio::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    correlation_lock: tokio::sync::Mutex<()>,
}

impl LocalProjectScanner {
    pub fn new(
        database: Database,
        app_data_dir: impl Into<PathBuf>,
        http_policy: HttpPolicy,
        settings: LocalScanSettings,
    ) -> Result<Self, security_monitor_advisory_providers::ProviderError> {
        let http = PublicDataHttp::new(http_policy)?;
        let app_data_dir = app_data_dir.into();
        let scanners = ScannerAdapters::new(http.clone(), app_data_dir.clone());
        Ok(Self {
            database,
            app_data_dir,
            http_policy,
            scanners,
            settings,
            project_locks: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            correlation_lock: tokio::sync::Mutex::new(()),
        })
    }

    pub fn queue(self: &Arc<Self>, limits: ScanLimits) -> Result<ScanQueue, QueueError> {
        ScanQueue::new(self.clone(), limits)
    }

    pub async fn startup_check(
        &self,
        projects: &[Project],
        queue: &ScanQueue,
    ) -> Result<StartupCheckReport, StartupCheckError> {
        let checkpoints = self.database.repository::<ProjectScanCheckpoint>();
        let mut handles = Vec::<(String, ScanHandle)>::new();
        let mut unchanged = Vec::new();
        let mut unverified = Vec::new();
        for project in projects {
            let root = canonical_project_path(&project.root_path).ok();
            let current = if let Some(root) = &root {
                let root = root.clone();
                let limits = self.settings.hash_limits;
                tokio::task::spawn_blocking(move || hash_dependency_inputs(root, limits))
                    .await
                    .unwrap_or_else(|_| incomplete_hash())
            } else {
                incomplete_hash()
            };
            let previous = checkpoints.get(&project.id).await?;
            let unchanged_inputs = current.complete
                && current.sha256.is_some()
                && previous.as_ref().is_some_and(|checkpoint| {
                    checkpoint.inventory_complete && checkpoint.input_hash == current.sha256
                });
            if unchanged_inputs {
                unchanged.push(project.id.clone());
                continue;
            }
            let Some(root) = root else {
                unverified.push(project.id.clone());
                continue;
            };
            let handle = queue
                .enqueue(ScanRequest {
                    project_id: project.id.clone(),
                    root,
                    profile: ScanProfile::Quick,
                    reason: ScanReason::StartupChanged,
                })
                .await?;
            handles.push((project.id.clone(), handle));
        }

        let mut scanned = Vec::new();
        for (project_id, handle) in handles {
            handle.wait().await?;
            scanned.push(project_id);
        }
        let correlated_finding_count = queue.refresh_advisories().await?;
        unverified.sort();
        Ok(StartupCheckReport {
            scanned_project_ids: scanned,
            unchanged_project_ids: unchanged,
            unverified_project_ids: unverified,
            correlated_finding_count,
        })
    }

    async fn run_project_scan(
        &self,
        request: ScanRequest,
        cancellation: CancellationToken,
    ) -> Result<ScanSummary, ScanError> {
        ensure_not_cancelled(&cancellation)?;
        let project = self
            .database
            .repository::<Project>()
            .get(&request.project_id)
            .await
            .map_err(|_| ScanError::Failed)?
            .ok_or(ScanError::Failed)?;
        let requested_root = canonical_project_path(&request.root.to_string_lossy())
            .map_err(|_| ScanError::Failed)?;
        let configured_root =
            canonical_project_path(&project.root_path).map_err(|_| ScanError::Failed)?;
        if requested_root != configured_root {
            return Err(ScanError::Failed);
        }
        let project_lock = {
            let mut locks = self.project_locks.lock().await;
            locks
                .entry(project.id.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let _project_guard = project_lock.lock().await;
        let root_for_task = requested_root.clone();
        let hash_limits = self.settings.hash_limits;
        let (inventory_result, input_hash) = tokio::task::spawn_blocking(move || {
            let inventory = scan_repository(&root_for_task);
            let hash = hash_dependency_inputs(&root_for_task, hash_limits);
            (inventory, hash)
        })
        .await
        .map_err(|_| ScanError::Failed)?;
        let inventory = inventory_result.map_err(|_| ScanError::Failed)?;
        ensure_not_cancelled(&cancellation)?;

        let now = Utc::now();
        self.persist_inventory(&project, &inventory, &input_hash, now)
            .await?;
        let advisory_fresh = self.provider_data_is_fresh(now);
        let freshness = inventory_freshness(&inventory, &input_hash, advisory_fresh);
        let correlated = self
            .correlate_project_inventory(&project.id, freshness, now)
            .await?;
        ensure_not_cancelled(&cancellation)?;

        let (executions, mut diagnostics) = if request.profile == ScanProfile::Full {
            self.execute_full_scans(&requested_root, &cancellation)
                .await
        } else {
            (Vec::new(), Vec::new())
        };
        ensure_not_cancelled(&cancellation)?;
        let scanner_findings = executions
            .iter()
            .filter_map(|execution| execution.result.as_ref())
            .map(|result| result.findings.len())
            .sum();
        let scanners_complete = request.profile == ScanProfile::Quick
            || (!executions.is_empty()
                && executions.iter().all(|execution| {
                    execution.detection.status == EngineStatus::Available
                        && execution.result.as_ref().is_some_and(|scan| scan.complete)
                })
                && !diagnostics.contains(&"semgrep_rules_not_configured".to_owned()));
        if !inventory.complete {
            diagnostics.push("inventory_incomplete".to_owned());
        }
        if !advisory_fresh {
            diagnostics.push("advisory_data_stale_or_unverified".to_owned());
        }
        let outcome = if inventory.complete && advisory_fresh && scanners_complete {
            ScanOutcome::Succeeded
        } else {
            ScanOutcome::Partial
        };
        let finished_at = Utc::now();
        let scan_id = Uuid::new_v4().to_string();
        self.database
            .repository::<ScanRun>()
            .create(&ScanRun {
                id: scan_id.clone(),
                scope: AuditScope {
                    resource_type: "project".to_owned(),
                    resource_id: Some(project.id.clone()),
                },
                scanner: "security-monitor".to_owned(),
                scanner_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
                started_at: now,
                finished_at: Some(finished_at),
                outcome: outcome.clone(),
                error: (!diagnostics.is_empty()).then(|| diagnostics.join(",")),
            })
            .await
            .map_err(|_| ScanError::Failed)?;
        let project_repository = self.database.repository::<Project>();
        let mut updated_project = project;
        updated_project.last_scan_at = Some(finished_at);
        updated_project.updated_at = finished_at;
        project_repository
            .update(&updated_project)
            .await
            .map_err(|_| ScanError::Failed)?;

        Ok(ScanSummary {
            scan_id,
            outcome,
            input_hash: input_hash.sha256,
            inventory_complete: inventory.complete,
            component_count: inventory.components.len(),
            correlated_finding_count: correlated.len(),
            scanner_findings,
            diagnostics,
            executions,
        })
    }

    async fn execute_full_scans(
        &self,
        root: &Path,
        cancellation: &CancellationToken,
    ) -> (Vec<ScanExecution>, Vec<String>) {
        let mut executions = Vec::new();
        let mut diagnostics = Vec::new();
        let requests = [
            EngineScanRequest::new(EngineKind::OsvScanner, ScanMode::Dependencies, root),
            EngineScanRequest::new(EngineKind::Trivy, ScanMode::Filesystem, root),
            EngineScanRequest::new(EngineKind::Trivy, ScanMode::Misconfiguration, root),
        ];
        for request in requests {
            if cancellation.is_cancelled() {
                diagnostics.push("scan_cancelled".to_owned());
                break;
            }
            match self.scanners.scan(request).await {
                Ok(execution) => executions.push(execution),
                Err(_) => diagnostics.push("scanner_execution_failed".to_owned()),
            }
        }
        if let Some(rules) = self.settings.semgrep_rules_file.clone() {
            if !cancellation.is_cancelled() {
                let request = EngineScanRequest::new(EngineKind::Semgrep, ScanMode::Code, root)
                    .with_local_rules(rules);
                match self.scanners.scan(request).await {
                    Ok(execution) => executions.push(execution),
                    Err(_) => diagnostics.push("scanner_execution_failed".to_owned()),
                }
            }
        } else {
            diagnostics.push("semgrep_rules_not_configured".to_owned());
            let detection = self.scanners.detect_engine(EngineKind::Semgrep).await;
            executions.push(ScanExecution {
                detection,
                result: None,
            });
        }
        (executions, diagnostics)
    }

    async fn persist_inventory(
        &self,
        project: &Project,
        inventory: &Inventory,
        input_hash: &InputHash,
        now: DateTime<Utc>,
    ) -> Result<(), ScanError> {
        let _guard = self.correlation_lock.lock().await;
        let component_repository = self.database.repository::<Component>();
        let instance_repository = self.database.repository::<ComponentInstance>();
        let mut stored_components = component_repository
            .list()
            .await
            .map_err(|_| ScanError::Failed)?
            .into_iter()
            .map(|component| (component.purl.clone(), component))
            .collect::<BTreeMap<_, _>>();
        let mut current_instance_ids = BTreeSet::new();
        for package in &inventory.components {
            let component = if let Some(component) = stored_components.get(&package.purl) {
                component.clone()
            } else {
                let component = component_record(package, now);
                component_repository
                    .create(&component)
                    .await
                    .map_err(|_| ScanError::Failed)?;
                stored_components.insert(package.purl.clone(), component.clone());
                component
            };
            let instance_id = stable_id("instance", &project.id, &component.id);
            current_instance_ids.insert(instance_id.clone());
            let instance = ComponentInstance {
                id: instance_id.clone(),
                component_id: component.id.clone(),
                project_id: Some(project.id.clone()),
                asset_id: None,
                service_id: None,
                deployment_id: None,
                evidence: package
                    .evidence_paths
                    .iter()
                    .map(|path| ComponentEvidence {
                        evidence_type: package.source_type.clone(),
                        file_path_redacted: Some(path.clone()),
                        reference: None,
                    })
                    .collect(),
                created_at: now,
            };
            if instance_repository
                .get(&instance_id)
                .await
                .map_err(|_| ScanError::Failed)?
                .is_some()
            {
                instance_repository
                    .update(&instance)
                    .await
                    .map_err(|_| ScanError::Failed)?;
            } else {
                instance_repository
                    .create(&instance)
                    .await
                    .map_err(|_| ScanError::Failed)?;
            }
        }
        for old in instance_repository
            .list()
            .await
            .map_err(|_| ScanError::Failed)?
            .into_iter()
            .filter(|instance| {
                instance.project_id.as_deref() == Some(project.id.as_str())
                    && !current_instance_ids.contains(&instance.id)
            })
        {
            instance_repository
                .delete(&old.id)
                .await
                .map_err(|_| ScanError::Failed)?;
        }

        let checkpoints = self.database.repository::<ProjectScanCheckpoint>();
        let existing = checkpoints
            .get(&project.id)
            .await
            .map_err(|_| ScanError::Failed)?;
        let inventory_json = serde_json::to_string(inventory).map_err(|_| ScanError::Failed)?;
        let checkpoint = ProjectScanCheckpoint {
            id: project.id.clone(),
            project_id: project.id.clone(),
            input_hash: input_hash.sha256.clone(),
            inventory_json,
            inventory_complete: inventory.complete && input_hash.complete,
            checked_at: now,
            created_at: existing.as_ref().map_or(now, |value| value.created_at),
            updated_at: now,
        };
        if existing.is_some() {
            checkpoints
                .update(&checkpoint)
                .await
                .map_err(|_| ScanError::Failed)?;
        } else {
            checkpoints
                .create(&checkpoint)
                .await
                .map_err(|_| ScanError::Failed)?;
        }
        Ok(())
    }

    async fn correlate_project_inventory(
        &self,
        project_id: &str,
        freshness: InventoryFreshness,
        now: DateTime<Utc>,
    ) -> Result<Vec<security_monitor_correlation::CorrelatedFinding>, ScanError> {
        let _guard = self.correlation_lock.lock().await;
        let instance_repository = self.database.repository::<ComponentInstance>();
        let component_repository = self.database.repository::<Component>();
        let instances = instance_repository
            .list()
            .await
            .map_err(|_| ScanError::Failed)?
            .into_iter()
            .filter(|instance| instance.project_id.as_deref() == Some(project_id))
            .collect::<Vec<_>>();
        let mut contexts = Vec::with_capacity(instances.len());
        for instance in instances {
            let component = component_repository
                .get(&instance.component_id)
                .await
                .map_err(|_| ScanError::Failed)?
                .ok_or(ScanError::Failed)?;
            contexts.push(CorrelationComponent {
                component,
                instance,
                scope_verification: ScopeVerification::Verified,
                inventory_freshness: freshness,
                priority: PriorityContext::default(),
            });
        }
        let advisories = self
            .database
            .repository::<Advisory>()
            .list()
            .await
            .map_err(|_| ScanError::Failed)?;
        correlate_and_persist(&self.database, &advisories, &contexts, now)
            .await
            .map_err(|_| ScanError::Failed)
    }

    async fn refresh_from_cached_inventories(
        &self,
        cancellation: CancellationToken,
    ) -> Result<usize, ScanError> {
        let checkpoints = self
            .database
            .repository::<ProjectScanCheckpoint>()
            .list()
            .await
            .map_err(|_| ScanError::AdvisoryRefreshFailed)?;
        let mut snapshots = Vec::new();
        let mut merged_components = BTreeMap::<String, InventoryComponent>::new();
        for checkpoint in &checkpoints {
            if cancellation.is_cancelled() {
                return Err(ScanError::Cancelled);
            }
            let inventory: Inventory = match serde_json::from_str(&checkpoint.inventory_json) {
                Ok(inventory) => inventory,
                Err(_) => continue,
            };
            for component in &inventory.components {
                merged_components
                    .entry(component.purl.clone())
                    .and_modify(|existing| {
                        existing
                            .evidence_paths
                            .extend(component.evidence_paths.iter().cloned());
                    })
                    .or_insert_with(|| component.clone());
            }
            snapshots.push((checkpoint.clone(), inventory));
        }
        if snapshots.is_empty() {
            return Ok(0);
        }
        let union = Inventory {
            components: merged_components.into_values().collect(),
            project_roots: Vec::new(),
            detected_files: Vec::new(),
            diagnostics: Vec::new(),
            complete: snapshots
                .iter()
                .all(|(checkpoint, inventory)| checkpoint.inventory_complete && inventory.complete),
        };
        let cache_root = self.app_data_dir.join("advisories");
        let service = AdvisoryService::new(self.http_policy, self.database.clone(), cache_root)
            .map_err(|_| ScanError::AdvisoryRefreshFailed)?;
        let refresh_succeeded = match service.refresh_and_match(&union).await {
            Ok(_) => true,
            Err(_) => {
                if service.mark_provider_statuses_stale().is_err() {
                    warn!(
                        "advisory refresh failed and cached provider status could not be updated"
                    );
                } else {
                    warn!("advisory refresh failed; cached provider data is stale");
                }
                false
            }
        };
        let now = Utc::now();
        let mut finding_count = 0;
        for (checkpoint, inventory) in snapshots {
            if cancellation.is_cancelled() {
                return Err(ScanError::Cancelled);
            }
            let project = self
                .database
                .repository::<Project>()
                .get(&checkpoint.project_id)
                .await
                .map_err(|_| ScanError::AdvisoryRefreshFailed)?;
            let Some(project) = project else { continue };
            let root = canonical_project_path(&project.root_path).ok();
            let current_hash = if let Some(root) = root {
                let limits = self.settings.hash_limits;
                tokio::task::spawn_blocking(move || hash_dependency_inputs(root, limits))
                    .await
                    .unwrap_or_else(|_| incomplete_hash())
            } else {
                incomplete_hash()
            };
            let freshness = if !checkpoint.inventory_complete || !inventory.complete {
                InventoryFreshness::Incomplete
            } else if !refresh_succeeded
                || checkpoint.input_hash != current_hash.sha256
                || !current_hash.complete
            {
                InventoryFreshness::Stale
            } else {
                inventory_freshness(&inventory, &current_hash, self.provider_data_is_fresh(now))
            };
            let findings = self
                .correlate_project_inventory(&project.id, freshness, now)
                .await?;
            finding_count += findings.len();
        }
        Ok(finding_count)
    }

    fn provider_data_is_fresh(&self, now: DateTime<Utc>) -> bool {
        let path = self.app_data_dir.join("advisories/provider-status.json");
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let statuses: Vec<ProviderFreshness> =
            match serde_json::from_slice::<Vec<ProviderFreshness>>(&bytes) {
                Ok(statuses) if !statuses.is_empty() => statuses,
                _ => return false,
            };
        statuses.iter().all(|status| {
            !status.stale
                && status.updated_at.is_some_and(|updated| {
                    updated <= now && now.signed_duration_since(updated).num_hours() < 24
                })
        })
    }
}

#[async_trait]
impl ScanExecutor for LocalProjectScanner {
    async fn scan(
        &self,
        request: ScanRequest,
        cancellation: CancellationToken,
    ) -> Result<ScanSummary, ScanError> {
        self.run_project_scan(request, cancellation).await
    }

    async fn refresh_advisories(
        &self,
        cancellation: CancellationToken,
    ) -> Result<usize, ScanError> {
        self.refresh_from_cached_inventories(cancellation).await
    }
}

fn canonical_project_path(path: &str) -> Result<PathBuf, ()> {
    let canonical = Path::new(path).canonicalize().map_err(|_| ())?;
    if canonical.is_dir() {
        Ok(canonical)
    } else {
        Err(())
    }
}

fn incomplete_hash() -> InputHash {
    InputHash {
        sha256: None,
        complete: false,
        files: 0,
        bytes: 0,
    }
}

fn inventory_freshness(
    inventory: &Inventory,
    hash: &InputHash,
    advisory_fresh: bool,
) -> InventoryFreshness {
    if !inventory.complete || !hash.complete {
        InventoryFreshness::Incomplete
    } else if !advisory_fresh {
        InventoryFreshness::Stale
    } else {
        InventoryFreshness::Current
    }
}

fn component_record(package: &InventoryComponent, now: DateTime<Utc>) -> Component {
    let id = stable_id("component", &package.purl, "");
    Component {
        id,
        purl: package.purl.clone(),
        ecosystem: package.ecosystem.clone(),
        name: package.name.clone(),
        version: package.version.clone().unwrap_or_default(),
        source_type: package.source_type.clone(),
        created_at: now,
    }
}

fn stable_id(prefix: &str, first: &str, second: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(first.as_bytes());
    digest.update([0]);
    digest.update(second.as_bytes());
    format!("{prefix}-{}", hex::encode(digest.finalize()))
}

fn ensure_not_cancelled(cancellation: &CancellationToken) -> Result<(), ScanError> {
    if cancellation.is_cancelled() {
        Err(ScanError::Cancelled)
    } else {
        Ok(())
    }
}
