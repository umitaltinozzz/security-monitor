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
    ProjectScanCheckpoint, ScanOutcome, ScanRun, ScannerFinding, Severity,
};
use security_monitor_correlation::{
    CorrelationComponent, InventoryFreshness, PriorityContext, ScopeVerification,
    correlate_and_persist,
};
use security_monitor_database::Database;
use security_monitor_inventory::{Inventory, InventoryComponent, scan_repository};
use security_monitor_scanner_adapters::{
    EngineKind, EngineStatus, FindingKind, NormalizedFinding, NormalizedSeverity, ScanExecution,
    ScanMode, ScanRequest as EngineScanRequest, ScannerAdapters,
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
        let advisory_fresh = self.refresh_inventory_advisories(&inventory).await;
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
        for execution in &executions {
            let state = match (&execution.detection.status, execution.result.as_ref()) {
                (EngineStatus::Available, Some(scan)) if scan.complete => "completed",
                (EngineStatus::Available, Some(_)) => "incomplete",
                _ => "unavailable",
            };
            diagnostics.push(format!(
                "scanner_coverage:{}:{}:{}",
                execution.detection.engine.as_str(),
                execution.mode.as_str(),
                state
            ));
        }
        ensure_not_cancelled(&cancellation)?;
        let scanner_findings = executions
            .iter()
            .filter_map(|execution| execution.result.as_ref())
            .map(|result| result.findings.len())
            .sum();
        let scanners_complete = request.profile == ScanProfile::Quick
            || full_scan_is_complete(&executions, &diagnostics);
        if !inventory.complete {
            diagnostics.push("inventory_incomplete".to_owned());
        }
        if !input_hash.complete {
            diagnostics.push("dependency_inputs_incomplete".to_owned());
        }
        if !advisory_fresh {
            diagnostics.push("advisory_data_stale_or_unverified".to_owned());
        }
        if request.profile == ScanProfile::Full && !scanners_complete {
            diagnostics.push("scanner_coverage_unverified".to_owned());
        }
        let outcome = scan_outcome(
            inventory.complete,
            input_hash.complete,
            advisory_fresh,
            scanners_complete,
        );
        let finished_at = Utc::now();
        let scan_id = Uuid::new_v4().to_string();
        let scan_run = ScanRun {
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
        };
        let scanner_records =
            scanner_finding_records(&project.id, &scan_id, &executions, finished_at)?;
        self.database
            .persist_scan_run_results(&scan_run, &scanner_records)
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
            inventory_complete: inventory.complete && input_hash.complete,
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
            let engine = request.engine;
            let mode = request.mode;
            match self.scanners.scan(request).await {
                Ok(execution) => executions.push(execution),
                Err(_) => diagnostics.push(format!(
                    "scanner_execution_failed:{}:{}",
                    engine.as_str(),
                    mode.as_str()
                )),
            }
        }
        if let Some(rules) = self.settings.semgrep_rules_file.clone() {
            if !cancellation.is_cancelled() {
                let request = EngineScanRequest::new(EngineKind::Semgrep, ScanMode::Code, root)
                    .with_local_rules(rules);
                match self.scanners.scan(request).await {
                    Ok(execution) => executions.push(execution),
                    Err(_) => diagnostics.push(format!(
                        "scanner_execution_failed:{}:{}",
                        EngineKind::Semgrep.as_str(),
                        ScanMode::Code.as_str()
                    )),
                }
            }
        } else {
            diagnostics.push("semgrep_rules_not_configured".to_owned());
            let detection = self.scanners.detect_engine(EngineKind::Semgrep).await;
            executions.push(ScanExecution {
                detection,
                mode: ScanMode::Code,
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
        let mut stored_components = self
            .database
            .repository::<Component>()
            .list()
            .await
            .map_err(|_| ScanError::Failed)?
            .into_iter()
            .map(|component| (component.purl.clone(), component))
            .collect::<BTreeMap<_, _>>();
        let mut new_components = Vec::new();
        let mut instances = Vec::with_capacity(inventory.components.len());
        for package in &inventory.components {
            let component = if let Some(component) = stored_components.get(&package.purl) {
                component.clone()
            } else {
                let component = component_record(package, now);
                new_components.push(component.clone());
                stored_components.insert(package.purl.clone(), component.clone());
                component
            };
            let instance_id = stable_id("instance", &project.id, &component.id);
            instances.push(ComponentInstance {
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
                last_seen_at: Some(now),
            });
        }

        let inventory_json = serde_json::to_string(inventory).map_err(|_| ScanError::Failed)?;
        let checkpoint = ProjectScanCheckpoint {
            id: project.id.clone(),
            project_id: project.id.clone(),
            input_hash: input_hash.sha256.clone(),
            inventory_json,
            inventory_complete: inventory.complete && input_hash.complete,
            checked_at: now,
            created_at: now,
            updated_at: now,
        };
        self.database
            .persist_project_inventory_snapshot(
                &project.id,
                &new_components,
                &instances,
                &checkpoint,
            )
            .await
            .map_err(|_| ScanError::Failed)?;
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
            Ok(_) => self.provider_data_is_fresh(Utc::now(), &union),
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
                inventory_freshness(
                    &inventory,
                    &current_hash,
                    refresh_succeeded && self.provider_data_is_fresh(now, &inventory),
                )
            };
            let findings = self
                .correlate_project_inventory(&project.id, freshness, now)
                .await?;
            finding_count += findings.len();
        }
        Ok(finding_count)
    }

    async fn refresh_inventory_advisories(&self, inventory: &Inventory) -> bool {
        let cache_root = self.app_data_dir.join("advisories");
        let service =
            match AdvisoryService::new(self.http_policy, self.database.clone(), cache_root) {
                Ok(service) => service,
                Err(_) => return false,
            };
        match service.refresh_and_match(inventory).await {
            Ok(_) => self.provider_data_is_fresh(Utc::now(), inventory),
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
        }
    }

    fn provider_data_is_fresh(&self, now: DateTime<Utc>, inventory: &Inventory) -> bool {
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
        provider_statuses_are_fresh(&statuses, now, inventory)
    }
}

fn provider_statuses_are_fresh(
    statuses: &[ProviderFreshness],
    now: DateTime<Utc>,
    inventory: &Inventory,
) -> bool {
    let is_fresh = |provider: &str| {
        statuses.iter().any(|status| {
            status.provider == provider
                && !status.stale
                && status.updated_at.is_some_and(|updated| {
                    updated <= now && now.signed_duration_since(updated).num_hours() < 24
                })
        })
    };
    if !is_fresh("cve.now")
        || !is_fresh("CISA KEV")
        || !is_fresh("FIRST EPSS")
        || statuses
            .iter()
            .any(|status| status.provider.starts_with("cve.now: ") && !is_fresh(&status.provider))
    {
        return false;
    }
    let ecosystems = inventory
        .components
        .iter()
        .map(|component| canonical_provider_ecosystem(&component.ecosystem))
        .collect::<BTreeSet<_>>();
    ecosystems
        .iter()
        .all(|ecosystem| is_fresh(&format!("OSV ({ecosystem})")))
}

fn canonical_provider_ecosystem(ecosystem: &str) -> String {
    match ecosystem.trim().to_ascii_lowercase().as_str() {
        "go" => "golang".to_owned(),
        "crates.io" => "cargo".to_owned(),
        "packagist" => "composer".to_owned(),
        "rubygems" | "gem" => "rubygems".to_owned(),
        "pip" => "pypi".to_owned(),
        other => other.to_owned(),
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
        version: package.version.clone(),
        source_type: package.source_type.clone(),
        created_at: now,
    }
}

fn scanner_finding_records(
    project_id: &str,
    scan_run_id: &str,
    executions: &[ScanExecution],
    observed_at: DateTime<Utc>,
) -> Result<Vec<ScannerFinding>, ScanError> {
    let mut records = BTreeMap::new();
    for execution in executions {
        let Some(scan) = execution.result.as_ref() else {
            continue;
        };
        for finding in &scan.findings {
            let fingerprint_bytes = serde_json::to_vec(&(
                scan.engine.as_str(),
                execution.mode.as_str(),
                finding.kind,
                finding.rule_id.as_deref(),
                finding.package.as_ref().map(|package| {
                    (
                        package.name.as_str(),
                        package.ecosystem.as_deref(),
                        package.version.as_deref(),
                    )
                }),
                finding.path.as_deref(),
                finding.line_start,
                finding.line_end,
            ))
            .map_err(|_| ScanError::Failed)?;
            let fingerprint = hex::encode(Sha256::digest(fingerprint_bytes));
            let record = normalized_scanner_finding(
                project_id,
                scan_run_id,
                scan.engine,
                execution.mode,
                finding,
                fingerprint,
                observed_at,
            );
            records.insert(record.id.clone(), record);
        }
    }
    Ok(records.into_values().collect())
}

fn full_scan_is_complete(executions: &[ScanExecution], diagnostics: &[String]) -> bool {
    !executions.is_empty()
        && executions.iter().all(|execution| {
            execution.detection.status == EngineStatus::Available
                && execution.result.as_ref().is_some_and(|scan| scan.complete)
        })
        && !diagnostics
            .iter()
            .any(|item| item == "semgrep_rules_not_configured")
}

fn scan_outcome(
    inventory_complete: bool,
    input_hash_complete: bool,
    advisory_fresh: bool,
    scanners_complete: bool,
) -> ScanOutcome {
    if inventory_complete && input_hash_complete && advisory_fresh && scanners_complete {
        ScanOutcome::Succeeded
    } else {
        ScanOutcome::Partial
    }
}

fn normalized_scanner_finding(
    project_id: &str,
    scan_run_id: &str,
    engine: EngineKind,
    mode: ScanMode,
    finding: &NormalizedFinding,
    fingerprint: String,
    observed_at: DateTime<Utc>,
) -> ScannerFinding {
    let (package_name, package_ecosystem, package_version) = finding
        .package
        .as_ref()
        .map(|package| {
            (
                Some(package.name.clone()),
                package.ecosystem.clone(),
                package.version.clone(),
            )
        })
        .unwrap_or((None, None, None));
    ScannerFinding {
        id: stable_id("scanner-finding", project_id, &fingerprint),
        project_id: project_id.to_owned(),
        scan_run_id: scan_run_id.to_owned(),
        scanner: engine.as_str().to_owned(),
        mode: mode.as_str().to_owned(),
        kind: match finding.kind {
            FindingKind::Vulnerability => "vulnerability",
            FindingKind::Secret => "secret",
            FindingKind::Misconfiguration => "misconfiguration",
            FindingKind::Code => "code",
        }
        .to_owned(),
        rule_id: finding.rule_id.clone(),
        aliases: finding.aliases.clone(),
        package_name,
        package_ecosystem,
        package_version,
        severity: match finding.severity {
            NormalizedSeverity::Unknown => Severity::Unknown,
            NormalizedSeverity::Low => Severity::Low,
            NormalizedSeverity::Medium => Severity::Medium,
            NormalizedSeverity::High => Severity::High,
            NormalizedSeverity::Critical => Severity::Critical,
        },
        title: finding.title.clone(),
        fixed_version: finding.fixed_version.clone(),
        path: finding.path.clone(),
        line_start: finding.line_start,
        line_end: finding.line_end,
        fingerprint,
        created_at: observed_at,
        last_seen_at: observed_at,
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

#[cfg(test)]
mod scanner_finding_tests {
    use super::{full_scan_is_complete, scan_outcome, scanner_finding_records};
    use chrono::{Duration, Utc};
    use security_monitor_core::ScanOutcome;
    use security_monitor_scanner_adapters::{
        EngineDetection, EngineKind, EngineStatus, FindingKind, NormalizedFinding, NormalizedScan,
        NormalizedSeverity, ScanExecution, ScanMode,
    };

    fn execution(complete: bool) -> ScanExecution {
        ScanExecution {
            detection: EngineDetection {
                engine: EngineKind::Semgrep,
                status: EngineStatus::Available,
                version: Some("1.0.0".to_owned()),
                executable: None,
            },
            mode: ScanMode::Code,
            result: Some(NormalizedScan {
                engine: EngineKind::Semgrep,
                complete,
                findings: vec![NormalizedFinding {
                    kind: FindingKind::Code,
                    rule_id: Some("fixture.rule".to_owned()),
                    aliases: Vec::new(),
                    package: None,
                    severity: NormalizedSeverity::High,
                    title: Some("Fixture finding".to_owned()),
                    fixed_version: None,
                    path: Some("src/main.rs".to_owned()),
                    line_start: Some(7),
                    line_end: Some(8),
                }],
                diagnostics: Vec::new(),
            }),
        }
    }

    #[test]
    fn complete_full_scan_can_succeed_and_incomplete_coverage_stays_partial() {
        let executions = [execution(true)];
        assert!(full_scan_is_complete(&executions, &[]));
        assert!(!full_scan_is_complete(
            &executions,
            &["semgrep_rules_not_configured".to_owned()]
        ));
        assert!(!full_scan_is_complete(&[execution(false)], &[]));
        assert_eq!(scan_outcome(true, true, true, true), ScanOutcome::Succeeded);
        assert_eq!(scan_outcome(true, true, true, false), ScanOutcome::Partial);
    }

    #[test]
    fn normalized_scanner_observations_get_stable_project_local_ids() {
        let first_seen = Utc::now();
        let executions = [execution(true)];
        let first =
            scanner_finding_records("project-1", "scan-1", &executions, first_seen).unwrap();
        let later = scanner_finding_records(
            "project-1",
            "scan-2",
            &executions,
            first_seen + Duration::seconds(5),
        )
        .unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].id, later[0].id);
        assert_eq!(first[0].fingerprint, later[0].fingerprint);
        assert_eq!(first[0].scanner, "semgrep");
        assert_eq!(first[0].path.as_deref(), Some("src/main.rs"));
        assert_eq!(first[0].line_start, Some(7));
        assert_eq!(first[0].severity, security_monitor_core::Severity::High);
    }
}

#[cfg(test)]
mod freshness_tests {
    use super::{ProviderFreshness, provider_statuses_are_fresh};
    use chrono::{Duration, Utc};
    use security_monitor_inventory::{Inventory, InventoryComponent};

    fn status(provider: &str, now: chrono::DateTime<Utc>) -> ProviderFreshness {
        ProviderFreshness {
            provider: provider.to_owned(),
            updated_at: Some(now),
            stale: false,
            error: None,
        }
    }

    fn base_statuses(now: chrono::DateTime<Utc>) -> Vec<ProviderFreshness> {
        vec![
            status("cve.now", now),
            status("CISA KEV", now),
            status("FIRST EPSS", now),
        ]
    }

    fn inventory(ecosystem: &str) -> Inventory {
        Inventory {
            components: vec![InventoryComponent {
                purl: format!("pkg:{ecosystem}/example@1.0.0"),
                ecosystem: ecosystem.to_owned(),
                name: "example".to_owned(),
                version: Some("1.0.0".to_owned()),
                source_type: "fixture".to_owned(),
                evidence_paths: vec!["lockfile".to_owned()],
            }],
            project_roots: Vec::new(),
            detected_files: Vec::new(),
            diagnostics: Vec::new(),
            complete: true,
        }
    }

    #[test]
    fn freshness_requires_osv_coverage_for_each_scanned_ecosystem() {
        let now = Utc::now();
        let mut statuses = base_statuses(now);
        statuses.push(status("OSV (npm)", now));
        assert!(!provider_statuses_are_fresh(
            &statuses,
            now,
            &inventory("cargo")
        ));

        statuses.push(status("OSV (cargo)", now));
        assert!(provider_statuses_are_fresh(
            &statuses,
            now,
            &inventory("cargo")
        ));
    }

    #[test]
    fn freshness_rejects_missing_and_stale_required_provider_statuses() {
        let now = Utc::now();
        let inventory = inventory("npm");
        let mut statuses = base_statuses(now);
        statuses.push(status("OSV (npm)", now));
        statuses.push(status("cve.now: upstream source status", now));
        assert!(provider_statuses_are_fresh(&statuses, now, &inventory));

        statuses.retain(|item| item.provider != "FIRST EPSS");
        assert!(!provider_statuses_are_fresh(&statuses, now, &inventory));

        statuses.push(ProviderFreshness {
            provider: "FIRST EPSS".to_owned(),
            updated_at: Some(now - Duration::hours(25)),
            stale: false,
            error: None,
        });
        assert!(!provider_statuses_are_fresh(&statuses, now, &inventory));
    }
}
