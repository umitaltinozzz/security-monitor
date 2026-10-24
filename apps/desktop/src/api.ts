import { invoke } from "@tauri-apps/api/core";
import type { Advisory } from "./generated/Advisory";
import type { AppSettings } from "./generated/AppSettings";
import type { AdvisoryUpdateStatus } from "./generated/AdvisoryUpdateStatus";
import type { Asset } from "./generated/Asset";
import type { AuditEvent } from "./generated/AuditEvent";
import type { CollectionSummary } from "./generated/CollectionSummary";
import type { Component } from "./generated/Component";
import type { ComponentInstance } from "./generated/ComponentInstance";
import type { Finding } from "./generated/Finding";
import type { FindingEvidence } from "./generated/FindingEvidence";
import type { FindingStatusChange } from "./generated/FindingStatusChange";
import type { PairingInstructionsView } from "./generated/PairingInstructionsView";
import type { Project } from "./generated/Project";
import type { ProjectDiscoveryView } from "./generated/ProjectDiscoveryView";
import type { ScanResult } from "./generated/ScanResult";
import type { ScanRun } from "./generated/ScanRun";
import type { ScannerAvailability } from "./generated/ScannerAvailability";
import type { SshHostSummary } from "./generated/SshHostSummary";
import type { SshTargetInput } from "./generated/SshTargetInput";

export type WorkspaceData = {
  settings: AppSettings;
  projects: Project[];
  assets: Asset[];
  findings: Finding[];
  advisories: Advisory[];
  components: Component[];
  instances: ComponentInstance[];
  evidence: FindingEvidence[];
  runs: ScanRun[];
  audit: AuditEvent[];
};

export const api = {
  settings: () => invoke<AppSettings>("get_app_settings"),
  saveSettings: (settings: AppSettings) => invoke<void>("save_app_settings", { settings }),
  projects: () => invoke<Project[]>("list_projects"),
  addProject: (path: string) => invoke<Project>("add_project", { path }),
  discoverProjects: (path: string) => invoke<ProjectDiscoveryView>("discover_local_projects", { path }),
  startScan: (projectId: string, profile: "quick" | "full") =>
    invoke<string>("start_project_scan", { projectId, profile }),
  cancelScan: (scanId: string) => invoke<boolean>("cancel_project_scan", { scanId }),
  scanResult: (scanId: string) => invoke<ScanResult | null>("get_scan_result", { scanId }),
  findings: () => invoke<Finding[]>("list_findings"),
  advisories: () => invoke<Advisory[]>("list_advisories"),
  components: () => invoke<Component[]>("list_components"),
  instances: () => invoke<ComponentInstance[]>("list_component_instances"),
  evidence: () => invoke<FindingEvidence[]>("list_finding_evidence"),
  runs: () => invoke<ScanRun[]>("list_scan_runs"),
  audit: () => invoke<AuditEvent[]>("list_audit_events"),
  setFindingStatus: (change: FindingStatusChange) =>
    invoke<Finding>("set_finding_status", { change }),
  assets: () => invoke<Asset[]>("list_server_assets"),
  scanners: () => invoke<ScannerAvailability[]>("detect_scanners"),
  installScanner: (engine: string, userApprovedDownload: boolean) =>
    invoke<void>("install_scanner", { engine, userApprovedDownload }),
  updateAdvisories: () => invoke<AdvisoryUpdateStatus[]>("update_advisory_data"),
  sshHosts: () => invoke<SshHostSummary[]>("list_ssh_config_hosts"),
  inspectHost: (input: SshTargetInput) => invoke<string>("inspect_server_host_key", { input }),
  pairServer: (input: SshTargetInput, fingerprint: string, fingerprintConfirmed: boolean, deviceLabel: string) =>
    invoke<PairingInstructionsView>("pair_server", {
      input,
      confirmedFingerprint: fingerprint,
      fingerprintConfirmed,
      deviceLabel,
    }),
  collectServer: (assetId: string, transferApproved: boolean) =>
    invoke<CollectionSummary>("collect_server_inventory", { assetId, transferApproved }),
  serverInventory: (assetId: string) =>
    invoke<CollectionSummary | null>("get_server_inventory_summary", { assetId }),
};

export async function loadWorkspace(): Promise<WorkspaceData> {
  const [settings, projects, assets, findings, advisories, components, instances, evidence, runs, audit] =
    await Promise.all([
      api.settings(),
      api.projects(),
      api.assets(),
      api.findings(),
      api.advisories(),
      api.components(),
      api.instances(),
      api.evidence(),
      api.runs(),
      api.audit(),
    ]);
  return { settings, projects, assets, findings, advisories, components, instances, evidence, runs, audit };
}
