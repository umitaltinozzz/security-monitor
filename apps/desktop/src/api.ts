import { invoke } from "@tauri-apps/api/core";
import type { Advisory } from "./generated/Advisory";
import type { AiConfigurationView } from "./generated/AiConfigurationView";
import type { AiProvider } from "./generated/AiProvider";
import type { AiProviderInput } from "./generated/AiProviderInput";
import type { AiRequestEstimate } from "./generated/AiRequestEstimate";
import type { AiRunResult } from "./generated/AiRunResult";
import type { AiSettings } from "./generated/AiSettings";
import type { AiTier } from "./generated/AiTier";
import type { AppSettings } from "./generated/AppSettings";
import type { AdvisoryUpdateStatus } from "./generated/AdvisoryUpdateStatus";
import type { Asset } from "./generated/Asset";
import type { AuditEvent } from "./generated/AuditEvent";
import type { CollectionSummary } from "./generated/CollectionSummary";
import type { Component } from "./generated/Component";
import type { ComponentInstance } from "./generated/ComponentInstance";
import type { Finding } from "./generated/Finding";
import type { FindingPageView } from "./generated/FindingPageView";
import type { FindingStatus } from "./generated/FindingStatus";
import type { FindingEvidence } from "./generated/FindingEvidence";
import type { FindingStatusChange } from "./generated/FindingStatusChange";
import type { Severity } from "./generated/Severity";
import type { NewsSignal } from "./generated/NewsSignal";
import type { ProjectServerLink } from "./generated/ProjectServerLink";
import type { NewsSyncReport } from "./generated/NewsSyncReport";
import type { PairingInstructionsView } from "./generated/PairingInstructionsView";
import type { Project } from "./generated/Project";
import type { ProjectDiscoveryView } from "./generated/ProjectDiscoveryView";
import type { Remediation } from "./generated/Remediation";
import type { RemediationSandboxStatus } from "./generated/RemediationSandboxStatus";
import type { SafeTestInput } from "./generated/SafeTestInput";
import type { McpRemediationRequest } from "./generated/McpRemediationRequest";
import type { Memory } from "./generated/Memory";
import type { MemoryArchive } from "./generated/MemoryArchive";
import type { MemoryKind } from "./generated/MemoryKind";
import type { MemoryScope } from "./generated/MemoryScope";
import type { ScanResult } from "./generated/ScanResult";
import type { ScanRun } from "./generated/ScanRun";
import type { ScannerAvailability } from "./generated/ScannerAvailability";
import type { SshHostSummary } from "./generated/SshHostSummary";
import type { SshTargetInput } from "./generated/SshTargetInput";
import type { UpdateCheckResult } from "./generated/UpdateCheckResult";
import type { NotificationChannelView } from "./generated/NotificationChannelView";
import type { NotificationPreview } from "./generated/NotificationPreview";
import type { SaveNotificationChannelInput } from "./generated/SaveNotificationChannelInput";
import type { UpdateNotificationChannelInput } from "./generated/UpdateNotificationChannelInput";

export type WorkspaceData = {
  settings: AppSettings;
  projects: Project[];
  assets: Asset[];
  links: ProjectServerLink[];
  findings: Finding[];
  advisories: Advisory[];
  newsSignals: NewsSignal[];
  components: Component[];
  instances: ComponentInstance[];
  evidence: FindingEvidence[];
  runs: ScanRun[];
  audit: AuditEvent[];
};

export const workspaceSections = [
  "settings",
  "projects",
  "assets",
  "links",
  "findings",
  "advisories",
  "newsSignals",
  "components",
  "instances",
  "evidence",
  "runs",
  "audit",
] as const satisfies readonly (keyof WorkspaceData)[];

export type WorkspaceSection = (typeof workspaceSections)[number];

export const api = {
  settings: () => invoke<AppSettings>("get_app_settings"),
  saveSettings: (settings: AppSettings) => invoke<void>("save_app_settings", { settings }),
  notificationChannels: () => invoke<NotificationChannelView[]>("list_notification_channels"),
  saveNotificationChannel: (input: SaveNotificationChannelInput) =>
    invoke<NotificationChannelView>("save_notification_channel", { input }),
  updateNotificationChannel: (input: UpdateNotificationChannelInput) =>
    invoke<NotificationChannelView>("update_notification_channel", { input }),
  deleteNotificationChannel: (channelId: string) =>
    invoke<void>("delete_notification_channel", { channelId }),
  previewNotification: (input: SaveNotificationChannelInput) =>
    invoke<NotificationPreview>("preview_notification", { input }),
  sendTestNotification: (channelId: string) =>
    invoke<void>("send_test_notification", { channelId }),
  aiConfiguration: () => invoke<AiConfigurationView>("get_ai_configuration"),
  saveAiSettings: (settings: AiSettings) => invoke<void>("save_ai_settings", { settings }),
  saveAiProvider: (input: AiProviderInput) => invoke<AiProvider>("save_ai_provider", { input }),
  setProjectAiProviders: (projectId: string, providerIds: string[]) =>
    invoke<Project>("set_project_ai_providers", { projectId, providerIds }),
  estimateAiRequest: (projectId: string, tier: AiTier, prompt: string, providerId?: string) =>
    invoke<AiRequestEstimate>("estimate_ai_request", { projectId, tier, prompt, providerId }),
  runAiRequest: (
    projectId: string,
    tier: AiTier,
    prompt: string,
    providerId: string,
    approvalDigest: string,
  ) =>
    invoke<AiRunResult>("run_ai_request", {
      projectId,
      tier,
      prompt,
      providerId,
      approvalDigest,
      transferApproved: true,
    }),
  projects: () => invoke<Project[]>("list_projects"),
  addProject: (path: string) => invoke<Project>("add_project", { path }),
  discoverProjects: (path: string) =>
    invoke<ProjectDiscoveryView>("discover_local_projects", { path }),
  startScan: (projectId: string, profile: "quick" | "full") =>
    invoke<string>("start_project_scan", { projectId, profile }),
  cancelScan: (scanId: string) => invoke<boolean>("cancel_project_scan", { scanId }),
  scanResult: (scanId: string) => invoke<ScanResult | null>("get_scan_result", { scanId }),
  findings: () => invoke<Finding[]>("list_findings"),
  findingsPage: (input: {
    offset: number;
    limit: number;
    status: FindingStatus | null;
    severity: Severity | null;
    projectId: string | null;
    query: string;
  }) =>
    invoke<FindingPageView>("list_findings_page", {
      offset: input.offset,
      limit: input.limit,
      status: input.status,
      severity: input.severity,
      projectId: input.projectId,
      query: input.query,
    }),
  advisories: () => invoke<Advisory[]>("list_advisories"),
  newsSignals: () => invoke<NewsSignal[]>("list_news_signals"),
  refreshNewsSignals: () => invoke<NewsSyncReport>("refresh_news_signals"),
  components: () => invoke<Component[]>("list_components"),
  instances: () => invoke<ComponentInstance[]>("list_component_instances"),
  evidence: () => invoke<FindingEvidence[]>("list_finding_evidence"),
  runs: () => invoke<ScanRun[]>("list_scan_runs"),
  audit: () => invoke<AuditEvent[]>("list_audit_events"),
  remediations: () => invoke<Remediation[]>("list_remediations"),
  remediationSandboxStatus: () => invoke<RemediationSandboxStatus>("remediation_sandbox_status"),
  mcpRemediationRequests: () => invoke<McpRemediationRequest[]>("list_mcp_remediation_requests"),
  dismissMcpRemediationRequest: (requestId: string) =>
    invoke<void>("dismiss_mcp_remediation_request", { requestId }),
  requestRemediation: (findingId: string, providerId: string) =>
    invoke<Remediation>("request_remediation", { findingId, providerId }),
  approveRemediation: (remediationId: string, sourceTransferApproved: boolean) =>
    invoke<Remediation>("approve_remediation", { remediationId, sourceTransferApproved }),
  rejectRemediation: (remediationId: string) =>
    invoke<Remediation>("reject_remediation", { remediationId }),
  runSafeTests: (remediationId: string, input: SafeTestInput, executeApproved: boolean) =>
    invoke<Remediation>("run_safe_tests", { remediationId, input, executeApproved }),
  setFindingStatus: (change: FindingStatusChange) =>
    invoke<Finding>("set_finding_status", { change }),
  memories: (scope: MemoryScope, scopeId?: string) =>
    invoke<Memory[]>("list_memories", { scope, scopeId: scopeId ?? null }),
  createMemory: (
    scope: MemoryScope,
    scopeId: string | null,
    kind: MemoryKind,
    content: string,
    pinned: boolean,
  ) => invoke<Memory>("create_memory", { scope, scopeId, kind, content, pinned }),
  updateMemory: (
    memoryId: string,
    content: string | null,
    pinned: boolean | null,
    verified: boolean | null,
  ) => invoke<Memory>("update_memory", { memoryId, content, pinned, verified }),
  deleteMemory: (memoryId: string) => invoke<void>("delete_memory", { memoryId }),
  exportMemories: () => invoke<MemoryArchive>("export_memories"),
  importMemories: (archive: MemoryArchive) => invoke<number>("import_memories", { archive }),
  deleteAllMemories: () => invoke<number>("delete_all_memories"),
  assets: () => invoke<Asset[]>("list_server_assets"),
  scanners: () => invoke<ScannerAvailability[]>("detect_scanners"),
  installScanner: (engine: string, userApprovedDownload: boolean) =>
    invoke<void>("install_scanner", { engine, userApprovedDownload }),
  updateAdvisories: () => invoke<AdvisoryUpdateStatus[]>("update_advisory_data"),
  checkForUpdates: () => invoke<UpdateCheckResult>("check_for_updates"),
  installUpdate: (expectedVersion: string) => invoke<void>("install_update", { expectedVersion }),
  sshHosts: () => invoke<SshHostSummary[]>("list_ssh_config_hosts"),
  inspectHost: (input: SshTargetInput) => invoke<string>("inspect_server_host_key", { input }),
  pairServer: (
    input: SshTargetInput,
    fingerprint: string,
    fingerprintConfirmed: boolean,
    deviceLabel: string,
  ) =>
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
  projectServerLinks: () => invoke<ProjectServerLink[]>("list_project_server_links"),
  linkProjectServer: (projectId: string, assetId: string, confirmed: boolean) =>
    invoke<ProjectServerLink>("link_project_server", { projectId, assetId, confirmed }),
  unlinkProjectServer: (linkId: string) => invoke<boolean>("unlink_project_server", { linkId }),
};

const workspaceLoaders: {
  [Section in WorkspaceSection]: () => Promise<WorkspaceData[Section]>;
} = {
  settings: api.settings,
  projects: api.projects,
  assets: api.assets,
  links: api.projectServerLinks,
  findings: api.findings,
  advisories: api.advisories,
  newsSignals: api.newsSignals,
  components: api.components,
  instances: api.instances,
  evidence: api.evidence,
  runs: api.runs,
  audit: api.audit,
};

export async function loadWorkspace(
  previous: WorkspaceData | null = null,
  sections: readonly WorkspaceSection[] = workspaceSections,
): Promise<WorkspaceData> {
  const workspace = previous ? { ...previous } : ({} as WorkspaceData);
  const selected = previous ? sections : workspaceSections;
  await Promise.all(
    selected.map(async <Section extends WorkspaceSection>(section: Section) => {
      workspace[section] = await workspaceLoaders[section]();
    }),
  );
  return workspace;
}
