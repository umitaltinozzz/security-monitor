import type { ReactNode } from "react";
import { render } from "@testing-library/react";
import type { Finding } from "./generated/Finding";
import type { WorkspaceData } from "./api";
import { WorkspaceContext, type WorkspaceContextValue } from "./WorkspaceContext";

export const translate = (key: string) => key;

export function findingFixture(id: string, severity: Finding["severity"]): Finding {
  return {
    id,
    advisory_id: id,
    component_instance_id: `instance-${id}`,
    status: "new",
    severity,
    priority_score: severity === "critical" ? 95 : 30,
    priority_reasons: [],
    fingerprint: `fingerprint-${id}`,
    repo_status: "unknown",
    production_status: "unknown",
    disposition: null,
    risk_expires_at: null,
    fix_version: null,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  };
}

export function workspaceData(overrides: Partial<WorkspaceData> = {}): WorkspaceData {
  return {
    settings: {
      language: "en",
      theme: "system",
      onboarding_completed: true,
      public_downloads_enabled: false,
      scan_interval_hours: 24,
      ecosystems: ["npm", "pypi", "cargo"],
      desktop_notifications_enabled: true,
      outbound_notifications_enabled: false,
      daily_summary_enabled: false,
    },
    projects: [],
    assets: [],
    links: [],
    findings: [],
    scannerFindings: [],
    advisories: [],
    newsSignals: [],
    components: [],
    instances: [],
    evidence: [],
    runs: [],
    audit: [],
    ...overrides,
  };
}

export function workspaceContext(
  data: WorkspaceData,
  overrides: Partial<WorkspaceContextValue> = {},
): WorkspaceContextValue {
  return {
    data,
    language: "en",
    t: translate,
    notice: null,
    setNotice: () => undefined,
    refresh: () => undefined,
    saveSettings: async () => undefined,
    addProject: async () => null,
    startScan: async () => undefined,
    cancelProjectScan: async () => undefined,
    scanState: {},
    activeScanIds: {},
    page: "findings",
    setPage: () => undefined,
    context: null,
    setContext: () => undefined,
    focusFindingId: null,
    setFocusFindingId: () => undefined,
    updateFinding: () => undefined,
    onCompleteOnboarding: () => undefined,
    ...overrides,
  };
}

export function renderWithWorkspace(
  node: ReactNode,
  data: WorkspaceData,
  overrides: Partial<WorkspaceContextValue> = {},
) {
  return render(
    <WorkspaceContext.Provider value={workspaceContext(data, overrides)}>
      {node}
    </WorkspaceContext.Provider>,
  );
}
