import { beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({ invoke: invokeMock }));

import { api, loadWorkspace, type WorkspaceData } from "./api";

describe("workspace IPC loading", () => {
  beforeEach(() => {
    invokeMock.mockReset().mockResolvedValue([]);
  });

  it("reloads only the requested sections when a workspace already exists", async () => {
    const previous = {
      settings: { language: "en" },
      projects: [],
      assets: [],
      links: [],
      findings: [],
      advisories: [],
      newsSignals: [],
      components: [],
      instances: [],
      evidence: [],
      runs: [],
      audit: [],
    } as unknown as WorkspaceData;

    const result = await loadWorkspace(previous, ["projects", "audit"]);

    expect(invokeMock).toHaveBeenCalledTimes(2);
    expect(invokeMock).toHaveBeenNthCalledWith(1, "list_projects");
    expect(invokeMock).toHaveBeenNthCalledWith(2, "list_audit_events", { offset: 0, limit: 250 });
    expect(result.settings).toBe(previous.settings);
  });

  it("sends the typed filters and offset for a findings page", async () => {
    await api.findingsPage({
      offset: 25,
      limit: 25,
      status: "needs_review",
      severity: "high",
      projectId: "project-1",
      query: "openssl",
    });

    expect(invokeMock).toHaveBeenCalledWith("list_findings_page", {
      offset: 25,
      limit: 25,
      status: "needs_review",
      severity: "high",
      projectId: "project-1",
      query: "openssl",
    });
  });
});
