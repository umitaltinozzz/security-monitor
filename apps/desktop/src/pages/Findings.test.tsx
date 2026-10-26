import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const apiMock = vi.hoisted(() => ({
  findingsPage: vi.fn(),
  setScannerFindingReview: vi.fn(),
}));

vi.mock("../api", () => ({ api: apiMock }));

import { Findings } from "./Findings";
import { findingFixture, renderWithWorkspace, workspaceData } from "../test-fixtures";

describe("Findings filters", () => {
  afterEach(cleanup);

  beforeEach(() => {
    apiMock.findingsPage.mockReset();
    apiMock.setScannerFindingReview.mockReset();
  });

  it("requests filtered pages by severity and advisory text", async () => {
    const critical = findingFixture("CVE-2026-1111", "critical");
    const low = findingFixture("GHSA-fixture-low", "low");
    apiMock.findingsPage.mockImplementation(async (input) => {
      const findings = [critical, low].filter(
        (finding) =>
          (!input.severity || finding.severity === input.severity) &&
          finding.advisory_id.toLowerCase().includes(input.query.toLowerCase()),
      );
      return {
        findings,
        total_count: findings.length,
        offset: input.offset,
        limit: input.limit,
      };
    });
    renderWithWorkspace(<Findings />, workspaceData({ findings: [critical, low] }));

    expect(await screen.findByRole("button", { name: critical.advisory_id })).toBeVisible();
    expect(screen.getByRole("button", { name: low.advisory_id })).toBeVisible();

    fireEvent.change(screen.getByLabelText("common.severity"), {
      target: { value: "critical" },
    });
    expect(await screen.findByRole("button", { name: critical.advisory_id })).toBeVisible();
    await waitFor(() => {
      expect(screen.queryByRole("button", { name: low.advisory_id })).not.toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText("common.severity"), { target: { value: "all" } });
    fireEvent.change(screen.getByPlaceholderText("common.searchPlaceholder"), {
      target: { value: "GHSA-fixture" },
    });
    expect(await screen.findByRole("button", { name: low.advisory_id })).toBeVisible();
    await waitFor(() => {
      expect(screen.queryByRole("button", { name: critical.advisory_id })).not.toBeInTheDocument();
    });
    expect(apiMock.findingsPage).toHaveBeenLastCalledWith({
      offset: 0,
      limit: 25,
      status: null,
      severity: null,
      projectId: null,
      query: "GHSA-fixture",
    });
  });

  it("loads the next page with the corresponding offset", async () => {
    const firstFinding = findingFixture("CVE-2026-0001", "high");
    const secondPageFinding = findingFixture("CVE-2026-0026", "high");
    const findings = [
      firstFinding,
      ...Array.from({ length: 24 }, (_, index) =>
        findingFixture(`CVE-2026-${String(index + 2).padStart(4, "0")}`, "high"),
      ),
      secondPageFinding,
    ];
    apiMock.findingsPage.mockImplementation(async (input) => ({
      findings: findings.slice(input.offset, input.offset + input.limit),
      total_count: findings.length,
      offset: input.offset,
      limit: input.limit,
    }));
    renderWithWorkspace(<Findings />, workspaceData({ findings }));

    expect(await screen.findByRole("button", { name: firstFinding.advisory_id })).toBeVisible();
    expect(
      screen.queryByRole("button", { name: secondPageFinding.advisory_id }),
    ).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "findings.nextPage" }));

    expect(
      await screen.findByRole("button", { name: secondPageFinding.advisory_id }),
    ).toBeVisible();
    expect(apiMock.findingsPage).toHaveBeenLastCalledWith({
      offset: 25,
      limit: 25,
      status: null,
      severity: null,
      projectId: null,
      query: "",
    });
  });

  it("shows persisted full scan observations with their source and location", async () => {
    apiMock.findingsPage.mockResolvedValue({ findings: [], total_count: 0, offset: 0, limit: 25 });
    renderWithWorkspace(
      <Findings />,
      workspaceData({
        scannerFindings: [
          {
            id: "scanner-finding-1",
            project_id: "project-1",
            scan_run_id: "scan-1",
            scanner: "semgrep",
            mode: "code",
            kind: "code",
            rule_id: "python.lang.security.audit.eval-detected",
            aliases: [],
            package_name: null,
            package_ecosystem: null,
            package_version: null,
            severity: "high",
            title: "Use of eval",
            fixed_version: null,
            path: "src/app.py",
            line_start: 8,
            line_end: 8,
            fingerprint: "b".repeat(64),
            status: "needs_review",
            review_reason: null,
            reviewed_at: null,
            created_at: "2026-10-26T10:00:00Z",
            last_seen_at: "2026-10-26T10:00:00Z",
          },
        ],
      }),
    );

    expect(await screen.findByText("findings.scannerFindings")).toBeVisible();
    expect(screen.getByText("Use of eval")).toBeVisible();
    expect(screen.getByText("semgrep · code")).toBeVisible();
    expect(screen.getByText("src/app.py:8")).toBeVisible();
    expect(screen.getByRole("row", { name: /Use of eval/ })).toHaveTextContent(
      "findings.scannerStatus.needs_review",
    );
    fireEvent.change(screen.getByLabelText("findings.scannerReviewStatus"), {
      target: { value: "confirmed" },
    });
    expect(screen.getByText("findings.scannerNoResults")).toBeVisible();
  });

  it("lets the user review a scanner observation with an auditable reason", async () => {
    apiMock.findingsPage.mockResolvedValue({ findings: [], total_count: 0, offset: 0, limit: 25 });
    apiMock.setScannerFindingReview.mockResolvedValue({});
    renderWithWorkspace(
      <Findings />,
      workspaceData({
        scannerFindings: [
          {
            id: "scanner-finding-2",
            project_id: "project-1",
            scan_run_id: "scan-2",
            scanner: "semgrep",
            mode: "code",
            kind: "code",
            rule_id: "fixture.rule",
            aliases: [],
            package_name: null,
            package_ecosystem: null,
            package_version: null,
            severity: "medium",
            title: "Fixture observation",
            fixed_version: null,
            path: "src/lib.rs",
            line_start: 12,
            line_end: 12,
            fingerprint: "c".repeat(64),
            status: "needs_review",
            review_reason: null,
            reviewed_at: null,
            created_at: "2026-10-26T10:00:00Z",
            last_seen_at: "2026-10-26T10:00:00Z",
          },
        ],
      }),
    );

    fireEvent.click(await screen.findByRole("button", { name: "actions.review" }));
    fireEvent.change(
      within(screen.getByRole("dialog")).getByLabelText("findings.scannerReviewStatus"),
      { target: { value: "false_positive" } },
    );
    fireEvent.change(screen.getByLabelText("findings.scannerReviewReason"), {
      target: { value: "Reviewed the source and confirmed this rule does not apply." },
    });
    fireEvent.click(screen.getByRole("button", { name: "actions.save" }));

    await waitFor(() => {
      expect(apiMock.setScannerFindingReview).toHaveBeenCalledWith({
        finding_id: "scanner-finding-2",
        status: "false_positive",
        reason: "Reviewed the source and confirmed this rule does not apply.",
      });
    });
  });
});
