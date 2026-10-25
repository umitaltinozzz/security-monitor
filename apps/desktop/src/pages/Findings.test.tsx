import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const apiMock = vi.hoisted(() => ({ findingsPage: vi.fn() }));

vi.mock("../api", () => ({ api: apiMock }));

import { Findings } from "./Findings";
import { findingFixture, renderWithWorkspace, workspaceData } from "../test-fixtures";

describe("Findings filters", () => {
  afterEach(cleanup);

  beforeEach(() => {
    apiMock.findingsPage.mockReset();
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
});
