import { fireEvent, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Findings } from "./Findings";
import { findingFixture, renderWithWorkspace, workspaceData } from "../test-fixtures";

describe("Findings filters", () => {
  it("filters the visible findings by severity and advisory text", () => {
    const critical = findingFixture("CVE-2026-1111", "critical");
    const low = findingFixture("GHSA-fixture-low", "low");
    renderWithWorkspace(<Findings />, workspaceData({ findings: [critical, low] }));

    expect(screen.getByRole("button", { name: critical.advisory_id })).toBeVisible();
    expect(screen.getByRole("button", { name: low.advisory_id })).toBeVisible();

    fireEvent.change(screen.getByLabelText("common.severity"), {
      target: { value: "critical" },
    });
    expect(screen.getByRole("button", { name: critical.advisory_id })).toBeVisible();
    expect(screen.queryByRole("button", { name: low.advisory_id })).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("common.severity"), { target: { value: "all" } });
    fireEvent.change(screen.getByPlaceholderText("common.searchPlaceholder"), {
      target: { value: "GHSA-fixture" },
    });
    expect(screen.getByRole("button", { name: low.advisory_id })).toBeVisible();
    expect(screen.queryByRole("button", { name: critical.advisory_id })).not.toBeInTheDocument();
  });
});
