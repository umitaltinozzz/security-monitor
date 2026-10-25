import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { StatusDialog } from "./StatusDialog";
import { findingFixture, translate } from "../test-fixtures";

describe("StatusDialog", () => {
  it("requires an expiry for accepted risk and submits the chosen disposition", () => {
    const finding = findingFixture("finding-1", "high");
    const onSave = vi.fn(async () => undefined);
    render(
      <StatusDialog
        finding={finding}
        instance={undefined}
        t={translate}
        close={vi.fn()}
        onSave={onSave}
      />,
    );

    fireEvent.change(screen.getByLabelText("findings.newStatus"), {
      target: { value: "accepted_risk" },
    });
    const save = screen.getByRole("button", { name: "actions.save" });
    expect(save).toBeDisabled();

    fireEvent.change(screen.getByLabelText("findings.expiry"), {
      target: { value: "2026-12-31" },
    });
    expect(save).toBeEnabled();
    fireEvent.click(save);

    expect(onSave).toHaveBeenCalledWith({
      finding_id: finding.id,
      status: "accepted_risk",
      reason: "business_accepted",
      scope: "finding",
      scope_id: finding.id,
      expires_at: "2026-12-31T23:59:59.000Z",
    });
  });
});
