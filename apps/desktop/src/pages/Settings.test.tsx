import { fireEvent, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("../AiSettings", () => ({ AiSettingsPanel: () => null }));

import { Settings } from "./Settings";
import { renderWithWorkspace, workspaceData } from "../test-fixtures";

describe("Settings", () => {
  it("keeps update checks disabled until public downloads are enabled", () => {
    const saveSettings = vi.fn(async () => undefined);
    const data = workspaceData();
    renderWithWorkspace(<Settings />, data, { saveSettings });

    expect(screen.getByRole("button", { name: "actions.checkUpdates" })).toBeDisabled();
    fireEvent.click(screen.getByRole("checkbox", { name: /settings.publicDownloads/ }));

    expect(saveSettings).toHaveBeenCalledWith({
      ...data.settings,
      public_downloads_enabled: true,
    });
  });
});
