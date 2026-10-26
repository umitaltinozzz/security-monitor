import { cleanup, fireEvent, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../AiSettings", () => ({ AiSettingsPanel: () => null }));

afterEach(() => cleanup());

import { Settings } from "./Settings";
import { api } from "../api";
import { renderWithWorkspace, workspaceData } from "../test-fixtures";

describe("Settings", () => {
  it("keeps update checks disabled until public downloads are enabled", () => {
    const saveSettings = vi.fn(async () => undefined);
    const data = workspaceData();
    vi.spyOn(api, "notificationChannels").mockResolvedValue([]);
    renderWithWorkspace(<Settings />, data, { saveSettings });

    expect(screen.getByRole("button", { name: "actions.checkUpdates" })).toBeDisabled();
    fireEvent.click(screen.getByRole("checkbox", { name: /settings.publicDownloads/ }));

    expect(saveSettings).toHaveBeenCalledWith({
      ...data.settings,
      public_downloads_enabled: true,
    });
  });

  it("saves notification preferences from Settings", () => {
    const saveSettings = vi.fn(async () => undefined);
    const data = workspaceData();
    vi.spyOn(api, "notificationChannels").mockResolvedValue([]);
    renderWithWorkspace(<Settings />, data, { saveSettings });

    fireEvent.click(screen.getByRole("checkbox", { name: /settings.desktopNotifications/ }));
    expect(saveSettings).toHaveBeenCalledWith({
      ...data.settings,
      desktop_notifications_enabled: false,
    });
  });
});
