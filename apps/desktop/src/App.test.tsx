import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const apiMocks = vi.hoisted(() => ({ loadWorkspace: vi.fn() }));

vi.mock("./api", () => ({
  api: {
    saveSettings: vi.fn(async () => undefined),
  },
  loadWorkspace: apiMocks.loadWorkspace,
}));

import { App } from "./App";

describe("Security Monitor first-run experience", () => {
  beforeEach(() => {
    apiMocks.loadWorkspace.mockResolvedValue({
      settings: {
        language: "en",
        theme: "system",
        onboarding_completed: false,
        public_downloads_enabled: false,
        notifications_enabled: true,
        scan_interval_hours: 24,
        ecosystems: ["npm", "pypi", "cargo"],
      },
      projects: [],
      assets: [],
      findings: [],
      advisories: [],
      components: [],
      instances: [],
      evidence: [],
      runs: [],
      audit: [],
    });
  });

  it("explains the local-first privacy defaults before setup choices", async () => {
    render(<App />);

    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Your data stays local by default" })).toBeVisible();
    });
    expect(screen.getByText(/Project paths, source code, lockfiles, and inventory stay on this device/)).toBeVisible();
    expect(screen.getByRole("button", { name: "Skip for now" })).toBeEnabled();
  });
});
