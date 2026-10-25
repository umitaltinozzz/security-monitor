import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const apiMocks = vi.hoisted(() => ({ loadWorkspace: vi.fn() }));

vi.mock("./api", () => ({
  api: {
    saveSettings: vi.fn(async () => undefined),
  },
  loadWorkspace: apiMocks.loadWorkspace,
  workspaceSections: [
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
  ],
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
        scan_interval_hours: 24,
        ecosystems: ["npm", "pypi", "cargo"],
      },
      projects: [],
      assets: [],
      findings: [],
      advisories: [],
      newsSignals: [],
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
      expect(
        screen.getByRole("heading", { name: "Your data stays local by default" }),
      ).toBeVisible();
    });
    expect(
      screen.getByText(/Project paths, source code, lockfiles, and inventory stay on this device/),
    ).toBeVisible();
    expect(screen.getByRole("button", { name: "Skip for now" })).toBeEnabled();
  });

  it("shows product-matched feed items in a separate unverified news row", async () => {
    apiMocks.loadWorkspace.mockResolvedValue({
      settings: {
        language: "en",
        theme: "system",
        onboarding_completed: true,
        public_downloads_enabled: false,
        scan_interval_hours: 24,
        ecosystems: ["npm", "pypi", "cargo"],
      },
      projects: [],
      assets: [],
      findings: [],
      advisories: [],
      newsSignals: [
        {
          id: "news-fixture",
          feed_id: "fixture-feed",
          external_id: "nextjs-1",
          title: "Next.js security update",
          summary: "A middleware issue affects Next.js deployments.",
          url: "https://security.example.test/nextjs/one",
          published_at: "2026-10-24T12:00:00Z",
          first_seen_at: "2026-10-24T12:00:00Z",
          last_seen_at: "2026-10-24T12:00:00Z",
          matched_projects: ["project-local"],
          matched_products: ["next"],
          advisory_id: null,
          archived_at: null,
        },
      ],
      components: [],
      instances: [],
      evidence: [],
      runs: [],
      audit: [],
    });

    render(<App />);

    expect(await screen.findByText("Unverified news")).toBeVisible();
    expect(screen.getByText("Next.js security update")).toBeVisible();
    expect(screen.getByText("A middleware issue affects Next.js deployments.")).toBeVisible();
  });

  it("keeps updater checks disabled until the user enables public downloads", async () => {
    apiMocks.loadWorkspace.mockResolvedValue({
      settings: {
        language: "en",
        theme: "system",
        onboarding_completed: true,
        public_downloads_enabled: false,
        scan_interval_hours: 24,
        ecosystems: ["npm", "pypi", "cargo"],
      },
      projects: [],
      assets: [],
      findings: [],
      advisories: [],
      newsSignals: [],
      components: [],
      instances: [],
      evidence: [],
      runs: [],
      audit: [],
    });

    render(<App />);

    (await screen.findByRole("button", { name: /^Settings$/ })).click();
    expect(await screen.findByRole("button", { name: "Check for updates" })).toBeDisabled();
    expect(screen.getByText(/Update checks are manual/)).toBeVisible();
  });
});
