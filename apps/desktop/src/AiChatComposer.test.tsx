import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const aiApi = vi.hoisted(() => ({
  aiConfiguration: vi.fn(),
  estimateAiRequest: vi.fn(),
  runAiRequest: vi.fn(),
}));

vi.mock("./api", () => ({ api: aiApi }));

import { AiChatComposer } from "./AiChatComposer";

describe("AI request approval", () => {
  beforeEach(() => {
    aiApi.aiConfiguration.mockReset().mockResolvedValue({
      settings: { assignments: [{ tier: "analysis", provider_id: "provider-1" }] },
      providers: [{ id: "provider-1", display_name: "Fixture provider" }],
    });
    aiApi.estimateAiRequest.mockReset().mockResolvedValue({
      project_id: "project-1",
      approval_digest: "digest-1",
      provider_id: "provider-1",
      provider_name: "Fixture provider",
      model: "fixture-model",
      destination_origin: "https://provider.invalid",
      data_region: null,
      tier: "analysis",
      data_category: "inventory",
      enabled_tools: [
        "list_projects",
        "list_assets",
        "list_findings",
        "read_project_file",
        "analyze_impact",
        "forget",
      ],
      redacted_values: 1,
      redacted_prompt: "Review this project.",
      estimated_input_tokens: 100,
      estimated_output_tokens: 200,
      estimated_cost_usd: 0.01,
      budget: {
        estimated_cost_usd: 0.01,
        daily_total_after_usd: 0.01,
        monthly_total_after_usd: 0.01,
        daily_provider_after_usd: 0.01,
        monthly_provider_after_usd: 0.01,
      },
    });
  });

  it("shows possible tool output categories before the user approves sending", async () => {
    render(
      <AiChatComposer
        context="fixture"
        projectId="project-1"
        t={(key) => key}
        setNotice={vi.fn()}
      />,
    );

    fireEvent.change(screen.getByPlaceholderText("composer.placeholder"), {
      target: { value: "Review this project." },
    });
    fireEvent.click(screen.getByRole("button", { name: "composer.send" }));

    expect(await screen.findByRole("dialog", { name: "ai.approvalTitle" })).toBeVisible();
    expect(screen.getByText("ai.toolOutputData")).toBeVisible();
    for (const category of [
      "project_metadata",
      "server_inventory",
      "finding_advisory_evidence",
      "project_files",
      "shared_memory",
      "tool_status",
    ]) {
      expect(screen.getByText(`ai.outputCategories.${category}`)).toBeVisible();
    }
    expect(aiApi.estimateAiRequest).toHaveBeenCalledWith(
      "project-1",
      "analysis",
      "Review this project.",
    );
    expect(aiApi.runAiRequest).not.toHaveBeenCalled();
  });
});
