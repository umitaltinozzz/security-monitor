import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Memory } from "./generated/Memory";

const memoryApi = vi.hoisted(() => ({
  memories: vi.fn(),
  createMemory: vi.fn(),
  updateMemory: vi.fn(),
  deleteMemory: vi.fn(),
}));

vi.mock("./api", () => ({ api: memoryApi }));

import { MemoryNotes } from "./MemoryNotes";

const note: Memory = {
  id: "memory-1",
  scope: "global",
  scope_id: null,
  kind: "agent_summary",
  content: "Review the affected endpoint after deployment.",
  author: "agent:codex",
  source_run_id: null,
  created_at: "2026-10-24T12:00:00Z",
  expires_at: "2027-04-22T12:00:00Z",
  pinned: false,
  verified_at: null,
  verified_by: null,
};

describe("shared local memory notes", () => {
  beforeEach(() => {
    memoryApi.memories.mockReset().mockResolvedValue([note]);
    memoryApi.createMemory.mockReset().mockResolvedValue(note);
    memoryApi.updateMemory.mockReset().mockResolvedValue(note);
    memoryApi.deleteMemory.mockReset().mockResolvedValue(undefined);
  });

  it("shows note content as text and lets the user mark it reviewed", async () => {
    render(<MemoryNotes scope="global" t={(key) => key} setNotice={vi.fn()} />);

    expect(await screen.findByDisplayValue(note.content)).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "memory.verify" }));

    await waitFor(() => {
      expect(memoryApi.updateMemory).toHaveBeenCalledWith(note.id, null, null, true);
    });
  });

  it("submits new user notes through the local memory command", async () => {
    render(<MemoryNotes scope="global" t={(key) => key} setNotice={vi.fn()} />);
    await screen.findByDisplayValue(note.content);
    const contentFields = screen.getAllByLabelText("memory.content");
    const addButtons = screen.getAllByRole("button", { name: "memory.add" });
    const entryField = contentFields[0];
    const addButton = addButtons[0];
    if (!entryField || !addButton) throw new Error("memory form was not rendered");
    fireEvent.change(entryField, { target: { value: "Keep the test offline." } });
    fireEvent.click(addButton);

    await waitFor(() => {
      expect(memoryApi.createMemory).toHaveBeenCalledWith(
        "global",
        null,
        "finding_note",
        "Keep the test offline.",
        false,
      );
    });
  });
});
