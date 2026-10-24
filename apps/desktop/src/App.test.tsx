import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";

describe("Security Monitor shell", () => {
  beforeEach(() => {
    vi.stubGlobal("navigator", { language: "en-US" });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows the English welcome view and switches to Turkish", () => {
    render(<App />);

    expect(screen.getByRole("heading", { name: "Security visibility, kept local" })).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Switch language to Turkish" }));
    expect(screen.getByRole("heading", { name: "Güvenlik görünürlüğü, cihazınızda" })).toBeVisible();
    expect(document.documentElement).toHaveAttribute("lang", "tr");
  });
});
