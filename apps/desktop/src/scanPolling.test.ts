import { describe, expect, it } from "vitest";
import { pollScanUntilDone } from "./scanPolling";

describe("scan polling", () => {
  it("returns a completed result", async () => {
    let attempts = 0;
    const outcome = await pollScanUntilDone(
      async () => (++attempts === 2 ? { outcome: "succeeded" } : null),
      {
        timeoutMs: 100,
        intervalMs: 10,
        isCancelled: () => false,
        now: () => attempts * 10,
        wait: async () => undefined,
      },
    );

    expect(outcome).toEqual({ kind: "complete", result: { outcome: "succeeded" } });
  });

  it("ends when the deadline expires", async () => {
    let currentTime = 0;
    const outcome = await pollScanUntilDone(async () => null, {
      timeoutMs: 20,
      intervalMs: 10,
      isCancelled: () => false,
      now: () => currentTime,
      wait: async (duration) => {
        currentTime += duration;
      },
    });

    expect(outcome).toEqual({ kind: "timedOut" });
  });

  it("stops after cancellation", async () => {
    let cancelled = false;
    const outcome = await pollScanUntilDone(async () => null, {
      timeoutMs: 100,
      intervalMs: 10,
      isCancelled: () => cancelled,
      now: () => 0,
      wait: async () => {
        cancelled = true;
      },
    });

    expect(outcome).toEqual({ kind: "cancelled" });
  });
});
