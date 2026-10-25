export type ScanPollOutcome<T> =
  { kind: "complete"; result: T } | { kind: "cancelled" } | { kind: "timedOut" };

export async function pollScanUntilDone<T>(
  poll: () => Promise<T | null>,
  options: {
    timeoutMs: number;
    intervalMs: number;
    isCancelled: () => boolean;
    now?: () => number;
    wait?: (durationMs: number) => Promise<void>;
  },
): Promise<ScanPollOutcome<T>> {
  const now = options.now ?? (() => performance.now());
  const wait =
    options.wait ??
    ((durationMs: number) =>
      new Promise<void>((resolve) => window.setTimeout(resolve, durationMs)));
  const deadline = now() + options.timeoutMs;

  while (!options.isCancelled()) {
    const result = await poll();
    if (result) return { kind: "complete", result };
    const remainingMs = deadline - now();
    if (remainingMs <= 0) return { kind: "timedOut" };
    await wait(Math.min(options.intervalMs, remainingMs));
  }

  return { kind: "cancelled" };
}
