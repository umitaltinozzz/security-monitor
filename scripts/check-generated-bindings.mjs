import { spawnSync } from "node:child_process";

const result = spawnSync(
  "git",
  ["status", "--porcelain", "--untracked-files=all", "--", "apps/desktop/src/generated"],
  { encoding: "utf8", windowsHide: true },
);

if (result.error) {
  console.error("Could not inspect generated TypeScript bindings.");
  process.exitCode = 1;
} else if (result.status !== 0) {
  console.error("Git could not inspect generated TypeScript bindings.");
  process.exitCode = result.status ?? 1;
} else if (result.stdout.trim()) {
  console.error("Generated TypeScript bindings are out of date:");
  console.error(result.stdout.trimEnd());
  process.exitCode = 1;
}
