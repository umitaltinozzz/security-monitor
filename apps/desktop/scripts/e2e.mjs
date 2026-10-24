import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const viteEntrypoint = fileURLToPath(new URL("../node_modules/vite/bin/vite.js", import.meta.url));
const server = spawn(process.execPath, [viteEntrypoint, "preview", "--host", "127.0.0.1", "--port", "4173", "--strictPort"], {
  cwd: projectRoot,
  stdio: "ignore",
  windowsHide: true,
});

let browser;

try {
  let ready = false;
  for (let attempt = 0; attempt < 40; attempt += 1) {
    if (server.exitCode !== null) {
      throw new Error(`Vite preview exited with code ${server.exitCode}.`);
    }
    try {
      const response = await fetch("http://127.0.0.1:4173");
      ready = response.ok;
      if (ready) break;
    } catch {
      await delay(250);
    }
  }
  assert.equal(ready, true, "Vite preview did not become ready.");

  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto("http://127.0.0.1:4173");
  assert.equal(await page.title(), "Security Monitor");
  const heading = page.getByRole("heading", { level: 1 });
  const initialHeading = await heading.textContent();
  await page.getByRole("button").click();
  assert.notEqual(await heading.textContent(), initialHeading, "The language toggle did not change the welcome heading.");
} finally {
  await browser?.close();
  server.kill();
}
