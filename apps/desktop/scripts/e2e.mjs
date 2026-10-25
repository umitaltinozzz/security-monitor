import assert from "node:assert/strict";
import { mkdir, readFile } from "node:fs/promises";
import { spawn, spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { createServer } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));
const fixture = JSON.parse(
  await readFile(
    new URL("../../../tests/fixtures/desktop/workspace.json", import.meta.url),
    "utf8",
  ),
);
const localeDictionaries = await Promise.all(
  ["en", "tr"].map(async (language) =>
    JSON.parse(await readFile(new URL(`../src/locales/${language}.json`, import.meta.url), "utf8")),
  ),
);
function localeKeys(dictionary, prefix = "") {
  return Object.entries(dictionary).flatMap(([key, value]) => {
    const path = prefix ? `${prefix}.${key}` : key;
    return value !== null && typeof value === "object"
      ? [path, ...localeKeys(value, path)]
      : [path];
  });
}
const rawLocaleKeys = new Set(localeDictionaries.flatMap((dictionary) => localeKeys(dictionary)));
async function assertCleanUi(page, label) {
  const renderedText = await page.locator("body *").evaluateAll((elements) =>
    elements
      .filter((element) => element.children.length === 0)
      .map((element) => element.textContent?.trim() ?? "")
      .filter(Boolean),
  );
  const rawKeys = renderedText.filter((text) => rawLocaleKeys.has(text));
  assert.deepEqual(rawKeys, [], `${label} rendered raw locale keys: ${rawKeys.join(", ")}`);
  assert.equal(await page.getByRole("alert").count(), 0, `${label} shows an error notice`);
}
const viteEntrypoint = fileURLToPath(new URL("../node_modules/vite/bin/vite.js", import.meta.url));
const require = createRequire(new URL("../package.json", import.meta.url));
const build = spawnSync(process.execPath, [viteEntrypoint, "build"], {
  cwd: projectRoot,
  stdio: "inherit",
  windowsHide: true,
});
assert.equal(build.status, 0, "Vite production build must pass before browser checks run.");
const previewPort = await new Promise((resolve, reject) => {
  const probe = createServer();
  probe.once("error", reject);
  probe.listen(0, "127.0.0.1", () => {
    const address = probe.address();
    if (!address || typeof address === "string") {
      probe.close();
      reject(new Error("Could not allocate a local preview port."));
      return;
    }
    probe.close((error) => (error ? reject(error) : resolve(address.port)));
  });
});
const previewUrl = `http://127.0.0.1:${previewPort}`;
const server = spawn(
  process.execPath,
  [viteEntrypoint, "preview", "--host", "127.0.0.1", "--port", String(previewPort), "--strictPort"],
  {
    cwd: projectRoot,
    stdio: "ignore",
    windowsHide: true,
  },
);

let browser;

try {
  let ready = false;
  for (let attempt = 0; attempt < 40; attempt += 1) {
    if (server.exitCode !== null)
      throw new Error(`Vite preview exited with code ${server.exitCode}.`);
    try {
      const response = await fetch(previewUrl);
      const available = response.ok;
      await response.arrayBuffer();
      ready = available;
      if (ready) break;
    } catch {
      await delay(250);
    }
  }
  assert.equal(ready, true, "Vite preview did not become ready.");

  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({
    viewport: { width: 1440, height: 1500 },
    deviceScaleFactor: 1,
  });
  const externalRequests = new Set();
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.protocol !== "data:" && url.hostname !== "127.0.0.1" && url.hostname !== "localhost") {
      externalRequests.add(url.origin);
    }
  });
  await page.addInitScript((initial) => {
    const state = {
      settings: initial.settings,
      aiConfiguration: initial.ai_configuration,
      projects: [],
      assets: [],
      links: [],
      findings: [],
      advisories: [],
      components: [],
      instances: [],
      evidence: [],
      runs: [],
      audit: [],
      scanResult: initial.scan_result,
      finding: initial.finding,
      advisory: initial.advisory,
      component: initial.component,
      instance: initial.instance,
      run: initial.run,
      ssh: initial.ssh,
      completedScan: false,
    };
    const timestamp = "2026-10-24T08:00:00Z";
    window.__TAURI_INTERNALS__ = {
      invoke: async (command, args = {}) => {
        switch (command) {
          case "get_app_settings":
            return state.settings;
          case "save_app_settings":
            state.settings = args.settings;
            return null;
          case "get_ai_configuration":
            return state.aiConfiguration;
          case "save_ai_settings": {
            const previous = state.aiConfiguration.settings.mcp_source_access_projects ?? [];
            const next = args.settings.mcp_source_access_projects ?? [];
            for (const projectId of next.filter((id) => !previous.includes(id))) {
              for (const action of [
                "mcp_source_access_permission_enable_approved",
                "mcp_source_access_permission_enabled",
              ]) {
                state.audit.push({
                  id: `audit-${action}-${projectId}`,
                  timestamp,
                  actor: "user",
                  action,
                  scope: { resource_type: "project", resource_id: projectId },
                  result: "succeeded",
                });
              }
            }
            for (const projectId of previous.filter((id) => !next.includes(id))) {
              for (const action of [
                "mcp_source_access_permission_revocation_requested",
                "mcp_source_access_permission_revoked",
              ]) {
                state.audit.push({
                  id: `audit-${action}-${projectId}`,
                  timestamp,
                  actor: "user",
                  action,
                  scope: { resource_type: "project", resource_id: projectId },
                  result: "succeeded",
                });
              }
            }
            state.aiConfiguration.settings = args.settings;
            return null;
          }
          case "list_projects":
            return state.projects;
          case "add_project": {
            const project = {
              id: "project-fixture-1",
              name: "Fixture Project",
              root_path: args.path,
              git_remote: null,
              reference_branch: null,
              allowed_ai_providers: [],
              last_scan_at: null,
              created_at: timestamp,
              updated_at: timestamp,
            };
            state.projects.push(project);
            state.audit.push({
              id: "audit-project-1",
              timestamp,
              actor: "user",
              action: "project_added",
              scope: { resource_type: "project", resource_id: project.id },
              result: "succeeded",
            });
            return project;
          }
          case "discover_local_projects":
            return { candidates: [], diagnostics: 0, complete: true };
          case "start_project_scan":
            if (!state.completedScan) {
              state.completedScan = true;
              state.findings = [state.finding];
              state.advisories = [state.advisory];
              state.components = [state.component];
              state.instances = [state.instance];
              state.runs = [state.run];
            }
            return "scan-fixture";
          case "get_scan_result":
            return state.scanResult;
          case "cancel_project_scan":
            return true;
          case "list_findings":
            return state.findings;
          case "list_advisories":
            return state.advisories;
          case "list_news_signals":
            return [];
          case "refresh_news_signals":
            return {
              updated_feeds: 0,
              not_modified_feeds: 0,
              skipped_feeds: 0,
              failed_feeds: 0,
              signals_updated: 0,
              signals_archived: 0,
            };
          case "list_components":
            return state.components;
          case "list_component_instances":
            return state.instances;
          case "list_finding_evidence":
            return state.evidence;
          case "list_scan_runs":
            return state.runs;
          case "list_audit_events":
            return state.audit;
          case "list_memories":
            return [];
          case "list_remediations":
            return [];
          case "list_mcp_remediation_requests":
            return [];
          case "remediation_sandbox_status":
            return { available: false, engine: null };
          case "set_finding_status": {
            state.finding = { ...state.finding, status: args.change.status, updated_at: timestamp };
            state.findings = [state.finding];
            state.audit.push({
              id: "audit-status-1",
              timestamp,
              actor: "user",
              action: `finding_status_changed:${args.change.status}:fixture`,
              scope: { resource_type: "finding", resource_id: args.change.finding_id },
              result: "succeeded",
            });
            return state.finding;
          }
          case "list_server_assets":
            return state.assets;
          case "detect_scanners":
            return ["osv-scanner", "trivy", "semgrep", "docker", "podman"].map((engine) => ({
              engine,
              status: "missing",
              version: null,
            }));
          case "install_scanner":
            return null;
          case "update_advisory_data":
            return [{ ecosystem: "npm", stale: false, updated_at: timestamp }];
          case "list_ssh_config_hosts":
            return [];
          case "inspect_server_host_key":
            return state.ssh.fingerprint;
          case "pair_server": {
            const asset = {
              id: "asset-fixture-1",
              asset_type: "server",
              hostname_alias: args.input.alias,
              environment: args.input.environment,
              ssh_target_ref: "secmon-keyring:v1:fixture",
              host_key_fingerprint: args.confirmedFingerprint,
              last_seen_at: timestamp,
              last_success_at: null,
              created_at: timestamp,
              updated_at: timestamp,
            };
            state.assets.push(asset);
            state.audit.push({
              id: "audit-pair-1",
              timestamp,
              actor: "user",
              action: "server_paired",
              scope: { resource_type: "asset", resource_id: asset.id },
              result: "succeeded",
            });
            return {
              asset,
              fingerprint: state.ssh.fingerprint,
              authorized_keys_line: state.ssh.authorized_keys_line,
            };
          }
          case "collect_server_inventory":
            return {
              asset_id: args.assetId,
              complete: false,
              package_count: 1,
              service_count: 1,
              container_count: 0,
              deployment_count: 0,
              approved_at: timestamp,
            };
          case "get_server_inventory_summary":
            return null;
          case "list_project_server_links":
            return state.links;
          case "link_project_server": {
            if (!args.confirmed) throw "permission_denied";
            const link = {
              id: "link-fixture-1",
              project_id: args.projectId,
              asset_id: args.assetId,
              confirmed_at: timestamp,
            };
            state.links.push(link);
            // The desktop backend reassesses drift after a confirmed link; mirror its result for the fixture.
            state.finding = {
              ...state.finding,
              repo_status: "fixed_in_repo",
              production_status: "still_affected",
            };
            state.findings = state.findings.length ? [state.finding] : state.findings;
            return link;
          }
          case "unlink_project_server":
            state.links = [];
            return true;
          case "list_memories":
          case "list_remediations":
          case "list_mcp_remediation_requests":
            return [];
          case "remediation_sandbox_status":
            return { available: false, engine: null };
          default:
            throw "unknown";
        }
      },
    };
    window.__securityMonitorE2eState = state;
  }, fixture);

  await page.goto(previewUrl);
  assert.equal(await page.title(), "Security Monitor");
  for (let step = 0; step < 6; step += 1) {
    await page.getByRole("button", { name: "Skip for now" }).click();
  }
  await page.getByRole("heading", { name: "Review", exact: true }).waitFor();

  await page.getByRole("button", { name: "Projects", exact: true }).first().click();
  await page.getByLabel("Project folder path").first().fill("C:/fixture/security-monitor");
  await page.getByLabel("Start a quick scan after adding").check();
  await page.getByRole("button", { name: "Add project", exact: true }).last().click();
  await page.getByText("Scan finished with missing or stale checks").waitFor({ timeout: 10_000 });
  await page.getByRole("button", { name: "All findings", exact: true }).click();
  await page.getByRole("textbox", { name: "Search", exact: true }).fill("GHSA-fixture-2025");
  await page.getByRole("button", { name: "GHSA-fixture-2025" }).click();
  await page.getByRole("dialog").getByRole("heading", { name: "GHSA-fixture-2025" }).waitFor();
  await page.getByRole("dialog").getByRole("heading", { name: "Why this matters" }).waitFor();
  await assertCleanUi(page, "finding detail");
  await page.getByRole("dialog").getByRole("button", { name: "Close", exact: true }).last().click();

  await page.getByRole("button", { name: "Servers", exact: true }).first().click();
  await page.getByRole("heading", { name: "Servers", exact: true }).waitFor();
  await page.getByRole("heading", { name: "Pair a Linux server" }).waitFor();
  await page.getByLabel("Host alias").fill("fixture-server");
  await page.getByLabel("Hostname or IP address").fill("fixture.invalid");
  await page.getByLabel("SSH username").fill("secmon");
  await page.locator("select").first().selectOption("production");
  await page.getByRole("button", { name: "Check host key" }).click();
  await page.getByText(fixture.ssh.fingerprint).waitFor();
  await page
    .getByLabel("I independently checked this fingerprint with the server administrator.")
    .check();
  await page.getByRole("button", { name: "Create pairing key" }).click();
  await page.getByRole("heading", { name: "fixture-server" }).waitFor();
  await page.getByLabel("Link a project").selectOption({ label: "Fixture Project" });
  await page.getByLabel("I confirm this server runs deployments of this project.").check();
  await page.getByRole("button", { name: "Link", exact: true }).click();
  await page
    .getByText("Project linked. Repository and production status were reassessed.")
    .waitFor();
  await page.getByRole("button", { name: "All findings", exact: true }).first().click();
  await page
    .locator("tr")
    .filter({ hasText: "GHSA-fixture-2025" })
    .getByText("Fixed in repo")
    .waitFor();
  await page
    .locator("tr")
    .filter({ hasText: "GHSA-fixture-2025" })
    .getByText("Still affected")
    .waitFor();
  assert.equal(
    await page.getByText("Local storage is unavailable.").count(),
    0,
    "no storage error notice during the flow",
  );

  const axePath = require.resolve("axe-core/axe.min.js");
  const screenshotDirectory = `${repositoryRoot}docs/screenshots`;
  await mkdir(screenshotDirectory, { recursive: true });
  const mainPages = [
    ["Review", "review"],
    ["All findings", "findings"],
    ["Projects", "projects"],
    ["Servers", "servers"],
    ["History", "history"],
    ["Settings", "settings"],
  ];

  for (const [theme, themeValue] of [
    ["light", "light"],
    ["dark", "dark"],
  ]) {
    await page.getByRole("button", { name: "Settings", exact: true }).click();
    await page.locator("select").first().selectOption(themeValue);
    if (themeValue === "light") {
      const sourceAccess = page.getByRole("checkbox", { name: "Fixture Project" });
      await sourceAccess.check();
      assert.equal(await sourceAccess.isChecked(), true);
      await sourceAccess.uncheck();
      const actions = await page.evaluate(() =>
        window.__securityMonitorE2eState.audit.map((event) => event.action),
      );
      assert.ok(actions.includes("mcp_source_access_permission_enabled"));
      assert.ok(actions.includes("mcp_source_access_permission_revoked"));
    }
    await page.waitForTimeout(150);
    const closeNotice = page.getByRole("button", { name: "Close" });
    if (await closeNotice.count()) await closeNotice.click();
    for (const [label, slug] of mainPages) {
      await page
        .getByRole("button", { name: label, exact: label !== "Review" })
        .first()
        .click();
      await page.waitForTimeout(80);
      if (slug === "settings") {
        await page.getByText("No AI providers are configured.").waitFor();
        await page
          .getByText("Mixed upstream terms; includes CC BY-SA and CC BY-NC-ND records")
          .waitFor();
        const updateButton = page.getByRole("button", { name: "Check for updates" });
        await updateButton.waitFor();
        assert.equal(await updateButton.isDisabled(), true);
      }
      await page.addScriptTag({ path: axePath });
      const accessibility = await page.evaluate(async () =>
        window.axe.run(document, {
          runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] },
        }),
      );
      assert.equal(
        accessibility.violations.length,
        0,
        `${theme} ${label} axe violations: ${JSON.stringify(accessibility.violations.map((item) => ({ id: item.id, nodes: item.nodes.map((node) => ({ target: node.target, checks: node.any.map((check) => check.data) })) })))}`,
      );
      await assertCleanUi(page, `${theme} ${label} screenshot`);
      await page.screenshot({ path: `${screenshotDirectory}/${slug}-${theme}.png` });
    }
  }

  await page.getByRole("button", { name: "All findings", exact: true }).click();
  await page.getByRole("textbox", { name: "Search", exact: true }).fill("GHSA-fixture-2025");
  await page.getByRole("button", { name: "GHSA-fixture-2025" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Change status" }).click();
  await page.getByRole("dialog").getByLabel("New status").selectOption("not_reachable");
  await page.getByRole("dialog").getByRole("button", { name: "Save changes" }).click();
  await page.getByText("Finding status updated").waitFor();
  await page
    .locator("tr")
    .filter({ hasText: "GHSA-fixture-2025" })
    .getByText("Not reachable")
    .waitFor();

  await page.keyboard.press("Control+k");
  await page
    .getByRole("dialog")
    .getByRole("textbox", { name: "Search", exact: true })
    .fill("Settings");
  await page.getByRole("dialog").getByRole("button", { name: "Settings" }).click();
  await page.getByRole("heading", { name: "Settings" }).waitFor();
  assert.deepEqual(
    [...externalRequests],
    [],
    "default startup, scans, and settings must not contact third-party hosts",
  );
} finally {
  await browser?.close();
  server.kill();
}
