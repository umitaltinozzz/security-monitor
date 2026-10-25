import en from "./locales/en.json";
import tr from "./locales/tr.json";
import type { Language, T } from "./WorkspaceContext";

type Dictionary = { [key: string]: string | Dictionary };

const dictionaries: Record<Language, Dictionary> = { en, tr };

export function readCopy(language: Language, key: string): string {
  const result = key.split(".").reduce<unknown>((value, part) => {
    if (value === null || typeof value !== "object") return undefined;
    return (value as Record<string, unknown>)[part];
  }, dictionaries[language]);
  return typeof result === "string" ? result : key;
}

export function initialLanguage(): Language {
  return navigator.language.toLowerCase().startsWith("tr") ? "tr" : "en";
}

export function safeError(error: unknown, t: T): string {
  const code =
    typeof error === "string" && error in (en.error as Record<string, string>) ? error : "unknown";
  return t(`error.${code}`);
}

export function date(value: string | null | undefined, language: Language): string {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? "—"
    : new Intl.DateTimeFormat(language, { dateStyle: "medium", timeStyle: "short" }).format(parsed);
}

export function safeExternalUrl(value: string): string | null {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && Boolean(url.hostname) && !url.username && !url.password
      ? url.toString()
      : null;
  } catch {
    return null;
  }
}

export function isFresh(value: string | null | undefined, hours: number): boolean {
  if (!value) return false;
  const timestamp = new Date(value).getTime();
  return (
    Number.isFinite(timestamp) &&
    timestamp >= Date.now() - hours * 60 * 60 * 1000 &&
    timestamp <= Date.now()
  );
}

export function auditAction(action: string, t: T): string {
  if (action.startsWith("finding_status_changed:")) return t("history.events.findingChanged");
  const keys: Record<string, string> = {
    project_added: "history.events.projectAdded",
    server_paired: "history.events.serverPaired",
    server_inventory_collection_approved: "history.events.inventoryApproved",
    scanner_installed: "history.events.scannerInstalled",
    mcp_source_access_permission_enable_approved: "history.events.mcpSourceAccessApproval",
    mcp_source_access_permission_enabled: "history.events.mcpSourceAccessEnabled",
    mcp_source_access_permission_revocation_requested: "history.events.mcpSourceAccessRevocation",
    mcp_source_access_permission_revoked: "history.events.mcpSourceAccessRevoked",
    mcp_remediation_request_received: "history.events.mcpRemediationRequestReceived",
    mcp_remediation_request_dismissed: "history.events.mcpRemediationRequestDismissed",
    remediation_write_approval_requested: "history.events.remediationWriteRequested",
    remediation_source_transfer_denied: "history.events.remediationSourceTransferDenied",
    remediation_source_transfer_approved: "history.events.remediationSourceTransferApproved",
    remediation_write_approved: "history.events.remediationWriteApproved",
    remediation_write_rejected: "history.events.remediationWriteRejected",
    remediation_worktree_failed: "history.events.remediationWorktreeFailed",
    remediation_agent_started: "history.events.remediationAgentStarted",
    remediation_agent_finished: "history.events.remediationAgentFinished",
    remediation_agent_failed: "history.events.remediationAgentFailed",
    remediation_test_execute_approved: "history.events.remediationTestApproved",
    remediation_test_passed: "history.events.remediationTestPassed",
    remediation_test_failed: "history.events.remediationTestFailed",
  };
  return t(keys[action] ?? "common.unknown");
}
