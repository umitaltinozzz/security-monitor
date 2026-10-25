import type { ReactNode } from "react";
import en from "../locales/en.json";
import type { T } from "../WorkspaceContext";
import type { WorkspaceData } from "../api";
export function PageHeading({
  title,
  description,
  actions,
}: {
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions}
    </div>
  );
}

export function Drift({ data, t }: { data: WorkspaceData; t: T }) {
  return (
    <section className="panel drift-section">
      <DriftSummary findings={data.findings} linkedServers={data.links.length} t={t} />
    </section>
  );
}

export function DriftSummary({
  findings,
  linkedServers,
  t,
}: {
  findings: WorkspaceData["findings"];
  linkedServers: number;
  t: T;
}) {
  const repoFixedStillProduction = findings.filter(
    (finding) =>
      finding.repo_status === "fixed_in_repo" && finding.production_status === "still_affected",
  ).length;
  const stillAffected = findings.filter(
    (finding) => finding.production_status === "still_affected",
  ).length;
  const fixedInProduction = findings.filter(
    (finding) => finding.production_status === "fixed_in_production",
  ).length;
  const unverified = findings.filter((finding) => finding.production_status === "unknown").length;
  const tag =
    findings.length === 0 || unverified === findings.length
      ? "unverified"
      : stillAffected > 0 || unverified > 0
        ? "partial"
        : "fixed_in_production";
  return (
    <>
      <div className="subsection-title">
        <h3>{t("drift.title")}</h3>
        <StatusTag value={tag} t={t} />
      </div>
      {linkedServers === 0 ? (
        <p>{t("drift.noLinkedServer")}</p>
      ) : (
        <ul className="drift-lines">
          <li>
            <span>{t("drift.repoFixedStillProduction")}</span>
            <strong>{repoFixedStillProduction}</strong>
          </li>
          <li>
            <span>{t("drift.stillAffectedInProduction")}</span>
            <strong>{stillAffected}</strong>
          </li>
          <li>
            <span>{t("drift.fixedInProductionCount")}</span>
            <strong>{fixedInProduction}</strong>
          </li>
          <li>
            <span>{t("common.unverified")}</span>
            <strong>{unverified}</strong>
          </li>
        </ul>
      )}
      <p className="link-note">{t("drift.noSnapshotBody")}</p>
    </>
  );
}

export function ScanDiagnostics({ error, t }: { error: string | null; t: T }) {
  if (!error) return null;
  const items = error.split(",").map((diagnostic) => {
    const [kind, engine, scope, state] = diagnostic.split(":");
    if (kind === "scanner_coverage" && engine && scope && state) {
      const scanner = t(`scanner.${engine.replaceAll("-", "_")}`);
      return `${scanner} · ${t(`scanCoverage.${scope}`)} · ${t(`scanCoverage.${state}`)}`;
    }
    if (kind === "scanner_execution_failed" && engine && scope) {
      return `${t(`scanner.${engine.replaceAll("-", "_")}`)} · ${t(`scanCoverage.${scope}`)} · ${t("scanCoverage.incomplete")}`;
    }
    const key = `scanDiagnostics.${diagnostic}`;
    return t(key) === key ? t("common.unverified") : t(key);
  });
  return (
    <ul className="scan-diagnostics">
      {items.map((item, index) => (
        <li key={`${item}-${index}`}>{item}</li>
      ))}
    </ul>
  );
}

export function Field({
  label,
  value,
  onChange,
  type = "text",
  required = false,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
  required?: boolean;
}) {
  return (
    <label className="field">
      <span>{label}</span>
      <input
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        required={required}
      />
    </label>
  );
}

export function Empty({ t, noResults = false }: { t: T; noResults?: boolean }) {
  return (
    <div className="empty-state">
      <span className="state-icon" aria-hidden="true">
        {noResults ? "⌕" : "◌"}
      </span>
      <h2>{t(noResults ? "common.noResults" : "common.empty")}</h2>
      <p>{t(noResults ? "common.noResultsDescription" : "common.emptyDescription")}</p>
    </div>
  );
}

export function StatusTag({ value, t }: { value: string; t: T }) {
  const key =
    value in (en.status as Record<string, string>)
      ? `status.${value}`
      : value === "unverified"
        ? "common.unverified"
        : value === "stale"
          ? "common.stale"
          : "common.partial";
  const tone = ["succeeded", "fixed_in_production"].includes(value)
    ? "verified"
    : ["partial", "needs_review", "running", "stale", "unverified"].includes(value)
      ? "needs-review"
      : ["failed", "cancelled"].includes(value)
        ? "error"
        : "neutral";
  return (
    <span className={`tag ${tone}`}>
      <span className="tag-mark" aria-hidden="true">
        {tone === "verified" ? "✓" : tone === "error" ? "!" : "•"}
      </span>
      {t(key)}
    </span>
  );
}

export function SeverityLabel({ severity, t }: { severity: string; t: T }) {
  const marks: Record<string, string> = {
    critical: "■",
    high: "●",
    medium: "◐",
    low: "○",
    unknown: "◌",
  };
  const label = severity === "unknown" ? t("common.unverified") : t(`severity.${severity}`);
  return (
    <span className={`severity-label severity-${severity}`}>
      <span className="severity-mark" aria-hidden="true">
        {marks[severity] ?? marks.unknown}
      </span>
      <span>{label}</span>
    </span>
  );
}

export function RepoProductionStatus({
  kind,
  value,
  compact = false,
  t,
}: {
  kind: "repo" | "production";
  value: string;
  compact?: boolean;
  t: T;
}) {
  const labels: Record<string, string> = {
    still_affected: "drift.stillAffected",
    fixed_in_repo: "drift.fixedInRepo",
    fixed_in_production: "drift.fixedInProduction",
    unknown: "common.unverified",
  };
  return (
    <span className={`tag repo-production-status${compact ? " compact" : ""}`}>
      <span className={compact ? "sr-only" : undefined}>
        {t(kind === "repo" ? "drift.repository" : "drift.production")}
      </span>
      <strong>{t(labels[value] ?? "common.unverified")}</strong>
    </span>
  );
}
