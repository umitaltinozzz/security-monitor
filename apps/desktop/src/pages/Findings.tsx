import { useCallback, useEffect, useMemo, useState } from "react";
import type { Finding } from "../generated/Finding";
import type { FindingPageView } from "../generated/FindingPageView";
import type { FindingStatus } from "../generated/FindingStatus";
import type { ScannerFinding } from "../generated/ScannerFinding";
import type { ScannerFindingStatus } from "../generated/ScannerFindingStatus";
import type { Severity } from "../generated/Severity";
import type { WorkspaceData } from "../api";
import { api } from "../api";
import {
  Empty,
  PageHeading,
  RepoProductionStatus,
  ScannerFindingReviewDialog,
  SeverityLabel,
  StatusDialog,
  StatusTag,
} from "../components";
import { MemoryNotes } from "../MemoryNotes";
import { RemediationSection } from "../RemediationSection";
import { useWorkspace, type Language, type NoticeSetter, type T } from "../WorkspaceContext";
import { date, safeError } from "../utils";

const FINDING_PAGE_SIZE = 25;

export function Findings() {
  const {
    data,
    t,
    refresh,
    setNotice,
    updateFinding,
    focusFindingId: initialFindingId,
    setFocusFindingId,
  } = useWorkspace();
  const onFocused = useCallback(() => setFocusFindingId(null), [setFocusFindingId]);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("all");
  const [project, setProject] = useState("all");
  const [pageIndex, setPageIndex] = useState(0);
  const [pageResult, setPageResult] = useState<FindingPageView | null>(null);
  const [pageLoading, setPageLoading] = useState(true);
  const [pageReload, setPageReload] = useState(0);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [selectedScannerFinding, setSelectedScannerFinding] = useState<ScannerFinding | null>(null);
  const [scannerStatus, setScannerStatus] = useState<ScannerFindingStatus | "all">("all");
  const [editingStatus, setEditingStatus] = useState(false);
  const advisories = useMemo(
    () => new Map(data.advisories.map((item) => [item.canonical_id, item])),
    [data.advisories],
  );
  const components = useMemo(
    () => new Map(data.components.map((item) => [item.id, item])),
    [data.components],
  );
  const instances = useMemo(
    () => new Map(data.instances.map((item) => [item.id, item])),
    [data.instances],
  );
  const projects = useMemo(
    () => new Map(data.projects.map((item) => [item.id, item])),
    [data.projects],
  );
  useEffect(() => {
    let active = true;
    setPageLoading(true);
    void api
      .findingsPage({
        offset: pageIndex * FINDING_PAGE_SIZE,
        limit: FINDING_PAGE_SIZE,
        status: status === "all" ? null : (status as FindingStatus),
        severity: severity === "all" ? null : (severity as Severity),
        projectId: project === "all" ? null : project,
        query,
      })
      .then((page) => {
        if (active) setPageResult(page);
      })
      .catch((error) => {
        if (active) setNotice({ kind: "error", message: safeError(error, t) });
      })
      .finally(() => {
        if (active) setPageLoading(false);
      });
    return () => {
      active = false;
    };
  }, [pageIndex, pageReload, project, query, severity, setNotice, status, t]);

  useEffect(() => {
    if (!initialFindingId) return;
    const finding = data.findings.find((item) => item.id === initialFindingId);
    if (finding) setSelected(finding);
    onFocused();
  }, [data.findings, initialFindingId, onFocused]);
  const filtered = pageResult?.findings ?? [];
  const scannerQuery = query.trim().toLowerCase();
  const filteredScannerFindings = data.scannerFindings.filter((finding) => {
    const matchesStatus = scannerStatus === "all" || finding.status === scannerStatus;
    const matchesSeverity = severity === "all" || finding.severity === severity;
    const matchesProject = project === "all" || finding.project_id === project;
    const searchText = [
      finding.title,
      finding.rule_id,
      finding.package_name,
      finding.path,
      finding.scanner,
    ]
      .filter((value): value is string => Boolean(value))
      .join(" ")
      .toLowerCase();
    return (
      matchesStatus &&
      matchesSeverity &&
      matchesProject &&
      (!scannerQuery || searchText.includes(scannerQuery))
    );
  });
  const totalPages = Math.max(1, Math.ceil((pageResult?.total_count ?? 0) / FINDING_PAGE_SIZE));
  return (
    <>
      <PageHeading title={t("findings.title")} description={t("findings.description")} />
      <section className="panel filters" aria-label={t("common.search")}>
        <label className="field grow">
          <span>{t("common.search")}</span>
          <input
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setPageIndex(0);
            }}
            placeholder={t("common.searchPlaceholder")}
          />
        </label>
        <label className="field">
          <span>{t("common.severity")}</span>
          <select
            value={severity}
            onChange={(event) => {
              setSeverity(event.target.value);
              setPageIndex(0);
            }}
          >
            <option value="all">{t("common.all")}</option>
            {["critical", "high", "medium", "low", "unknown"].map((value) => (
              <option key={value} value={value}>
                {t(`severity.${value}`)}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>{t("common.status")}</span>
          <select
            value={status}
            onChange={(event) => {
              setStatus(event.target.value);
              setPageIndex(0);
            }}
          >
            <option value="all">{t("common.all")}</option>
            {[
              "new",
              "needs_review",
              "confirmed_affected",
              "not_reachable",
              "mitigated",
              "fix_proposed",
              "fixed_in_repo",
              "fixed_in_production",
              "accepted_risk",
              "false_positive",
            ].map((value) => (
              <option key={value} value={value}>
                {t(`status.${value}`)}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>{t("common.project")}</span>
          <select
            value={project}
            onChange={(event) => {
              setProject(event.target.value);
              setPageIndex(0);
            }}
          >
            <option value="all">{t("common.all")}</option>
            {data.projects.map((item) => (
              <option value={item.id} key={item.id}>
                {item.name}
              </option>
            ))}
          </select>
        </label>
      </section>
      {pageLoading && !pageResult ? (
        <p role="status">{t("common.loading")}</p>
      ) : filtered.length === 0 ? (
        <Empty t={t} noResults={data.findings.length > 0} />
      ) : (
        <section className="panel table-panel" aria-busy={pageLoading}>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t("findings.advisory")}</th>
                  <th>{t("findings.package")}</th>
                  <th>{t("common.severity")}</th>
                  <th>{t("common.status")}</th>
                  <th>{t("drift.repository")}</th>
                  <th>{t("drift.production")}</th>
                  <th>{t("common.project")}</th>
                  <th>{t("findings.priority")}</th>
                  <th>{t("common.updated")}</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((finding) => {
                  const advisory = advisories.get(finding.advisory_id);
                  const instance = instances.get(finding.component_instance_id);
                  const component = instance ? components.get(instance.component_id) : undefined;
                  return (
                    <tr key={finding.id}>
                      <td>
                        <button className="text-button" onClick={() => setSelected(finding)}>
                          {advisory?.canonical_id ?? finding.advisory_id}
                        </button>
                        <small className="cell-subtitle">
                          {advisory?.title ?? t("common.unverified")}
                        </small>
                      </td>
                      <td>
                        {component
                          ? `${component.name}@${component.version ?? t("common.unverified")}`
                          : t("common.unverified")}
                      </td>
                      <td>
                        <SeverityLabel severity={finding.severity} t={t} />
                      </td>
                      <td>
                        <StatusTag value={finding.status} t={t} />
                      </td>
                      <td>
                        <RepoProductionStatus
                          kind="repo"
                          value={finding.repo_status}
                          compact
                          t={t}
                        />
                      </td>
                      <td>
                        <RepoProductionStatus
                          kind="production"
                          value={finding.production_status}
                          compact
                          t={t}
                        />
                      </td>
                      <td>
                        {instance?.project_id
                          ? (projects.get(instance.project_id)?.name ?? t("common.unverified"))
                          : t("common.unknown")}
                      </td>
                      <td>{finding.priority_score}</td>
                      <td>{date(finding.updated_at, data.settings.language)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}
      <nav className="button-row finding-pagination" aria-label={t("findings.pagination")}>
        <button
          className="button quiet"
          disabled={pageIndex === 0 || pageLoading}
          onClick={() => setPageIndex((current) => Math.max(0, current - 1))}
        >
          {t("findings.previousPage")}
        </button>
        <span aria-live="polite">
          {t("findings.pageStatus")
            .replace("{current}", String(Math.min(pageIndex + 1, totalPages)))
            .replace("{total}", String(totalPages))
            .replace("{count}", String(pageResult?.total_count ?? 0))}
        </span>
        <button
          className="button quiet"
          disabled={pageIndex + 1 >= totalPages || pageLoading}
          onClick={() => setPageIndex((current) => current + 1)}
        >
          {t("findings.nextPage")}
        </button>
      </nav>
      {data.scannerFindings.length > 0 && (
        <section className="panel table-panel scanner-findings-panel">
          <div className="panel-heading">
            <div>
              <h2>{t("findings.scannerFindings")}</h2>
              <p>{t("findings.scannerFindingsDescription")}</p>
            </div>
            <label className="field">
              <span>{t("findings.scannerReviewStatus")}</span>
              <select
                value={scannerStatus}
                onChange={(event) =>
                  setScannerStatus(event.target.value as ScannerFindingStatus | "all")
                }
              >
                <option value="all">{t("common.all")}</option>
                {["needs_review", "confirmed", "accepted_risk", "false_positive", "resolved"].map(
                  (value) => (
                    <option key={value} value={value}>
                      {t(`findings.scannerStatus.${value}`)}
                    </option>
                  ),
                )}
              </select>
            </label>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t("findings.rule")}</th>
                  <th>{t("findings.source")}</th>
                  <th>{t("findings.package")}</th>
                  <th>{t("findings.location")}</th>
                  <th>{t("common.severity")}</th>
                  <th>{t("common.status")}</th>
                  <th>{t("findings.lastSeen")}</th>
                  <th>{t("actions.review")}</th>
                </tr>
              </thead>
              <tbody>
                {filteredScannerFindings.length === 0 ? (
                  <tr>
                    <td colSpan={8}>{t("findings.scannerNoResults")}</td>
                  </tr>
                ) : (
                  filteredScannerFindings.map((finding) => (
                    <tr key={finding.id}>
                      <td>
                        {finding.title ?? finding.rule_id ?? t("common.unverified")}
                        {finding.rule_id && (
                          <small className="cell-subtitle">{finding.rule_id}</small>
                        )}
                      </td>
                      <td>
                        {finding.scanner} · {finding.mode}
                      </td>
                      <td>
                        {finding.package_name
                          ? `${finding.package_name}${finding.package_version ? `@${finding.package_version}` : ""}`
                          : t("common.notAvailable")}
                      </td>
                      <td>
                        {finding.path ? (
                          <code>
                            {finding.path}
                            {finding.line_start ? `:${finding.line_start}` : ""}
                            {finding.line_end && finding.line_end !== finding.line_start
                              ? `-${finding.line_end}`
                              : ""}
                          </code>
                        ) : (
                          t("common.notAvailable")
                        )}
                      </td>
                      <td>
                        <SeverityLabel severity={finding.severity} t={t} />
                      </td>
                      <td>{t(`findings.scannerStatus.${finding.status}`)}</td>
                      <td>{date(finding.last_seen_at, data.settings.language)}</td>
                      <td>
                        <button
                          className="button quiet"
                          onClick={() => setSelectedScannerFinding(finding)}
                        >
                          {t("actions.review")}
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}
      {selectedScannerFinding && (
        <ScannerFindingReviewDialog
          finding={selectedScannerFinding}
          t={t}
          close={() => setSelectedScannerFinding(null)}
          onSave={async (change) => {
            try {
              await api.setScannerFindingReview(change);
              setSelectedScannerFinding(null);
              setNotice({ kind: "success", message: t("findings.scannerReviewSaved") });
              refresh();
            } catch (error) {
              setNotice({ kind: "error", message: safeError(error, t) });
            }
          }}
        />
      )}
      {selected &&
        (editingStatus ? (
          <StatusDialog
            finding={selected}
            instance={instances.get(selected.component_instance_id)}
            t={t}
            close={() => setEditingStatus(false)}
            onSave={async (change) => {
              try {
                const updated = await api.setFindingStatus(change);
                updateFinding(updated);
                setPageReload((current) => current + 1);
                setSelected(null);
                setEditingStatus(false);
                setNotice({ kind: "success", message: t("findings.statusSaved") });
                refresh(["audit"]);
              } catch (error) {
                setNotice({ kind: "error", message: safeError(error, t) });
              }
            }}
          />
        ) : (
          <FindingDetail
            finding={selected}
            advisory={advisories.get(selected.advisory_id)}
            component={components.get(
              instances.get(selected.component_instance_id)?.component_id ?? "",
            )}
            instance={instances.get(selected.component_instance_id)}
            projectName={
              projects.get(instances.get(selected.component_instance_id)?.project_id ?? "")?.name
            }
            evidence={data.evidence.filter((item) => item.finding_id === selected.id)}
            data={data}
            language={data.settings.language}
            t={t}
            setNotice={setNotice}
            close={() => setSelected(null)}
            changeStatus={() => setEditingStatus(true)}
          />
        ))}
    </>
  );
}

function FindingDetail({
  finding,
  advisory,
  component,
  instance,
  projectName,
  evidence,
  data,
  language,
  t,
  setNotice,
  close,
  changeStatus,
}: {
  finding: Finding;
  advisory: WorkspaceData["advisories"][number] | undefined;
  component: WorkspaceData["components"][number] | undefined;
  instance: WorkspaceData["instances"][number] | undefined;
  projectName: string | undefined;
  evidence: WorkspaceData["evidence"];
  data: WorkspaceData;
  language: Language;
  t: T;
  setNotice: NoticeSetter;
  close: () => void;
  changeStatus: () => void;
}) {
  const why = finding.priority_reasons.map((reason) => {
    const key = `priorityReasons.${reason}`;
    const translated = t(key);
    return translated === key ? t("common.unverified") : translated;
  });
  const instanceEvidence = instance?.evidence ?? [];
  return (
    <div
      className="dialog-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) close();
      }}
    >
      <article
        className="finding-detail panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="finding-detail-title"
      >
        <div className="panel-heading">
          <div>
            <span className="eyebrow">{t("findings.detailTitle")}</span>
            <h2 id="finding-detail-title">{advisory?.canonical_id ?? finding.advisory_id}</h2>
          </div>
          <button className="icon-button" aria-label={t("actions.close")} onClick={close}>
            ×
          </button>
        </div>
        <p className="finding-detail-package">
          {component
            ? `${component.name}@${component.version ?? t("common.unverified")}`
            : t("common.unverified")}{" "}
          · {projectName ?? t("common.unverified")}
        </p>
        <div className="finding-detail-tags">
          <SeverityLabel severity={finding.severity} t={t} />
          <StatusTag value={finding.status} t={t} />
          <RepoProductionStatus kind="repo" value={finding.repo_status} t={t} />
          <RepoProductionStatus kind="production" value={finding.production_status} t={t} />
          <span className="tag">
            {t("findings.priority")}: {finding.priority_score}
          </span>
        </div>
        <section>
          <h3>{t("findings.whyMatters")}</h3>
          <p>{advisory?.description || advisory?.summary || t("common.unverified")}</p>
          {why.length > 0 && (
            <ul>
              {why.map((reason, index) => (
                <li key={`${reason}-${index}`}>{reason}</li>
              ))}
            </ul>
          )}
        </section>
        <section>
          <h3>{t("findings.evidence")}</h3>
          {evidence.length === 0 && instanceEvidence.length === 0 ? (
            <p>{t("findings.noEvidence")}</p>
          ) : (
            <ul>
              {evidence.map((item) => {
                const evidenceKey = `evidence.${item.evidence_type}`;
                const evidenceName =
                  t(evidenceKey) === evidenceKey ? t("common.unverified") : t(evidenceKey);
                return (
                  <li key={item.id}>
                    <strong>{evidenceName}</strong>
                    {item.file_path_redacted && <code>{item.file_path_redacted}</code>}
                    {item.reference && <span>{item.reference}</span>}
                    {item.confidence !== null && (
                      <small>
                        {t("findings.confidence")}: {Math.round(item.confidence * 100)}%
                      </small>
                    )}
                  </li>
                );
              })}
              {instanceEvidence.map((item, index) => {
                const evidenceKey = `evidence.${item.evidence_type}`;
                const evidenceName =
                  t(evidenceKey) === evidenceKey ? t("common.unverified") : t(evidenceKey);
                return (
                  <li key={`instance-${index}`}>
                    <strong>{evidenceName}</strong>
                    {item.file_path_redacted && <code>{item.file_path_redacted}</code>}
                    {item.reference && <span>{item.reference}</span>}
                  </li>
                );
              })}
            </ul>
          )}
        </section>
        <section>
          <h3>{t("findings.remediation")}</h3>
          <p>
            {finding.fix_version
              ? `${t("findings.fixedVersion")}: ${finding.fix_version}`
              : t("common.unverified")}
          </p>
          <RemediationSection
            findingId={finding.id}
            projectId={instance?.project_id ?? null}
            data={data}
            t={t}
            setNotice={setNotice}
          />
        </section>
        <MemoryNotes scope="finding" scopeId={finding.id} t={t} setNotice={setNotice} />
        <details>
          <summary>{t("findings.details")}</summary>
          <dl>
            <dt>{t("findings.cvss")}</dt>
            <dd>{advisory?.cvss ?? t("common.unknown")}</dd>
            <dt>{t("findings.epss")}</dt>
            <dd>
              {advisory?.epss === null || advisory?.epss === undefined
                ? t("common.unknown")
                : `${Math.round(advisory.epss * 100)}%`}
            </dd>
            <dt>{t("findings.kev")}</dt>
            <dd>{t(advisory?.kev ? "common.yes" : "common.no")}</dd>
            <dt>{t("common.updated")}</dt>
            <dd>{date(advisory?.source_updated_at, language)}</dd>
          </dl>
          {advisory?.aliases.length ? (
            <p>
              {t("findings.aliases")}: {advisory.aliases.join(", ")}
            </p>
          ) : null}
          {advisory?.source_urls.map((url) => (
            <p key={url}>
              <a href={url} target="_blank" rel="noreferrer">
                {url}
              </a>
            </p>
          ))}
        </details>
        <div className="button-row end">
          <button className="button quiet" onClick={close}>
            {t("actions.close")}
          </button>
          <button className="button primary" onClick={changeStatus}>
            {t("findings.changeStatus")}
          </button>
        </div>
      </article>
    </div>
  );
}
