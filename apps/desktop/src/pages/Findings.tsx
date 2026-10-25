import { useCallback, useEffect, useMemo, useState } from "react";
import type { Finding } from "../generated/Finding";
import type { WorkspaceData } from "../api";
import { api } from "../api";
import { Empty, PageHeading, RepoProductionStatus, SeverityLabel, StatusDialog, StatusTag } from "../components";
import { MemoryNotes } from "../MemoryNotes";
import { RemediationSection } from "../RemediationSection";
import { useWorkspace, type Language, type NoticeSetter, type T } from "../WorkspaceContext";
import { date, safeError } from "../utils";
export function Findings() {
  const { data, t, refresh, setNotice, updateFinding, focusFindingId: initialFindingId, setFocusFindingId } = useWorkspace();
  const onFocused = useCallback(() => setFocusFindingId(null), [setFocusFindingId]);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("all");
  const [project, setProject] = useState("all");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [editingStatus, setEditingStatus] = useState(false);
  const advisories = useMemo(() => new Map(data.advisories.map((item) => [item.canonical_id, item])), [data.advisories]);
  const components = useMemo(() => new Map(data.components.map((item) => [item.id, item])), [data.components]);
  const instances = useMemo(() => new Map(data.instances.map((item) => [item.id, item])), [data.instances]);
  const projects = useMemo(() => new Map(data.projects.map((item) => [item.id, item])), [data.projects]);
  useEffect(() => {
    if (!initialFindingId) return;
    const finding = data.findings.find((item) => item.id === initialFindingId);
    if (finding) setSelected(finding);
    onFocused();
  }, [data.findings, initialFindingId, onFocused]);
  const filtered = data.findings.filter((finding) => {
    const advisory = advisories.get(finding.advisory_id);
    const instance = instances.get(finding.component_instance_id);
    const component = instance ? components.get(instance.component_id) : undefined;
    const projectName = instance?.project_id ? projects.get(instance.project_id)?.name ?? "" : "";
    const text = `${advisory?.canonical_id ?? finding.advisory_id} ${advisory?.title ?? ""} ${component?.name ?? ""} ${component?.version ?? ""} ${projectName}`.toLowerCase();
    return text.includes(query.toLowerCase()) && (severity === "all" || finding.severity === severity) && (status === "all" || finding.status === status) && (project === "all" || instance?.project_id === project);
  });
  return <>
    <PageHeading title={t("findings.title")} description={t("findings.description")} />
    <section className="panel filters" aria-label={t("common.search")}><label className="field grow"><span>{t("common.search")}</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("common.searchPlaceholder")} /></label><label className="field"><span>{t("common.severity")}</span><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">{t("common.all")}</option>{["critical", "high", "medium", "low", "unknown"].map((value) => <option key={value} value={value}>{t(`severity.${value}`)}</option>)}</select></label><label className="field"><span>{t("common.status")}</span><select value={status} onChange={(event) => setStatus(event.target.value)}><option value="all">{t("common.all")}</option>{["new", "needs_review", "confirmed_affected", "not_reachable", "mitigated", "fix_proposed", "fixed_in_repo", "fixed_in_production", "accepted_risk", "false_positive"].map((value) => <option key={value} value={value}>{t(`status.${value}`)}</option>)}</select></label><label className="field"><span>{t("common.project")}</span><select value={project} onChange={(event) => setProject(event.target.value)}><option value="all">{t("common.all")}</option>{data.projects.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}</select></label></section>
    {filtered.length === 0 ? <Empty t={t} noResults={data.findings.length > 0} /> : <section className="panel table-panel"><div className="table-wrap"><table><thead><tr><th>{t("findings.advisory")}</th><th>{t("findings.package")}</th><th>{t("common.severity")}</th><th>{t("common.status")}</th><th>{t("drift.repository")}</th><th>{t("drift.production")}</th><th>{t("common.project")}</th><th>{t("findings.priority")}</th><th>{t("common.updated")}</th></tr></thead><tbody>{filtered.map((finding) => {
      const advisory = advisories.get(finding.advisory_id); const instance = instances.get(finding.component_instance_id); const component = instance ? components.get(instance.component_id) : undefined;
      return <tr key={finding.id}><td><button className="text-button" onClick={() => setSelected(finding)}>{advisory?.canonical_id ?? finding.advisory_id}</button><small className="cell-subtitle">{advisory?.title ?? t("common.unverified")}</small></td><td>{component ? `${component.name}@${component.version}` : t("common.unverified")}</td><td><SeverityLabel severity={finding.severity} t={t} /></td><td><StatusTag value={finding.status} t={t} /></td><td><RepoProductionStatus kind="repo" value={finding.repo_status} compact t={t} /></td><td><RepoProductionStatus kind="production" value={finding.production_status} compact t={t} /></td><td>{instance?.project_id ? projects.get(instance.project_id)?.name ?? t("common.unverified") : t("common.unknown")}</td><td>{finding.priority_score}</td><td>{date(finding.updated_at, data.settings.language)}</td></tr>;
    })}</tbody></table></div></section>}
    {selected && (editingStatus
      ? <StatusDialog finding={selected} instance={instances.get(selected.component_instance_id)} t={t} close={() => setEditingStatus(false)} onSave={async (change) => { try { const updated = await api.setFindingStatus(change); updateFinding(updated); setSelected(null); setEditingStatus(false); setNotice({ kind: "success", message: t("findings.statusSaved") }); refresh(); } catch (error) { setNotice({ kind: "error", message: safeError(error, t) }); } }} />
      : <FindingDetail
        finding={selected}
        advisory={advisories.get(selected.advisory_id)}
        component={components.get(instances.get(selected.component_instance_id)?.component_id ?? "")}
        instance={instances.get(selected.component_instance_id)}
        projectName={projects.get(instances.get(selected.component_instance_id)?.project_id ?? "")?.name}
        evidence={data.evidence.filter((item) => item.finding_id === selected.id)}
        data={data}
        language={data.settings.language}
        t={t}
        setNotice={setNotice}
        close={() => setSelected(null)}
        changeStatus={() => setEditingStatus(true)}
      />)}
  </>;
}

function FindingDetail({ finding, advisory, component, instance, projectName, evidence, data, language, t, setNotice, close, changeStatus }: {
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
  return <div className="dialog-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) close(); }}><article className="finding-detail panel" role="dialog" aria-modal="true" aria-labelledby="finding-detail-title">
    <div className="panel-heading"><div><span className="eyebrow">{t("findings.detailTitle")}</span><h2 id="finding-detail-title">{advisory?.canonical_id ?? finding.advisory_id}</h2></div><button className="icon-button" aria-label={t("actions.close")} onClick={close}>×</button></div>
    <p className="finding-detail-package">{component ? `${component.name}@${component.version}` : t("common.unverified")} · {projectName ?? t("common.unverified")}</p>
    <div className="finding-detail-tags"><SeverityLabel severity={finding.severity} t={t} /><StatusTag value={finding.status} t={t} /><RepoProductionStatus kind="repo" value={finding.repo_status} t={t} /><RepoProductionStatus kind="production" value={finding.production_status} t={t} /><span className="tag">{t("findings.priority")}: {finding.priority_score}</span></div>
    <section><h3>{t("findings.whyMatters")}</h3><p>{advisory?.description || advisory?.summary || t("common.unverified")}</p>{why.length > 0 && <ul>{why.map((reason, index) => <li key={`${reason}-${index}`}>{reason}</li>)}</ul>}</section>
    <section><h3>{t("findings.evidence")}</h3>{evidence.length === 0 && instanceEvidence.length === 0 ? <p>{t("findings.noEvidence")}</p> : <ul>{evidence.map((item) => {
      const evidenceKey = `evidence.${item.evidence_type}`;
      const evidenceName = t(evidenceKey) === evidenceKey ? t("common.unverified") : t(evidenceKey);
      return <li key={item.id}><strong>{evidenceName}</strong>{item.file_path_redacted && <code>{item.file_path_redacted}</code>}{item.reference && <span>{item.reference}</span>}{item.confidence !== null && <small>{t("findings.confidence")}: {Math.round(item.confidence * 100)}%</small>}</li>;
    })}{instanceEvidence.map((item, index) => {
      const evidenceKey = `evidence.${item.evidence_type}`;
      const evidenceName = t(evidenceKey) === evidenceKey ? t("common.unverified") : t(evidenceKey);
      return <li key={`instance-${index}`}><strong>{evidenceName}</strong>{item.file_path_redacted && <code>{item.file_path_redacted}</code>}{item.reference && <span>{item.reference}</span>}</li>;
    })}</ul>}</section>
    <section><h3>{t("findings.remediation")}</h3><p>{finding.fix_version ? `${t("findings.fixedVersion")}: ${finding.fix_version}` : t("common.unverified")}</p><RemediationSection findingId={finding.id} projectId={instance?.project_id ?? null} data={data} t={t} setNotice={setNotice} /></section>
    <MemoryNotes scope="finding" scopeId={finding.id} t={t} setNotice={setNotice} />
    <details><summary>{t("findings.details")}</summary><dl><dt>{t("findings.cvss")}</dt><dd>{advisory?.cvss ?? t("common.unknown")}</dd><dt>{t("findings.epss")}</dt><dd>{advisory?.epss === null || advisory?.epss === undefined ? t("common.unknown") : `${Math.round(advisory.epss * 100)}%`}</dd><dt>{t("findings.kev")}</dt><dd>{t(advisory?.kev ? "common.yes" : "common.no")}</dd><dt>{t("common.updated")}</dt><dd>{date(advisory?.source_updated_at, language)}</dd></dl>{advisory?.aliases.length ? <p>{t("findings.aliases")}: {advisory.aliases.join(", ")}</p> : null}{advisory?.source_urls.map((url) => <p key={url}><a href={url} target="_blank" rel="noreferrer">{url}</a></p>)}</details>
    <div className="button-row end"><button className="button quiet" onClick={close}>{t("actions.close")}</button><button className="button primary" onClick={changeStatus}>{t("findings.changeStatus")}</button></div>
  </article></div>;
}
