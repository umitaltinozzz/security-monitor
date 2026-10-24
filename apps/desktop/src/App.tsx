import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import en from "./locales/en.json";
import tr from "./locales/tr.json";
import type { AppSettings } from "./generated/AppSettings";
import type { Finding } from "./generated/Finding";
import type { FindingDispositionReason } from "./generated/FindingDispositionReason";
import type { FindingStatus } from "./generated/FindingStatus";
import type { Project } from "./generated/Project";
import type { WorkspaceData } from "./api";
import { api, loadWorkspace } from "./api";
import { AiSettingsPanel } from "./AiSettings";
import { RemediationSection } from "./RemediationSection";
import { AiChatComposer } from "./AiChatComposer";
import { MemoryNotes } from "./MemoryNotes";
import "./app.css";

type Language = "en" | "tr";
type Page = "review" | "findings" | "projects" | "servers" | "history" | "settings";
type Dictionary = { [key: string]: string | Dictionary };
type Notice = { message: string; kind: "error" | "success" } | null;

const dictionaries: Record<Language, Dictionary> = { en, tr };
const pages: Page[] = ["review", "findings", "projects", "servers", "history", "settings"];
const dispositionStatuses: FindingStatus[] = ["not_reachable", "accepted_risk", "false_positive"];

function readCopy(language: Language, key: string): string {
  const result = key.split(".").reduce<unknown>((value, part) => {
    if (value === null || typeof value !== "object") return undefined;
    return (value as Record<string, unknown>)[part];
  }, dictionaries[language]);
  return typeof result === "string" ? result : key;
}

function initialLanguage(): Language {
  return navigator.language.toLowerCase().startsWith("tr") ? "tr" : "en";
}

function safeError(error: unknown, t: (key: string) => string): string {
  const code = typeof error === "string" && error in (en.error as Record<string, string>) ? error : "unknown";
  return t(`error.${code}`);
}

function date(value: string | null | undefined, language: Language): string {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "—" : new Intl.DateTimeFormat(language, { dateStyle: "medium", timeStyle: "short" }).format(parsed);
}

function isFresh(value: string | null | undefined, hours: number): boolean {
  if (!value) return false;
  const timestamp = new Date(value).getTime();
  return Number.isFinite(timestamp) && timestamp >= Date.now() - hours * 60 * 60 * 1000 && timestamp <= Date.now();
}

function auditAction(action: string, t: T): string {
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

export function App() {
  const [data, setData] = useState<WorkspaceData | null>(null);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState<Notice>(null);
  const [page, setPage] = useState<Page>("review");
  const [language, setLanguage] = useState<Language>(initialLanguage);
  const [refreshToken, setRefreshToken] = useState(0);
  const [scanState, setScanState] = useState<Record<string, string>>({});
  const [activeScanIds, setActiveScanIds] = useState<Record<string, string>>({});
  const cancelledScans = useRef(new Set<string>());
  const [context, setContext] = useState<string | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [paletteQuery, setPaletteQuery] = useState("");
  const [focusFindingId, setFocusFindingId] = useState<string | null>(null);
  const t = useCallback((key: string) => readCopy(language, key), [language]);
  const shortcutLabel = /Mac|iPhone|iPad/.test(navigator.platform) ? "⌘K" : "Ctrl+K";

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const workspace = await loadWorkspace();
      setData(workspace);
      setLanguage(workspace.settings.language);
    } catch (error) {
      setNotice({ message: safeError(error, t), kind: "error" });
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => { void refresh(); }, [refresh, refreshToken]);
  useEffect(() => {
    if (!data?.settings.public_downloads_enabled) return;
    let active = true;
    const refreshNews = async () => {
      try {
        await api.refreshNewsSignals();
        if (active) setRefreshToken((current) => current + 1);
      } catch {
        // Existing local signals remain visible; a failed poll never implies a clean state.
      }
    };
    void refreshNews();
    const timer = window.setInterval(() => void refreshNews(), 30 * 60 * 1000);
    return () => { active = false; window.clearInterval(timer); };
  }, [data?.settings.public_downloads_enabled]);
  useEffect(() => { document.documentElement.lang = language; }, [language]);
  useEffect(() => {
    document.documentElement.dataset.theme = data?.settings.theme ?? "system";
  }, [data?.settings.theme]);
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen(true);
      }
      if (event.key === "Escape") setPaletteOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  async function saveSettings(settings: AppSettings) {
    try {
      await api.saveSettings(settings);
      setData((current) => current ? { ...current, settings } : current);
      setLanguage(settings.language);
      setNotice({ message: t("settings.saved"), kind: "success" });
    } catch (error) {
      setNotice({ message: safeError(error, t), kind: "error" });
    }
  }

  async function addProject(path: string): Promise<Project | null> {
    try {
      const project = await api.addProject(path);
      setData((current) => current ? { ...current, projects: [...current.projects, project] } : current);
      setNotice({ message: t("projects.addSuccess"), kind: "success" });
      return project;
    } catch (error) {
      setNotice({ message: safeError(error, t), kind: "error" });
      return null;
    }
  }

  async function startScan(project: Project, profile: "quick" | "full") {
    try {
      const scanId = await api.startScan(project.id, profile);
      cancelledScans.current.delete(scanId);
      setActiveScanIds((current) => ({ ...current, [project.id]: scanId }));
      setScanState((current) => ({ ...current, [project.id]: "running" }));
      const poll = async () => {
        const result = await api.scanResult(scanId);
        if (!result) return false;
        setScanState((current) => ({ ...current, [project.id]: result.outcome }));
        setActiveScanIds((current) => { const next = { ...current }; delete next[project.id]; return next; });
        setRefreshToken((current) => current + 1);
        setNotice({ message: t(result.outcome === "succeeded" && result.inventory_complete ? "projects.scanComplete" : "projects.scanPartial"), kind: result.outcome === "failed" ? "error" : "success" });
        return true;
      };
      let finished = false;
      while (!finished && !cancelledScans.current.has(scanId)) {
        await new Promise((resolve) => window.setTimeout(resolve, 700));
        finished = await poll();
      }
    } catch (error) {
      setScanState((current) => ({ ...current, [project.id]: "failed" }));
      setActiveScanIds((current) => { const next = { ...current }; delete next[project.id]; return next; });
      setNotice({ message: safeError(error, t), kind: "error" });
    }
  }

  async function cancelProjectScan(projectId: string) {
    const scanId = activeScanIds[projectId];
    if (!scanId) return;
    try {
      if (await api.cancelScan(scanId)) {
        cancelledScans.current.add(scanId);
        setActiveScanIds((current) => { const next = { ...current }; delete next[projectId]; return next; });
        setScanState((current) => ({ ...current, [projectId]: "cancelled" }));
        setNotice({ kind: "success", message: t("projects.scanCancelled") });
      }
    } catch (error) { setNotice({ kind: "error", message: safeError(error, t) }); }
  }

  if (loading && !data) {
    return <main className="center-state" aria-live="polite"><span className="spinner" aria-hidden="true" /><h1>{t("common.loading")}</h1><p>{t("common.loadingDescription")}</p></main>;
  }
  if (!data) {
    return <main className="center-state"><h1>{t("common.error")}</h1><p>{notice?.message ?? t("common.errorDescription")}</p><button className="button primary" onClick={() => setRefreshToken((n) => n + 1)}>{t("actions.retry")}</button></main>;
  }

  const reviewCount = data.findings.filter((finding) => ["new", "needs_review", "confirmed_affected", "fix_proposed"].includes(finding.status)).length;
  const doneOnboarding = data.settings.onboarding_completed;
  if (!doneOnboarding) {
    return <Onboarding data={data} language={language} t={t} notice={notice} setNotice={setNotice} saveSettings={saveSettings} addProject={addProject} startScan={startScan} onComplete={() => setRefreshToken((n) => n + 1)} />;
  }

  return (
    <div className="app-frame">
      <a className="skip-link" href="#main-content">{t("skipToContent")}</a>
      <aside className="sidebar">
        <a className="brand" href="#review" onClick={(event) => { event.preventDefault(); setPage("review"); setContext(null); }}>
          <span className="brand-mark" aria-hidden="true">S</span><span>{t("appName")}</span>
        </a>
        <button className="nav-item command-search" onClick={() => setPaletteOpen(true)}><span className="nav-icon" aria-hidden="true">⌕</span>{t("actions.commandPalette")}<kbd>{shortcutLabel}</kbd></button>
        <nav aria-label={t("navigationLabel")}>
          {pages.filter((item) => item !== "projects" && item !== "servers" && item !== "settings").map((item) => <button key={item} className={`nav-item ${page === item ? "selected" : ""}`} aria-current={page === item ? "page" : undefined} onClick={() => { setPage(item); setContext(null); }}>
            <span className="nav-icon" aria-hidden="true">{item === "review" ? "◉" : item === "findings" ? "⚠" : item === "history" ? "◷" : "⌕"}</span>{t(`navigation.${item}`)}{item === "review" && reviewCount > 0 && <span className="nav-count">{reviewCount}</span>}
          </button>)}
          <div className="sidebar-section"><div className="sidebar-section-header"><span className="sidebar-section-label">{t("common.projects")}</span><button className="sidebar-add" aria-label={t("actions.addProject")} onClick={() => { setPage("projects"); setContext(null); }}>+</button></div><button className="nav-item compact" aria-current={page === "projects" ? "page" : undefined} onClick={() => { setPage("projects"); setContext(null); }}>{t("navigation.projects")}</button>{data.projects.map((project) => <button className="context-item" key={project.id} onClick={() => { setPage("projects"); setContext(project.name); }}><span className={`state-dot ${project.last_scan_at ? "attention" : "unknown"}`} aria-hidden="true" /><span className="context-name">{project.name}</span></button>)}</div>
          <div className="sidebar-section"><div className="sidebar-section-header"><span className="sidebar-section-label">{t("common.servers")}</span><button className="sidebar-add" aria-label={t("actions.pairServer")} onClick={() => { setPage("servers"); setContext(null); }}>+</button></div><button className="nav-item compact" aria-current={page === "servers" ? "page" : undefined} onClick={() => { setPage("servers"); setContext(null); }}>{t("navigation.servers")}</button>{data.assets.map((asset) => <button className="context-item" key={asset.id} onClick={() => { setPage("servers"); setContext(asset.hostname_alias); }}><span className={`state-dot ${asset.last_success_at ? "attention" : "unknown"}`} aria-hidden="true" /><span className="context-name">{asset.hostname_alias}</span></button>)}</div>
          <button className={`nav-item ${page === "settings" ? "selected" : ""}`} aria-current={page === "settings" ? "page" : undefined} onClick={() => { setPage("settings"); setContext(null); }}><span className="nav-icon" aria-hidden="true">⚙</span>{t("navigation.settings")}</button>
        </nav>
        <div className="sidebar-footer"><span className="privacy-dot" aria-hidden="true" />{t("common.localOnly")}</div>
      </aside>
      <div className="content-column">
        <header className="topbar">
          <div><span className="eyebrow">{t("appName")}</span><p className="topbar-subtitle">{t(`navigation.${page}`)}</p></div>
          <button className="button quiet" type="button" aria-label={t("languageToggleLabel")} onClick={() => void saveSettings({ ...data.settings, language: language === "en" ? "tr" : "en" })}>{language === "en" ? "TR" : "EN"}</button>
        </header>
        {notice && <div className={`notice ${notice.kind}`} role={notice.kind === "error" ? "alert" : "status"}>{notice.message}<button type="button" aria-label={t("actions.close")} onClick={() => setNotice(null)}>×</button></div>}
        <main id="main-content" className="main-content" tabIndex={-1}>
          {page === "review" && <Overview data={data} t={t} setPage={setPage} setContext={setContext} setFocusFindingId={setFocusFindingId} />}
          {page === "projects" && <Projects data={data} t={t} addProject={addProject} startScan={startScan} cancelScan={cancelProjectScan} scanState={scanState} activeScanIds={activeScanIds} refresh={() => setRefreshToken((n) => n + 1)} setPage={setPage} setContext={setContext} setFocusFindingId={setFocusFindingId} setNotice={setNotice} />}
          {page === "servers" && <Servers data={data} t={t} refresh={() => setRefreshToken((n) => n + 1)} setNotice={setNotice} />}
          {page === "findings" && <Findings data={data} t={t} refresh={() => setRefreshToken((n) => n + 1)} setNotice={setNotice} updateFinding={(finding) => setData((current) => current ? { ...current, findings: current.findings.map((item) => item.id === finding.id ? finding : item) } : current)} initialFindingId={focusFindingId} onFocused={() => setFocusFindingId(null)} />}
          {page === "history" && <History data={data} t={t} />}
          {page === "settings" && <Settings data={data} t={t} saveSettings={saveSettings} setNotice={setNotice} refresh={() => setRefreshToken((n) => n + 1)} />}
        </main>
        <ContextComposer context={context} projectId={data.projects.find((project) => project.name === context)?.id ?? null} t={t} setNotice={setNotice} />
      </div>
      {paletteOpen && <CommandPalette query={paletteQuery} setQuery={setPaletteQuery} pages={pages} t={t} close={() => { setPaletteOpen(false); setPaletteQuery(""); }} navigate={(next) => { setPage(next); setContext(null); setPaletteOpen(false); setPaletteQuery(""); }} />}
    </div>
  );
}

type T = (key: string) => string;
type NoticeSetter = (notice: Notice) => void;

function PageHeading({ title, description, actions }: { title: string; description: string; actions?: ReactNode }) {
  return <div className="page-heading"><div><h1>{title}</h1><p>{description}</p></div>{actions}</div>;
}

function Overview({ data, t, setPage, setContext, setFocusFindingId }: { data: WorkspaceData; t: T; setPage: (page: Page) => void; setContext: (value: string | null) => void; setFocusFindingId: (value: string | null) => void }) {
  const staleAssets = data.assets.filter((asset) => !isFresh(asset.last_success_at, data.settings.scan_interval_hours));
  const projectNeedsReview = data.projects.filter((project) => {
    const latest = data.runs.filter((run) => run.scope.resource_id === project.id).sort((left, right) => (right.finished_at ?? right.started_at).localeCompare(left.finished_at ?? left.started_at))[0];
    return !isFresh(project.last_scan_at, data.settings.scan_interval_hours) || latest?.outcome !== "succeeded";
  });
  const advisories = new Map(data.advisories.map((advisory) => [advisory.canonical_id, advisory]));
  const actionable = data.findings.filter((finding) => ["new", "needs_review", "confirmed_affected", "fix_proposed"].includes(finding.status));
  const queue = [...actionable].sort((left, right) => right.priority_score - left.priority_score).slice(0, 5);
  const unverifiedNews = data.newsSignals.filter((signal) =>
    !signal.archived_at && !signal.advisory_id && signal.matched_projects.length > 0,
  );
  const latestScan = [...data.runs].sort((left, right) => (right.finished_at ?? right.started_at).localeCompare(left.finished_at ?? left.started_at))[0];
  return <>
    <PageHeading title={t("navigation.review")} description={t("overview.reviewDescription")} actions={<span className="local-badge"><span className="privacy-dot" />{t("common.localOnly")}</span>} />
    <p className="review-summary">{actionable.length > 0 ? `${actionable.length} ${t("overview.actionRequired")}` : t("overview.noActionableFindings")}</p>
    <section className="review-section" aria-labelledby="review-items-title"><div className="panel-heading"><h2 id="review-items-title">{t("overview.reviewItems")}</h2><button className="text-button" onClick={() => setPage("findings")}>{t("navigation.findings")}</button></div>
      {queue.length === 0 && projectNeedsReview.length === 0 && staleAssets.length === 0 && unverifiedNews.length === 0 ? <p className="unverified-line">{t("overview.reviewUnknown")}</p> : <div className="review-list">{queue.map((finding) => {
        const advisory = advisories.get(finding.advisory_id);
        const reason = finding.priority_reasons[0];
        const reasonKey = reason ? `priorityReasons.${reason}` : "";
        const reasonText = reasonKey && t(reasonKey) !== reasonKey ? t(reasonKey) : t("common.unverified");
        return <article className="review-item" key={finding.id}><div className="review-item-copy"><div className="review-item-title"><SeverityLabel severity={finding.severity} t={t} /><strong>{advisory?.canonical_id ?? finding.advisory_id}</strong><StatusTag value={finding.status} t={t} /></div><p>{advisory?.title ?? t("common.unverified")}</p><small>{reasonText}</small></div><div className="review-item-actions"><button className="button secondary" onClick={() => { setPage("findings"); setFocusFindingId(finding.id); }}>{t("actions.review")}</button><button className="button quiet" onClick={() => setContext(advisory?.canonical_id ?? finding.id)}>{t("actions.ask")}</button></div></article>;
      })}{projectNeedsReview.map((project) => { const latest = data.runs.filter((run) => run.scope.resource_id === project.id).sort((left, right) => (right.finished_at ?? right.started_at).localeCompare(left.finished_at ?? left.started_at))[0]; const projectStatus = !project.last_scan_at ? "unverified" : !isFresh(project.last_scan_at, data.settings.scan_interval_hours) ? "stale" : "partial"; return <article className="review-item" key={`project-${project.id}`}><div className="review-item-copy"><div className="review-item-title"><StatusTag value={projectStatus} t={t} /><strong>{project.name}</strong></div><p>{t("overview.projectInventoryNeedsReview")}</p><small>{t("common.lastChecked")}: {date(latest?.finished_at ?? project.last_scan_at, data.settings.language)}</small></div><button className="button secondary" onClick={() => { setPage("projects"); setContext(project.name); }}>{t("actions.review")}</button></article>; })}{staleAssets.map((asset) => <article className="review-item" key={`asset-${asset.id}`}><div className="review-item-copy"><div className="review-item-title"><span className="tag unverified">{asset.last_success_at ? t("common.stale") : t("common.unverified")}</span><strong>{asset.hostname_alias}</strong></div><p>{t("overview.serverInventoryNeedsReview")}</p><small>{t("common.lastChecked")}: {date(asset.last_success_at, data.settings.language)}</small></div><button className="button secondary" onClick={() => { setPage("servers"); setContext(asset.hostname_alias); }}>{t("actions.review")}</button></article>)}{unverifiedNews.map((signal) => <article className="review-item" key={signal.id}><div className="review-item-copy"><div className="review-item-title"><span className="tag unverified">{t("news.unverifiedLabel")}</span><strong>{signal.title}</strong></div><p>{signal.summary ?? t("news.statusDescription")}</p><small>{t("news.matchedProducts")}: {signal.matched_products.join(", ")} · {date(signal.published_at, data.settings.language)}</small></div></article>)}</div>}
    </section>
    <p className="review-meta"><span>{t("overview.latestScan")}: {date(latestScan?.finished_at ?? latestScan?.started_at, data.settings.language)}</span><span>{t("overview.advisoryFreshness")}: {data.settings.public_downloads_enabled ? t("common.partial") : t("common.unverified")}</span><button className="text-button" onClick={() => setPage("history")}>{t("navigation.history")}</button></p>
  </>;
}

function Projects({ data, t, addProject, startScan, cancelScan, scanState, activeScanIds, refresh, setPage, setContext, setFocusFindingId, setNotice }: { data: WorkspaceData; t: T; addProject: (path: string) => Promise<Project | null>; startScan: (project: Project, profile: "quick" | "full") => Promise<void>; cancelScan: (projectId: string) => Promise<void>; scanState: Record<string, string>; activeScanIds: Record<string, string>; refresh: () => void; setPage: (page: Page) => void; setContext: (value: string | null) => void; setFocusFindingId: (id: string) => void; setNotice: NoticeSetter }) {
  const [path, setPath] = useState("");
  const [scanAfterAdd, setScanAfterAdd] = useState(true);
  const [parentPath, setParentPath] = useState("");
  const [candidates, setCandidates] = useState<{ name: string; root_path: string; component_count: number; inventory_complete: boolean }[]>([]);
  const [selectedCandidates, setSelectedCandidates] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) { event.preventDefault(); if (!path.trim()) return; const project = await addProject(path.trim()); if (project) { setPath(""); if (scanAfterAdd) await startScan(project, "quick"); } }
  async function discover(event: FormEvent) { event.preventDefault(); setBusy(true); try { const found = await api.discoverProjects(parentPath); setCandidates(found.candidates); setSelectedCandidates([]); } catch (error) { setCandidates([]); setSelectedCandidates([]); setNotice({ kind: "error", message: safeError(error, t) }); } finally { setBusy(false); } }
  async function addSelectedProjects() { setBusy(true); let added = 0; for (const candidatePath of selectedCandidates) { if (await addProject(candidatePath)) added += 1; } setCandidates((current) => current.filter((candidate) => !selectedCandidates.includes(candidate.root_path))); setSelectedCandidates([]); setBusy(false); if (added > 0) refresh(); }
  return <>
    <PageHeading title={t("projects.title")} description={t("projects.description")} />
    <section className="panel form-panel"><h2>{t("projects.addTitle")}</h2><p>{t("projects.addDescription")}</p>
      <form onSubmit={(event) => void submit(event)}><div className="inline-form"><label className="field grow"><span>{t("projects.rootPath")}</span><input value={path} onChange={(event) => setPath(event.target.value)} autoComplete="off" required aria-describedby="path-help" /></label><button className="button primary" type="submit">{t("actions.addProject")}</button></div><p id="path-help" className="field-hint">{t("projects.rootPathHint")}</p><label className="check-field"><input type="checkbox" checked={scanAfterAdd} onChange={(event) => setScanAfterAdd(event.target.checked)} />{t("projects.scanAfterAdd")}</label></form>
    </section>
    <section className="panel form-panel"><h2>{t("projects.discoveryTitle")}</h2><p>{t("projects.discoveryBody")}</p><form className="inline-form" onSubmit={(event) => void discover(event)}><label className="field grow"><span>{t("projects.rootPath")}</span><input value={parentPath} onChange={(event) => setParentPath(event.target.value)} required /></label><button className="button secondary" disabled={busy}>{t("actions.discoverProjects")}</button></form>
      {candidates.length > 0 && <><ul className="candidate-list">{candidates.map((candidate) => <li key={candidate.root_path}><label className="check-field"><input type="checkbox" checked={selectedCandidates.includes(candidate.root_path)} onChange={(event) => setSelectedCandidates((current) => event.target.checked ? [...current, candidate.root_path] : current.filter((path) => path !== candidate.root_path))} /><span><strong>{candidate.name}</strong><small>{candidate.root_path} · {candidate.component_count} {t("projects.components")}</small></span></label><StatusTag value={candidate.inventory_complete ? "partial" : "unverified"} t={t} /></li>)}</ul><button className="button primary" disabled={busy || selectedCandidates.length === 0} onClick={() => void addSelectedProjects()}>{t("actions.addSelectedProjects")}</button></>}
    </section>
      {data.projects.length === 0 ? <Empty t={t} /> : <section className="project-list">{data.projects.map((project) => {
        const projectInstances = data.instances.filter((instance) => instance.project_id === project.id);
        const instanceIds = new Set(projectInstances.map((instance) => instance.id));
        const projectFindings = data.findings.filter((finding) => instanceIds.has(finding.component_instance_id)).sort((left, right) => right.priority_score - left.priority_score);
        const componentIds = new Set(projectInstances.map((instance) => instance.component_id));
        const projectComponents = data.components.filter((component) => componentIds.has(component.id));
        const projectRuns = data.runs.filter((run) => run.scope.resource_id === project.id).sort((left, right) => (right.finished_at ?? right.started_at).localeCompare(left.finished_at ?? left.started_at)).slice(0, 3);
        return <article className="panel project-card" key={project.id}>
          <div className="project-card-head"><div><h2>{project.name}</h2><p className="mono path">{project.root_path}</p></div><StatusTag value={scanState[project.id] ?? (project.last_scan_at ? "partial" : "unverified")} t={t} /></div>
          <div className="project-meta"><span>{t("projects.lastScan")}: {date(project.last_scan_at, data.settings.language)}</span><span>{project.reference_branch ? `${t("projects.referenceBranch")}: ${project.reference_branch}` : t("common.unverified")}</span></div>
          <section className="project-subsection"><h3>{t("navigation.findings")}</h3>{projectFindings.length === 0 ? <p>{t("common.unverified")}</p> : <><p className="risk-summary">{(["critical", "high", "medium", "low"] as const).map((severity) => `${projectFindings.filter((finding) => finding.severity === severity).length} ${t(`severity.${severity}`)}`).join(" · ")}</p><ul>{projectFindings.slice(0, 3).map((finding) => <li key={finding.id}><button className="text-button" onClick={() => { setPage("findings"); setFocusFindingId(finding.id); setContext(project.name); }}>{data.advisories.find((item) => item.canonical_id === finding.advisory_id)?.canonical_id ?? finding.advisory_id}</button><span><StatusTag value={finding.status} t={t} /> <small>{t("findings.priority")}: {finding.priority_score}</small></span></li>)}</ul></>}</section>
          <section className="project-subsection"><h3>{t("projects.inventory")}</h3>{projectComponents.length === 0 ? <p>{project.last_scan_at ? t("common.noResults") : t("common.unverified")}</p> : <ul>{projectComponents.slice(0, 8).map((component) => <li key={component.id}><span>{component.name}@{component.version}</span><small>{t(`ecosystems.${component.ecosystem}`) === `ecosystems.${component.ecosystem}` ? t("common.unverified") : t(`ecosystems.${component.ecosystem}`)}</small></li>)}</ul>}</section>
          <section className="project-subsection"><div className="subsection-title"><h3>{t("drift.title")}</h3><StatusTag value="unverified" t={t} /></div><p>{t("drift.noSnapshotBody")}</p></section>
          <section className="project-subsection"><h3>{t("projects.scanHistory")}</h3>{projectRuns.length === 0 ? <p>{t("common.unverified")}</p> : <ul>{projectRuns.map((run) => <li key={run.id}><StatusTag value={run.outcome} t={t} /><small>{date(run.finished_at ?? run.started_at, data.settings.language)}</small></li>)}</ul>}</section>
          <MemoryNotes scope="project" scopeId={project.id} t={t} setNotice={setNotice} />
          <div className="project-meta"><span>{project.git_remote ? t("projects.remoteConfigured") : t("projects.noRemote")}</span><span>{t("common.updated")}: {date(project.updated_at, data.settings.language)}</span></div>
          <div className="button-row">{activeScanIds[project.id] ? <button className="button quiet" onClick={() => void cancelScan(project.id)}>{t("actions.cancel")}</button> : <><button className="button primary" onClick={() => void startScan(project, "quick")}>{t("actions.scanQuick")}</button><button className="button secondary" onClick={() => void startScan(project, "full")}>{t("actions.scanFull")}</button></>}</div>
        </article>;
      })}</section>}
    <Drift data={data} t={t} />
  </>;
}

function Servers({ data, t, refresh, setNotice }: { data: WorkspaceData; t: T; refresh: () => void; setNotice: NoticeSetter }) {
  const [input, setInput] = useState({ alias: "", hostname: "", username: "", port: 22, environment: "unknown" as "production" | "staging" | "development" | "unknown" });
  const [fingerprint, setFingerprint] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [pairing, setPairing] = useState<{ asset_id: string; fingerprint: string; authorized_keys_line: string } | null>(null);
  const [approvedAsset, setApprovedAsset] = useState<string | null>(null);
  const [hosts, setHosts] = useState<{ alias: string; hostname: string; username: string; port: number; has_proxy_jump: boolean }[]>([]);
  const [summaries, setSummaries] = useState<Record<string, Awaited<ReturnType<typeof api.serverInventory>> | undefined>>({});
  useEffect(() => {
    let active = true;
    void Promise.all(data.assets.map(async (asset) => [asset.id, await api.serverInventory(asset.id)] as const))
      .then((items) => { if (active) setSummaries(Object.fromEntries(items)); })
      .catch(() => { if (active) setSummaries({}); });
    return () => { active = false; };
  }, [data.assets]);
  async function inspect() { try { setFingerprint(await api.inspectHost(input)); setConfirmed(false); } catch (error) { setNotice({ kind: "error", message: safeError(error, t) }); } }
  async function pair(event: FormEvent) { event.preventDefault(); try { const result = await api.pairServer(input, fingerprint, confirmed, t("servers.deviceLabel")); setPairing({ asset_id: result.asset.id, fingerprint: result.fingerprint, authorized_keys_line: result.authorized_keys_line }); refresh(); } catch (error) { setNotice({ kind: "error", message: safeError(error, t) }); } }
  async function collect(assetId: string) { try { const result = await api.collectServer(assetId, true); setNotice({ kind: "success", message: t(result.complete ? "servers.collectionComplete" : "servers.collectionPartial") }); setApprovedAsset(null); refresh(); } catch (error) { setNotice({ kind: "error", message: safeError(error, t) }); } }
  return <>
    <PageHeading title={t("servers.title")} description={t("servers.description")} />
    <section className="panel form-panel"><h2>{t("servers.pairTitle")}</h2><p>{t("servers.pairDescription")}</p>
      <form onSubmit={(event) => void pair(event)}><div className="form-grid"><Field label={t("servers.alias")} value={input.alias} onChange={(value) => setInput({ ...input, alias: value })} required /><Field label={t("servers.hostname")} value={input.hostname} onChange={(value) => setInput({ ...input, hostname: value })} required /><Field label={t("servers.username")} value={input.username} onChange={(value) => setInput({ ...input, username: value })} required /><Field label={t("servers.port")} type="number" value={String(input.port)} onChange={(value) => setInput({ ...input, port: Number(value) })} required /><label className="field"><span>{t("servers.environment")}</span><select value={input.environment} onChange={(event) => setInput({ ...input, environment: event.target.value as typeof input.environment })}>{["production", "staging", "development", "unknown"].map((value) => <option key={value} value={value}>{t(`servers.${value === "unknown" ? "unknownEnvironment" : value}`)}</option>)}</select></label></div>
        <div className="button-row"><button className="button secondary" type="button" onClick={() => void inspect()}>{t("actions.inspectHost")}</button>{fingerprint && <button className="button primary" type="submit" disabled={!confirmed}>{t("actions.createKey")}</button>}</div>
      </form>
      {fingerprint && <div className="fingerprint-box"><strong>{t("servers.fingerprint")}</strong><code>{fingerprint}</code><p>{t("servers.fingerprintWarning")}</p><label className="check-field"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />{t("servers.verifyFingerprint")}</label></div>}
      {pairing && <div className="pairing-result" role="status"><h3>{t("servers.keyCreated")}</h3><p><strong>{t("servers.fingerprint")}</strong> <code>{pairing.fingerprint}</code></p><p>{t("servers.installInstructions")}</p><pre>{pairing.authorized_keys_line}</pre><p>{t("servers.manualInstall")}</p></div>}
    </section>
    <section className="panel form-panel"><div className="panel-heading"><h2>{t("servers.sshConfig")}</h2><button className="button secondary" onClick={async () => { try { setHosts(await api.sshHosts()); } catch { setHosts([]); } }}>{t("actions.retry")}</button></div><p>{t("servers.noHosts")}</p>{hosts.length > 0 && <ul className="simple-list">{hosts.map((host) => <li key={host.alias}><strong>{host.alias}</strong><span>{host.username}@{host.hostname}:{host.port}{host.has_proxy_jump ? " · ProxyJump" : ""}</span><button className="text-button" onClick={() => setInput({ alias: host.alias, hostname: host.hostname, username: host.username, port: host.port, environment: "unknown" })}>{t("actions.pairServer")}</button></li>)}</ul>}</section>
    {data.assets.length === 0 ? <Empty t={t} /> : <><section className="server-list">{data.assets.map((asset) => { const summary = summaries[asset.id]; const status = !summary ? "unverified" : !isFresh(summary.approved_at, data.settings.scan_interval_hours) ? "stale" : summary.complete ? "succeeded" : "partial"; return <article className="panel project-card" key={asset.id}><div className="project-card-head"><div><h2>{asset.hostname_alias}</h2><p className="mono">{asset.host_key_fingerprint ?? t("common.unverified")}</p><p>{t(`servers.${asset.environment === "unknown" ? "unknownEnvironment" : asset.environment}`)}</p></div><StatusTag value={status} t={t} /></div><div className="project-meta"><span>{t("servers.lastSuccess")}: {date(summary?.approved_at ?? asset.last_success_at, data.settings.language)}</span></div>{summary && <div className="inventory-counts"><span>{summary.package_count} {t("servers.packages")}</span><span>{summary.service_count} {t("servers.services")}</span><span>{summary.container_count} {t("servers.containers")}</span></div>}{summary?.kernel_restart_required === true && <p className="unverified-line">{t("servers.kernelRestartNeeded")}: {summary.running_kernel_release} → {summary.installed_kernel_release}</p>}{summary?.kernel_restart_required == null && <p className="unverified-line">{t("servers.kernelStateUnknown")}</p>}{summary && summary.deleted_shared_library_count > 0 && <p className="unverified-line">{summary.deleted_shared_library_count} {t("servers.deletedSharedLibraries")}{summary.services_needing_restart.length > 0 ? ` · ${summary.services_needing_restart.join(", ")} ${t("servers.needsRestart")}` : ` · ${t("servers.processNeedsRestart")}`}</p>}{approvedAsset === asset.id ? <div className="approval-box"><p>{t("servers.transferWarning")}</p><button className="button primary" onClick={() => void collect(asset.id)}>{t("actions.approveAndCollect")}</button><button className="button quiet" onClick={() => setApprovedAsset(null)}>{t("actions.cancel")}</button></div> : <button className="button secondary" onClick={() => setApprovedAsset(asset.id)}>{t("actions.collect")}</button>}</article>; })}</section><section className="server-list">{data.assets.map((asset) => <article className="panel" key={`memory-${asset.id}`}><MemoryNotes scope="server" scopeId={asset.id} t={t} setNotice={setNotice} /></article>)}</section></>}
  </>;
}

function Findings({ data, t, refresh, setNotice, updateFinding, initialFindingId, onFocused }: { data: WorkspaceData; t: T; refresh: () => void; setNotice: NoticeSetter; updateFinding: (finding: Finding) => void; initialFindingId: string | null; onFocused: () => void }) {
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
    {filtered.length === 0 ? <Empty t={t} noResults={data.findings.length > 0} /> : <section className="panel table-panel"><div className="table-wrap"><table><thead><tr><th>{t("findings.advisory")}</th><th>{t("findings.package")}</th><th>{t("common.severity")}</th><th>{t("common.status")}</th><th>{t("common.project")}</th><th>{t("findings.priority")}</th><th>{t("common.updated")}</th></tr></thead><tbody>{filtered.map((finding) => {
      const advisory = advisories.get(finding.advisory_id); const instance = instances.get(finding.component_instance_id); const component = instance ? components.get(instance.component_id) : undefined;
      return <tr key={finding.id}><td><button className="text-button" onClick={() => setSelected(finding)}>{advisory?.canonical_id ?? finding.advisory_id}</button><small className="cell-subtitle">{advisory?.title ?? t("common.unverified")}</small></td><td>{component ? `${component.name}@${component.version}` : t("common.unverified")}</td><td><SeverityLabel severity={finding.severity} t={t} /></td><td><StatusTag value={finding.status} t={t} /></td><td>{instance?.project_id ? projects.get(instance.project_id)?.name ?? t("common.unverified") : t("common.unknown")}</td><td>{finding.priority_score}</td><td>{date(finding.updated_at, data.settings.language)}</td></tr>;
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
    <div className="finding-detail-tags"><SeverityLabel severity={finding.severity} t={t} /><StatusTag value={finding.status} t={t} /><span className="tag">{t("findings.priority")}: {finding.priority_score}</span></div>
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

function StatusDialog({ finding, instance, t, close, onSave }: { finding: Finding; instance: WorkspaceData["instances"][number] | undefined; t: T; close: () => void; onSave: (change: { finding_id: string; status: FindingStatus; reason: FindingDispositionReason; scope: string; scope_id: string; expires_at: string | null }) => Promise<void> }) {
  const [status, setStatus] = useState<FindingStatus>("not_reachable");
  const [reason, setReason] = useState<FindingDispositionReason>("no_affected_code_path");
  const [scope, setScope] = useState("finding");
  const [expires, setExpires] = useState("");
  const allowedReasons = status === "accepted_risk"
    ? ["business_accepted", "compensating_control", "temporary_exception", "fix_planned"] as FindingDispositionReason[]
    : status === "false_positive"
      ? ["duplicate_finding", "incorrect_package", "unaffected_version", "no_affected_code_path", "other_reviewed"] as FindingDispositionReason[]
      : ["no_affected_code_path", "configuration_prevents_reachability", "other_reviewed"] as FindingDispositionReason[];
  const scopes = [
    { value: "finding", id: finding.id },
    ...(instance?.project_id ? [{ value: "project", id: instance.project_id }] : []),
    ...(instance?.asset_id ? [{ value: "asset", id: instance.asset_id }] : []),
    ...(instance?.deployment_id ? [{ value: "deployment", id: instance.deployment_id }] : []),
  ];
  const scopeId = scopes.find((item) => item.value === scope)?.id ?? finding.id;
  return <div className="dialog-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) close(); }}><section className="dialog panel" role="dialog" aria-modal="true" aria-labelledby="status-dialog-title"><div className="panel-heading"><h2 id="status-dialog-title">{t("findings.changeTitle")}</h2><button className="icon-button" aria-label={t("actions.close")} onClick={close}>×</button></div><p>{t("findings.statusHelp")}</p><label className="field"><span>{t("findings.newStatus")}</span><select value={status} onChange={(event) => { const next = event.target.value as FindingStatus; setStatus(next); setReason(next === "accepted_risk" ? "business_accepted" : "no_affected_code_path"); }}>{dispositionStatuses.map((value) => <option key={value} value={value}>{t(`status.${value}`)}</option>)}</select></label><label className="field"><span>{t("findings.dispositionReason")}</span><select value={reason} onChange={(event) => setReason(event.target.value as FindingDispositionReason)}>{allowedReasons.map((value) => <option key={value} value={value}>{t(`reason.${value}`)}</option>)}</select></label><label className="field"><span>{t("findings.scope")}</span><select value={scope} onChange={(event) => setScope(event.target.value)}>{scopes.map((item) => <option value={item.value} key={item.value}>{t(`scope.${item.value}`)}</option>)}</select></label><label className="field"><span>{t("findings.expiry")}</span><input type="date" value={expires} onChange={(event) => setExpires(event.target.value)} required={status === "accepted_risk" || status === "false_positive"} /></label><div className="button-row end"><button className="button quiet" onClick={close}>{t("actions.cancel")}</button><button className="button primary" disabled={((status === "accepted_risk" || status === "false_positive") && !expires)} onClick={() => void onSave({ finding_id: finding.id, status, reason, scope, scope_id: scopeId, expires_at: expires ? new Date(`${expires}T23:59:59Z`).toISOString() : null })}>{t("actions.save")}</button></div></section></div>;
}

function Drift({ data, t }: { data: WorkspaceData; t: T }) {
  return <section className="panel drift-section"><div className="panel-heading"><h2>{t("drift.title")}</h2><StatusTag value="unverified" t={t} /></div><p>{t("drift.noSnapshotBody")}</p><div className="drift-summary"><span>{t("drift.repository")}: {t("common.unverified")}</span><span>{t("drift.deployment")}: {data.assets.length || t("common.unknown")}</span></div></section>;
}

function History({ data, t }: { data: WorkspaceData; t: T }) {
  return <><PageHeading title={t("history.title")} description={t("history.description")} /><section className="panel table-panel"><div className="panel-heading"><h2>{t("history.scanRuns")}</h2></div>{data.runs.length === 0 ? <Empty t={t} /> : <div className="table-wrap"><table><thead><tr><th>{t("common.project")}</th><th>{t("common.status")}</th><th>{t("common.updated")}</th></tr></thead><tbody>{data.runs.map((run) => <tr key={run.id}><td>{run.scanner === "security-monitor" ? t("appName") : t("common.unknown")}</td><td><StatusTag value={run.outcome} t={t} /></td><td>{date(run.finished_at ?? run.started_at, data.settings.language)}</td></tr>)}</tbody></table></div>}</section><section className="panel table-panel"><div className="panel-heading"><h2>{t("history.auditEvents")}</h2></div>{data.audit.length === 0 ? <Empty t={t} /> : <div className="table-wrap"><table><thead><tr><th>{t("common.updated")}</th><th>{t("history.actor")}</th><th>{t("history.action")}</th><th>{t("history.scope")}</th><th>{t("history.outcome")}</th></tr></thead><tbody>{[...data.audit].sort((a, b) => b.timestamp.localeCompare(a.timestamp)).map((event) => <tr key={event.id}><td>{date(event.timestamp, data.settings.language)}</td><td>{event.actor === "user" ? t("common.user") : t("common.unknown")}</td><td>{auditAction(event.action, t)}</td><td>{event.scope.resource_type === "project" ? t("common.project") : event.scope.resource_type === "asset" ? t("common.server") : t("common.unknown")}</td><td>{t(`status.${event.result}`)}</td></tr>)}</tbody></table></div>}</section></>;
}

function Settings({ data, t, saveSettings, setNotice, refresh }: { data: WorkspaceData; t: T; saveSettings: (settings: AppSettings) => Promise<void>; setNotice: NoticeSetter; refresh: () => void }) {
  const settings = data.settings;
  const [scanners, setScanners] = useState<{ engine: string; status: string; version: string | null }[]>([]);
  const [busyEngine, setBusyEngine] = useState<string | null>(null);
  const ecosystemChoices = ["npm", "pypi", "cargo", "golang", "composer", "maven", "rubygems", "nuget"];
  async function updateAdvisories() {
    try {
      const statuses = await api.updateAdvisories();
      setNotice({ kind: statuses.some((status) => status.stale) ? "error" : "success", message: statuses.some((status) => status.stale) ? t("common.stale") : t("settings.saved") });
    } catch (error) {
      setNotice({ kind: "error", message: safeError(error, t) });
    }
  }
  async function detect() {
    try { setScanners(await api.scanners()); }
    catch (error) { setNotice({ kind: "error", message: safeError(error, t) }); }
  }
  async function install(engine: string) {
    setBusyEngine(engine);
    try {
      await api.installScanner(engine, true);
      setNotice({ kind: "success", message: t("settings.installed") });
      await detect();
    } catch (error) { setNotice({ kind: "error", message: safeError(error, t) }); }
    finally { setBusyEngine(null); }
  }
  function toggleEcosystem(ecosystem: string, enabled: boolean) {
    const ecosystems = enabled ? [...new Set([...settings.ecosystems, ecosystem])] : settings.ecosystems.filter((item) => item !== ecosystem);
    void saveSettings({ ...settings, ecosystems });
  }
  return <>
    <PageHeading title={t("settings.title")} description={t("settings.description")} />
    <section className="panel settings-panel"><h2>{t("settings.privacyTitle")}</h2>
      <label className="setting-row"><span><strong>{t("settings.publicDownloads")}</strong><small>{t("settings.publicDownloadsHelp")}</small></span><input type="checkbox" checked={settings.public_downloads_enabled} onChange={(event) => void saveSettings({ ...settings, public_downloads_enabled: event.target.checked })} /></label>
      <div className="ecosystem-settings"><h3>{t("settings.ecosystems")}</h3><div className="ecosystem-grid">{ecosystemChoices.map((ecosystem) => <label className="check-field" key={ecosystem}><input type="checkbox" checked={settings.ecosystems.includes(ecosystem)} onChange={(event) => toggleEcosystem(ecosystem, event.target.checked)} />{t(`ecosystems.${ecosystem}`)}</label>)}</div></div>
      {settings.public_downloads_enabled && <div className="setting-row"><span>{t("onboarding.advisoryBody")}</span><button className="button secondary" onClick={() => void updateAdvisories()}>{t("actions.updateAdvisories")}</button></div>}
      <label className="setting-row"><span><strong>{t("settings.notifications")}</strong></span><input type="checkbox" checked={settings.notifications_enabled} onChange={(event) => void saveSettings({ ...settings, notifications_enabled: event.target.checked })} /></label>
      <label className="setting-row"><span><strong>{t("settings.scanInterval")}</strong></span><span className="inline-control"><input className="number-input" type="number" min={1} max={168} value={settings.scan_interval_hours} onChange={(event) => void saveSettings({ ...settings, scan_interval_hours: Number(event.target.value) })} /><span>{t("settings.hours")}</span></span></label>
    </section>
    <section className="panel settings-panel"><div className="panel-heading"><h2>{t("settings.scanners")}</h2><button className="button secondary" onClick={() => void detect()}>{t("onboarding.scannerCheck")}</button></div>
      {scanners.length === 0 ? <p>{t("common.unverified")}</p> : <ul className="scanner-list">{scanners.map((scanner) => <li key={scanner.engine}><span>{t(`scanner.${scanner.engine.replaceAll("-", "_")}`)}</span><span className={`tag ${scanner.status === "available" ? "verified" : "unverified"}`}>{t(`scanner.${scanner.status}`)}</span>{scanner.version && <small>{scanner.version}</small>}{scanner.status === "missing" && ["osv-scanner", "trivy", "semgrep"].includes(scanner.engine) && <button className="button secondary" disabled={!settings.public_downloads_enabled || busyEngine === scanner.engine} onClick={() => void install(scanner.engine)}>{busyEngine === scanner.engine ? t("common.loading") : t("actions.install")}</button>}</li>)}</ul>}
    </section>
    <section className="panel settings-panel"><h2>{t("settings.appearance")}</h2><label className="field"><span>{t("settings.appearance")}</span><select value={settings.theme} onChange={(event) => void saveSettings({ ...settings, theme: event.target.value as AppSettings["theme"] })}>{["system", "light", "dark"].map((value) => <option value={value} key={value}>{t(`theme.${value}`)}</option>)}</select></label><label className="field"><span>{t("settings.language")}</span><select value={settings.language} onChange={(event) => void saveSettings({ ...settings, language: event.target.value as AppSettings["language"] })}><option value="en">{en.languageName}</option><option value="tr">{tr.languageName}</option></select></label></section>
    <AiSettingsPanel data={data} t={t} setNotice={setNotice} refresh={refresh} />
    <section className="panel settings-panel"><h2>{t("settings.backup")}</h2><p>{t("settings.backupHelp")}</p></section>
  </>;
}

function ContextComposer({ context, projectId, t, setNotice }: { context: string | null; projectId: string | null; t: T; setNotice: NoticeSetter }) {
  return <AiChatComposer context={context} projectId={projectId} t={t} setNotice={setNotice} />;
}
function CommandPalette({ query, setQuery, pages: availablePages, t, close, navigate }: { query: string; setQuery: (value: string) => void; pages: Page[]; t: T; close: () => void; navigate: (page: Page) => void }) {
  const results = availablePages.filter((page) => t(`navigation.${page}`).toLowerCase().includes(query.toLowerCase()));
  return <div className="dialog-backdrop palette-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) close(); }}><section className="command-palette panel" role="dialog" aria-modal="true" aria-labelledby="palette-title"><h2 id="palette-title">{t("actions.commandPalette")}</h2><label className="sr-only" htmlFor="command-search">{t("common.search")}</label><input id="command-search" autoFocus value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("common.search")} />{results.length === 0 ? <p>{t("common.noResults")}</p> : <ul>{results.map((page) => <li key={page}><button onClick={() => navigate(page)}>{t(`navigation.${page}`)}</button></li>)}</ul>}</section></div>;
}

function Onboarding({ data, language, t, notice, setNotice, saveSettings, addProject, startScan, onComplete }: { data: WorkspaceData; language: Language; t: T; notice: Notice; setNotice: NoticeSetter; saveSettings: (settings: AppSettings) => Promise<void>; addProject: (path: string) => Promise<Project | null>; startScan: (project: Project, profile: "quick" | "full") => Promise<void>; onComplete: () => void }) {
  const [step, setStep] = useState(0);
  const [completedSteps, setCompletedSteps] = useState<Record<number, "continued" | "skipped">>({});
  const [path, setPath] = useState("");
  const [scanners, setScanners] = useState<{ engine: string; status: string; version: string | null }[]>([]);
  const [busy, setBusy] = useState(false);
  const [installingEngine, setInstallingEngine] = useState<string | null>(null);
  const [updatingAdvisories, setUpdatingAdvisories] = useState(false);
  const titles = ["privacyTitle", "scannerTitle", "advisoryTitle", "projectTitle", "serverTitle", "aiTitle"];
  async function complete() {
    await saveSettings({ ...data.settings, onboarding_completed: true });
    onComplete();
  }
  async function next(skip = false) {
    if (step === 3 && path.trim() && !skip && data.projects.length === 0) {
      const project = await addProject(path.trim());
      if (!project) return;
      await startScan(project, "quick");
    }
    setCompletedSteps((current) => ({ ...current, [step]: skip || (step === 3 && !path.trim()) ? "skipped" : "continued" }));
    if (step >= titles.length - 1) await complete(); else setStep((current) => current + 1);
  }
  async function checkScanners() { setBusy(true); try { setScanners(await api.scanners()); } catch (error) { setScanners([]); setNotice({ kind: "error", message: safeError(error, t) }); } finally { setBusy(false); } }
  async function allowDownloads(allowed: boolean) { await saveSettings({ ...data.settings, public_downloads_enabled: allowed }); }
  async function installScanner(engine: string) { setInstallingEngine(engine); try { await api.installScanner(engine, true); setNotice({ kind: "success", message: t("settings.installed") }); await checkScanners(); } catch (error) { setNotice({ kind: "error", message: safeError(error, t) }); } finally { setInstallingEngine(null); } }
  async function updateAdvisories() { setUpdatingAdvisories(true); try { const statuses = await api.updateAdvisories(); setNotice({ kind: statuses.some((status) => status.stale) ? "error" : "success", message: statuses.some((status) => status.stale) ? t("common.stale") : t("settings.saved") }); } catch (error) { setNotice({ kind: "error", message: safeError(error, t) }); } finally { setUpdatingAdvisories(false); } }
  function toggleEcosystem(ecosystem: string, enabled: boolean) { const ecosystems = enabled ? [...new Set([...data.settings.ecosystems, ecosystem])] : data.settings.ecosystems.filter((item) => item !== ecosystem); void saveSettings({ ...data.settings, ecosystems }); }
  return <main className="onboarding-shell"><header className="onboarding-header"><a className="brand" href="#setup"><span className="brand-mark" aria-hidden="true">S</span>{t("appName")}</a><button className="button quiet" aria-label={t("languageToggleLabel")} onClick={() => void saveSettings({ ...data.settings, language: language === "en" ? "tr" : "en" })}>{language === "en" ? "TR" : "EN"}</button></header><section className="onboarding-card panel" aria-labelledby="onboarding-title"><div className="welcome-flow" aria-live="polite">{titles.slice(0, step).map((title, index) => { const bodyKey = title === "privacyTitle" ? "privacyBody" : title === "scannerTitle" ? "scannerBody" : title === "advisoryTitle" ? "advisoryBody" : title === "projectTitle" ? "projectBody" : title === "serverTitle" ? "serverBody" : "aiBody"; return <article className="flow-turn past" key={title}><span className="eyebrow">{t("onboarding.assistant")}</span><p>{t(`onboarding.${title}`)}</p><small>{t(`onboarding.${completedSteps[index] ?? "skipped"}`)}</small><p className="flow-body">{t(`onboarding.${bodyKey}`)}</p></article>; })}<article className="flow-turn current"><span className="eyebrow">{t("onboarding.assistant")}</span><h1 id="onboarding-title">{t(`onboarding.${titles[step]}`)}</h1><p className="onboarding-description">{t(`onboarding.${titles[step] === "privacyTitle" ? "privacyBody" : titles[step] === "scannerTitle" ? "scannerBody" : titles[step] === "advisoryTitle" ? "advisoryBody" : titles[step] === "projectTitle" ? "projectBody" : titles[step] === "serverTitle" ? "serverBody" : "aiBody"}`)}</p>
    {step === 0 && <><div className="form-grid"><label className="field"><span>{t("settings.language")}</span><select value={data.settings.language} onChange={(event) => void saveSettings({ ...data.settings, language: event.target.value as AppSettings["language"] })}><option value="en">{en.languageName}</option><option value="tr">{tr.languageName}</option></select></label><label className="field"><span>{t("settings.appearance")}</span><select value={data.settings.theme} onChange={(event) => void saveSettings({ ...data.settings, theme: event.target.value as AppSettings["theme"] })}>{["system", "light", "dark"].map((value) => <option value={value} key={value}>{t(`theme.${value}`)}</option>)}</select></label><label className="check-field full"><input type="checkbox" checked={data.settings.public_downloads_enabled} onChange={(event) => void allowDownloads(event.target.checked)} />{t("settings.publicDownloads")}</label></div><details className="privacy-details"><summary>{t("onboarding.privacyDetails")}</summary><p>{t("onboarding.privacyDetailsBody")}</p></details></>}
    {step === 1 && <div><button className="button secondary" onClick={() => void checkScanners()} disabled={busy}>{busy ? t("common.loading") : t("onboarding.scannerCheck")}</button>{scanners.length > 0 && <ul className="scanner-list">{scanners.map((scanner) => <li key={scanner.engine}><span>{t(`scanner.${scanner.engine.replaceAll("-", "_")}`)}</span><span className={`tag ${scanner.status === "available" ? "verified" : "unverified"}`}>{t(`scanner.${scanner.status}`)}</span>{scanner.version && <small>{scanner.version}</small>}{scanner.status === "missing" && ["osv-scanner", "trivy", "semgrep"].includes(scanner.engine) && <button className="button secondary" disabled={!data.settings.public_downloads_enabled || installingEngine === scanner.engine} onClick={() => void installScanner(scanner.engine)}>{installingEngine === scanner.engine ? t("common.loading") : t("actions.install")}</button>}</li>)}</ul>}</div>}
    {step === 2 && <div><label className="check-field"><input type="checkbox" checked={data.settings.public_downloads_enabled} onChange={(event) => void allowDownloads(event.target.checked)} />{t("settings.publicDownloads")}</label><div className="ecosystem-grid">{["npm", "pypi", "cargo", "golang", "composer", "maven", "rubygems", "nuget"].map((ecosystem) => <label className="check-field" key={ecosystem}><input type="checkbox" checked={data.settings.ecosystems.includes(ecosystem)} onChange={(event) => toggleEcosystem(ecosystem, event.target.checked)} />{t(`ecosystems.${ecosystem}`)}</label>)}</div>{data.settings.public_downloads_enabled && <button className="button secondary advisory-download" disabled={updatingAdvisories} onClick={() => void updateAdvisories()}>{updatingAdvisories ? t("common.loading") : t("actions.updateAdvisories")}</button>}</div>}
    {step === 3 && <label className="field"><span>{t("projects.rootPath")}</span><input value={path} onChange={(event) => setPath(event.target.value)} />{data.projects.length > 0 && <small>{t("projects.addSuccess")}</small>}</label>}
    {step === 4 && <div className="callout"><p>{t("servers.pairDescription")}</p><span className="tag unverified">{t("common.optional")}</span></div>}
    {step === 5 && <div className="callout"><p>{t("ai.notReadyBody")}</p><span className="tag unverified">{t("common.optional")}</span></div>}
    {notice?.kind === "error" && <p role="alert" className="form-error">{notice.message}</p>}
    <div className="onboarding-actions"><button className="button quiet" onClick={() => void next(true)}>{t("actions.skip")}</button><button className="button primary" onClick={() => void next(false)}>{step === titles.length - 1 ? t("actions.finish") : t("actions.continue")}</button></div></article></div>
    </section><p className="onboarding-footnote">{t("common.localOnly")}</p></main>;
}

function Field({ label, value, onChange, type = "text", required = false }: { label: string; value: string; onChange: (value: string) => void; type?: string; required?: boolean }) {
  return <label className="field"><span>{label}</span><input type={type} value={value} onChange={(event) => onChange(event.target.value)} required={required} /></label>;
}

function Empty({ t, noResults = false }: { t: T; noResults?: boolean }) {
  return <div className="empty-state"><span className="state-icon" aria-hidden="true">{noResults ? "⌕" : "◌"}</span><h2>{t(noResults ? "common.noResults" : "common.empty")}</h2><p>{t(noResults ? "common.noResultsDescription" : "common.emptyDescription")}</p></div>;
}

function StatusTag({ value, t }: { value: string; t: T }) {
  const key = value in (en.status as Record<string, string>) ? `status.${value}` : value === "unverified" ? "common.unverified" : value === "stale" ? "common.stale" : "common.partial";
  const tone = ["succeeded", "fixed_in_production"].includes(value) ? "verified" : ["partial", "needs_review", "running", "stale", "unverified"].includes(value) ? "needs-review" : ["failed", "cancelled"].includes(value) ? "error" : "neutral";
  return <span className={`tag ${tone}`}><span className="tag-mark" aria-hidden="true">{tone === "verified" ? "✓" : tone === "error" ? "!" : "•"}</span>{t(key)}</span>;
}

function SeverityLabel({ severity, t }: { severity: string; t: T }) {
  return <span className="severity-label"><span className={`severity-dot ${severity}`} />{t(`severity.${severity}`)}</span>;
}
