import { useCallback, useEffect, useRef, useState } from "react";
import type { AppSettings } from "./generated/AppSettings";
import type { Finding } from "./generated/Finding";
import type { Project } from "./generated/Project";
import {
  api,
  loadWorkspace,
  workspaceSections,
  type WorkspaceData,
  type WorkspaceSection,
} from "./api";
import { CommandPalette, ContextComposer } from "./components";
import { Findings } from "./pages/Findings";
import { History } from "./pages/History";
import { Onboarding } from "./pages/Onboarding";
import { Projects } from "./pages/Projects";
import { Review } from "./pages/Review";
import { Servers } from "./pages/Servers";
import { Settings } from "./pages/Settings";
import {
  WorkspaceContext,
  pages,
  type Language,
  type Notice,
  type Page,
  type WorkspaceContextValue,
} from "./WorkspaceContext";
import { initialLanguage, readCopy, safeError } from "./utils";
import { pollScanUntilDone } from "./scanPolling";
import "./app.css";

export function App() {
  const [data, setData] = useState<WorkspaceData | null>(null);
  const workspaceRef = useRef<WorkspaceData | null>(null);
  const pendingSections = useRef(new Set<WorkspaceSection>());
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
      const previous = workspaceRef.current;
      const sections = pendingSections.current.size
        ? [...pendingSections.current]
        : workspaceSections;
      pendingSections.current.clear();
      const workspace = await loadWorkspace(previous, sections);
      workspaceRef.current = workspace;
      setData(workspace);
      setLanguage(workspace.settings.language);
    } catch (error) {
      setNotice({ message: safeError(error, t), kind: "error" });
    } finally {
      setLoading(false);
    }
  }, [t]);

  const requestRefresh = useCallback(
    (sections: readonly WorkspaceSection[] = workspaceSections) => {
      sections.forEach((section) => pendingSections.current.add(section));
      setRefreshToken((current) => current + 1);
    },
    [],
  );

  const updateWorkspace = useCallback(
    (update: (current: WorkspaceData | null) => WorkspaceData | null) => {
      const next = update(workspaceRef.current);
      workspaceRef.current = next;
      setData(next);
    },
    [],
  );

  useEffect(() => {
    void refresh();
  }, [refresh, refreshToken]);

  useEffect(() => {
    if (!data?.settings.public_downloads_enabled) return;
    let active = true;
    const refreshNews = async () => {
      try {
        await api.refreshNewsSignals();
        if (active) requestRefresh(["newsSignals"]);
      } catch {
        // Existing local signals remain visible; a failed poll never implies a clean state.
      }
    };
    void refreshNews();
    const timer = window.setInterval(() => void refreshNews(), 30 * 60 * 1000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [data?.settings.public_downloads_enabled, requestRefresh]);

  useEffect(() => {
    document.documentElement.lang = language;
  }, [language]);

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
      updateWorkspace((current) => (current ? { ...current, settings } : current));
      setLanguage(settings.language);
      setNotice({ message: t("settings.saved"), kind: "success" });
    } catch (error) {
      setNotice({ message: safeError(error, t), kind: "error" });
    }
  }

  async function addProject(path: string): Promise<Project | null> {
    try {
      const project = await api.addProject(path);
      updateWorkspace((current) =>
        current ? { ...current, projects: [...current.projects, project] } : current,
      );
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
      const outcome = await pollScanUntilDone(() => api.scanResult(scanId), {
        timeoutMs: 10 * 60 * 1000,
        intervalMs: 700,
        isCancelled: () => cancelledScans.current.has(scanId),
      });
      if (outcome.kind === "cancelled") return;
      if (outcome.kind === "timedOut") {
        cancelledScans.current.add(scanId);
        await api.cancelScan(scanId).catch(() => false);
        setScanState((current) => ({ ...current, [project.id]: "failed" }));
        setActiveScanIds((current) => {
          const next = { ...current };
          delete next[project.id];
          return next;
        });
        setNotice({ message: t("projects.scanTimedOut"), kind: "error" });
        requestRefresh([
          "projects",
          "findings",
          "advisories",
          "components",
          "instances",
          "evidence",
          "runs",
          "audit",
        ]);
        return;
      }

      {
        const result = outcome.result;
        setScanState((current) => ({ ...current, [project.id]: result.outcome }));
        setActiveScanIds((current) => {
          const next = { ...current };
          delete next[project.id];
          return next;
        });
        requestRefresh([
          "projects",
          "findings",
          "advisories",
          "components",
          "instances",
          "evidence",
          "runs",
          "audit",
        ]);
        setNotice({
          message: t(
            result.outcome === "succeeded" && result.inventory_complete
              ? "projects.scanComplete"
              : "projects.scanPartial",
          ),
          kind: result.outcome === "failed" ? "error" : "success",
        });
      }
    } catch (error) {
      setScanState((current) => ({ ...current, [project.id]: "failed" }));
      setActiveScanIds((current) => {
        const next = { ...current };
        delete next[project.id];
        return next;
      });
      setNotice({ message: safeError(error, t), kind: "error" });
    }
  }

  async function cancelProjectScan(projectId: string) {
    const scanId = activeScanIds[projectId];
    if (!scanId) return;
    try {
      if (await api.cancelScan(scanId)) {
        cancelledScans.current.add(scanId);
        setActiveScanIds((current) => {
          const next = { ...current };
          delete next[projectId];
          return next;
        });
        setScanState((current) => ({ ...current, [projectId]: "cancelled" }));
        setNotice({ kind: "success", message: t("projects.scanCancelled") });
      }
    } catch (error) {
      setNotice({ kind: "error", message: safeError(error, t) });
    }
  }

  const updateFinding = useCallback(
    (finding: Finding) => {
      updateWorkspace((current) =>
        current
          ? {
              ...current,
              findings: current.findings.map((item) => (item.id === finding.id ? finding : item)),
            }
          : current,
      );
    },
    [updateWorkspace],
  );

  if (loading && !data) {
    return (
      <main className="center-state" aria-live="polite">
        <span className="spinner" aria-hidden="true" />
        <h1>{t("common.loading")}</h1>
        <p>{t("common.loadingDescription")}</p>
      </main>
    );
  }

  if (!data) {
    return (
      <main className="center-state">
        <h1>{t("common.error")}</h1>
        <p>{notice?.message ?? t("common.errorDescription")}</p>
        <button className="button primary" onClick={() => requestRefresh()}>
          {t("actions.retry")}
        </button>
      </main>
    );
  }

  const reviewCount = data.findings.filter((finding) =>
    ["new", "needs_review", "confirmed_affected", "fix_proposed"].includes(finding.status),
  ).length;

  const workspace: WorkspaceContextValue = {
    data,
    language,
    t,
    notice,
    setNotice,
    refresh: requestRefresh,
    saveSettings,
    addProject,
    startScan,
    cancelProjectScan,
    scanState,
    activeScanIds,
    page,
    setPage,
    context,
    setContext,
    focusFindingId,
    setFocusFindingId,
    updateFinding,
    onCompleteOnboarding: requestRefresh,
  };

  return (
    <WorkspaceContext.Provider value={workspace}>
      {!data.settings.onboarding_completed ? (
        <Onboarding />
      ) : (
        <div className="app-frame">
          <a className="skip-link" href="#main-content">
            {t("skipToContent")}
          </a>
          <aside className="sidebar">
            <a
              className="brand"
              href="#review"
              onClick={(event) => {
                event.preventDefault();
                setPage("review");
                setContext(null);
              }}
            >
              <span className="brand-mark" aria-hidden="true" />
              <span>{t("appName")}</span>
            </a>
            <button className="nav-item command-search" onClick={() => setPaletteOpen(true)}>
              <span className="nav-icon" aria-hidden="true">
                ⌕
              </span>
              {t("actions.commandPalette")}
              <kbd>{shortcutLabel}</kbd>
            </button>
            <nav aria-label={t("navigationLabel")}>
              {pages
                .filter((item) => item !== "projects" && item !== "servers" && item !== "settings")
                .map((item) => (
                  <button
                    key={item}
                    className={"nav-item " + (page === item ? "selected" : "")}
                    aria-current={page === item ? "page" : undefined}
                    onClick={() => {
                      setPage(item);
                      setContext(null);
                    }}
                  >
                    <span className="nav-icon" aria-hidden="true">
                      {item === "review"
                        ? "◉"
                        : item === "findings"
                          ? "⚠"
                          : item === "history"
                            ? "◷"
                            : "⌕"}
                    </span>
                    {t("navigation." + item)}
                    {item === "review" && reviewCount > 0 && (
                      <span className="nav-count">{reviewCount}</span>
                    )}
                  </button>
                ))}
              <div className="sidebar-section">
                <div className="sidebar-section-header">
                  <span className="sidebar-section-label">{t("common.projects")}</span>
                  <button
                    className="sidebar-add"
                    aria-label={t("actions.addProject")}
                    onClick={() => {
                      setPage("projects");
                      setContext(null);
                    }}
                  >
                    +
                  </button>
                </div>
                <button
                  className="nav-item compact"
                  aria-current={page === "projects" ? "page" : undefined}
                  onClick={() => {
                    setPage("projects");
                    setContext(null);
                  }}
                >
                  {t("navigation.projects")}
                </button>
                {data.projects.map((project) => (
                  <button
                    className="context-item"
                    key={project.id}
                    onClick={() => {
                      setPage("projects");
                      setContext(project.name);
                    }}
                  >
                    <span
                      className={"state-dot " + (project.last_scan_at ? "attention" : "unknown")}
                      aria-hidden="true"
                    />
                    <span className="context-name">{project.name}</span>
                  </button>
                ))}
              </div>
              <div className="sidebar-section">
                <div className="sidebar-section-header">
                  <span className="sidebar-section-label">{t("common.servers")}</span>
                  <button
                    className="sidebar-add"
                    aria-label={t("actions.pairServer")}
                    onClick={() => {
                      setPage("servers");
                      setContext(null);
                    }}
                  >
                    +
                  </button>
                </div>
                <button
                  className="nav-item compact"
                  aria-current={page === "servers" ? "page" : undefined}
                  onClick={() => {
                    setPage("servers");
                    setContext(null);
                  }}
                >
                  {t("navigation.servers")}
                </button>
                {data.assets.map((asset) => (
                  <button
                    className="context-item"
                    key={asset.id}
                    onClick={() => {
                      setPage("servers");
                      setContext(asset.hostname_alias);
                    }}
                  >
                    <span
                      className={"state-dot " + (asset.last_success_at ? "attention" : "unknown")}
                      aria-hidden="true"
                    />
                    <span className="context-name">{asset.hostname_alias}</span>
                  </button>
                ))}
              </div>
              <button
                className={"nav-item " + (page === "settings" ? "selected" : "")}
                aria-current={page === "settings" ? "page" : undefined}
                onClick={() => {
                  setPage("settings");
                  setContext(null);
                }}
              >
                <span className="nav-icon" aria-hidden="true">
                  ⚙
                </span>
                {t("navigation.settings")}
              </button>
            </nav>
            <div className="sidebar-footer">
              <span className="privacy-dot" aria-hidden="true" />
              {t("common.localOnly")}
            </div>
          </aside>
          <div className="content-column">
            <header className="topbar">
              <div>
                <span className="eyebrow">{t("appName")}</span>
                <p className="topbar-subtitle">{t("navigation." + page)}</p>
              </div>
              <button
                className="button quiet"
                type="button"
                aria-label={t("languageToggleLabel")}
                onClick={() =>
                  void saveSettings({
                    ...data.settings,
                    language: language === "en" ? "tr" : "en",
                  })
                }
              >
                {language === "en" ? "TR" : "EN"}
              </button>
            </header>
            {notice && (
              <div
                className={"notice " + notice.kind}
                role={notice.kind === "error" ? "alert" : "status"}
              >
                {notice.message}
                <button
                  type="button"
                  aria-label={t("actions.close")}
                  onClick={() => setNotice(null)}
                >
                  ×
                </button>
              </div>
            )}
            <main id="main-content" className="main-content" tabIndex={-1}>
              {page === "review" && <Review />}
              {page === "projects" && <Projects />}
              {page === "servers" && <Servers />}
              {page === "findings" && <Findings />}
              {page === "history" && <History />}
              {page === "settings" && <Settings />}
            </main>
            <ContextComposer
              context={context}
              projectId={data.projects.find((project) => project.name === context)?.id ?? null}
              t={t}
              setNotice={setNotice}
            />
          </div>
          {paletteOpen && (
            <CommandPalette
              query={paletteQuery}
              setQuery={setPaletteQuery}
              pages={pages}
              t={t}
              close={() => {
                setPaletteOpen(false);
                setPaletteQuery("");
              }}
              navigate={(next) => {
                setPage(next);
                setContext(null);
                setPaletteOpen(false);
                setPaletteQuery("");
              }}
            />
          )}
        </div>
      )}
    </WorkspaceContext.Provider>
  );
}
