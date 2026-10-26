import { useState, type FormEvent } from "react";
import { api } from "../api";
import { Drift, DriftSummary, Empty, PageHeading, ScanDiagnostics, StatusTag } from "../components";
import { MemoryNotes } from "../MemoryNotes";
import { useWorkspace } from "../WorkspaceContext";
import { date, safeError } from "../utils";
export function Projects() {
  const {
    data,
    t,
    addProject,
    startScan,
    cancelProjectScan: cancelScan,
    scanState,
    activeScanIds,
    refresh,
    setPage,
    setContext,
    setFocusFindingId,
    setNotice,
  } = useWorkspace();
  const [path, setPath] = useState("");
  const [scanAfterAdd, setScanAfterAdd] = useState(true);
  const [parentPath, setParentPath] = useState("");
  const [candidates, setCandidates] = useState<
    { name: string; root_path: string; component_count: number; inventory_complete: boolean }[]
  >([]);
  const [selectedCandidates, setSelectedCandidates] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!path.trim()) return;
    const project = await addProject(path.trim());
    if (project) {
      setPath("");
      if (scanAfterAdd) await startScan(project, "quick");
    }
  }
  async function discover(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      const found = await api.discoverProjects(parentPath);
      setCandidates(found.candidates);
      setSelectedCandidates([]);
    } catch (error) {
      setCandidates([]);
      setSelectedCandidates([]);
      setNotice({ kind: "error", message: safeError(error, t) });
    } finally {
      setBusy(false);
    }
  }
  async function addSelectedProjects() {
    setBusy(true);
    let added = 0;
    for (const candidatePath of selectedCandidates) {
      if (await addProject(candidatePath)) added += 1;
    }
    setCandidates((current) =>
      current.filter((candidate) => !selectedCandidates.includes(candidate.root_path)),
    );
    setSelectedCandidates([]);
    setBusy(false);
    if (added > 0) refresh(["projects"]);
  }
  return (
    <>
      <PageHeading title={t("projects.title")} description={t("projects.description")} />
      <section className="panel form-panel">
        <h2>{t("projects.addTitle")}</h2>
        <p>{t("projects.addDescription")}</p>
        <form onSubmit={(event) => void submit(event)}>
          <div className="inline-form">
            <label className="field grow">
              <span>{t("projects.rootPath")}</span>
              <input
                value={path}
                onChange={(event) => setPath(event.target.value)}
                autoComplete="off"
                required
                aria-describedby="path-help"
              />
            </label>
            <button className="button primary" type="submit">
              {t("actions.addProject")}
            </button>
          </div>
          <p id="path-help" className="field-hint">
            {t("projects.rootPathHint")}
          </p>
          <label className="check-field">
            <input
              type="checkbox"
              checked={scanAfterAdd}
              onChange={(event) => setScanAfterAdd(event.target.checked)}
            />
            {t("projects.scanAfterAdd")}
          </label>
        </form>
      </section>
      <section className="panel form-panel">
        <h2>{t("projects.discoveryTitle")}</h2>
        <p>{t("projects.discoveryBody")}</p>
        <form className="inline-form" onSubmit={(event) => void discover(event)}>
          <label className="field grow">
            <span>{t("projects.rootPath")}</span>
            <input
              value={parentPath}
              onChange={(event) => setParentPath(event.target.value)}
              required
            />
          </label>
          <button className="button secondary" disabled={busy}>
            {t("actions.discoverProjects")}
          </button>
        </form>
        {candidates.length > 0 && (
          <>
            <ul className="candidate-list">
              {candidates.map((candidate) => (
                <li key={candidate.root_path}>
                  <label className="check-field">
                    <input
                      type="checkbox"
                      checked={selectedCandidates.includes(candidate.root_path)}
                      onChange={(event) =>
                        setSelectedCandidates((current) =>
                          event.target.checked
                            ? [...current, candidate.root_path]
                            : current.filter((path) => path !== candidate.root_path),
                        )
                      }
                    />
                    <span>
                      <strong>{candidate.name}</strong>
                      <small>
                        {candidate.root_path} · {candidate.component_count}{" "}
                        {t("projects.components")}
                      </small>
                    </span>
                  </label>
                  <StatusTag
                    value={candidate.inventory_complete ? "partial" : "unverified"}
                    t={t}
                  />
                </li>
              ))}
            </ul>
            <button
              className="button primary"
              disabled={busy || selectedCandidates.length === 0}
              onClick={() => void addSelectedProjects()}
            >
              {t("actions.addSelectedProjects")}
            </button>
          </>
        )}
      </section>
      {data.projects.length === 0 ? (
        <Empty t={t} />
      ) : (
        <section className="project-list">
          {data.projects.map((project) => {
            const projectInstances = data.instances.filter(
              (instance) => instance.project_id === project.id,
            );
            const instanceIds = new Set(projectInstances.map((instance) => instance.id));
            const projectFindings = data.findings
              .filter((finding) => instanceIds.has(finding.component_instance_id))
              .sort((left, right) => right.priority_score - left.priority_score);
            const componentIds = new Set(projectInstances.map((instance) => instance.component_id));
            const projectComponents = data.components.filter((component) =>
              componentIds.has(component.id),
            );
            const projectRuns = data.runs
              .filter((run) => run.scope.resource_id === project.id)
              .sort((left, right) =>
                (right.finished_at ?? right.started_at).localeCompare(
                  left.finished_at ?? left.started_at,
                ),
              )
              .slice(0, 3);
            return (
              <article className="panel project-card" key={project.id}>
                <div className="project-card-head">
                  <div>
                    <h2>{project.name}</h2>
                    <p className="mono path">{project.root_path}</p>
                  </div>
                  <StatusTag
                    value={
                      scanState[project.id] ?? (project.last_scan_at ? "partial" : "unverified")
                    }
                    t={t}
                  />
                </div>
                <div className="project-meta">
                  <span>
                    {t("projects.lastScan")}: {date(project.last_scan_at, data.settings.language)}
                  </span>
                  <span>
                    {project.reference_branch
                      ? `${t("projects.referenceBranch")}: ${project.reference_branch}`
                      : t("common.unverified")}
                  </span>
                </div>
                <section className="project-subsection">
                  <h3>{t("navigation.findings")}</h3>
                  {projectFindings.length === 0 ? (
                    <p>{t("common.unverified")}</p>
                  ) : (
                    <>
                      <p className="risk-summary">
                        {(["critical", "high", "medium", "low"] as const)
                          .map(
                            (severity) =>
                              `${projectFindings.filter((finding) => finding.severity === severity).length} ${t(`severity.${severity}`)}`,
                          )
                          .join(" · ")}
                      </p>
                      <ul>
                        {projectFindings.slice(0, 3).map((finding) => (
                          <li key={finding.id}>
                            <button
                              className="text-button"
                              onClick={() => {
                                setPage("findings");
                                setFocusFindingId(finding.id);
                                setContext(project.name);
                              }}
                            >
                              {data.advisories.find(
                                (item) => item.canonical_id === finding.advisory_id,
                              )?.canonical_id ?? finding.advisory_id}
                            </button>
                            <span>
                              <StatusTag value={finding.status} t={t} />{" "}
                              <small>
                                {t("findings.priority")}: {finding.priority_score}
                              </small>
                            </span>
                          </li>
                        ))}
                      </ul>
                    </>
                  )}
                </section>
                <section className="project-subsection">
                  <h3>{t("projects.inventory")}</h3>
                  {projectComponents.length === 0 ? (
                    <p>{project.last_scan_at ? t("common.noResults") : t("common.unverified")}</p>
                  ) : (
                    <ul>
                      {projectComponents.slice(0, 8).map((component) => (
                        <li key={component.id}>
                          <span>
                            {component.name}@{component.version ?? t("common.unverified")}
                          </span>
                          <small>
                            {t(`ecosystems.${component.ecosystem}`) ===
                            `ecosystems.${component.ecosystem}`
                              ? t("common.unverified")
                              : t(`ecosystems.${component.ecosystem}`)}
                          </small>
                        </li>
                      ))}
                    </ul>
                  )}
                </section>
                <section className="project-subsection">
                  <DriftSummary
                    findings={projectFindings}
                    linkedServers={
                      data.links.filter((link) => link.project_id === project.id).length
                    }
                    t={t}
                  />
                </section>
                <section className="project-subsection">
                  <h3>{t("projects.scanHistory")}</h3>
                  {projectRuns.length === 0 ? (
                    <p>{t("common.unverified")}</p>
                  ) : (
                    <ul>
                      {projectRuns.map((run) => (
                        <li key={run.id}>
                          <StatusTag value={run.outcome} t={t} />
                          <small>
                            {date(run.finished_at ?? run.started_at, data.settings.language)}
                          </small>
                          <ScanDiagnostics error={run.error} t={t} />
                        </li>
                      ))}
                    </ul>
                  )}
                </section>
                <MemoryNotes scope="project" scopeId={project.id} t={t} setNotice={setNotice} />
                <div className="project-meta">
                  <span>
                    {project.git_remote ? t("projects.remoteConfigured") : t("projects.noRemote")}
                  </span>
                  <span>
                    {t("common.updated")}: {date(project.updated_at, data.settings.language)}
                  </span>
                </div>
                <div className="button-row">
                  {activeScanIds[project.id] ? (
                    <button className="button quiet" onClick={() => void cancelScan(project.id)}>
                      {t("actions.cancel")}
                    </button>
                  ) : (
                    <>
                      <button
                        className="button primary"
                        onClick={() => void startScan(project, "quick")}
                      >
                        {t("actions.scanQuick")}
                      </button>
                      <button
                        className="button secondary"
                        onClick={() => void startScan(project, "full")}
                      >
                        {t("actions.scanFull")}
                      </button>
                    </>
                  )}
                </div>
              </article>
            );
          })}
        </section>
      )}
      <Drift data={data} t={t} />
    </>
  );
}
