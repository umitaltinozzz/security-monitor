import { PageHeading, SeverityLabel, StatusTag } from "../components";
import { useWorkspace } from "../WorkspaceContext";
import { date, isFresh } from "../utils";
export function Review() {
  const { data, t, setPage, setContext, setFocusFindingId } = useWorkspace();
  const staleAssets = data.assets.filter(
    (asset) => !isFresh(asset.last_success_at, data.settings.scan_interval_hours),
  );
  const projectNeedsReview = data.projects.filter((project) => {
    const latest = data.runs
      .filter((run) => run.scope.resource_id === project.id)
      .sort((left, right) =>
        (right.finished_at ?? right.started_at).localeCompare(left.finished_at ?? left.started_at),
      )[0];
    return (
      !isFresh(project.last_scan_at, data.settings.scan_interval_hours) ||
      latest?.outcome !== "succeeded"
    );
  });
  const advisories = new Map(data.advisories.map((advisory) => [advisory.canonical_id, advisory]));
  const actionable = data.findings.filter((finding) =>
    ["new", "needs_review", "confirmed_affected", "fix_proposed"].includes(finding.status),
  );
  const queue = [...actionable]
    .sort((left, right) => right.priority_score - left.priority_score)
    .slice(0, 5);
  const unverifiedNews = data.newsSignals.filter(
    (signal) => !signal.archived_at && !signal.advisory_id && signal.matched_projects.length > 0,
  );
  const latestScan = [...data.runs].sort((left, right) =>
    (right.finished_at ?? right.started_at).localeCompare(left.finished_at ?? left.started_at),
  )[0];
  return (
    <>
      <PageHeading
        title={t("navigation.review")}
        description={t("overview.reviewDescription")}
        actions={
          <span className="local-badge">
            <span className="privacy-dot" />
            {t("common.localOnly")}
          </span>
        }
      />
      <p className="review-summary">
        {actionable.length > 0
          ? `${actionable.length} ${t("overview.actionRequired")}`
          : t("overview.noActionableFindings")}
      </p>
      <section className="review-section" aria-labelledby="review-items-title">
        <div className="panel-heading">
          <h2 id="review-items-title">{t("overview.reviewItems")}</h2>
          <button className="text-button" onClick={() => setPage("findings")}>
            {t("navigation.findings")}
          </button>
        </div>
        {queue.length === 0 &&
        projectNeedsReview.length === 0 &&
        staleAssets.length === 0 &&
        unverifiedNews.length === 0 ? (
          <p className="unverified-line">{t("overview.reviewUnknown")}</p>
        ) : (
          <div className="review-list">
            {queue.map((finding) => {
              const advisory = advisories.get(finding.advisory_id);
              const reason = finding.priority_reasons[0];
              const reasonKey = reason ? `priorityReasons.${reason}` : "";
              const reasonText =
                reasonKey && t(reasonKey) !== reasonKey ? t(reasonKey) : t("common.unverified");
              return (
                <article className="review-item" key={finding.id}>
                  <div className="review-item-copy">
                    <div className="review-item-title">
                      <SeverityLabel severity={finding.severity} t={t} />
                      <strong>{advisory?.canonical_id ?? finding.advisory_id}</strong>
                      <StatusTag value={finding.status} t={t} />
                    </div>
                    <p>{advisory?.title ?? t("common.unverified")}</p>
                    <small>{reasonText}</small>
                  </div>
                  <div className="review-item-actions">
                    <button
                      className="button secondary"
                      onClick={() => {
                        setPage("findings");
                        setFocusFindingId(finding.id);
                      }}
                    >
                      {t("actions.review")}
                    </button>
                    <button
                      className="button quiet"
                      onClick={() => setContext(advisory?.canonical_id ?? finding.id)}
                    >
                      {t("actions.ask")}
                    </button>
                  </div>
                </article>
              );
            })}
            {projectNeedsReview.map((project) => {
              const latest = data.runs
                .filter((run) => run.scope.resource_id === project.id)
                .sort((left, right) =>
                  (right.finished_at ?? right.started_at).localeCompare(
                    left.finished_at ?? left.started_at,
                  ),
                )[0];
              const projectStatus = !project.last_scan_at
                ? "unverified"
                : !isFresh(project.last_scan_at, data.settings.scan_interval_hours)
                  ? "stale"
                  : "partial";
              return (
                <article className="review-item" key={`project-${project.id}`}>
                  <div className="review-item-copy">
                    <div className="review-item-title">
                      <StatusTag value={projectStatus} t={t} />
                      <strong>{project.name}</strong>
                    </div>
                    <p>{t("overview.projectInventoryNeedsReview")}</p>
                    <small>
                      {t("common.lastChecked")}:{" "}
                      {date(latest?.finished_at ?? project.last_scan_at, data.settings.language)}
                    </small>
                  </div>
                  <button
                    className="button secondary"
                    onClick={() => {
                      setPage("projects");
                      setContext(project.name);
                    }}
                  >
                    {t("actions.review")}
                  </button>
                </article>
              );
            })}
            {staleAssets.map((asset) => (
              <article className="review-item" key={`asset-${asset.id}`}>
                <div className="review-item-copy">
                  <div className="review-item-title">
                    <span className="tag unverified">
                      {asset.last_success_at ? t("common.stale") : t("common.unverified")}
                    </span>
                    <strong>{asset.hostname_alias}</strong>
                  </div>
                  <p>{t("overview.serverInventoryNeedsReview")}</p>
                  <small>
                    {t("common.lastChecked")}: {date(asset.last_success_at, data.settings.language)}
                  </small>
                </div>
                <button
                  className="button secondary"
                  onClick={() => {
                    setPage("servers");
                    setContext(asset.hostname_alias);
                  }}
                >
                  {t("actions.review")}
                </button>
              </article>
            ))}
            {unverifiedNews.map((signal) => (
              <article className="review-item" key={signal.id}>
                <div className="review-item-copy">
                  <div className="review-item-title">
                    <span className="tag unverified">{t("news.unverifiedLabel")}</span>
                    <strong>{signal.title}</strong>
                  </div>
                  <p>{signal.summary ?? t("news.statusDescription")}</p>
                  <small>
                    {t("news.matchedProducts")}: {signal.matched_products.join(", ")} ·{" "}
                    {date(signal.published_at, data.settings.language)}
                  </small>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
      <p className="review-meta">
        <span>
          {t("overview.latestScan")}:{" "}
          {date(latestScan?.finished_at ?? latestScan?.started_at, data.settings.language)}
        </span>
        <span>
          {t("overview.advisoryFreshness")}:{" "}
          {data.settings.public_downloads_enabled ? t("common.partial") : t("common.unverified")}
        </span>
        <button className="text-button" onClick={() => setPage("history")}>
          {t("navigation.history")}
        </button>
      </p>
    </>
  );
}
