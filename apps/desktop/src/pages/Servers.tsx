import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api";
import { Empty, Field, PageHeading, ServerProjectLinks, StatusTag } from "../components";
import { MemoryNotes } from "../MemoryNotes";
import { useWorkspace } from "../WorkspaceContext";
import { date, isFresh, safeError } from "../utils";
export function Servers() {
  const { data, t, refresh, setNotice } = useWorkspace();
  const [input, setInput] = useState({
    alias: "",
    hostname: "",
    username: "",
    port: 22,
    environment: "unknown" as "production" | "staging" | "development" | "unknown",
  });
  const [fingerprint, setFingerprint] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [pairing, setPairing] = useState<{
    asset_id: string;
    fingerprint: string;
    authorized_keys_line: string;
  } | null>(null);
  const [approvedAsset, setApprovedAsset] = useState<string | null>(null);
  const [hosts, setHosts] = useState<
    { alias: string; hostname: string; username: string; port: number; has_proxy_jump: boolean }[]
  >([]);
  const [summaries, setSummaries] = useState<
    Record<string, Awaited<ReturnType<typeof api.serverInventory>> | undefined>
  >({});
  useEffect(() => {
    let active = true;
    void Promise.all(
      data.assets.map(async (asset) => [asset.id, await api.serverInventory(asset.id)] as const),
    )
      .then((items) => {
        if (active) setSummaries(Object.fromEntries(items));
      })
      .catch(() => {
        if (active) setSummaries({});
      });
    return () => {
      active = false;
    };
  }, [data.assets]);
  async function inspect() {
    try {
      setFingerprint(await api.inspectHost(input));
      setConfirmed(false);
    } catch (error) {
      setNotice({ kind: "error", message: safeError(error, t) });
    }
  }
  async function pair(event: FormEvent) {
    event.preventDefault();
    try {
      const result = await api.pairServer(input, fingerprint, confirmed, t("servers.deviceLabel"));
      setPairing({
        asset_id: result.asset.id,
        fingerprint: result.fingerprint,
        authorized_keys_line: result.authorized_keys_line,
      });
      refresh();
    } catch (error) {
      setNotice({ kind: "error", message: safeError(error, t) });
    }
  }
  async function collect(assetId: string) {
    try {
      const result = await api.collectServer(assetId, true);
      setNotice({
        kind: "success",
        message: t(result.complete ? "servers.collectionComplete" : "servers.collectionPartial"),
      });
      setApprovedAsset(null);
      refresh();
    } catch (error) {
      setNotice({ kind: "error", message: safeError(error, t) });
    }
  }
  return (
    <>
      <PageHeading title={t("servers.title")} description={t("servers.description")} />
      <section className="panel form-panel">
        <h2>{t("servers.pairTitle")}</h2>
        <p>{t("servers.pairDescription")}</p>
        <form onSubmit={(event) => void pair(event)}>
          <div className="form-grid">
            <Field
              label={t("servers.alias")}
              value={input.alias}
              onChange={(value) => setInput({ ...input, alias: value })}
              required
            />
            <Field
              label={t("servers.hostname")}
              value={input.hostname}
              onChange={(value) => setInput({ ...input, hostname: value })}
              required
            />
            <Field
              label={t("servers.username")}
              value={input.username}
              onChange={(value) => setInput({ ...input, username: value })}
              required
            />
            <Field
              label={t("servers.port")}
              type="number"
              value={String(input.port)}
              onChange={(value) => setInput({ ...input, port: Number(value) })}
              required
            />
            <label className="field">
              <span>{t("servers.environment")}</span>
              <select
                value={input.environment}
                onChange={(event) =>
                  setInput({
                    ...input,
                    environment: event.target.value as typeof input.environment,
                  })
                }
              >
                {["production", "staging", "development", "unknown"].map((value) => (
                  <option key={value} value={value}>
                    {t(`servers.${value === "unknown" ? "unknownEnvironment" : value}`)}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <div className="button-row">
            <button className="button secondary" type="button" onClick={() => void inspect()}>
              {t("actions.inspectHost")}
            </button>
            {fingerprint && (
              <button className="button primary" type="submit" disabled={!confirmed}>
                {t("actions.createKey")}
              </button>
            )}
          </div>
        </form>
        {fingerprint && (
          <div className="fingerprint-box">
            <strong>{t("servers.fingerprint")}</strong>
            <code>{fingerprint}</code>
            <p>{t("servers.fingerprintWarning")}</p>
            <label className="check-field">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(event) => setConfirmed(event.target.checked)}
              />
              {t("servers.verifyFingerprint")}
            </label>
          </div>
        )}
        {pairing && (
          <div className="pairing-result" role="status">
            <h3>{t("servers.keyCreated")}</h3>
            <p>
              <strong>{t("servers.fingerprint")}</strong> <code>{pairing.fingerprint}</code>
            </p>
            <p>{t("servers.installInstructions")}</p>
            <pre>{pairing.authorized_keys_line}</pre>
            <p>{t("servers.manualInstall")}</p>
          </div>
        )}
      </section>
      <section className="panel form-panel">
        <div className="panel-heading">
          <h2>{t("servers.sshConfig")}</h2>
          <button
            className="button secondary"
            onClick={async () => {
              try {
                setHosts(await api.sshHosts());
              } catch {
                setHosts([]);
              }
            }}
          >
            {t("actions.retry")}
          </button>
        </div>
        <p>{t("servers.noHosts")}</p>
        {hosts.length > 0 && (
          <ul className="simple-list">
            {hosts.map((host) => (
              <li key={host.alias}>
                <strong>{host.alias}</strong>
                <span>
                  {host.username}@{host.hostname}:{host.port}
                  {host.has_proxy_jump ? " · ProxyJump" : ""}
                </span>
                <button
                  className="text-button"
                  onClick={() =>
                    setInput({
                      alias: host.alias,
                      hostname: host.hostname,
                      username: host.username,
                      port: host.port,
                      environment: "unknown",
                    })
                  }
                >
                  {t("actions.pairServer")}
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>
      {data.assets.length === 0 ? (
        <Empty t={t} />
      ) : (
        <>
          <section className="server-list">
            {data.assets.map((asset) => {
              const summary = summaries[asset.id];
              const status = !summary
                ? "unverified"
                : !isFresh(summary.approved_at, data.settings.scan_interval_hours)
                  ? "stale"
                  : summary.complete
                    ? "succeeded"
                    : "partial";
              return (
                <article className="panel project-card" key={asset.id}>
                  <div className="project-card-head">
                    <div>
                      <h2>{asset.hostname_alias}</h2>
                      <p className="mono">{asset.host_key_fingerprint ?? t("common.unverified")}</p>
                      <p>
                        {t(
                          `servers.${asset.environment === "unknown" ? "unknownEnvironment" : asset.environment}`,
                        )}
                      </p>
                    </div>
                    <StatusTag value={status} t={t} />
                  </div>
                  <div className="project-meta">
                    <span>
                      {t("servers.lastSuccess")}:{" "}
                      {date(summary?.approved_at ?? asset.last_success_at, data.settings.language)}
                    </span>
                  </div>
                  {summary && (
                    <div className="inventory-counts">
                      <span>
                        {summary.package_count} {t("servers.packages")}
                      </span>
                      <span>
                        {summary.service_count} {t("servers.services")}
                      </span>
                      <span>
                        {summary.container_count} {t("servers.containers")}
                      </span>
                    </div>
                  )}
                  {summary?.kernel_restart_required === true && (
                    <p className="unverified-line">
                      {t("servers.kernelRestartNeeded")}: {summary.running_kernel_release} →{" "}
                      {summary.installed_kernel_release}
                    </p>
                  )}
                  {summary?.kernel_restart_required == null && (
                    <p className="unverified-line">{t("servers.kernelStateUnknown")}</p>
                  )}
                  {summary && summary.deleted_shared_library_count > 0 && (
                    <p className="unverified-line">
                      {summary.deleted_shared_library_count} {t("servers.deletedSharedLibraries")}
                      {summary.services_needing_restart.length > 0
                        ? ` · ${summary.services_needing_restart.join(", ")} ${t("servers.needsRestart")}`
                        : ` · ${t("servers.processNeedsRestart")}`}
                    </p>
                  )}
                  {summary && summary.maps_unverified_process_count > 0 && (
                    <p className="unverified-line">
                      {t("servers.mapsUnverified").replace(
                        "{count}",
                        String(summary.maps_unverified_process_count),
                      )}
                    </p>
                  )}
                  {summary && (
                    <div className="os-package-review">
                      <p
                        className={
                          summary.os_package_evaluation_status === "evaluated"
                            ? "muted"
                            : "unverified-line"
                        }
                      >
                        {t(`servers.osPackageEvaluation.${summary.os_package_evaluation_status}`)}
                      </p>
                      {summary.os_package_findings.length > 0 && (
                        <div>
                          <h3>{t("servers.osPackageFindings")}</h3>
                          <ul className="simple-list">
                            {summary.os_package_findings.map((finding) => (
                              <li
                                key={`${finding.advisory_id}:${finding.package_name}:${finding.installed_version}`}
                              >
                                <strong>
                                  {finding.package_name} {finding.installed_version}
                                </strong>
                                <span>
                                  {finding.advisory_id} · {t(`severity.${finding.severity}`)} ·{" "}
                                  {t(`status.${finding.status}`)}
                                  {finding.fix_version ? ` · ${finding.fix_version}` : ""}
                                </span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}
                  <ServerProjectLinks asset={asset} />
                  {approvedAsset === asset.id ? (
                    <div className="approval-box">
                      <p>{t("servers.transferWarning")}</p>
                      <button className="button primary" onClick={() => void collect(asset.id)}>
                        {t("actions.approveAndCollect")}
                      </button>
                      <button className="button quiet" onClick={() => setApprovedAsset(null)}>
                        {t("actions.cancel")}
                      </button>
                    </div>
                  ) : (
                    <button className="button secondary" onClick={() => setApprovedAsset(asset.id)}>
                      {t("actions.collect")}
                    </button>
                  )}
                </article>
              );
            })}
          </section>
          <section className="server-list">
            {data.assets.map((asset) => (
              <article className="panel" key={`memory-${asset.id}`}>
                <MemoryNotes scope="server" scopeId={asset.id} t={t} setNotice={setNotice} />
              </article>
            ))}
          </section>
        </>
      )}
    </>
  );
}
