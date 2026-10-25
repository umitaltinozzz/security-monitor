import { useState } from "react";
import en from "../locales/en.json";
import tr from "../locales/tr.json";
import type { AppSettings } from "../generated/AppSettings";
import type { UpdateCheckResult } from "../generated/UpdateCheckResult";
import { api } from "../api";
import { AiSettingsPanel } from "../AiSettings";
import { PageHeading } from "../components";
import { useWorkspace } from "../WorkspaceContext";
import { safeError, safeExternalUrl } from "../utils";
export function Settings() {
  const { data, t, saveSettings, setNotice, refresh } = useWorkspace();
  const settings = data.settings;
  const builtInAttributions = [
    { name: "cve.now", url: "https://cve.now/", license: "CC-BY 4.0" },
    { name: "OSV", url: "https://osv.dev/", license: t("settings.osvLicenses") },
    {
      name: "GitHub Advisory Database",
      url: "https://github.com/advisories",
      license: "CC-BY 4.0",
    },
    {
      name: "CISA KEV",
      url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
      license: null,
    },
    {
      name: "FIRST EPSS",
      url: "https://www.first.org/epss/",
      license: "Attribution requested by FIRST",
    },
  ];
  const attributions = [
    ...new Map(
      [
        ...builtInAttributions,
        ...data.advisories.flatMap((advisory) => advisory.source_attributions),
      ].map((source) => [`${source.name}\u0000${source.url}\u0000${source.license ?? ""}`, source]),
    ).values(),
  ].sort((left, right) => left.name.localeCompare(right.name) || left.url.localeCompare(right.url));
  const [scanners, setScanners] = useState<
    { engine: string; status: string; version: string | null }[]
  >([]);
  const [busyEngine, setBusyEngine] = useState<string | null>(null);
  const [update, setUpdate] = useState<UpdateCheckResult | null>(null);
  const [checkingUpdate, setCheckingUpdate] = useState(false);
  const [installingUpdate, setInstallingUpdate] = useState(false);
  const ecosystemChoices = [
    "npm",
    "pypi",
    "cargo",
    "golang",
    "composer",
    "maven",
    "rubygems",
    "nuget",
  ];
  async function updateAdvisories() {
    try {
      const statuses = await api.updateAdvisories();
      setNotice({
        kind: statuses.some((status) => status.stale) ? "error" : "success",
        message: statuses.some((status) => status.stale) ? t("common.stale") : t("settings.saved"),
      });
    } catch (error) {
      setNotice({ kind: "error", message: safeError(error, t) });
    }
  }
  async function detect() {
    try {
      setScanners(await api.scanners());
    } catch (error) {
      setNotice({ kind: "error", message: safeError(error, t) });
    }
  }
  async function install(engine: string) {
    setBusyEngine(engine);
    try {
      await api.installScanner(engine, true);
      setNotice({ kind: "success", message: t("settings.installed") });
      await detect();
    } catch (error) {
      setNotice({ kind: "error", message: safeError(error, t) });
    } finally {
      setBusyEngine(null);
    }
  }
  async function checkForUpdates() {
    setCheckingUpdate(true);
    setUpdate(null);
    try {
      const result = await api.checkForUpdates();
      setUpdate(result);
      if (!result.available)
        setNotice({ kind: "success", message: t("settings.noUpdateAvailable") });
    } catch (error) {
      setNotice({ kind: "error", message: safeError(error, t) });
    } finally {
      setCheckingUpdate(false);
    }
  }
  async function installUpdate() {
    const version = update?.version;
    if (!version) return;
    setInstallingUpdate(true);
    try {
      await api.installUpdate(version);
      setNotice({ kind: "success", message: t("settings.updateInstalled") });
    } catch (error) {
      setNotice({ kind: "error", message: safeError(error, t) });
    } finally {
      setInstallingUpdate(false);
    }
  }
  function toggleEcosystem(ecosystem: string, enabled: boolean) {
    const ecosystems = enabled
      ? [...new Set([...settings.ecosystems, ecosystem])]
      : settings.ecosystems.filter((item) => item !== ecosystem);
    void saveSettings({ ...settings, ecosystems });
  }
  return (
    <>
      <PageHeading title={t("settings.title")} description={t("settings.description")} />
      <section className="panel settings-panel">
        <h2>{t("settings.privacyTitle")}</h2>
        <label className="setting-row">
          <span>
            <strong>{t("settings.publicDownloads")}</strong>
            <small>{t("settings.publicDownloadsHelp")}</small>
          </span>
          <input
            type="checkbox"
            checked={settings.public_downloads_enabled}
            onChange={(event) =>
              void saveSettings({ ...settings, public_downloads_enabled: event.target.checked })
            }
          />
        </label>
        <div className="ecosystem-settings">
          <h3>{t("settings.ecosystems")}</h3>
          <div className="ecosystem-grid">
            {ecosystemChoices.map((ecosystem) => (
              <label className="check-field" key={ecosystem}>
                <input
                  type="checkbox"
                  checked={settings.ecosystems.includes(ecosystem)}
                  onChange={(event) => toggleEcosystem(ecosystem, event.target.checked)}
                />
                {t(`ecosystems.${ecosystem}`)}
              </label>
            ))}
          </div>
          <small>{t("settings.unsupportedRangeEcosystems")}</small>
        </div>
        {settings.public_downloads_enabled && (
          <div className="setting-row">
            <span>{t("onboarding.advisoryBody")}</span>
            <button className="button secondary" onClick={() => void updateAdvisories()}>
              {t("actions.updateAdvisories")}
            </button>
          </div>
        )}
        <div className="setting-row">
          <span>
            <strong>{t("settings.notifications")}</strong>
            <small>{t("settings.notificationsUnavailable")}</small>
          </span>
        </div>
        <label className="setting-row">
          <span>
            <strong>{t("settings.scanInterval")}</strong>
          </span>
          <span className="inline-control">
            <input
              className="number-input"
              type="number"
              min={1}
              max={168}
              value={settings.scan_interval_hours}
              onChange={(event) =>
                void saveSettings({ ...settings, scan_interval_hours: Number(event.target.value) })
              }
            />
            <span>{t("settings.hours")}</span>
          </span>
        </label>
      </section>
      <section className="panel settings-panel">
        <h2>{t("settings.applicationUpdates")}</h2>
        <p>{t("settings.applicationUpdatesHelp")}</p>
        <div className="button-row">
          <button
            className="button secondary"
            disabled={!settings.public_downloads_enabled || checkingUpdate || installingUpdate}
            onClick={() => void checkForUpdates()}
          >
            {checkingUpdate ? t("settings.checkingUpdates") : t("actions.checkUpdates")}
          </button>
          {update?.available && update.version && (
            <button
              className="button primary"
              disabled={!settings.public_downloads_enabled || checkingUpdate || installingUpdate}
              onClick={() => void installUpdate()}
            >
              {installingUpdate ? t("common.loading") : t("actions.installUpdate")} {update.version}
            </button>
          )}
        </div>
        {!settings.public_downloads_enabled && (
          <p className="privacy-details">{t("settings.updatesNeedDownloads")}</p>
        )}
        {update?.available && update.notes && (
          <div className="update-notes">
            <h3>{t("settings.releaseNotes")}</h3>
            <p>{update.notes}</p>
          </div>
        )}
      </section>
      <section className="panel settings-panel">
        <div className="panel-heading">
          <h2>{t("settings.scanners")}</h2>
          <button className="button secondary" onClick={() => void detect()}>
            {t("onboarding.scannerCheck")}
          </button>
        </div>
        {scanners.length === 0 ? (
          <p>{t("common.unverified")}</p>
        ) : (
          <ul className="scanner-list">
            {scanners.map((scanner) => (
              <li key={scanner.engine}>
                <span>{t(`scanner.${scanner.engine.replaceAll("-", "_")}`)}</span>
                <span
                  className={`tag ${scanner.status === "available" ? "verified" : "unverified"}`}
                >
                  {t(`scanner.${scanner.status}`)}
                </span>
                {scanner.version && <small>{scanner.version}</small>}
                {scanner.status === "missing" &&
                  ["osv-scanner", "trivy", "semgrep"].includes(scanner.engine) && (
                    <button
                      className="button secondary"
                      disabled={!settings.public_downloads_enabled || busyEngine === scanner.engine}
                      onClick={() => void install(scanner.engine)}
                    >
                      {busyEngine === scanner.engine ? t("common.loading") : t("actions.install")}
                    </button>
                  )}
              </li>
            ))}
          </ul>
        )}
      </section>
      <section className="panel settings-panel">
        <h2>{t("settings.appearance")}</h2>
        <label className="field">
          <span>{t("settings.appearance")}</span>
          <select
            value={settings.theme}
            onChange={(event) =>
              void saveSettings({ ...settings, theme: event.target.value as AppSettings["theme"] })
            }
          >
            {["system", "light", "dark"].map((value) => (
              <option value={value} key={value}>
                {t(`theme.${value}`)}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>{t("settings.language")}</span>
          <select
            value={settings.language}
            onChange={(event) =>
              void saveSettings({
                ...settings,
                language: event.target.value as AppSettings["language"],
              })
            }
          >
            <option value="en">{en.languageName}</option>
            <option value="tr">{tr.languageName}</option>
          </select>
        </label>
      </section>
      <section className="panel settings-panel">
        <h2>{t("settings.dataSources")}</h2>
        <p>{t("settings.dataSourcesHelp")}</p>
        <ul className="simple-list">
          {attributions.map((source) => {
            const url = safeExternalUrl(source.url);
            return (
              <li key={`${source.name}-${source.url}-${source.license ?? ""}`}>
                <span>
                  <strong>{source.name}</strong>
                  <small>{source.license ?? t("settings.licenseUnverified")}</small>
                </span>
                {url ? (
                  <a href={url} target="_blank" rel="noreferrer">
                    {source.url}
                  </a>
                ) : (
                  <code>{t("common.unverified")}</code>
                )}
              </li>
            );
          })}
        </ul>
      </section>
      <AiSettingsPanel data={data} t={t} setNotice={setNotice} refresh={refresh} />
      <section className="panel settings-panel">
        <h2>{t("settings.backup")}</h2>
        <p>{t("settings.backupHelp")}</p>
      </section>
    </>
  );
}
