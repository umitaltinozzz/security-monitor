import { useEffect, useState, type ReactNode } from "react";
import en from "../locales/en.json";
import tr from "../locales/tr.json";
import type { AppSettings } from "../generated/AppSettings";
import type { UpdateCheckResult } from "../generated/UpdateCheckResult";
import { api } from "../api";
import { AiSettingsPanel } from "../AiSettings";
import { NotificationSettingsPanel } from "../NotificationSettingsPanel";
import { PageHeading } from "../components";
import { useWorkspace } from "../WorkspaceContext";
import { safeError, safeExternalUrl } from "../utils";

type SectionId = "general" | "privacy" | "ai" | "notifications" | "sources";

function SettingRow({
  title,
  help,
  children,
}: {
  title: string;
  help?: string;
  children: ReactNode;
}) {
  return (
    <div className="settings-row">
      <div className="settings-row-copy">
        <strong>{title}</strong>
        {help && <small>{help}</small>}
      </div>
      <div className="settings-row-control">{children}</div>
    </div>
  );
}

export function Settings() {
  const { data, t, saveSettings, setNotice, refresh } = useWorkspace();
  const settings = data.settings;
  const [activeSection, setActiveSection] = useState<SectionId>("general");
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
  const [updatingAdvisories, setUpdatingAdvisories] = useState(false);
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
  const sections: { id: SectionId; label: string }[] = [
    { id: "general", label: t("settings.tabGeneral") },
    { id: "privacy", label: t("settings.tabPrivacy") },
    { id: "ai", label: t("settings.tabAi") },
    { id: "notifications", label: t("settings.tabNotifications") },
    { id: "sources", label: t("settings.tabSources") },
  ];

  useEffect(() => {
    if (typeof api.scanners !== "function") return;
    let cancelled = false;
    void api
      .scanners()
      .then((detected) => {
        if (!cancelled && Array.isArray(detected)) setScanners(detected);
      })
      .catch(() => {
        // The explicit "check installed tools" button reports errors; a silent mount check avoids noise.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (typeof IntersectionObserver === "undefined") return;
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((entry) => entry.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
        const id = visible?.target.getAttribute("data-section") as SectionId | null;
        if (id) setActiveSection(id);
      },
      { rootMargin: "-10% 0px -70% 0px" },
    );
    document.querySelectorAll("[data-section]").forEach((node) => observer.observe(node));
    return () => observer.disconnect();
  }, []);

  function jumpTo(id: SectionId) {
    setActiveSection(id);
    document
      .getElementById(`settings-${id}`)
      ?.scrollIntoView?.({ behavior: "smooth", block: "start" });
  }

  async function updateAdvisories() {
    setUpdatingAdvisories(true);
    try {
      const statuses = await api.updateAdvisories();
      setNotice({
        kind: statuses.some((status) => status.stale) ? "error" : "success",
        message: statuses.some((status) => status.stale) ? t("common.stale") : t("settings.saved"),
      });
    } catch (error) {
      setNotice({ kind: "error", message: safeError(error, t) });
    } finally {
      setUpdatingAdvisories(false);
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
      <div className="settings-layout">
        <nav className="settings-nav" aria-label={t("settings.title")}>
          {sections.map((section) => (
            <button
              key={section.id}
              type="button"
              className={`settings-nav-item ${activeSection === section.id ? "active" : ""}`}
              aria-current={activeSection === section.id ? "true" : undefined}
              onClick={() => jumpTo(section.id)}
            >
              {section.label}
            </button>
          ))}
        </nav>

        <div className="settings-content">
          <div className="settings-group" id="settings-general" data-section="general">
            <h2 className="settings-group-title">{t("settings.tabGeneral")}</h2>
            <section className="panel settings-panel">
              <div className="settings-card-head">
                <h3>{t("settings.appearance")}</h3>
              </div>
              <div className="form-grid">
                <label className="field">
                  <span>{t("settings.appearance")}</span>
                  <select
                    value={settings.theme}
                    onChange={(event) =>
                      void saveSettings({
                        ...settings,
                        theme: event.target.value as AppSettings["theme"],
                      })
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
              </div>
              <SettingRow
                title={t("settings.reopenOnboarding")}
                help={t("settings.reopenOnboardingHelp")}
              >
                <button
                  type="button"
                  className="button secondary"
                  onClick={() => void saveSettings({ ...settings, onboarding_completed: false })}
                >
                  {t("settings.reopenOnboardingShort")}
                </button>
              </SettingRow>
            </section>

            <section className="panel settings-panel">
              <div className="settings-card-head">
                <h3>{t("settings.applicationUpdates")}</h3>
                <p>{t("settings.applicationUpdatesHelp")}</p>
              </div>
              <div className="settings-inline-actions">
                <button
                  className="button secondary"
                  disabled={
                    !settings.public_downloads_enabled || checkingUpdate || installingUpdate
                  }
                  onClick={() => void checkForUpdates()}
                >
                  {checkingUpdate ? t("settings.checkingUpdates") : t("actions.checkUpdates")}
                </button>
                {update?.available && update.version && (
                  <button
                    className="button primary"
                    disabled={
                      !settings.public_downloads_enabled || checkingUpdate || installingUpdate
                    }
                    onClick={() => void installUpdate()}
                  >
                    {installingUpdate ? t("common.loading") : t("actions.installUpdate")}{" "}
                    {update.version}
                  </button>
                )}
                {!settings.public_downloads_enabled && (
                  <small className="settings-hint">{t("settings.updatesNeedDownloads")}</small>
                )}
              </div>
              {update?.available && update.notes && (
                <div className="update-notes">
                  <h3>{t("settings.releaseNotes")}</h3>
                  <p>{update.notes}</p>
                </div>
              )}
            </section>
          </div>

          <div className="settings-group" id="settings-privacy" data-section="privacy">
            <h2 className="settings-group-title">{t("settings.tabPrivacy")}</h2>
            <section className="panel settings-panel">
              <div className="settings-card-head">
                <h3>{t("settings.privacyTitle")}</h3>
              </div>
              <label className="settings-row">
                <span className="settings-row-copy">
                  <strong>{t("settings.publicDownloads")}</strong>
                  <small>{t("settings.publicDownloadsHelp")}</small>
                </span>
                <span className="settings-row-control">
                  <input
                    type="checkbox"
                    className="switch"
                    checked={settings.public_downloads_enabled}
                    onChange={(event) =>
                      void saveSettings({
                        ...settings,
                        public_downloads_enabled: event.target.checked,
                      })
                    }
                  />
                </span>
              </label>
              <label className="settings-row">
                <span className="settings-row-copy">
                  <strong>{t("settings.scanInterval")}</strong>
                </span>
                <span className="settings-row-control inline-control">
                  <input
                    className="number-input"
                    type="number"
                    min={1}
                    max={168}
                    value={settings.scan_interval_hours}
                    onChange={(event) =>
                      void saveSettings({
                        ...settings,
                        scan_interval_hours: Number(event.target.value),
                      })
                    }
                  />
                  <span>{t("settings.hours")}</span>
                </span>
              </label>
              <div className="settings-subsection">
                <div className="settings-subsection-head">
                  <strong>{t("settings.ecosystems")}</strong>
                  {settings.public_downloads_enabled && (
                    <button
                      className="button secondary small"
                      disabled={updatingAdvisories}
                      onClick={() => void updateAdvisories()}
                    >
                      {updatingAdvisories ? t("common.loading") : t("actions.updateAdvisories")}
                    </button>
                  )}
                </div>
                <div className="choice-grid">
                  {ecosystemChoices.map((ecosystem) => (
                    <label className="check-field pill-check" key={ecosystem}>
                      <input
                        type="checkbox"
                        checked={settings.ecosystems.includes(ecosystem)}
                        onChange={(event) => toggleEcosystem(ecosystem, event.target.checked)}
                      />
                      <span>{t(`ecosystems.${ecosystem}`)}</span>
                    </label>
                  ))}
                </div>
                <small className="settings-hint">{t("settings.unsupportedRangeEcosystems")}</small>
              </div>
            </section>

            <section className="panel settings-panel">
              <div className="settings-card-head row">
                <h3>{t("settings.scanners")}</h3>
                <button className="button secondary small" onClick={() => void detect()}>
                  {t("onboarding.scannerCheck")}
                </button>
              </div>
              {scanners.length === 0 ? (
                <p className="settings-empty">{t("common.unverified")}</p>
              ) : (
                <ul className="settings-list">
                  {scanners.map((scanner) => (
                    <li key={scanner.engine}>
                      <div className="settings-list-copy">
                        <strong>{t(`scanner.${scanner.engine.replaceAll("-", "_")}`)}</strong>
                        {scanner.version && <small>{scanner.version}</small>}
                      </div>
                      <div className="settings-list-actions">
                        <span
                          className={`tag ${scanner.status === "available" ? "verified" : "unverified"}`}
                        >
                          {t(`scanner.${scanner.status}`)}
                        </span>
                        {scanner.status === "missing" &&
                          ["osv-scanner", "trivy", "semgrep"].includes(scanner.engine) && (
                            <button
                              className="button secondary small"
                              title={t("actions.install")}
                              disabled={
                                !settings.public_downloads_enabled || busyEngine === scanner.engine
                              }
                              onClick={() => void install(scanner.engine)}
                            >
                              {busyEngine === scanner.engine
                                ? t("common.loading")
                                : t("actions.installShort")}
                            </button>
                          )}
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>

          <div className="settings-group" id="settings-ai" data-section="ai">
            <h2 className="settings-group-title">{t("settings.tabAi")}</h2>
            <AiSettingsPanel
              data={data}
              t={t}
              setNotice={setNotice}
              refreshProjects={() => refresh(["projects"])}
            />
          </div>

          <div className="settings-group" id="settings-notifications" data-section="notifications">
            <h2 className="settings-group-title">{t("settings.tabNotifications")}</h2>
            <NotificationSettingsPanel
              settings={settings}
              saveSettings={saveSettings}
              setNotice={setNotice}
              t={t}
            />
          </div>

          <div className="settings-group" id="settings-sources" data-section="sources">
            <h2 className="settings-group-title">{t("settings.tabSources")}</h2>
            <section className="panel settings-panel">
              <div className="settings-card-head">
                <h3>{t("settings.dataSources")}</h3>
                <p>{t("settings.dataSourcesHelp")}</p>
              </div>
              <ul className="settings-list">
                {attributions.map((source) => {
                  const url = safeExternalUrl(source.url);
                  return (
                    <li key={`${source.name}-${source.url}-${source.license ?? ""}`}>
                      <div className="settings-list-copy">
                        <strong>{source.name}</strong>
                        <small>{source.license ?? t("settings.licenseUnverified")}</small>
                      </div>
                      <div className="settings-list-actions">
                        {url ? (
                          <a className="settings-link" href={url} target="_blank" rel="noreferrer">
                            {url.replace(/^https:\/\//, "").replace(/\/$/, "")}
                          </a>
                        ) : (
                          <code>{t("common.unverified")}</code>
                        )}
                      </div>
                    </li>
                  );
                })}
              </ul>
            </section>
            <section className="panel settings-panel">
              <div className="settings-card-head">
                <h3>{t("settings.backup")}</h3>
                <p>{t("settings.backupHelp")}</p>
              </div>
            </section>
          </div>
        </div>
      </div>
    </>
  );
}
