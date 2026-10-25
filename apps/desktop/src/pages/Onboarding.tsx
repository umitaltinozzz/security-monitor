import { useState } from "react";
import en from "../locales/en.json";
import tr from "../locales/tr.json";
import type { AppSettings } from "../generated/AppSettings";
import { api } from "../api";
import { useWorkspace } from "../WorkspaceContext";
import { safeError } from "../utils";
export function Onboarding() {
  const { data, language, t, notice, setNotice, saveSettings, addProject, startScan, onCompleteOnboarding: onComplete } = useWorkspace();
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
  return <main className="onboarding-shell"><header className="onboarding-header"><a className="brand" href="#setup"><span className="brand-mark" aria-hidden="true" />{t("appName")}</a><button className="button quiet" aria-label={t("languageToggleLabel")} onClick={() => void saveSettings({ ...data.settings, language: language === "en" ? "tr" : "en" })}>{language === "en" ? "TR" : "EN"}</button></header><section className="onboarding-card panel" aria-labelledby="onboarding-title"><div className="welcome-flow" aria-live="polite">{titles.slice(0, step).map((title, index) => { const bodyKey = title === "privacyTitle" ? "privacyBody" : title === "scannerTitle" ? "scannerBody" : title === "advisoryTitle" ? "advisoryBody" : title === "projectTitle" ? "projectBody" : title === "serverTitle" ? "serverBody" : "aiBody"; return <article className="flow-turn past" key={title}><span className="eyebrow">{t("onboarding.assistant")}</span><p>{t(`onboarding.${title}`)}</p><small>{t(`onboarding.${completedSteps[index] ?? "skipped"}`)}</small><p className="flow-body">{t(`onboarding.${bodyKey}`)}</p></article>; })}<article className="flow-turn current"><span className="eyebrow">{t("onboarding.assistant")}</span><h1 id="onboarding-title">{t(`onboarding.${titles[step]}`)}</h1><p className="onboarding-description">{t(`onboarding.${titles[step] === "privacyTitle" ? "privacyBody" : titles[step] === "scannerTitle" ? "scannerBody" : titles[step] === "advisoryTitle" ? "advisoryBody" : titles[step] === "projectTitle" ? "projectBody" : titles[step] === "serverTitle" ? "serverBody" : "aiBody"}`)}</p>
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
