import { useState } from "react";
import type { WorkspaceData } from "../api";
import { api } from "../api";
import { useWorkspace } from "../WorkspaceContext";
import { safeError } from "../utils";
export function ServerProjectLinks({ asset }: { asset: WorkspaceData["assets"][number] }) {
  const { data, t, refresh, setNotice } = useWorkspace();
  const [projectId, setProjectId] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const linked = data.links.filter((link) => link.asset_id === asset.id);
  const available = data.projects.filter((project) => !linked.some((link) => link.project_id === project.id));
  const projectName = (id: string) => data.projects.find((project) => project.id === id)?.name ?? t("common.unverified");
  async function link() { try { await api.linkProjectServer(projectId, asset.id, confirmed); setNotice({ kind: "success", message: t("servers.linkCreated") }); setProjectId(""); setConfirmed(false); refresh(); } catch (error) { setNotice({ kind: "error", message: safeError(error, t) }); } }
  async function unlink(linkId: string) { try { await api.unlinkProjectServer(linkId); setNotice({ kind: "success", message: t("servers.linkRemoved") }); refresh(); } catch (error) { setNotice({ kind: "error", message: safeError(error, t) }); } }
  return <div className="server-links"><h3>{t("servers.linkedProjects")}</h3>{linked.length === 0 ? <p className="unverified-line">{t("servers.noLinkedProjects")}</p> : <ul className="simple-list">{linked.map((item) => <li key={item.id}><strong>{projectName(item.project_id)}</strong><button className="button quiet" onClick={() => void unlink(item.id)}>{t("actions.unlink")}</button></li>)}</ul>}{available.length > 0 && <div className="link-form"><label className="field"><span>{t("servers.linkProject")}</span><select value={projectId} onChange={(event) => { setProjectId(event.target.value); setConfirmed(false); }}><option value="">{t("servers.chooseProject")}</option>{available.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}</select></label>{projectId && <label className="check-field"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />{t("servers.confirmLink")}</label>}<button className="button secondary" disabled={!projectId || !confirmed} onClick={() => void link()}>{t("actions.link")}</button></div>}<p className="link-note">{t("servers.linkExplanation")}</p></div>;
}
