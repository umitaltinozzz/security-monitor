import { useCallback, useEffect, useState, type FormEvent } from "react";
import type { Memory } from "./generated/Memory";
import type { MemoryKind } from "./generated/MemoryKind";
import type { MemoryScope } from "./generated/MemoryScope";
import { api } from "./api";

type T = (key: string) => string;
type NoticeSetter = (notice: { message: string; kind: "error" | "success" } | null) => void;

export function MemoryNotes({ scope, scopeId = null, t, setNotice }: {
  scope: MemoryScope;
  scopeId?: string | null;
  t: T;
  setNotice: NoticeSetter;
}) {
  const [memories, setMemories] = useState<Memory[]>([]);
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [kind, setKind] = useState<MemoryKind>("finding_note");
  const [content, setContent] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const result = await api.memories(scope, scopeId ?? undefined);
      setMemories(result);
      setDrafts(Object.fromEntries(result.map((memory) => [memory.id, memory.content])));
    } catch {
      setNotice({ kind: "error", message: t("error.storage_unavailable") });
    }
  }, [scope, scopeId, setNotice, t]);

  useEffect(() => { void load(); }, [load]);

  async function add(event: FormEvent) {
    event.preventDefault();
    if (!content.trim()) return;
    setBusy(true);
    try {
      await api.createMemory(scope, scopeId, kind, content, false);
      setContent("");
      setNotice({ kind: "success", message: t("memory.created") });
      await load();
    } catch {
      setNotice({ kind: "error", message: t("error.invalid_input") });
    } finally {
      setBusy(false);
    }
  }

  async function update(memory: Memory, changes: { content?: string; pinned?: boolean; verified?: boolean }) {
    setBusy(true);
    try {
      await api.updateMemory(
        memory.id,
        changes.content ?? null,
        changes.pinned ?? null,
        changes.verified ?? null,
      );
      setNotice({ kind: "success", message: t("memory.updated") });
      await load();
    } catch {
      setNotice({ kind: "error", message: t("error.invalid_input") });
    } finally {
      setBusy(false);
    }
  }

  async function remove(memory: Memory) {
    setBusy(true);
    try {
      await api.deleteMemory(memory.id);
      setNotice({ kind: "success", message: t("memory.deleted") });
      await load();
    } catch {
      setNotice({ kind: "error", message: t("error.storage_unavailable") });
    } finally {
      setBusy(false);
    }
  }

  // Notes stay collapsed so each project and server card leads with its security state.
  return <details className="memory-notes project-subsection" open={memories.length > 0 && scope === "global"}>
    <summary><h3>{t("memory.title")}{memories.length > 0 ? ` (${memories.length})` : ""}</h3></summary>
    <form className="memory-create" onSubmit={(event) => void add(event)}>
      <label className="field"><span>{t("memory.kind")}</span><select value={kind} onChange={(event) => setKind(event.target.value as MemoryKind)}>
        {(["finding_note", "user_decision", "project_context", "failed_fix", "agent_summary"] as const).map((value) => <option value={value} key={value}>{t(`memory.kinds.${value}`)}</option>)}
      </select></label>
      <label className="field"><span>{t("memory.content")}</span><textarea value={content} maxLength={8192} rows={3} onChange={(event) => setContent(event.target.value)} /></label>
      <button className="button secondary" disabled={busy || !content.trim()}>{t("memory.add")}</button>
    </form>
    {memories.length === 0 ? <p>{t("memory.empty")}</p> : <ul className="memory-list">{memories.map((memory) => <li key={memory.id}>
      <div className="memory-meta"><span>{t(`memory.kinds.${memory.kind}`)}</span><span>{memory.author === "user" ? t("memory.userAuthored") : t("memory.agentAuthored")}</span>{memory.pinned && <span>{t("memory.pinned")}</span>}</div>
      <textarea aria-label={t("memory.content")} value={drafts[memory.id] ?? memory.content} rows={3} onChange={(event) => setDrafts((current) => ({ ...current, [memory.id]: event.target.value }))} />
      <div className="button-row">
        <button className="button quiet" disabled={busy || (drafts[memory.id] ?? memory.content) === memory.content} onClick={() => void update(memory, { content: drafts[memory.id] ?? memory.content })}>{t("actions.save")}</button>
        <button className="button quiet" disabled={busy} onClick={() => void update(memory, { pinned: !memory.pinned })}>{t(memory.pinned ? "memory.unpin" : "memory.pin")}</button>
        <button className="button quiet" disabled={busy} onClick={() => void update(memory, { verified: memory.verified_at === null })}>{t(memory.verified_at === null ? "memory.verify" : "memory.unverify")}</button>
        <button className="button danger" disabled={busy} onClick={() => void remove(memory)}>{t("actions.delete")}</button>
      </div>
      <small>{t("memory.expires")}: {memory.expires_at ? new Date(memory.expires_at).toLocaleDateString() : t("common.unknown")}</small>
    </li>)}</ul>}
  </details>;
}
