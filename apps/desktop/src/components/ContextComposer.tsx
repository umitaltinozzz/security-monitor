import type { NoticeSetter, T } from "../WorkspaceContext";
import { AiChatComposer } from "../AiChatComposer";
export function ContextComposer({ context, projectId, t, setNotice }: { context: string | null; projectId: string | null; t: T; setNotice: NoticeSetter }) {
  return <AiChatComposer context={context} projectId={projectId} t={t} setNotice={setNotice} />;
}
