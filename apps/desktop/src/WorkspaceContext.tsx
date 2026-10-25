import { createContext, useContext } from "react";
import type { AppSettings } from "./generated/AppSettings";
import type { Finding } from "./generated/Finding";
import type { Project } from "./generated/Project";
import type { WorkspaceData, WorkspaceSection } from "./api";

export type Language = "en" | "tr";
export type Page = "review" | "findings" | "projects" | "servers" | "history" | "settings";
export type Notice = { message: string; kind: "error" | "success" } | null;
export type T = (key: string) => string;
export type NoticeSetter = (notice: Notice) => void;

export type WorkspaceContextValue = {
  data: WorkspaceData;
  language: Language;
  t: T;
  notice: Notice;
  setNotice: NoticeSetter;
  refresh: (sections?: readonly WorkspaceSection[]) => void;
  saveSettings: (settings: AppSettings) => Promise<void>;
  addProject: (path: string) => Promise<Project | null>;
  startScan: (project: Project, profile: "quick" | "full") => Promise<void>;
  cancelProjectScan: (projectId: string) => Promise<void>;
  scanState: Record<string, string>;
  activeScanIds: Record<string, string>;
  page: Page;
  setPage: (page: Page) => void;
  context: string | null;
  setContext: (value: string | null) => void;
  focusFindingId: string | null;
  setFocusFindingId: (value: string | null) => void;
  updateFinding: (finding: Finding) => void;
  onCompleteOnboarding: () => void;
};

export const pages: Page[] = ["review", "findings", "projects", "servers", "history", "settings"];

export const WorkspaceContext = createContext<WorkspaceContextValue | null>(null);

export function useWorkspace(): WorkspaceContextValue {
  const workspace = useContext(WorkspaceContext);
  if (!workspace) throw new Error("Workspace context is unavailable");
  return workspace;
}
