import { useCallback, useEffect, useState } from "react";
import type { Remediation } from "./generated/Remediation";
import type { AiConfigurationView } from "./generated/AiConfigurationView";
import type { RemediationSandboxStatus } from "./generated/RemediationSandboxStatus";
import type { SafeTestInput } from "./generated/SafeTestInput";
import type { McpRemediationRequest } from "./generated/McpRemediationRequest";
import type { WorkspaceData } from "./api";
import { api } from "./api";

type T = (key: string) => string;
type Notice = { message: string; kind: "error" | "success" } | null;

export function RemediationSection({
  findingId,
  projectId,
  data,
  t,
  setNotice,
}: {
  findingId: string;
  projectId: string | null;
  data: WorkspaceData;
  t: T;
  setNotice: (notice: Notice) => void;
}) {
  const [configuration, setConfiguration] = useState<AiConfigurationView | null>(null);
  const [remediations, setRemediations] = useState<Remediation[]>([]);
  const [sandbox, setSandbox] = useState<RemediationSandboxStatus | null>(null);
  const [mcpRequests, setMcpRequests] = useState<McpRemediationRequest[]>([]);
  const [providerId, setProviderId] = useState("");
  const [sourceTransferApproved, setSourceTransferApproved] = useState(false);
  const [executeApproved, setExecuteApproved] = useState(false);
  const [testExecutable, setTestExecutable] = useState("");
  const [testArgs, setTestArgs] = useState("");
  const [testImage, setTestImage] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [nextConfiguration, nextRemediations, nextSandbox, nextRequests] = await Promise.all([
        api.aiConfiguration(),
        api.remediations(),
        api.remediationSandboxStatus(),
        api.mcpRemediationRequests(),
      ]);
      setConfiguration(nextConfiguration);
      setRemediations(nextRemediations.filter((item) => item.finding_id === findingId));
      setSandbox(nextSandbox);
      setMcpRequests(nextRequests.filter((item) => item.finding_id === findingId));
      const project = data.projects.find((item) => item.id === projectId);
      const providers = nextConfiguration.providers.filter(
        (provider) =>
          provider.kind === "agent_cli" && project?.allowed_ai_providers.includes(provider.id),
      );
      setProviderId((current) =>
        providers.some((provider) => provider.id === current) ? current : (providers[0]?.id ?? ""),
      );
    } catch {
      setNotice({ kind: "error", message: t("error.storage_unavailable") });
    }
  }, [data.projects, findingId, projectId, setNotice, t]);

  useEffect(() => {
    void load();
  }, [load]);

  const providers =
    configuration?.providers.filter((provider) => {
      const project = data.projects.find((item) => item.id === projectId);
      return provider.kind === "agent_cli" && project?.allowed_ai_providers.includes(provider.id);
    }) ?? [];
  const active = remediations.some(
    (item) => item.approval_state === "pending" || item.approval_state === "approved",
  );

  async function requestPatch() {
    if (!providerId) return;
    setBusyId("new");
    try {
      await api.requestRemediation(findingId, providerId);
      setSourceTransferApproved(false);
      await load();
    } catch {
      setNotice({ kind: "error", message: t("error.remediation_request_failed") });
    } finally {
      setBusyId(null);
    }
  }

  async function queueMcpPatch(request: McpRemediationRequest) {
    if (!request.provider_id) return;
    setBusyId(request.id);
    try {
      await api.requestRemediation(findingId, request.provider_id);
      await api.dismissMcpRemediationRequest(request.id);
      setSourceTransferApproved(false);
      await load();
    } catch {
      setNotice({ kind: "error", message: t("error.remediation_request_failed") });
    } finally {
      setBusyId(null);
    }
  }

  async function dismissMcpRequest(request: McpRemediationRequest) {
    try {
      await api.dismissMcpRemediationRequest(request.id);
      await load();
    } catch {
      setNotice({ kind: "error", message: t("error.storage_unavailable") });
    }
  }

  async function approve(item: Remediation) {
    setBusyId(item.id);
    try {
      await api.approveRemediation(item.id, sourceTransferApproved);
      setSourceTransferApproved(false);
      await load();
    } catch (error) {
      setNotice({
        kind: "error",
        message: remediationErrorMessage(error, t, "remediation_agent_failed"),
      });
    } finally {
      setBusyId(null);
    }
  }

  async function reject(item: Remediation) {
    setBusyId(item.id);
    try {
      await api.rejectRemediation(item.id);
      await load();
    } catch {
      setNotice({ kind: "error", message: t("error.storage_unavailable") });
    } finally {
      setBusyId(null);
    }
  }

  async function runTests(item: Remediation) {
    const input: SafeTestInput = {
      executable: testExecutable,
      args: testArgs.split(/\r?\n/).filter((argument) => argument.length > 0),
      image: testImage,
    };
    setBusyId(item.id);
    try {
      await api.runSafeTests(item.id, input, executeApproved);
      for (const request of mcpRequests.filter(
        (candidate) => candidate.remediation_id === item.id,
      )) {
        await api.dismissMcpRemediationRequest(request.id);
      }
      setExecuteApproved(false);
      await load();
    } catch {
      setNotice({ kind: "error", message: t("error.remediation_test_failed") });
    } finally {
      setBusyId(null);
    }
  }

  return (
    <section className="remediation-workflow" aria-labelledby="remediation-workflow-title">
      <h4 id="remediation-workflow-title">{t("findings.remediationWorkflow.workflowTitle")}</h4>
      {projectId === null ? (
        <p className="unverified-line">{t("findings.remediationWorkflow.projectRequired")}</p>
      ) : (
        <>
          {mcpRequests.map((request) => (
            <article className="remediation-mcp-request" key={request.id}>
              <strong>
                {request.action === "prepare_patch"
                  ? t("findings.remediationWorkflow.mcpPatchRequest")
                  : t("findings.remediationWorkflow.mcpTestRequest")}
              </strong>
              <small>{t("findings.remediationWorkflow.mcpQueueHelp")}</small>
              <div className="button-row end">
                {request.action === "prepare_patch" && (
                  <button
                    className="button secondary"
                    disabled={
                      busyId !== null ||
                      active ||
                      !request.provider_id ||
                      !providers.some((provider) => provider.id === request.provider_id)
                    }
                    onClick={() => void queueMcpPatch(request)}
                  >
                    {busyId === request.id
                      ? t("common.loading")
                      : t("findings.remediationWorkflow.reviewMcpRequest")}
                  </button>
                )}
                <button
                  className="button quiet"
                  disabled={busyId !== null}
                  onClick={() => void dismissMcpRequest(request)}
                >
                  {t("actions.cancel")}
                </button>
              </div>
            </article>
          ))}
          {providers.length === 0 ? (
            <p className="unverified-line">{t("findings.remediationWorkflow.providerRequired")}</p>
          ) : (
            <div className="remediation-request-row">
              <label className="field">
                <span>{t("findings.remediationWorkflow.agentProvider")}</span>
                <select value={providerId} onChange={(event) => setProviderId(event.target.value)}>
                  {providers.map((provider) => (
                    <option key={provider.id} value={provider.id}>
                      {provider.display_name}
                    </option>
                  ))}
                </select>
              </label>
              <button
                className="button secondary"
                disabled={busyId !== null || active || !providerId}
                onClick={() => void requestPatch()}
              >
                {busyId === "new"
                  ? t("common.loading")
                  : t("findings.remediationWorkflow.requestPatch")}
              </button>
            </div>
          )}
          {sandbox && !sandbox.available && (
            <p className="unverified-line">
              {t("findings.remediationWorkflow.sandboxUnavailable")}
            </p>
          )}
          {remediations.length === 0 ? (
            <p>{t("findings.remediationWorkflow.noRequests")}</p>
          ) : (
            <ul className="remediation-list">
              {[...remediations]
                .sort((left, right) => right.created_at.localeCompare(left.created_at))
                .map((item) => (
                  <li key={item.id}>
                    <div className="remediation-head">
                      <strong>
                        {t(`findings.remediationWorkflow.states.${item.approval_state}`)}
                      </strong>
                      <code>{item.branch}</code>
                    </div>
                    {item.approval_state === "pending" && (
                      <div className="approval-box">
                        <p>{t("findings.remediationWorkflow.patchApprovalHelp")}</p>
                        <label className="check-field">
                          <input
                            type="checkbox"
                            checked={sourceTransferApproved}
                            onChange={(event) => setSourceTransferApproved(event.target.checked)}
                          />
                          {t("findings.remediationWorkflow.sourceTransferApproval")}
                        </label>
                        <div className="button-row end">
                          <button
                            className="button quiet"
                            disabled={busyId !== null}
                            onClick={() => void reject(item)}
                          >
                            {t("actions.cancel")}
                          </button>
                          <button
                            className="button primary"
                            disabled={busyId !== null || !sourceTransferApproved}
                            onClick={() => void approve(item)}
                          >
                            {busyId === item.id
                              ? t("common.loading")
                              : t("findings.remediationWorkflow.approveAndPrepare")}
                          </button>
                        </div>
                      </div>
                    )}
                    {item.approval_state === "approved" && (
                      <>
                        <div className="button-row end">
                          <button
                            className="button quiet"
                            disabled={busyId !== null}
                            onClick={() => void reject(item)}
                          >
                            {t("findings.remediationWorkflow.discardPatch")}
                          </button>
                        </div>
                        {mcpRequests.some((request) => request.remediation_id === item.id) && (
                          <p className="unverified-line">
                            {t("findings.remediationWorkflow.mcpTestRequest")}
                          </p>
                        )}
                        <p className="remediation-path">
                          <span>{t("findings.remediationWorkflow.worktree")}</span>
                          <code>{item.worktree_path}</code>
                        </p>
                        {item.diff_hash ? (
                          <p className="remediation-path">
                            <span>{t("findings.remediationWorkflow.diffHash")}</span>
                            <code>{item.diff_hash}</code>
                          </p>
                        ) : (
                          <p className="unverified-line">
                            {t("findings.remediationWorkflow.noDiff")}
                          </p>
                        )}
                        {item.tests.map((test, index) => (
                          <p className="remediation-test" key={`${item.id}-${index}`}>
                            <StatusTag value={test.passed ? "succeeded" : "failed"} t={t} />
                            <span>{test.name}</span>
                            <small>
                              {test.exit_code === null
                                ? t("findings.remediationWorkflow.exitUnknown")
                                : `${t("findings.remediationWorkflow.exitCode")}: ${test.exit_code}`}
                            </small>
                          </p>
                        ))}
                        {sandbox?.available && (
                          <div className="remediation-test-form">
                            <h5>{t("findings.remediationWorkflow.runTests")}</h5>
                            <label className="field">
                              <span>{t("findings.remediationWorkflow.testExecutable")}</span>
                              <input
                                value={testExecutable}
                                onChange={(event) => setTestExecutable(event.target.value)}
                              />
                            </label>
                            <label className="field">
                              <span>{t("findings.remediationWorkflow.testArguments")}</span>
                              <textarea
                                rows={3}
                                value={testArgs}
                                onChange={(event) => setTestArgs(event.target.value)}
                              />
                            </label>
                            <label className="field">
                              <span>{t("findings.remediationWorkflow.testImage")}</span>
                              <input
                                value={testImage}
                                onChange={(event) => setTestImage(event.target.value)}
                                placeholder={t("findings.remediationWorkflow.imagePlaceholder")}
                              />
                            </label>
                            <label className="check-field">
                              <input
                                type="checkbox"
                                checked={executeApproved}
                                onChange={(event) => setExecuteApproved(event.target.checked)}
                              />
                              {t("findings.remediationWorkflow.executeApproval")}
                            </label>
                            <button
                              className="button secondary"
                              disabled={
                                busyId !== null ||
                                !executeApproved ||
                                !testExecutable.trim() ||
                                !testImage.trim()
                              }
                              onClick={() => void runTests(item)}
                            >
                              {busyId === item.id
                                ? t("common.loading")
                                : t("findings.remediationWorkflow.approveAndRun")}
                            </button>
                          </div>
                        )}
                      </>
                    )}
                  </li>
                ))}
            </ul>
          )}
        </>
      )}
    </section>
  );
}

function StatusTag({ value, t }: { value: string; t: T }) {
  return (
    <span
      className={`tag ${value === "succeeded" ? "verified" : value === "failed" ? "unverified" : ""}`}
    >
      {t(`findings.remediationWorkflow.testStates.${value}`)}
    </span>
  );
}

function remediationErrorMessage(error: unknown, t: T, fallback: string) {
  const knownErrors = new Set([
    "remediation_opencode_project_config",
    "remediation_git_filter_not_allowed",
  ]);
  return typeof error === "string" && knownErrors.has(error)
    ? t(`error.${error}`)
    : t(`error.${fallback}`);
}
