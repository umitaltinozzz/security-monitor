import { useEffect, useState, type FormEvent } from "react";
import type { AiRequestEstimate } from "./generated/AiRequestEstimate";
import type { AiTier } from "./generated/AiTier";
import { api } from "./api";

type T = (key: string) => string;
type Notice = { message: string; kind: "error" | "success" } | null;

function toolOutputCategories(enabledTools: string[]): string[] {
  const categories = new Set<string>();
  for (const tool of enabledTools) {
    switch (tool) {
      case "list_projects":
        categories.add("project_metadata");
        break;
      case "list_assets":
        categories.add("server_inventory");
        break;
      case "list_findings":
      case "get_finding_evidence":
      case "compare_repo_deployment":
        categories.add("finding_advisory_evidence");
        break;
      case "read_project_file":
      case "search_project":
        categories.add("project_files");
        break;
      case "analyze_impact":
        categories.add("finding_advisory_evidence");
        categories.add("shared_memory");
        break;
      case "recall":
      case "remember":
        categories.add("shared_memory");
        break;
      case "forget":
      case "prepare_patch":
      case "run_safe_tests":
        categories.add("tool_status");
        break;
      default:
        categories.add("other_tool_output");
    }
  }
  return [...categories];
}

export function AiChatComposer({
  context,
  projectId,
  t,
  setNotice,
}: {
  context: string | null;
  projectId: string | null;
  t: T;
  setNotice: (notice: Notice) => void;
}) {
  const [draft, setDraft] = useState("");
  const [tier, setTier] = useState<AiTier>("analysis");
  const [estimate, setEstimate] = useState<AiRequestEstimate | null>(null);
  const [approvedPrompt, setApprovedPrompt] = useState("");
  const [busy, setBusy] = useState(false);
  const [response, setResponse] = useState("");
  const [primaryProviderName, setPrimaryProviderName] = useState<string | null>(null);
  const [fallbackProvider, setFallbackProvider] = useState<{ id: string; name: string } | null>(
    null,
  );
  const [fallbackAvailable, setFallbackAvailable] = useState(false);
  const outputCategories = estimate ? toolOutputCategories(estimate.enabled_tools) : [];

  useEffect(() => {
    let active = true;
    setFallbackAvailable(false);
    if (!projectId) {
      setPrimaryProviderName(null);
      setFallbackProvider(null);
      return () => {
        active = false;
      };
    }
    void api
      .aiConfiguration()
      .then((configuration) => {
        if (!active) return;
        const assignment = configuration.settings.assignments.find((item) => item.tier === tier);
        const primary = configuration.providers.find(
          (provider) => provider.id === assignment?.provider_id,
        );
        const fallback = configuration.providers.find(
          (provider) => provider.id === assignment?.fallback_provider_id,
        );
        setPrimaryProviderName(primary?.display_name ?? null);
        setFallbackProvider(fallback ? { id: fallback.id, name: fallback.display_name } : null);
      })
      .catch(() => {
        if (active) {
          setPrimaryProviderName(null);
          setFallbackProvider(null);
        }
      });
    return () => {
      active = false;
    };
  }, [projectId, tier]);

  async function requestEstimate(event: FormEvent) {
    event.preventDefault();
    if (!projectId) {
      setNotice({ kind: "error", message: t("ai.selectProject") });
      return;
    }
    setBusy(true);
    try {
      setApprovedPrompt(draft);
      setEstimate(await api.estimateAiRequest(projectId, tier, draft));
    } catch (error) {
      setNotice({ kind: "error", message: errorCopy(error, t) });
      setFallbackAvailable(error === "ai_budget_exceeded" && Boolean(fallbackProvider));
    } finally {
      setBusy(false);
    }
  }

  async function approveAndSend() {
    if (!estimate) return;
    setBusy(true);
    try {
      const result = await api.runAiRequest(
        estimate.project_id,
        estimate.tier,
        approvedPrompt,
        estimate.provider_id,
        estimate.approval_digest,
      );
      setResponse(result.response);
      setDraft("");
      setEstimate(null);
    } catch (error) {
      setNotice({ kind: "error", message: errorCopy(error, t) });
      setFallbackAvailable(false);
      setEstimate(null);
    } finally {
      setBusy(false);
    }
  }

  async function reviewFallback() {
    if (!projectId || !fallbackProvider) return;
    setBusy(true);
    try {
      setEstimate(
        await api.estimateAiRequest(projectId, tier, approvedPrompt, fallbackProvider.id),
      );
      setFallbackAvailable(false);
    } catch (error) {
      setNotice({ kind: "error", message: errorCopy(error, t) });
      setFallbackAvailable(false);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <form className="composer" onSubmit={(event) => void requestEstimate(event)}>
        <div className="composer-context">
          <span>{t("composer.context")}</span>
          <span className="context-chip">@{context ?? t("common.workspace")}</span>
          <span className="tag unverified">
            {projectId ? t("ai.readyToReview") : t("composer.notConfigured")}
          </span>
        </div>
        <label className="sr-only" htmlFor="question-composer">
          {t("composer.placeholder")}
        </label>
        <div className="composer-input">
          <textarea
            id="question-composer"
            value={draft}
            onChange={(event) => {
              setDraft(event.target.value);
              setFallbackAvailable(false);
            }}
            placeholder={t("composer.placeholder")}
            rows={2}
            disabled={!projectId || busy}
          />
          <button
            className="button primary"
            type="submit"
            aria-label={t("composer.send")}
            disabled={!projectId || !draft.trim() || busy}
          >
            <span aria-hidden="true">↑</span>
          </button>
        </div>
        <div className="composer-meta">
          <label className="inline-control">
            <span>{t("ai.tier")}</span>
            <select
              value={tier}
              onChange={(event) => {
                setTier(event.target.value as AiTier);
                setFallbackAvailable(false);
              }}
            >
              {["triage", "analysis", "patch"].map((value) => (
                <option key={value} value={value}>
                  {t(`ai.tiers.${value}`)}
                </option>
              ))}
            </select>
          </label>
          <span>
            {t("composer.provider")}: {primaryProviderName ?? t("common.notConfigured")}
          </span>
          <span>{t("ai.costShownAfterReview")}</span>
        </div>
        {fallbackAvailable && fallbackProvider && (
          <div className="ai-response">
            <span>
              {t("ai.fallbackAvailable")}: {fallbackProvider.name}
            </span>
            <button
              className="button secondary"
              type="button"
              disabled={busy}
              onClick={() => void reviewFallback()}
            >
              {t("ai.reviewFallback")}
            </button>
          </div>
        )}
        {response && (
          <div className="ai-response" aria-live="polite">
            <strong>{t("ai.response")}</strong>
            <p>{response}</p>
          </div>
        )}
      </form>
      {estimate && (
        <div className="dialog-backdrop" role="presentation">
          <section
            className="dialog panel"
            role="dialog"
            aria-modal="true"
            aria-labelledby="ai-approval-title"
          >
            <div className="panel-heading">
              <h2 id="ai-approval-title">{t("ai.approvalTitle")}</h2>
              <button
                className="icon-button"
                aria-label={t("actions.close")}
                onClick={() => setEstimate(null)}
              >
                ×
              </button>
            </div>
            <p>{t("ai.approvalHelp")}</p>
            <dl className="ai-approval-details">
              <dt>{t("ai.provider")}</dt>
              <dd>
                {estimate.provider_name} · {estimate.model}
              </dd>
              <dt>{t("ai.destination")}</dt>
              <dd>{estimate.destination_origin}</dd>
              <dt>{t("ai.dataRegion")}</dt>
              <dd>{estimate.data_region ?? t("ai.regionUnknown")}</dd>
              <dt>{t("ai.dataCategory")}</dt>
              <dd>{t(`ai.categories.${estimate.data_category}`)}</dd>
              <dt>{t("ai.enabledForRun")}</dt>
              <dd>
                {estimate.enabled_tools.length
                  ? estimate.enabled_tools.map((name) => t(`ai.tools.${name}`)).join(", ")
                  : t("ai.noTools")}
              </dd>
              <dt>{t("ai.toolOutputData")}</dt>
              <dd>
                {outputCategories.length ? (
                  <ul className="ai-tool-categories">
                    {outputCategories.map((category) => (
                      <li key={category}>{t(`ai.outputCategories.${category}`)}</li>
                    ))}
                  </ul>
                ) : (
                  t("ai.noToolOutputData")
                )}
              </dd>
              <dt>{t("ai.estimatedTokens")}</dt>
              <dd>
                {estimate.estimated_input_tokens} {t("ai.tokenInput")} /{" "}
                {estimate.estimated_output_tokens} {t("ai.tokenOutput")}
              </dd>
              <dt>{t("ai.estimatedCost")}</dt>
              <dd>${estimate.estimated_cost_usd.toFixed(4)}</dd>
              <dt>{t("ai.redactions")}</dt>
              <dd>{estimate.redacted_values}</dd>
            </dl>
            <label className="field">
              <span>{t("ai.redactedPrompt")}</span>
              <textarea readOnly rows={5} value={estimate.redacted_prompt} />
            </label>
            <div className="button-row end">
              <button
                className="button quiet"
                onClick={() => {
                  setEstimate(null);
                  setFallbackAvailable(false);
                }}
              >
                {t("actions.cancel")}
              </button>
              <button
                className="button primary"
                disabled={busy}
                onClick={() => void approveAndSend()}
              >
                {busy ? t("common.loading") : t("ai.approveAndSend")}
              </button>
            </div>
          </section>
        </div>
      )}
    </>
  );
}

function errorCopy(error: unknown, t: T): string {
  const code = typeof error === "string" ? error : "unknown";
  return t(`error.${code}`);
}
