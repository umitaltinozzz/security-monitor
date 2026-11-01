import { useCallback, useEffect, useState, type ChangeEvent, type FormEvent } from "react";
import type { AiConfigurationView } from "./generated/AiConfigurationView";
import type { AgentCliProduct } from "./generated/AgentCliProduct";
import type { AiProviderInput } from "./generated/AiProviderInput";
import type { AiSettings } from "./generated/AiSettings";
import type { AiTier } from "./generated/AiTier";
import type { MemoryArchive } from "./generated/MemoryArchive";
import type { Project } from "./generated/Project";
import type { WorkspaceData } from "./api";
import { api } from "./api";
import { MemoryNotes } from "./MemoryNotes";

type T = (key: string) => string;
type Notice = { message: string; kind: "error" | "success" } | null;

export function AiSettingsPanel({
  data,
  t,
  setNotice,
  refreshProjects,
}: {
  data: WorkspaceData;
  t: T;
  setNotice: (notice: Notice) => void;
  refreshProjects: () => void;
}) {
  const [configuration, setConfiguration] = useState<AiConfigurationView | null>(null);
  const [providerName, setProviderName] = useState("");
  const [kind, setKind] = useState<AiProviderInput["kind"]>("open_ai_compatible");
  const [cliProduct, setCliProduct] = useState<AgentCliProduct>("codex");
  const [baseUrl, setBaseUrl] = useState("");
  const [model, setModel] = useState("");
  const [region, setRegion] = useState("");
  const [inputPrice, setInputPrice] = useState("");
  const [outputPrice, setOutputPrice] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [editId, setEditId] = useState<string | null>(null);
  const [showProviderForm, setShowProviderForm] = useState(false);
  const [toolCalling, setToolCalling] = useState(true);
  const [busy, setBusy] = useState(false);
  const [retentionDays, setRetentionDays] = useState(180);
  const tierOptions: AiTier[] = ["triage", "analysis", "patch"];
  const toolOptions = [
    "list_projects",
    "list_assets",
    "list_findings",
    "get_finding_evidence",
    "compare_repo_deployment",
    "read_project_file",
    "search_project",
    "analyze_impact",
    "prepare_patch",
    "run_safe_tests",
    "recall",
    "remember",
    "forget",
  ];

  const load = useCallback(async () => {
    try {
      setConfiguration(await api.aiConfiguration());
    } catch {
      setNotice({ kind: "error", message: t("error.storage_unavailable") });
    }
  }, [setNotice, t]);
  useEffect(() => {
    void load();
  }, [load]);
  const configuredRetentionDays = configuration?.settings.memory_retention_days;
  useEffect(() => {
    if (configuredRetentionDays !== undefined) setRetentionDays(configuredRetentionDays);
  }, [configuredRetentionDays]);

  async function saveProvider(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      await api.saveAiProvider({
        id: editId,
        kind,
        cli_product: kind === "agent_cli" ? cliProduct : null,
        display_name: providerName,
        base_url: kind === "agent_cli" ? null : baseUrl,
        model: kind === "agent_cli" ? null : model,
        capabilities: {
          tool_calling: kind === "agent_cli" ? false : toolCalling,
          context_window: null,
          json_mode: false,
        },
        price_in: kind === "agent_cli" || inputPrice === "" ? null : Number(inputPrice),
        price_out: kind === "agent_cli" || outputPrice === "" ? null : Number(outputPrice),
        data_region: kind === "agent_cli" ? null : region || null,
        api_key: kind === "agent_cli" ? null : apiKey || null,
      });
      resetForm();
      setNotice({ kind: "success", message: t("ai.providerSaved") });
      await load();
    } catch {
      setNotice({ kind: "error", message: t("error.invalid_input") });
    } finally {
      setBusy(false);
    }
  }

  function resetForm() {
    setProviderName("");
    setBaseUrl("");
    setModel("");
    setRegion("");
    setInputPrice("");
    setOutputPrice("");
    setApiKey("");
    setEditId(null);
    setShowProviderForm(false);
    setKind("open_ai_compatible");
    setCliProduct("codex");
    setToolCalling(true);
  }

  function applyPreset(
    preset: "opencode_go" | "opencode_zen" | "openai" | "anthropic" | "ollama" | "opencode_cli",
  ) {
    setShowProviderForm(true);
    if (preset === "opencode_go") {
      setKind("open_ai_compatible");
      setProviderName("OpenCode Go");
      setBaseUrl("https://opencode.ai/zen/go/v1");
      setModel("glm-5");
      setToolCalling(true);
    } else if (preset === "opencode_zen") {
      setKind("open_ai_compatible");
      setProviderName("OpenCode Zen");
      setBaseUrl("https://opencode.ai/zen/v1");
      setModel("claude-sonnet-4-5");
      setToolCalling(true);
    } else if (preset === "openai") {
      setKind("open_ai_compatible");
      setProviderName("OpenAI");
      setBaseUrl("https://api.openai.com/v1");
      setModel("gpt-4.1-mini");
      setToolCalling(true);
    } else if (preset === "anthropic") {
      setKind("anthropic");
      setProviderName("Anthropic Claude");
      setBaseUrl("https://api.anthropic.com");
      setModel("claude-sonnet-4-5");
      setToolCalling(true);
    } else if (preset === "ollama") {
      setKind("local");
      setProviderName("Ollama");
      setBaseUrl("http://localhost:11434/v1");
      setModel("qwen2.5-coder:14b");
      setToolCalling(true);
    } else if (preset === "opencode_cli") {
      setKind("agent_cli");
      setCliProduct("opencode");
      setProviderName("OpenCode CLI");
    }
  }

  function editProvider(provider: AiConfigurationView["providers"][number]) {
    setEditId(provider.id);
    setShowProviderForm(true);
    setKind(provider.kind);
    setProviderName(provider.display_name);
    setBaseUrl(provider.base_url ?? "");
    setCliProduct(provider.cli_product ?? "codex");
    setModel(provider.model ?? "");
    setRegion(provider.data_region ?? "");
    setInputPrice(provider.price_in?.toString() ?? "");
    setOutputPrice(provider.price_out?.toString() ?? "");
    setToolCalling(provider.capabilities.tool_calling);
    setApiKey("");
  }

  async function saveSettings(next: AiSettings) {
    try {
      await api.saveAiSettings(next);
      setConfiguration((current) => (current ? { ...current, settings: next } : current));
      setNotice({ kind: "success", message: t("ai.settingsSaved") });
    } catch {
      setNotice({ kind: "error", message: t("error.invalid_input") });
    }
  }

  async function exportMemoryArchive() {
    try {
      const archive = await api.exportMemories();
      const url = URL.createObjectURL(
        new Blob([JSON.stringify(archive, null, 2)], { type: "application/json" }),
      );
      const link = document.createElement("a");
      link.href = url;
      link.download = "security-monitor-memories.json";
      link.click();
      URL.revokeObjectURL(url);
    } catch {
      setNotice({ kind: "error", message: t("ai.memoryExportFailed") });
    }
  }

  async function importMemoryArchive(event: ChangeEvent<HTMLInputElement>) {
    const file = event.currentTarget.files?.[0];
    event.currentTarget.value = "";
    if (!file) return;
    try {
      const archive = JSON.parse(await file.text()) as MemoryArchive;
      const imported = await api.importMemories(archive);
      setNotice({
        kind: "success",
        message: t("ai.memoryImported").replace("{count}", String(imported)),
      });
    } catch {
      setNotice({ kind: "error", message: t("ai.memoryImportFailed") });
    }
  }

  async function clearMemories() {
    if (!window.confirm(t("ai.memoryClearConfirm"))) return;
    try {
      const count = await api.deleteAllMemories();
      setNotice({
        kind: "success",
        message: t("ai.memoryDeletedAll").replace("{count}", String(count)),
      });
    } catch {
      setNotice({ kind: "error", message: t("error.storage_unavailable") });
    }
  }

  async function setProjectProviders(project: Project, providerId: string, enabled: boolean) {
    const ids = enabled
      ? [...new Set([...project.allowed_ai_providers, providerId])]
      : project.allowed_ai_providers.filter((id) => id !== providerId);
    try {
      await api.setProjectAiProviders(project.id, ids);
      refreshProjects();
      setNotice({ kind: "success", message: t("ai.projectPermissionsSaved") });
    } catch {
      setNotice({ kind: "error", message: t("error.storage_unavailable") });
    }
  }

  if (!configuration)
    return (
      <section className="panel settings-panel">
        <h2>{t("ai.title")}</h2>
        <p>{t("common.loading")}</p>
      </section>
    );
  const aiSettings = configuration.settings;
  const apiProviders = configuration.providers.filter((provider) => provider.kind !== "agent_cli");
  function setAssignment(
    tier: AiTier,
    field: "provider_id" | "fallback_provider_id",
    value: string,
  ) {
    const previous = aiSettings.assignments.find((item) => item.tier === tier);
    const assignments = aiSettings.assignments.filter((item) => item.tier !== tier);
    assignments.push({
      tier,
      provider_id: field === "provider_id" ? value || null : (previous?.provider_id ?? null),
      fallback_provider_id:
        field === "fallback_provider_id" ? value || null : (previous?.fallback_provider_id ?? null),
    });
    void saveSettings({ ...aiSettings, assignments });
  }
  function toggleTool(tool: string, enabled: boolean) {
    const enabledTools = enabled
      ? [...new Set([...aiSettings.enabled_tools, tool])]
      : aiSettings.enabled_tools.filter((item) => item !== tool);
    void saveSettings({ ...aiSettings, enabled_tools: enabledTools });
  }
  function toggleMcpSourceProject(projectId: string, enabled: boolean) {
    const projects = enabled
      ? [...new Set([...aiSettings.mcp_source_access_projects, projectId])]
      : aiSettings.mcp_source_access_projects.filter((item) => item !== projectId);
    void saveSettings({ ...aiSettings, mcp_source_access_projects: projects });
  }
  function saveBudget(field: "daily_total_usd" | "monthly_total_usd", value: string) {
    const numberValue = value === "" ? null : Number(value);
    void saveSettings({ ...aiSettings, budget: { ...aiSettings.budget, [field]: numberValue } });
  }
  function saveProviderBudget(
    providerId: string,
    field: "daily_by_provider_usd" | "monthly_by_provider_usd",
    value: string,
  ) {
    const next = { ...aiSettings.budget[field] };
    if (value === "") delete next[providerId];
    else next[providerId] = Number(value);
    void saveSettings({ ...aiSettings, budget: { ...aiSettings.budget, [field]: next } });
  }

  return (
    <>
      <section className="panel settings-panel ai-panel">
        <div className="settings-card-head row">
          <div>
            <h3>{t("ai.title")}</h3>
            <p>{t("ai.description")}</p>
          </div>
          {!showProviderForm && (
            <button
              type="button"
              className="button primary small"
              onClick={() => setShowProviderForm(true)}
            >
              + {t("ai.addProvider")}
            </button>
          )}
        </div>

        {!showProviderForm && (
          <div className="preset-block">
            <span className="settings-label">{t("ai.presetsTitle")}</span>
            <div className="preset-grid">
              {(
                [
                  ["opencode_go", "ai.presetOpenCodeGo"],
                  ["opencode_zen", "ai.presetOpenCodeZen"],
                  ["openai", "ai.presetOpenAi"],
                  ["anthropic", "ai.presetAnthropic"],
                  ["ollama", "ai.presetOllama"],
                  ["opencode_cli", "ai.presetOpenCodeCli"],
                ] as const
              ).map(([preset, label]) => (
                <button
                  key={preset}
                  type="button"
                  className="preset-card"
                  onClick={() => applyPreset(preset)}
                >
                  {t(label)}
                </button>
              ))}
            </div>
          </div>
        )}

        <span className="settings-label">{t("ai.providers")}</span>
        {configuration.providers.length === 0 ? (
          <p className="settings-empty">{t("ai.noProviders")}</p>
        ) : (
          <ul className="ai-provider-list">
            {configuration.providers.map((provider) => (
              <li key={provider.id}>
                <span>
                  <strong>{provider.display_name}</strong>
                  <small>
                    {provider.kind === "agent_cli"
                      ? t(`ai.cliProducts.${provider.cli_product ?? "unknown"}`)
                      : `${provider.model ?? t("common.unknown")} · ${provider.data_region ?? t("ai.regionUnknown")}`}
                  </small>
                  {provider.base_url && <small>{provider.base_url}</small>}
                  <small>
                    {provider.kind === "agent_cli"
                      ? t("ai.agentCli")
                      : provider.keychain_ref
                        ? t("ai.keySaved")
                        : t("ai.noKey")}
                  </small>
                </span>
                <span
                  className={`tag ${provider.kind === "local" || provider.kind === "agent_cli" ? "verified" : "unverified"}`}
                >
                  {provider.kind === "agent_cli"
                    ? t("ai.agentCli")
                    : provider.kind === "local"
                      ? t("ai.local")
                      : t("ai.remote")}
                </span>
                <button
                  type="button"
                  className="button secondary small"
                  onClick={() => editProvider(provider)}
                >
                  {t("actions.edit")}
                </button>
              </li>
            ))}
          </ul>
        )}

        {showProviderForm && (
          <form className="ai-provider-form" onSubmit={(event) => void saveProvider(event)}>
            <span className="settings-label full-span">
              {editId ? t("ai.editProvider") : t("ai.addProvider")}
            </span>
            <label className="field">
              <span>{t("ai.providerName")}</span>
              <input
                required
                maxLength={120}
                value={providerName}
                onChange={(event) => setProviderName(event.target.value)}
              />
            </label>
            <label className="field">
              <span>{t("ai.providerType")}</span>
              <select
                value={kind}
                onChange={(event) => setKind(event.target.value as AiProviderInput["kind"])}
              >
                <option value="open_ai_compatible">{t("ai.openAiCompatible")}</option>
                <option value="anthropic">{t("ai.anthropic")}</option>
                <option value="local">{t("ai.local")}</option>
                <option value="agent_cli">{t("ai.agentCli")}</option>
              </select>
            </label>
            {kind === "agent_cli" ? (
              <label className="field">
                <span>{t("ai.agentCliProduct")}</span>
                <select
                  value={cliProduct}
                  onChange={(event) => setCliProduct(event.target.value as AgentCliProduct)}
                >
                  <option value="claude_code">{t("ai.cliProducts.claude_code")}</option>
                  <option value="codex">{t("ai.cliProducts.codex")}</option>
                  <option value="opencode">{t("ai.cliProducts.opencode")}</option>
                </select>
              </label>
            ) : (
              <>
                <label className="field">
                  <span>{t("ai.baseUrl")}</span>
                  <input
                    type="url"
                    required
                    value={baseUrl}
                    onChange={(event) => setBaseUrl(event.target.value)}
                    placeholder={
                      kind === "local"
                        ? "http://localhost:11434/v1"
                        : "https://opencode.ai/zen/go/v1"
                    }
                  />
                </label>
                <label className="field">
                  <span>{t("ai.modelId")}</span>
                  <input
                    required={toolCalling}
                    value={model}
                    onChange={(event) => setModel(event.target.value)}
                    placeholder="glm-5, kimi-k2.5, minimax-m2.5..."
                  />
                </label>
                <label className="field full-span">
                  <span>{t("ai.apiKey")}</span>
                  <input
                    type="password"
                    autoComplete="new-password"
                    value={apiKey}
                    onChange={(event) => setApiKey(event.target.value)}
                    placeholder={editId ? t("ai.keepExistingKey") : ""}
                  />
                </label>
                <label className="settings-row full-span">
                  <span className="settings-row-copy">
                    <strong>{t("ai.toolCalling")}</strong>
                  </span>
                  <input
                    type="checkbox"
                    className="switch"
                    checked={toolCalling}
                    onChange={(event) => setToolCalling(event.target.checked)}
                  />
                </label>
                <details className="settings-details full-span">
                  <summary>{t("ai.advancedProviderFields")}</summary>
                  <div className="form-grid settings-details-body">
                    <label className="field">
                      <span>{t("ai.dataRegion")}</span>
                      <input value={region} onChange={(event) => setRegion(event.target.value)} />
                    </label>
                    <label className="field">
                      <span>{t("ai.priceIn")}</span>
                      <input
                        type="number"
                        min="0"
                        step="any"
                        value={inputPrice}
                        onChange={(event) => setInputPrice(event.target.value)}
                      />
                    </label>
                    <label className="field">
                      <span>{t("ai.priceOut")}</span>
                      <input
                        type="number"
                        min="0"
                        step="any"
                        value={outputPrice}
                        onChange={(event) => setOutputPrice(event.target.value)}
                      />
                    </label>
                  </div>
                </details>
              </>
            )}
            <div className="button-row full-span">
              <button className="button primary" disabled={busy}>
                {busy ? t("common.loading") : t("actions.save")}
              </button>
              <button type="button" className="button quiet" onClick={resetForm}>
                {t("actions.cancel")}
              </button>
            </div>
          </form>
        )}

        <div className="ai-tier-section">
          <span className="settings-label">{t("ai.tierAssignments")}</span>
          <div className="ai-tier-grid">
            {tierOptions.map((tier) => {
              const assignment = aiSettings.assignments.find((item) => item.tier === tier);
              return (
                <div className="ai-tier-card" key={tier}>
                  <strong>{t(`ai.tiers.${tier}`)}</strong>
                  <label className="field">
                    <span>{t("ai.primaryProvider")}</span>
                    <select
                      value={assignment?.provider_id ?? ""}
                      onChange={(event) => setAssignment(tier, "provider_id", event.target.value)}
                    >
                      <option value="">{t("ai.noProvider")}</option>
                      {apiProviders.map((provider) => (
                        <option key={provider.id} value={provider.id}>
                          {provider.display_name}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="field">
                    <span>{t("ai.fallbackProvider")}</span>
                    <select
                      value={assignment?.fallback_provider_id ?? ""}
                      onChange={(event) =>
                        setAssignment(tier, "fallback_provider_id", event.target.value)
                      }
                    >
                      <option value="">{t("ai.noProvider")}</option>
                      {apiProviders.map((provider) => (
                        <option key={provider.id} value={provider.id}>
                          {provider.display_name}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      <>
        <section className="panel settings-panel ai-panel">
          <div className="settings-card-head">
            <h3>{t("ai.projectPermissions")}</h3>
          </div>
          {data.projects.length === 0 ? (
            <p className="settings-empty">{t("projects.empty")}</p>
          ) : configuration.providers.length === 0 ? (
            <p className="settings-empty">{t("ai.permissionsNeedProvider")}</p>
          ) : (
            data.projects.map((project) => (
              <div className="ai-project-row" key={project.id}>
                <strong>{project.name}</strong>
                <div className="choice-grid">
                  {configuration.providers.map((provider) => (
                    <label className="check-field pill-check" key={provider.id}>
                      <input
                        type="checkbox"
                        checked={project.allowed_ai_providers.includes(provider.id)}
                        onChange={(event) =>
                          void setProjectProviders(project, provider.id, event.target.checked)
                        }
                      />
                      <span>{provider.display_name}</span>
                    </label>
                  ))}
                </div>
              </div>
            ))
          )}
        </section>

        <section className="panel settings-panel ai-panel">
          <div className="settings-card-head">
            <h3>{t("ai.mcpSourceAccess")}</h3>
            <p>{t("ai.mcpSourceAccessHelp")}</p>
          </div>
          {data.projects.length === 0 ? (
            <p>{t("projects.empty")}</p>
          ) : (
            <div className="choice-grid">
              {data.projects.map((project) => (
                <label className="check-field pill-check" key={project.id}>
                  <input
                    type="checkbox"
                    checked={aiSettings.mcp_source_access_projects.includes(project.id)}
                    onChange={(event) => toggleMcpSourceProject(project.id, event.target.checked)}
                  />
                  <span>{project.name}</span>
                </label>
              ))}
            </div>
          )}
        </section>
      </>

      <details className="panel settings-panel ai-panel settings-collapsible">
        <summary>
          <h3>{t("ai.advancedBudgetAndTools")}</h3>
        </summary>
        <div className="settings-collapsible-body">
          <h4>{t("ai.budget")}</h4>
          <div className="form-grid">
            <label className="field">
              <span>{t("ai.dailyTotal")}</span>
              <input
                type="number"
                min="0"
                step="any"
                value={aiSettings.budget.daily_total_usd ?? ""}
                onChange={(event) => saveBudget("daily_total_usd", event.target.value)}
              />
            </label>
            <label className="field">
              <span>{t("ai.monthlyTotal")}</span>
              <input
                type="number"
                min="0"
                step="any"
                value={aiSettings.budget.monthly_total_usd ?? ""}
                onChange={(event) => saveBudget("monthly_total_usd", event.target.value)}
              />
            </label>
          </div>
          {configuration.providers.map((provider) => (
            <div className="ai-tier-row" key={`budget-${provider.id}`}>
              <strong>{provider.display_name}</strong>
              <label className="field">
                <span>{t("ai.dailyProvider")}</span>
                <input
                  type="number"
                  min="0"
                  step="any"
                  value={aiSettings.budget.daily_by_provider_usd[provider.id] ?? ""}
                  onChange={(event) =>
                    saveProviderBudget(provider.id, "daily_by_provider_usd", event.target.value)
                  }
                />
              </label>
              <label className="field">
                <span>{t("ai.monthlyProvider")}</span>
                <input
                  type="number"
                  min="0"
                  step="any"
                  value={aiSettings.budget.monthly_by_provider_usd[provider.id] ?? ""}
                  onChange={(event) =>
                    saveProviderBudget(provider.id, "monthly_by_provider_usd", event.target.value)
                  }
                />
              </label>
            </div>
          ))}
          <label className="setting-row">
            <span>
              <strong>{t("ai.allowTriageCode")}</strong>
              <small>{t("ai.allowTriageCodeHelp")}</small>
            </span>
            <input
              type="checkbox"
              checked={aiSettings.triage_code_enabled}
              onChange={(event) =>
                void saveSettings({ ...aiSettings, triage_code_enabled: event.target.checked })
              }
            />
          </label>
          <h4>{t("ai.enabledTools")}</h4>
          <div className="choice-grid wide">
            {toolOptions.map((tool) => (
              <label className="check-field pill-check" key={tool}>
                <input
                  type="checkbox"
                  checked={aiSettings.enabled_tools.includes(tool)}
                  onChange={(event) => toggleTool(tool, event.target.checked)}
                />
                <span>{t(`ai.tools.${tool}`)}</span>
              </label>
            ))}
          </div>
        </div>
      </details>

      <details className="panel settings-panel ai-panel settings-collapsible">
        <summary>
          <h3>{t("ai.memoryTitle")}</h3>
        </summary>
        <div className="settings-collapsible-body">
          <p>{t("ai.memoryDescription")}</p>
          <div className="form-grid">
            <label className="check-field">
              <input
                type="checkbox"
                checked={aiSettings.memory_agent_writes_enabled}
                onChange={(event) =>
                  void saveSettings({
                    ...aiSettings,
                    memory_agent_writes_enabled: event.target.checked,
                  })
                }
              />
              {t("ai.memoryAgentWrites")}
            </label>
            <label className="field">
              <span>{t("ai.memoryRetention")}</span>
              <input
                type="number"
                min={1}
                max={3650}
                value={retentionDays}
                onChange={(event) => setRetentionDays(Number(event.target.value))}
                onBlur={() => {
                  if (
                    Number.isInteger(retentionDays) &&
                    retentionDays >= 1 &&
                    retentionDays <= 3650
                  )
                    void saveSettings({ ...aiSettings, memory_retention_days: retentionDays });
                  else setRetentionDays(aiSettings.memory_retention_days);
                }}
              />
            </label>
          </div>
          <div className="button-row">
            <button
              type="button"
              className="button secondary"
              onClick={() => void exportMemoryArchive()}
            >
              {t("ai.memoryExport")}
            </button>
            <label className="button secondary file-button">
              {t("ai.memoryImport")}
              <input
                type="file"
                accept="application/json,.json"
                onChange={(event) => void importMemoryArchive(event)}
              />
            </label>
            <button type="button" className="button danger" onClick={() => void clearMemories()}>
              {t("ai.memoryDeleteAll")}
            </button>
          </div>
          <MemoryNotes scope="global" t={t} setNotice={setNotice} />
        </div>
      </details>

      <details className="panel settings-panel ai-panel settings-collapsible">
        <summary>
          <h3>{t("ai.runHistory")}</h3>
        </summary>
        <div className="settings-collapsible-body">
          {configuration.runs.length === 0 ? (
            <p>{t("common.noResults")}</p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>{t("ai.modelId")}</th>
                    <th>{t("ai.tier")}</th>
                    <th>{t("ai.tokens")}</th>
                    <th>{t("ai.cost")}</th>
                    <th>{t("common.status")}</th>
                  </tr>
                </thead>
                <tbody>
                  {[...configuration.runs]
                    .sort((a, b) => b.started_at.localeCompare(a.started_at))
                    .map((run) => (
                      <tr key={run.id}>
                        <td>{run.model || t("common.unknown")}</td>
                        <td>{t(`ai.tiers.${run.tier}`)}</td>
                        <td>{run.tokens_in + run.tokens_out}</td>
                        <td>
                          {run.cost === null ? t("common.unverified") : `$${run.cost.toFixed(4)}`}
                        </td>
                        <td>{run.outcome}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </details>
    </>
  );
}
