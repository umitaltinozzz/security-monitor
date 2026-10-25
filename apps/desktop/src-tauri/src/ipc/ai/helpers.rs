use super::*;

pub(super) async fn prepare_ai_request(
    state: &AppState,
    project_id: &str,
    tier: &AiTier,
    prompt: &str,
    provider_override_id: Option<&str>,
) -> Result<(Project, AiProvider, AiSettings, String, usize), String> {
    if prompt.trim().is_empty() || prompt.len() > 128 * 1024 {
        return Err("invalid_input".to_owned());
    }
    let project = state
        .database
        .repository::<Project>()
        .get(project_id)
        .await
        .map_err(|_| "storage_unavailable".to_owned())?
        .ok_or_else(|| "project_not_found".to_owned())?;
    let settings = state.ai_settings.read().await.clone();
    let assignment = settings
        .assignments
        .iter()
        .find(|assignment| assignment.tier == *tier)
        .ok_or_else(|| "ai_provider_not_configured".to_owned())?;
    let primary_provider_id = assignment
        .provider_id
        .as_deref()
        .ok_or_else(|| "ai_provider_not_configured".to_owned())?;
    let provider_id = match provider_override_id {
        Some(id)
            if id == primary_provider_id
                || assignment.fallback_provider_id.as_deref() == Some(id) =>
        {
            id
        }
        Some(_) => return Err("invalid_input".to_owned()),
        None => primary_provider_id,
    };
    if !project
        .allowed_ai_providers
        .iter()
        .any(|id| id == provider_id)
    {
        return Err("ai_provider_not_allowed".to_owned());
    }
    let provider = state
        .database
        .repository::<AiProvider>()
        .get(provider_id)
        .await
        .map_err(|_| "storage_unavailable".to_owned())?
        .ok_or_else(|| "provider_not_found".to_owned())?;
    validate_provider_config(&provider).map_err(|_| "invalid_input".to_owned())?;
    let host_aliases = load_ai_host_aliases(&state.database).await;
    let redacted = redact_text_with_host_aliases(prompt, &host_aliases);
    Ok((
        project,
        provider,
        settings,
        redacted.text,
        redacted.redacted_values,
    ))
}

pub(super) async fn load_ai_host_aliases(database: &Database) -> BTreeMap<String, String> {
    let mut aliases = BTreeMap::new();
    if let Ok((hosts, _warnings)) = load_user_ssh_hosts() {
        aliases.extend(
            hosts
                .into_iter()
                .map(|host| (host.hostname.to_ascii_lowercase(), host.alias)),
        );
    }
    let Ok(assets) = database.repository::<Asset>().list().await else {
        return aliases;
    };
    let store = OsCredentialStore;
    for asset in assets {
        let Some(reference) = asset.ssh_target_ref.as_deref() else {
            continue;
        };
        let Ok(bytes) = store.get(reference) else {
            continue;
        };
        let Ok(stored) = serde_json::from_slice::<StoredSshTarget>(&bytes) else {
            continue;
        };
        let Ok(target) = to_ssh_target(stored.target) else {
            continue;
        };
        aliases.insert(target.hostname.to_ascii_lowercase(), asset.hostname_alias);
    }
    aliases
}

pub(super) async fn make_ai_estimate(
    state: &AppState,
    project_id: &str,
    tier: &AiTier,
    prompt: &str,
    provider_override_id: Option<&str>,
) -> Result<AiRequestEstimate, String> {
    let (project, provider, settings, content, redacted_values) =
        prepare_ai_request(state, project_id, tier, prompt, provider_override_id).await?;
    if !provider.capabilities.tool_calling
        && !settings.enabled_tools.is_empty()
        && !matches!(tier, AiTier::Triage)
    {
        return Err("ai_tool_calling_unsupported".to_owned());
    }
    let initial_input_tokens = estimate_tokens(&content).saturating_add(256);
    let output_tokens_per_call = MAX_OUTPUT_TOKENS_PER_CALL;
    let tools_enabled = provider.capabilities.tool_calling && !settings.enabled_tools.is_empty();
    let (estimated_input_tokens, estimated_output_tokens) =
        maximum_run_token_bounds(content.len(), tools_enabled, output_tokens_per_call);
    if provider
        .capabilities
        .context_window
        .is_some_and(|limit| initial_input_tokens.saturating_add(output_tokens_per_call) > limit)
    {
        return Err("ai_context_too_large".to_owned());
    }
    let cost = estimate_cost(&provider, estimated_input_tokens, estimated_output_tokens)
        .map_err(|error| ai_error_code(&error.to_string()))?;
    let runs = state
        .database
        .repository::<AiRun>()
        .list()
        .await
        .map_err(|_| "storage_unavailable".to_owned())?;
    let budget = enforce_budget(&settings.budget, &provider, &runs, cost, Utc::now())
        .map_err(|error| ai_error_code(&error.to_string()))?;
    let destination_origin = Url::parse(
        provider
            .base_url
            .as_deref()
            .ok_or_else(|| "invalid_input".to_owned())?,
    )
    .map_err(|_| "invalid_input".to_owned())?
    .origin()
    .ascii_serialization();
    let data_category = configured_data_category(&settings, provider.capabilities.tool_calling);
    let enabled_tools = if provider.capabilities.tool_calling {
        settings.enabled_tools.clone()
    } else {
        Vec::new()
    };
    let approval_digest = make_ai_approval_digest(
        &project,
        &provider,
        tier,
        data_category,
        &content,
        &enabled_tools,
        &settings,
        estimated_input_tokens,
        estimated_output_tokens,
        cost,
        &budget,
        &destination_origin,
    )?;
    Ok(AiRequestEstimate {
        project_id: project.id,
        approval_digest,
        provider_id: provider.id,
        provider_name: provider.display_name,
        model: provider.model.unwrap_or_default(),
        destination_origin,
        data_region: provider.data_region,
        tier: tier.clone(),
        data_category: data_category.to_owned(),
        enabled_tools,
        redacted_values,
        redacted_prompt: content,
        estimated_input_tokens,
        estimated_output_tokens,
        estimated_cost_usd: cost,
        budget,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn make_ai_approval_digest(
    project: &Project,
    provider: &AiProvider,
    tier: &AiTier,
    data_category: &str,
    redacted_prompt: &str,
    enabled_tools: &[String],
    settings: &AiSettings,
    estimated_input_tokens: u64,
    estimated_output_tokens: u64,
    estimated_cost_usd: f64,
    budget: &security_monitor_ai::BudgetDecision,
    destination_origin: &str,
) -> Result<String, String> {
    let mut tools = enabled_tools.to_vec();
    tools.sort();
    tools.dedup();
    let binding = serde_json::to_vec(&(
        (
            "security-monitor-ai-approval-v1",
            &project.id,
            &project.allowed_ai_providers,
            &provider.id,
            provider.updated_at,
            provider.model.as_deref(),
            destination_origin,
            provider.data_region.as_deref(),
            tier,
        ),
        (
            data_category,
            redacted_prompt,
            tools,
            settings.triage_code_enabled,
            estimated_input_tokens,
            estimated_output_tokens,
            estimated_cost_usd,
            budget,
        ),
    ))
    .map_err(|_| "storage_unavailable".to_owned())?;
    Ok(hex::encode(Sha256::digest(binding)))
}

fn configured_data_category(settings: &AiSettings, tool_calling: bool) -> &'static str {
    if !tool_calling {
        return "user_prompt";
    }
    if settings.enabled_tools.is_empty() {
        return "user_prompt";
    }
    if settings
        .enabled_tools
        .iter()
        .any(|tool| matches!(tool.as_str(), "read_project_file" | "search_project"))
    {
        "source_code"
    } else if settings.enabled_tools.iter().any(|tool| {
        matches!(
            tool.as_str(),
            "list_assets"
                | "list_findings"
                | "get_finding_evidence"
                | "compare_repo_deployment"
                | "analyze_impact"
        )
    }) {
        "inventory"
    } else {
        "user_prompt"
    }
}

pub(super) fn configured_data_category_enum(
    settings: &AiSettings,
    tool_calling: bool,
) -> DataCategory {
    match configured_data_category(settings, tool_calling) {
        "source_code" => DataCategory::SourceCode,
        "inventory" => DataCategory::Inventory,
        _ => DataCategory::UserPrompt,
    }
}

fn estimate_tokens(text: &str) -> u64 {
    u64::try_from(text.len().saturating_add(3) / 4).unwrap_or(u64::MAX)
}

pub(super) fn ai_error_code(message: &str) -> &'static str {
    match message {
        "provider pricing is incomplete" => "ai_price_unknown",
        "AI daily or monthly budget would be exceeded" => "ai_budget_exceeded",
        "usage history contains an unknown cost; budget cannot be verified" => {
            "ai_budget_unverified"
        }
        "project has not allowed this provider" => "ai_provider_not_allowed",
        "source code is disabled for the selected tier" => "ai_code_not_allowed",
        "explicit data transfer approval is required" => "permission_denied",
        _ => "ai_request_failed",
    }
}
