use super::*;

pub struct WorkspaceTools {
    pub(super) database: Database,
    pub(super) approved_projects: BTreeSet<String>,
    pub(super) global_memory_allowed: bool,
    pub(super) host_aliases: BTreeMap<String, String>,
    pub(super) remediation_queue_dir: Option<PathBuf>,
    pub(super) memory_agent: String,
    pub(super) memory_writes_enabled: bool,
    pub(super) memory_retention_days: u32,
    pub(super) memory_context_enabled: bool,
}

impl WorkspaceTools {
    pub fn new(database: Database, source_access_project: Option<String>) -> Self {
        let global_memory_allowed = source_access_project.is_none();
        let mut tools = Self::with_approved_source_projects(database, source_access_project);
        tools.global_memory_allowed = global_memory_allowed;
        tools
    }

    pub fn with_approved_source_projects(
        database: Database,
        source_access_projects: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            database,
            approved_projects: source_access_projects.into_iter().collect(),
            global_memory_allowed: true,
            host_aliases: BTreeMap::new(),
            remediation_queue_dir: None,
            memory_agent: "agent".into(),
            memory_writes_enabled: false,
            memory_retention_days: 180,
            memory_context_enabled: false,
        }
    }

    pub fn with_host_aliases(
        mut self,
        aliases: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        self.host_aliases = aliases
            .into_iter()
            .map(|(hostname, alias)| (hostname.to_ascii_lowercase(), alias))
            .collect();
        self
    }

    pub fn with_remediation_queue_dir(mut self, app_data_dir: impl Into<PathBuf>) -> Self {
        self.remediation_queue_dir = Some(app_data_dir.into());
        self
    }

    pub fn with_memory_settings(
        mut self,
        agent: &str,
        writes_enabled: bool,
        retention_days: u32,
        context_enabled: bool,
    ) -> Self {
        self.memory_agent = agent.to_owned();
        self.memory_writes_enabled = writes_enabled;
        self.memory_retention_days = retention_days.clamp(1, 3650);
        self.memory_context_enabled = context_enabled;
        self
    }

    async fn call(&self, name: &str, arguments: &Value) -> Result<Value, McpError> {
        match name {
            "list_projects" => {
                let projects = self
                    .database
                    .repository::<Project>()
                    .list()
                    .await
                    .map_err(McpError::Database)?;
                Ok(json!(
                    projects
                        .into_iter()
                        .filter(|project| self.approved_projects.contains(&project.id))
                        .map(|project| json!({"id":project.id,"name":project.name,
                    "last_scan_at":project.last_scan_at}))
                        .collect::<Vec<_>>()
                ))
            }
            "list_assets" => {
                let assets = self
                    .database
                    .repository::<Asset>()
                    .list()
                    .await
                    .map_err(McpError::Database)?;
                let links = self
                    .database
                    .repository::<ProjectServerLink>()
                    .list()
                    .await
                    .map_err(McpError::Database)?;
                let approved_assets: BTreeSet<_> = links
                    .into_iter()
                    .filter(|link| self.approved_projects.contains(&link.project_id))
                    .map(|link| link.asset_id)
                    .collect();
                Ok(json!(assets.into_iter().filter(|asset| approved_assets.contains(&asset.id)).map(|asset| json!({"id":asset.id,"alias":asset.hostname_alias,
                    "environment":asset.environment,"last_success_at":asset.last_success_at,
                    "verification":if asset.last_success_at.is_some() {"observed"} else {"needs_review"}})).collect::<Vec<_>>()))
            }
            "list_findings" => self.list_findings(arguments).await,
            "get_finding_evidence" => self.get_finding_evidence(arguments).await,
            "compare_repo_deployment" => self.compare_repo_deployment(arguments).await,
            "read_project_file" => self.read_project_file(arguments).await,
            "search_project" => self.search_project(arguments).await,
            "analyze_impact" => self.analyze_impact(arguments).await,
            "recall" => self.recall(arguments).await,
            "remember" => self.remember(arguments).await,
            "forget" => self.forget(arguments).await,
            "prepare_patch" => self.prepare_patch(arguments).await,
            "run_safe_tests" => self.request_safe_tests(arguments).await,
            _ => Err(McpError::ResourceUnavailable),
        }
    }

    pub(super) async fn project(&self, id: &str) -> Result<Project, McpError> {
        self.database
            .repository::<Project>()
            .get(id)
            .await
            .map_err(McpError::Database)?
            .ok_or(McpError::ResourceUnavailable)
    }

    async fn list_findings(&self, arguments: &Value) -> Result<Value, McpError> {
        let project_id = optional_string(arguments, "project_id")?;
        if project_id
            .as_deref()
            .is_some_and(|id| !self.approved_projects.contains(id))
        {
            return Err(McpError::PermissionDenied);
        }
        let findings = self
            .database
            .repository::<Finding>()
            .list()
            .await
            .map_err(McpError::Database)?;
        let instances = self
            .database
            .repository::<ComponentInstance>()
            .list()
            .await
            .map_err(McpError::Database)?;
        let components = self
            .database
            .repository::<Component>()
            .list()
            .await
            .map_err(McpError::Database)?;
        let advisories = self
            .database
            .repository::<Advisory>()
            .list()
            .await
            .map_err(McpError::Database)?;
        let instance_by_id: BTreeMap<_, _> = instances
            .into_iter()
            .map(|item| (item.id.clone(), item))
            .collect();
        let component_by_id: BTreeMap<_, _> = components
            .into_iter()
            .map(|item| (item.id.clone(), item))
            .collect();
        let advisory_by_id: BTreeMap<_, _> = advisories
            .into_iter()
            .map(|item| (item.canonical_id.clone(), item))
            .collect();
        let output = findings.into_iter().filter_map(|finding| {
            let instance = instance_by_id.get(&finding.component_instance_id)?;
            let instance_project_id = instance.project_id.as_deref()?;
            if !self.approved_projects.contains(instance_project_id)
                || project_id
                    .as_deref()
                    .is_some_and(|id| instance_project_id != id)
            {
                return None;
            }
            let component = component_by_id.get(&instance.component_id)?;
            let advisory = advisory_by_id.get(&finding.advisory_id)?;
            Some(json!({"id":finding.id,"advisory_id":advisory.canonical_id,"title":untrusted_text(advisory.title.clone()),
                "component":component.name,"version":component.version,"purl":component.purl,
                "status":finding.status,"severity":finding.severity,"priority_score":finding.priority_score,
                "priority_reasons":finding.priority_reasons,"repo_status":finding.repo_status,
                "production_status":finding.production_status}))
        }).collect::<Vec<_>>();
        Ok(json!(output))
    }

    async fn get_finding_evidence(&self, arguments: &Value) -> Result<Value, McpError> {
        let finding_id = required_string(arguments, "finding_id")?;
        self.require_finding_in_approved_project(finding_id).await?;
        let evidence = self
            .database
            .repository::<FindingEvidence>()
            .list()
            .await
            .map_err(McpError::Database)?;
        Ok(json!(
            evidence
                .into_iter()
                .filter(|item| item.finding_id == finding_id)
                .map(
                    |item| json!({"evidence_type":item.evidence_type,"path":item.file_path_redacted,
                "reference":item.reference,"confidence":item.confidence})
                )
                .collect::<Vec<_>>()
        ))
    }

    async fn compare_repo_deployment(&self, arguments: &Value) -> Result<Value, McpError> {
        let finding_id = required_string(arguments, "finding_id")?;
        let (finding, _) = self.require_finding_in_approved_project(finding_id).await?;
        Ok(
            json!({"finding_id":finding.id,"repo_status":finding.repo_status,
            "production_status":finding.production_status,
            "verification":if format!("{:?}",finding.repo_status) == "Unknown" || format!("{:?}",finding.production_status) == "Unknown" {"needs_review"} else {"observed"}}),
        )
    }

    async fn analyze_impact(&self, arguments: &Value) -> Result<Value, McpError> {
        let finding_id = required_string(arguments, "finding_id")?;
        let (finding, instance) = self.require_finding_in_approved_project(finding_id).await?;
        let component = self
            .database
            .repository::<Component>()
            .get(&instance.component_id)
            .await
            .map_err(McpError::Database)?
            .ok_or(McpError::ResourceUnavailable)?;
        let advisory = self
            .database
            .repository::<Advisory>()
            .get(&finding.advisory_id)
            .await
            .map_err(McpError::Database)?
            .ok_or(McpError::ResourceUnavailable)?;
        let evidence = self
            .database
            .repository::<FindingEvidence>()
            .list()
            .await
            .map_err(McpError::Database)?
            .into_iter()
            .filter(|item| item.finding_id == finding.id)
            .collect::<Vec<_>>();
        let memory_context = if self.memory_context_enabled {
            let mut scopes = vec![(MemoryScope::Finding, Some(finding.id.clone()))];
            if let Some(project_id) = instance.project_id.clone() {
                scopes.push((MemoryScope::Project, Some(project_id)));
            }
            if let Some(asset_id) = instance.asset_id.clone()
                && self.is_asset_approved_for_any_project(&asset_id).await?
            {
                scopes.push((MemoryScope::Server, Some(asset_id)));
            }
            self.memories_for_scopes(&scopes, "", 12).await?
        } else {
            Vec::new()
        };
        Ok(
            json!({"finding_id":finding.id,"advisory":{"id":advisory.canonical_id,"title":untrusted_text(advisory.title),
                "description":advisory.description.map(untrusted_text),"affected_ranges":advisory.affected_ranges},
            "component":{"name":component.name,"version":component.version,"purl":component.purl},
            "status":finding.status,"repo_status":finding.repo_status,"production_status":finding.production_status,
            "evidence":evidence.into_iter().map(|item| json!({"type":item.evidence_type,"path":item.file_path_redacted,
                "reference":item.reference,"confidence":item.confidence})).collect::<Vec<_>>(),
            "shared_memory":memory_context,
            "priority_score_is_read_only":true}),
        )
    }

    async fn prepare_patch(&self, arguments: &Value) -> Result<Value, McpError> {
        let finding_id = required_string(arguments, "finding_id")?;
        let provider_id = required_string(arguments, "provider_id")?;
        let (finding, instance) = self.require_finding_in_approved_project(finding_id).await?;
        let project_id = instance.project_id.ok_or(McpError::ResourceUnavailable)?;
        let project = self.project(&project_id).await?;
        let provider = self
            .database
            .repository::<AiProvider>()
            .get(provider_id)
            .await
            .map_err(McpError::Database)?
            .ok_or(McpError::ResourceUnavailable)?;
        if provider.kind != AiProviderKind::AgentCli
            || provider.cli_product.is_none()
            || !project
                .allowed_ai_providers
                .iter()
                .any(|id| id == provider_id)
        {
            return Err(McpError::PermissionDenied);
        }
        self.write_approval_request(McpRemediationRequest {
            id: uuid::Uuid::new_v4().to_string(),
            action: McpRemediationAction::PreparePatch,
            finding_id: finding.id,
            provider_id: Some(provider.id),
            remediation_id: None,
            created_at: chrono::Utc::now(),
        })?;
        Ok(json!({"approval_state":"pending_user_approval","source_code_sent":false}))
    }

    async fn request_safe_tests(&self, arguments: &Value) -> Result<Value, McpError> {
        let remediation_id = required_string(arguments, "remediation_id")?;
        let remediation = self
            .database
            .repository::<Remediation>()
            .get(remediation_id)
            .await
            .map_err(McpError::Database)?
            .ok_or(McpError::ResourceUnavailable)?;
        self.require_finding_in_approved_project(&remediation.finding_id)
            .await?;
        if remediation.approval_state != ApprovalState::Approved {
            return Err(McpError::PermissionDenied);
        }
        self.write_approval_request(McpRemediationRequest {
            id: uuid::Uuid::new_v4().to_string(),
            action: McpRemediationAction::RunSafeTests,
            finding_id: remediation.finding_id,
            provider_id: None,
            remediation_id: Some(remediation.id),
            created_at: chrono::Utc::now(),
        })?;
        Ok(json!({"approval_state":"pending_user_approval","tests_started":false}))
    }

    fn write_approval_request(&self, request: McpRemediationRequest) -> Result<(), McpError> {
        let app_data_dir = self
            .remediation_queue_dir
            .as_deref()
            .ok_or(McpError::ResourceUnavailable)?;
        write_mcp_remediation_request(app_data_dir, &request)
            .map_err(|_| McpError::ResourceUnavailable)
    }

    async fn read_project_file(&self, arguments: &Value) -> Result<Value, McpError> {
        let project = self
            .project(required_string(arguments, "project_id")?)
            .await?;
        self.require_approved_project(&project.id)?;
        let relative = safe_relative_path(required_string(arguments, "path")?)?;
        let root = CapabilityDir::open_ambient_dir(&project.root_path, ambient_authority())
            .map_err(|_| McpError::ResourceUnavailable)?;
        let resolved = root
            .canonicalize(&relative)
            .map_err(|_| McpError::ResourceUnavailable)?;
        if is_sensitive_path(&resolved.to_string_lossy()) {
            return Err(McpError::ResourceUnavailable);
        }
        let file = root
            .open(&resolved)
            .map_err(|_| McpError::ResourceUnavailable)?;
        if !file
            .metadata()
            .map_err(|_| McpError::ResourceUnavailable)?
            .is_file()
        {
            return Err(McpError::ResourceUnavailable);
        }
        let mut contents = String::new();
        file.take(MAX_FILE_BYTES + 1)
            .read_to_string(&mut contents)
            .map_err(|_| McpError::ResourceUnavailable)?;
        if contents.len() as u64 > MAX_FILE_BYTES {
            return Err(McpError::ResourceUnavailable);
        }
        let redacted = redact_text_with_host_aliases(&contents, &self.host_aliases);
        Ok(
            json!({"path":format!("<project>/{}",relative.to_string_lossy().replace('\\',"/")),
            "contents":redacted.text,"redacted_values":redacted.redacted_values,"untrusted_data":true}),
        )
    }

    async fn search_project(&self, arguments: &Value) -> Result<Value, McpError> {
        let project = self
            .project(required_string(arguments, "project_id")?)
            .await?;
        self.require_approved_project(&project.id)?;
        let query = required_string(arguments, "query")?.to_ascii_lowercase();
        if query.is_empty() || query.len() > 256 {
            return Err(McpError::InvalidArguments);
        }
        let root = CapabilityDir::open_ambient_dir(&project.root_path, ambient_authority())
            .map_err(|_| McpError::ResourceUnavailable)?;
        let mut pending = vec![(root, PathBuf::new())];
        let mut files_seen = 0_usize;
        let mut bytes_seen = 0_u64;
        let mut results = Vec::new();
        'walk: while let Some((directory, relative_directory)) = pending.pop() {
            let entries = match directory.entries() {
                Ok(entries) => entries,
                Err(_) => continue,
            };
            for entry in entries {
                let Ok(entry) = entry else { continue };
                let name = entry.file_name();
                let Some(name_text) = name.to_str() else {
                    continue;
                };
                if name_text.starts_with('.') {
                    continue;
                }
                let relative = relative_directory.join(&name);
                let relative_text = relative.to_string_lossy().replace('\\', "/");
                if is_sensitive_path(&relative_text) {
                    continue;
                }
                let file_type = match entry.file_type() {
                    Ok(file_type) => file_type,
                    Err(_) => continue,
                };
                if file_type.is_symlink() {
                    continue;
                }
                if file_type.is_dir() {
                    if !matches!(
                        name_text,
                        "node_modules" | "target" | "vendor" | "dist" | "build"
                    ) && let Ok(child) = entry.open_dir()
                    {
                        pending.push((child, relative));
                    }
                    continue;
                }
                if !file_type.is_file() {
                    continue;
                }
                files_seen += 1;
                if files_seen > MAX_SEARCH_FILES || results.len() >= MAX_SEARCH_RESULTS {
                    break 'walk;
                }
                let Ok(mut file) = entry.open() else { continue };
                let Ok(metadata) = file.metadata() else {
                    continue;
                };
                if metadata.len() > 512 * 1024 {
                    continue;
                }
                bytes_seen = bytes_seen.saturating_add(metadata.len());
                if bytes_seen > MAX_SEARCH_BYTES {
                    break 'walk;
                }
                let mut contents = String::new();
                if file
                    .by_ref()
                    .take(512 * 1024 + 1)
                    .read_to_string(&mut contents)
                    .is_err()
                {
                    continue;
                }
                let redacted_contents =
                    redact_text_with_host_aliases(&contents, &self.host_aliases).text;
                for (line_index, line) in redacted_contents.lines().enumerate() {
                    if line.to_ascii_lowercase().contains(&query) {
                        results.push(json!({"path":format!("<project>/{relative_text}"),"line":line_index + 1,
                            "snippet":line,"untrusted_data":true}));
                        if results.len() >= MAX_SEARCH_RESULTS {
                            break 'walk;
                        }
                    }
                }
            }
        }
        Ok(
            json!({"results":results,"files_examined":files_seen,"truncated":files_seen >= MAX_SEARCH_FILES || results.len() >= MAX_SEARCH_RESULTS || bytes_seen > MAX_SEARCH_BYTES}),
        )
    }

    pub(super) fn require_approved_project(&self, project_id: &str) -> Result<(), McpError> {
        if self.approved_projects.contains(project_id) {
            Ok(())
        } else {
            Err(McpError::PermissionDenied)
        }
    }

    pub(super) async fn require_finding_in_approved_project(
        &self,
        finding_id: &str,
    ) -> Result<(Finding, ComponentInstance), McpError> {
        let finding = self
            .database
            .repository::<Finding>()
            .get(finding_id)
            .await
            .map_err(McpError::Database)?
            .ok_or(McpError::ResourceUnavailable)?;
        let instance = self
            .database
            .repository::<ComponentInstance>()
            .get(&finding.component_instance_id)
            .await
            .map_err(McpError::Database)?
            .ok_or(McpError::ResourceUnavailable)?;
        let project_id = instance
            .project_id
            .as_deref()
            .ok_or(McpError::PermissionDenied)?;
        self.require_approved_project(project_id)?;
        Ok((finding, instance))
    }

    pub(super) async fn is_asset_approved_for_any_project(
        &self,
        asset_id: &str,
    ) -> Result<bool, McpError> {
        let links = self
            .database
            .repository::<ProjectServerLink>()
            .list()
            .await
            .map_err(McpError::Database)?;
        Ok(links.iter().any(|link| {
            link.asset_id == asset_id && self.approved_projects.contains(&link.project_id)
        }))
    }
}
#[async_trait::async_trait]
impl ToolExecutor for WorkspaceTools {
    async fn execute(&self, call: &ToolCall) -> Result<Value, ToolError> {
        self.call(&call.name, &call.arguments)
            .await
            .map_err(|_| ToolError::InvalidArguments)
    }
}

fn safe_relative_path(path: &str) -> Result<PathBuf, McpError> {
    let path = Path::new(path);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, PathComponent::Normal(_)))
    {
        return Err(McpError::ResourceUnavailable);
    }
    Ok(path.to_path_buf())
}
