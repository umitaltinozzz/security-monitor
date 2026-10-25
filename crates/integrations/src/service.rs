use super::*;

pub struct IntegrationService<S: CredentialStore> {
    credential_store: S,
}

impl<S: CredentialStore> IntegrationService<S> {
    pub fn new(credential_store: S) -> Self {
        Self { credential_store }
    }

    pub fn plan(
        &self,
        agent: Agent,
        scope: Scope,
        home: &Path,
        project: Option<&Path>,
    ) -> Result<IntegrationPlan, IntegrationError> {
        let spec = agent_spec(agent)?;
        let root = scope_root(scope, home, project)?;
        let mut plan = IntegrationPlan::default();
        let mcp_path = scoped_path(&spec, "mcp", scope)?;
        let skill_path = scoped_path(&spec, "skill", scope)?;
        let hook_path = scoped_path(&spec, "hook", scope)?;

        let mcp_before = read_scoped(&root, &mcp_path)?;
        let mcp_after = match spec.mcp_format.as_str() {
            "claude_json" => claude::merge_mcp(&mcp_before)?,
            "opencode_json" => opencode::merge_mcp(&mcp_before)?,
            "codex_toml" => codex::merge_mcp(&mcp_before)?,
            _ => return Err(IntegrationError::InvalidConfiguration),
        };
        push_change(
            &mut plan,
            mcp_path,
            mcp_before,
            mcp_after,
            "Adds the local Security Monitor MCP server with stdio transport.",
        );

        let skill_before = read_scoped(&root, &skill_path)?;
        if skill_before
            .as_deref()
            .is_some_and(|existing| existing != SKILL.as_bytes())
        {
            return Err(IntegrationError::Conflict);
        }
        push_change(
            &mut plan,
            skill_path,
            skill_before,
            Some(SKILL.as_bytes().to_vec()),
            "Installs the Security Monitor skill and pre-commit/push instruction.",
        );

        let hook_before = read_scoped(&root, &hook_path)?;
        let hook_after = match spec.hook_format.as_str() {
            "claude_json" => claude::merge_hook(&hook_before)?,
            "codex_json" => codex::merge_hook(&hook_before)?,
            "opencode_plugin" => opencode::merge_hook(&hook_before)?,
            _ => return Err(IntegrationError::InvalidConfiguration),
        };
        push_change(
            &mut plan,
            hook_path,
            hook_before,
            hook_after,
            "Installs a local pre-tool Git hook that checks commit and push commands.",
        );
        Ok(plan)
    }

    pub fn install(
        &self,
        agent: Agent,
        scope: Scope,
        home: &Path,
        project: Option<&Path>,
    ) -> Result<IntegrationPlan, IntegrationError> {
        let root = scope_root(scope, home, project)?;
        let manifest_path = manifest_path(home, agent, scope, &root)?;
        if manifest_path.exists() {
            return Err(IntegrationError::AlreadyInstalled);
        }
        let plan = self.plan(agent, scope, home, project)?;
        if plan.changes.is_empty() {
            return Ok(plan);
        }

        let mut entries = Vec::with_capacity(plan.changes.len());
        for change in &plan.changes {
            let backup_key_ref = match change.before.as_deref() {
                Some(bytes) => match self.credential_store.put(bytes) {
                    Ok(reference) => Some(reference),
                    Err(_) => {
                        delete_backups(&self.credential_store, &entries);
                        return Err(IntegrationError::BackupUnavailable);
                    }
                },
                None => None,
            };
            entries.push(ManifestEntry {
                relative_path: change.relative_path.clone(),
                existed_before: change.before.is_some(),
                backup_key_ref,
                installed_sha256: sha256(&change.after),
                original_sha256: change.before.as_deref().map(sha256),
            });
        }

        let mut written = Vec::<&PlannedChange>::new();
        for change in &plan.changes {
            if let Err(error) = write_scoped(&root, &change.relative_path, &change.after) {
                rollback_plan(&root, &written);
                delete_backups(&self.credential_store, &entries);
                return Err(error);
            }
            written.push(change);
        }

        let manifest = IntegrationManifest {
            version: 1,
            agent,
            scope,
            entries,
        };
        if write_json_atomic(&manifest_path, &manifest).is_err() {
            rollback_plan(&root, &written);
            delete_backups(&self.credential_store, &manifest.entries);
            return Err(IntegrationError::StateUnavailable);
        }
        Ok(plan)
    }

    pub fn remove(
        &self,
        agent: Agent,
        scope: Scope,
        home: &Path,
        project: Option<&Path>,
    ) -> Result<(), IntegrationError> {
        let root = scope_root(scope, home, project)?;
        let manifest_path = manifest_path(home, agent, scope, &root)?;
        let bytes = fs::read(&manifest_path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                IntegrationError::NotInstalled
            } else {
                IntegrationError::StateUnavailable
            }
        })?;
        let manifest: IntegrationManifest =
            serde_json::from_slice(&bytes).map_err(|_| IntegrationError::StateUnavailable)?;
        if manifest.version != 1 || manifest.agent != agent || manifest.scope != scope {
            return Err(IntegrationError::StateUnavailable);
        }

        let mut current = Vec::with_capacity(manifest.entries.len());
        for entry in &manifest.entries {
            let contents = read_scoped(&root, &entry.relative_path)?;
            let installed = contents
                .as_deref()
                .is_some_and(|value| sha256(value) == entry.installed_sha256);
            let already_restored = match (contents.as_deref(), entry.original_sha256.as_deref()) {
                (Some(value), Some(expected)) => sha256(value) == expected,
                (None, None) => true,
                _ => false,
            };
            if !installed && !already_restored {
                return Err(IntegrationError::ModifiedAfterInstall);
            }
            current.push(contents);
        }

        let mut restore = Vec::with_capacity(manifest.entries.len());
        for (index, entry) in manifest.entries.iter().enumerate() {
            if current[index]
                .as_deref()
                .is_some_and(|value| sha256(value) == entry.installed_sha256)
            {
                let original = if entry.existed_before {
                    let reference = entry
                        .backup_key_ref
                        .as_deref()
                        .ok_or(IntegrationError::StateUnavailable)?;
                    Some(
                        self.credential_store
                            .get(reference)
                            .map_err(|_| IntegrationError::BackupUnavailable)?
                            .to_vec(),
                    )
                } else {
                    None
                };
                restore.push((entry, original));
            }
        }

        let mut restored = Vec::<(&ManifestEntry, Option<Vec<u8>>)>::new();
        for (entry, original) in &restore {
            let target_result = match original {
                Some(contents) => write_scoped(&root, &entry.relative_path, contents),
                None => remove_scoped(&root, &entry.relative_path),
            };
            if let Err(error) = target_result {
                for (prior, previous) in restored.iter().rev() {
                    if let Some(previous) = previous {
                        let _ = write_scoped(&root, &prior.relative_path, previous);
                    } else {
                        let _ = remove_scoped(&root, &prior.relative_path);
                    }
                }
                return Err(error);
            }
            let old_current = manifest
                .entries
                .iter()
                .position(|candidate| candidate.relative_path == entry.relative_path)
                .and_then(|position| current[position].clone());
            restored.push((entry, old_current));
        }

        for entry in &manifest.entries {
            if let Some(reference) = entry.backup_key_ref.as_deref()
                && self.credential_store.delete(reference).is_err()
            {
                return Err(IntegrationError::BackupUnavailable);
            }
        }
        fs::remove_file(manifest_path).map_err(|_| IntegrationError::StateUnavailable)?;
        Ok(())
    }
}
