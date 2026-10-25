use super::*;

impl WorkspaceTools {
    pub(super) async fn recall(&self, arguments: &Value) -> Result<Value, McpError> {
        let query = arguments
            .get("query")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if query.len() > 256 {
            return Err(McpError::InvalidArguments);
        }
        let scope = arguments.get("scope").map(parse_memory_scope).transpose()?;
        let scope_id = optional_string(arguments, "scope_id")?;
        let scopes = if let Some(scope) = scope {
            if scope == MemoryScope::Global {
                if scope_id.is_some() {
                    return Err(McpError::InvalidArguments);
                }
                if !self.global_memory_allowed {
                    return Err(McpError::PermissionDenied);
                }
                vec![(MemoryScope::Global, None)]
            } else {
                let Some(scope_id) = scope_id else {
                    return Err(McpError::InvalidArguments);
                };
                self.require_memory_scope_exists(scope, &scope_id).await?;
                vec![(scope, Some(scope_id))]
            }
        } else {
            if scope_id.is_some() {
                return Err(McpError::InvalidArguments);
            }
            if self.approved_projects.is_empty() {
                if self.global_memory_allowed {
                    vec![(MemoryScope::Global, None)]
                } else {
                    Vec::new()
                }
            } else {
                self.approved_projects
                    .iter()
                    .map(|project_id| (MemoryScope::Project, Some(project_id.clone())))
                    .collect()
            }
        };
        let notes = self.memories_for_scopes(&scopes, query, 30).await?;
        Ok(json!({"memories":notes,"untrusted_data":true}))
    }

    pub(super) async fn remember(&self, arguments: &Value) -> Result<Value, McpError> {
        if !self.memory_writes_enabled {
            return Err(McpError::PermissionDenied);
        }
        if arguments.get("pinned").is_some() {
            return Err(McpError::PermissionDenied);
        }
        let scope = parse_memory_scope(arguments.get("scope").ok_or(McpError::InvalidArguments)?)?;
        let scope_id = optional_string(arguments, "scope_id")?;
        if scope_id.is_some() != (scope != MemoryScope::Global) {
            return Err(McpError::InvalidArguments);
        }
        if let Some(scope_id) = scope_id.as_deref() {
            self.require_memory_scope_exists(scope, scope_id).await?;
        } else if !self.global_memory_allowed {
            return Err(McpError::PermissionDenied);
        }
        let kind: MemoryKind = serde_json::from_value(
            arguments
                .get("kind")
                .cloned()
                .ok_or(McpError::InvalidArguments)?,
        )
        .map_err(|_| McpError::InvalidArguments)?;
        if kind == MemoryKind::UserDecision {
            return Err(McpError::PermissionDenied);
        }
        let content = arguments
            .get("content")
            .and_then(Value::as_str)
            .filter(|content| !content.trim().is_empty() && content.len() <= 32 * 1024)
            .ok_or(McpError::InvalidArguments)?;
        let redacted = redact_text_with_host_aliases(content, &self.host_aliases);
        if redacted.text.len() > 8192 || is_source_code_like(&redacted.text) {
            return Err(McpError::InvalidArguments);
        }
        let now = chrono::Utc::now();
        let author = format!("agent:{}", self.memory_agent);
        let memory = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            scope,
            scope_id,
            kind,
            content: redacted.text,
            author: author.clone(),
            source_run_id: None,
            created_at: now,
            expires_at: Some(now + chrono::Duration::days(i64::from(self.memory_retention_days))),
            pinned: false,
            verified_at: None,
            verified_by: None,
        };
        self.database
            .repository::<Memory>()
            .create(&memory)
            .await
            .map_err(McpError::Database)?;
        if let Err(error) = self
            .write_memory_audit("mcp_memory_created", &memory.id)
            .await
        {
            let _ = self
                .database
                .repository::<Memory>()
                .delete(&memory.id)
                .await;
            return Err(error);
        }
        Ok(json!({"memory":self.memory_json(memory),"untrusted_data":true}))
    }

    pub(super) async fn forget(&self, arguments: &Value) -> Result<Value, McpError> {
        if !self.memory_writes_enabled {
            return Err(McpError::PermissionDenied);
        }
        let id = required_string(arguments, "id")?;
        let author = format!("agent:{}", self.memory_agent);
        let memory = self
            .database
            .repository::<Memory>()
            .get(id)
            .await
            .map_err(McpError::Database)?
            .ok_or(McpError::ResourceUnavailable)?;
        self.require_memory_scope_exists(
            memory.scope,
            memory.scope_id.as_deref().unwrap_or_default(),
        )
        .await?;
        if memory.author != author {
            return Err(McpError::PermissionDenied);
        }
        self.write_memory_audit("mcp_memory_deletion_requested", id)
            .await?;
        let deleted = self
            .database
            .delete_memory_authored_by(id, &author)
            .await
            .map_err(McpError::Database)?;
        if !deleted {
            return Err(McpError::PermissionDenied);
        }
        self.write_memory_audit("mcp_memory_deleted", id).await?;
        Ok(json!({"deleted":true}))
    }

    async fn write_memory_audit(&self, action: &str, memory_id: &str) -> Result<(), McpError> {
        self.database
            .repository::<AuditEvent>()
            .create(&AuditEvent {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                actor: format!("agent:{}", self.memory_agent),
                action: action.to_owned(),
                scope: AuditScope {
                    resource_type: "memory".into(),
                    resource_id: Some(memory_id.to_owned()),
                },
                result: AuditResult::Succeeded,
            })
            .await
            .map_err(McpError::Database)
    }

    async fn require_memory_scope_exists(
        &self,
        scope: MemoryScope,
        scope_id: &str,
    ) -> Result<(), McpError> {
        let exists = match scope {
            MemoryScope::Global => self.global_memory_allowed,
            MemoryScope::Project => {
                self.require_approved_project(scope_id)?;
                self.project(scope_id).await?;
                true
            }
            MemoryScope::Server => {
                if !self.is_asset_approved_for_any_project(scope_id).await? {
                    return Err(McpError::PermissionDenied);
                }
                self.database
                    .repository::<Asset>()
                    .get(scope_id)
                    .await
                    .map_err(McpError::Database)?
                    .is_some()
            }
            MemoryScope::Finding => {
                self.require_finding_in_approved_project(scope_id).await?;
                true
            }
        };
        if exists {
            Ok(())
        } else {
            Err(McpError::ResourceUnavailable)
        }
    }

    pub(super) async fn memories_for_scopes(
        &self,
        scopes: &[(MemoryScope, Option<String>)],
        query: &str,
        limit: usize,
    ) -> Result<Vec<Value>, McpError> {
        let memories = self
            .database
            .search_memories(query, chrono::Utc::now(), 100)
            .await
            .map_err(McpError::Database)?;
        Ok(memories
            .into_iter()
            .filter(|memory| {
                scopes
                    .iter()
                    .any(|(scope, scope_id)| memory.scope == *scope && memory.scope_id == *scope_id)
            })
            .take(limit)
            .map(|memory| self.memory_json(memory))
            .collect())
    }

    fn memory_json(&self, memory: Memory) -> Value {
        let content = redact_text_with_host_aliases(&memory.content, &self.host_aliases).text;
        json!({"id":memory.id,"scope":memory.scope,"scope_id":memory.scope_id,
            "kind":memory.kind,"content":untrusted_text(content),"author":memory.author,
            "created_at":memory.created_at,"expires_at":memory.expires_at,
            "pinned":memory.pinned,"verified_at":memory.verified_at,
            "verified_by":memory.verified_by,"untrusted_data":true})
    }
}

fn parse_memory_scope(value: &Value) -> Result<MemoryScope, McpError> {
    match value.as_str() {
        Some("global") => Ok(MemoryScope::Global),
        Some("project") => Ok(MemoryScope::Project),
        Some("server") => Ok(MemoryScope::Server),
        Some("finding") => Ok(MemoryScope::Finding),
        _ => Err(McpError::InvalidArguments),
    }
}
