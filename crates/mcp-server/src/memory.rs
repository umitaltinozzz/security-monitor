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
        if scope == Some(MemoryScope::Global) && scope_id.is_some()
            || scope.is_some_and(|scope| scope != MemoryScope::Global) && scope_id.is_none()
        {
            return Err(McpError::InvalidArguments);
        }
        if let Some(scope) = scope
            && scope != MemoryScope::Global
        {
            self.require_memory_scope_exists(scope, scope_id.as_deref().unwrap_or_default())
                .await?;
        }
        let notes = self
            .database
            .search_memories(query, chrono::Utc::now(), 100)
            .await
            .map_err(McpError::Database)?
            .into_iter()
            .filter(|memory| memory_matches_scope(memory, scope, scope_id.as_deref()))
            .take(30)
            .map(|memory| self.memory_json(memory))
            .collect::<Vec<_>>();
        Ok(json!({"memories":notes,"untrusted_data":true}))
    }

    pub(super) async fn remember(&self, arguments: &Value) -> Result<Value, McpError> {
        if !self.memory_writes_enabled {
            return Err(McpError::PermissionDenied);
        }
        let scope = parse_memory_scope(arguments.get("scope").ok_or(McpError::InvalidArguments)?)?;
        let scope_id = optional_string(arguments, "scope_id")?;
        if scope == MemoryScope::Global && scope_id.is_some()
            || scope != MemoryScope::Global && scope_id.is_none()
        {
            return Err(McpError::InvalidArguments);
        }
        if let Some(scope_id) = scope_id.as_deref() {
            self.require_memory_scope_exists(scope, scope_id).await?;
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
            pinned: arguments
                .get("pinned")
                .and_then(Value::as_bool)
                .unwrap_or(false),
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
            MemoryScope::Global => true,
            MemoryScope::Project => {
                self.project(scope_id).await?;
                true
            }
            MemoryScope::Server => self
                .database
                .repository::<Asset>()
                .get(scope_id)
                .await
                .map_err(McpError::Database)?
                .is_some(),
            MemoryScope::Finding => self
                .database
                .repository::<Finding>()
                .get(scope_id)
                .await
                .map_err(McpError::Database)?
                .is_some(),
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

    fn memory_json(&self, mut memory: Memory) -> Value {
        memory.content = redact_text_with_host_aliases(&memory.content, &self.host_aliases).text;
        json!({"id":memory.id,"scope":memory.scope,"scope_id":memory.scope_id,
            "kind":memory.kind,"content":memory.content,"author":memory.author,
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

fn memory_matches_scope(
    memory: &Memory,
    scope: Option<MemoryScope>,
    scope_id: Option<&str>,
) -> bool {
    match scope {
        None => true,
        Some(MemoryScope::Global) => memory.scope == MemoryScope::Global,
        Some(scope) if scope_id.is_some() => {
            memory.scope == MemoryScope::Global
                || (memory.scope == scope && memory.scope_id.as_deref() == scope_id)
        }
        Some(_) => false,
    }
}
