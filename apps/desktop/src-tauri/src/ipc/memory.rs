use super::*;

#[tauri::command]
pub async fn list_memories(
    state: State<'_, AppState>,
    scope: Option<MemoryScope>,
    scope_id: Option<String>,
) -> Result<Vec<Memory>, String> {
    if (scope == Some(MemoryScope::Global) && scope_id.is_some())
        || (scope.is_some_and(|scope| scope != MemoryScope::Global) && scope_id.is_none())
    {
        return Err("invalid_input".to_owned());
    }
    if let (Some(scope), Some(scope_id)) = (scope, scope_id.as_deref()) {
        validate_memory_scope(&state.database, scope, scope_id).await?;
    }
    let now = Utc::now();
    let mut memories = state
        .database
        .repository::<Memory>()
        .list()
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?
        .into_iter()
        .filter(|memory| memory.expires_at.is_none_or(|expires| expires > now))
        .filter(|memory| match scope {
            None => true,
            Some(MemoryScope::Global) => memory.scope == MemoryScope::Global,
            Some(scope) => {
                memory.scope == scope && memory.scope_id.as_deref() == scope_id.as_deref()
            }
        })
        .collect::<Vec<_>>();
    memories.sort_by(|left, right| {
        right
            .pinned
            .cmp(&left.pinned)
            .then_with(|| right.created_at.cmp(&left.created_at))
    });
    memories.truncate(1000);
    Ok(memories)
}

#[tauri::command]
pub async fn create_memory(
    state: State<'_, AppState>,
    scope: MemoryScope,
    scope_id: Option<String>,
    kind: MemoryKind,
    content: String,
    pinned: bool,
) -> Result<Memory, String> {
    if (scope == MemoryScope::Global && scope_id.is_some())
        || (scope != MemoryScope::Global && scope_id.is_none())
    {
        return Err("invalid_input".to_owned());
    }
    if let Some(scope_id) = scope_id.as_deref() {
        validate_memory_scope(&state.database, scope, scope_id).await?;
    }
    let content = sanitize_memory_content(&content)?;
    let settings = state.ai_settings.read().await.clone();
    let now = Utc::now();
    let memory = Memory {
        id: Uuid::new_v4().to_string(),
        scope,
        scope_id,
        kind,
        content,
        author: "user".into(),
        source_run_id: None,
        created_at: now,
        expires_at: Some(now + chrono::Duration::days(i64::from(settings.memory_retention_days))),
        pinned,
        verified_at: None,
        verified_by: None,
    };
    state
        .database
        .repository::<Memory>()
        .create(&memory)
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?;
    write_audit_event(
        &state.database,
        "memory_created",
        "memory",
        Some(memory.id.clone()),
        now,
        AuditResult::Succeeded,
    )
    .await?;
    Ok(memory)
}

#[tauri::command]
pub async fn update_memory(
    state: State<'_, AppState>,
    memory_id: String,
    content: Option<String>,
    pinned: Option<bool>,
    verified: Option<bool>,
) -> Result<Memory, String> {
    let mut memory = state
        .database
        .repository::<Memory>()
        .get(&memory_id)
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?
        .ok_or_else(|| "not_found".to_owned())?;
    let now = Utc::now();
    if let Some(content) = content {
        let sanitized = sanitize_memory_content(&content)?;
        if sanitized != memory.content {
            memory.content = sanitized;
            memory.verified_at = None;
            memory.verified_by = None;
        }
    }
    if let Some(pinned) = pinned {
        memory.pinned = pinned;
    }
    if let Some(verified) = verified {
        memory.verified_at = verified.then_some(now);
        memory.verified_by = verified.then(|| "user".to_owned());
    }
    if !state
        .database
        .repository::<Memory>()
        .update(&memory)
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?
    {
        return Err("not_found".to_owned());
    }
    write_audit_event(
        &state.database,
        "memory_updated",
        "memory",
        Some(memory.id.clone()),
        now,
        AuditResult::Succeeded,
    )
    .await?;
    Ok(memory)
}

#[tauri::command]
pub async fn delete_memory(state: State<'_, AppState>, memory_id: String) -> Result<(), String> {
    if !state
        .database
        .repository::<Memory>()
        .delete(&memory_id)
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?
    {
        return Err("not_found".to_owned());
    }
    write_audit_event(
        &state.database,
        "memory_deleted",
        "memory",
        Some(memory_id),
        Utc::now(),
        AuditResult::Succeeded,
    )
    .await
}

#[tauri::command]
pub async fn export_memories(state: State<'_, AppState>) -> Result<MemoryArchive, String> {
    let now = Utc::now();
    let memories = state
        .database
        .repository::<Memory>()
        .list()
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?
        .into_iter()
        .filter(|memory| memory.expires_at.is_none_or(|expires| expires > now))
        .collect::<Vec<_>>();
    if memories.len() > 10_000 {
        return Err("invalid_input".to_owned());
    }
    Ok(MemoryArchive {
        version: 1,
        exported_at: now,
        memories: memories
            .into_iter()
            .map(|memory| MemoryArchiveEntry {
                scope: memory.scope,
                scope_id: memory.scope_id,
                kind: memory.kind,
                content: redact_memory_content(&memory.content),
                pinned: memory.pinned,
            })
            .collect(),
    })
}

#[tauri::command]
pub async fn import_memories(
    state: State<'_, AppState>,
    archive: MemoryArchive,
) -> Result<usize, String> {
    if archive.version != 1 || archive.memories.len() > 10_000 {
        return Err("invalid_input".to_owned());
    }
    let now = Utc::now();
    let settings = state.ai_settings.read().await.clone();
    let mut imported = Vec::with_capacity(archive.memories.len());
    for entry in archive.memories {
        if (entry.scope == MemoryScope::Global && entry.scope_id.is_some())
            || (entry.scope != MemoryScope::Global && entry.scope_id.is_none())
        {
            return Err("invalid_input".to_owned());
        }
        if let Some(scope_id) = entry.scope_id.as_deref() {
            validate_memory_scope(&state.database, entry.scope, scope_id).await?;
        }
        let content = sanitize_memory_content(&entry.content)?;
        imported.push(Memory {
            id: Uuid::new_v4().to_string(),
            scope: entry.scope,
            scope_id: entry.scope_id,
            kind: entry.kind,
            content,
            author: "user".into(),
            source_run_id: None,
            created_at: now,
            expires_at: Some(
                now + chrono::Duration::days(i64::from(settings.memory_retention_days)),
            ),
            pinned: entry.pinned,
            verified_at: None,
            verified_by: None,
        });
    }
    for memory in &imported {
        state
            .database
            .repository::<Memory>()
            .create(memory)
            .await
            .map_err(|error| opaque(error, "storage_unavailable"))?;
    }
    write_audit_event(
        &state.database,
        "memories_imported",
        "memories",
        None,
        now,
        AuditResult::Succeeded,
    )
    .await?;
    Ok(imported.len())
}

#[tauri::command]
pub async fn delete_all_memories(state: State<'_, AppState>) -> Result<u64, String> {
    let deleted = state
        .database
        .delete_all_memories()
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?;
    write_audit_event(
        &state.database,
        "memories_deleted_all",
        "memories",
        None,
        Utc::now(),
        AuditResult::Succeeded,
    )
    .await?;
    Ok(deleted)
}

async fn validate_memory_scope(
    database: &Database,
    scope: MemoryScope,
    scope_id: &str,
) -> Result<(), String> {
    let exists = match scope {
        MemoryScope::Global => false,
        MemoryScope::Project => database
            .repository::<Project>()
            .get(scope_id)
            .await
            .map_err(|error| opaque(error, "storage_unavailable"))?
            .is_some(),
        MemoryScope::Server => database
            .repository::<Asset>()
            .get(scope_id)
            .await
            .map_err(|error| opaque(error, "storage_unavailable"))?
            .is_some(),
        MemoryScope::Finding => database
            .repository::<Finding>()
            .get(scope_id)
            .await
            .map_err(|error| opaque(error, "storage_unavailable"))?
            .is_some(),
    };
    if exists {
        Ok(())
    } else {
        Err("invalid_input".to_owned())
    }
}

fn sanitize_memory_content(content: &str) -> Result<String, String> {
    if content.trim().is_empty() || content.len() > 32 * 1024 {
        return Err("invalid_input".to_owned());
    }
    let sanitized = redact_memory_content(content);
    if sanitized.len() > 8192 || is_source_code_like(&sanitized) {
        return Err("invalid_input".to_owned());
    }
    Ok(sanitized)
}

fn redact_memory_content(content: &str) -> String {
    let aliases = std::collections::BTreeMap::new();
    redact_text_with_host_aliases(content, &aliases).text
}
