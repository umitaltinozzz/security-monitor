use super::drift::{collection_summary, refresh_linked_projects};
use super::os_packages::evaluate_os_packages;
use super::*;

#[tauri::command]
pub async fn list_server_assets(state: State<'_, AppState>) -> Result<Vec<Asset>, String> {
    state
        .database
        .repository::<Asset>()
        .list()
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))
}

#[tauri::command]
pub async fn list_ssh_config_hosts() -> Result<Vec<SshHostSummary>, String> {
    let Ok((hosts, _warnings)) = load_user_ssh_hosts() else {
        return Ok(Vec::new());
    };
    Ok(hosts
        .into_iter()
        .map(|host| SshHostSummary {
            alias: host.alias,
            hostname: host.hostname,
            username: host.username,
            port: host.port,
            has_proxy_jump: host.proxy_jump.is_some(),
            proxy_jump: host.proxy_jump,
        })
        .collect())
}

fn with_ssh_config_proxy_jump(mut input: SshTargetInput) -> SshTargetInput {
    let has_explicit_jump = input
        .proxy_jump
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    if !has_explicit_jump
        && let Ok((hosts, _)) = load_user_ssh_hosts()
        && let Some(host) = hosts.into_iter().find(|host| {
            host.alias == input.alias
                && host.hostname == input.hostname
                && host.username == input.username
                && host.port == input.port
                && host.proxy_jump.is_some()
        })
    {
        input.proxy_jump = host.proxy_jump;
    }
    input
}

async fn resolve_pinned_proxy_jump(
    database: &Database,
    store: &dyn CredentialStore,
    jump_spec: &str,
    target_alias: &str,
) -> Result<(PinnedProxyJump, SshIdentity), String> {
    let assets = database
        .repository::<Asset>()
        .list()
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?;
    for asset in assets {
        if asset.removed_at.is_some() {
            continue;
        }
        let (Some(target_ref), Some(confirmed_fingerprint)) =
            (asset.ssh_target_ref.as_deref(), asset.host_key_fingerprint)
        else {
            continue;
        };
        let Ok(Some(bytes)) = store.get_optional(target_ref) else {
            continue;
        };
        let Ok(stored) = serde_json::from_slice::<StoredSshTarget>(&bytes) else {
            continue;
        };
        let Ok(jump_target) = to_ssh_target(stored.target) else {
            continue;
        };
        if jump_target.proxy_jump.is_none()
            && jump_target.alias != target_alias
            && proxy_jump_matches(jump_spec, &jump_target)
        {
            return Ok((
                PinnedProxyJump {
                    target: jump_target,
                    confirmed_fingerprint,
                },
                SshIdentity::PrivateKeyRef(stored.private_key_ref),
            ));
        }
    }
    Err("invalid_input".to_owned())
}

async fn inspect_target_host_key(
    database: &Database,
    store: &dyn CredentialStore,
    target: &SshTarget,
) -> Result<String, String> {
    let candidate = if let Some(jump_spec) = target.proxy_jump.as_deref() {
        let (jump, jump_identity) =
            resolve_pinned_proxy_jump(database, store, jump_spec, &target.alias).await?;
        inspect_host_key_via_jump(target, &jump, &jump_identity, store)
            .await
            .map_err(|error| opaque(error, "host_key_failed"))?
    } else {
        inspect_host_key(target)
            .await
            .map_err(|error| opaque(error, "host_key_failed"))?
    };
    Ok(candidate.fingerprint)
}

#[tauri::command]
pub async fn inspect_server_host_key(
    state: State<'_, AppState>,
    input: SshTargetInput,
) -> Result<String, String> {
    let input = with_ssh_config_proxy_jump(input);
    let target = to_ssh_target(input)?;
    inspect_target_host_key(&state.database, &OsCredentialStore, &target).await
}

#[tauri::command]
pub async fn pair_server(
    state: State<'_, AppState>,
    input: SshTargetInput,
    confirmed_fingerprint: String,
    fingerprint_confirmed: bool,
    device_label: String,
) -> Result<PairingInstructionsView, String> {
    if !fingerprint_confirmed {
        return Err("permission_denied".to_owned());
    }
    let input = with_ssh_config_proxy_jump(input);
    let target = to_ssh_target(input.clone())?;
    let store = OsCredentialStore;
    let observed_fingerprint = inspect_target_host_key(&state.database, &store, &target).await?;
    if observed_fingerprint != confirmed_fingerprint {
        return Err("host_key_changed".to_owned());
    }
    let instructions = create_pairing_instructions(&store, &device_label)
        .map_err(|error| opaque(error, "pairing_failed"))?;
    let credential = StoredSshTarget {
        target: input.clone(),
        private_key_ref: instructions.private_key_ref.clone(),
    };
    let credential_bytes =
        serde_json::to_vec(&credential).map_err(|error| opaque(error, "pairing_failed"))?;
    let target_ref = match store.put(&credential_bytes) {
        Ok(reference) => reference,
        Err(_) => {
            let _ = store.delete(&instructions.private_key_ref);
            return Err("pairing_failed".to_owned());
        }
    };
    let now = Utc::now();
    let asset = Asset {
        id: Uuid::new_v4().to_string(),
        asset_type: AssetType::Server,
        hostname_alias: input.alias,
        environment: input.environment,
        ssh_target_ref: Some(target_ref.clone()),
        host_key_fingerprint: Some(confirmed_fingerprint.clone()),
        last_seen_at: Some(now),
        last_success_at: None,
        removed_at: None,
        created_at: now,
        updated_at: now,
    };
    if state
        .database
        .repository::<Asset>()
        .create(&asset)
        .await
        .is_err()
    {
        let _ = store.delete(&target_ref);
        let _ = store.delete(&instructions.private_key_ref);
        return Err("storage_unavailable".to_owned());
    }
    write_audit_event(
        &state.database,
        "server_paired",
        "asset",
        Some(asset.id.clone()),
        now,
        AuditResult::Succeeded,
    )
    .await?;
    Ok(PairingInstructionsView {
        asset,
        fingerprint: confirmed_fingerprint,
        authorized_keys_line: instructions.authorized_keys_line,
    })
}

#[tauri::command]
pub async fn unpair_server(
    state: State<'_, AppState>,
    server_id: String,
    delete_history: bool,
) -> Result<UnpairServerResult, String> {
    unpair_server_with_store(
        &state.database,
        &state.app_data_dir,
        &server_id,
        delete_history,
        &OsCredentialStore,
    )
    .await
}

async fn unpair_server_with_store(
    database: &Database,
    app_data_dir: &Path,
    server_id: &str,
    delete_history: bool,
    store: &dyn CredentialStore,
) -> Result<UnpairServerResult, String> {
    let record = database
        .repository::<Asset>()
        .unpair_server(server_id, delete_history, Utc::now())
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?
        .ok_or_else(|| "server_not_found".to_owned())?;

    let mut credential_cleanup_warning = false;
    if let Some(target_ref) = record.ssh_target_ref {
        let (private_key_ref, target_entry_present) = match store.get_optional(&target_ref) {
            Ok(Some(bytes)) => match serde_json::from_slice::<StoredSshTarget>(&bytes) {
                Ok(stored) => (Some(stored.private_key_ref), true),
                Err(error) => {
                    tracing::warn!(
                        error = %redact_text(&format!("{error:?}" )).text,
                        "could not read SSH private-key reference during server unpair"
                    );
                    credential_cleanup_warning = true;
                    (None, true)
                }
            },
            Ok(None) => {
                tracing::warn!(
                    "SSH target credential was already absent; private-key cleanup could not be confirmed"
                );
                credential_cleanup_warning = true;
                (None, false)
            }
            Err(error) => {
                tracing::warn!(
                    error = %redact_text(&format!("{error:?}" )).text,
                    "could not read SSH credential during server unpair"
                );
                credential_cleanup_warning = true;
                (None, true)
            }
        };
        if let Some(private_key_ref) = private_key_ref {
            credential_cleanup_warning |=
                !delete_credential(store, &private_key_ref, "ssh_private_key");
        }
        if target_entry_present {
            credential_cleanup_warning |= !delete_credential(store, &target_ref, "ssh_target");
        }
    }

    let snapshot_cleanup_warning =
        delete_history && delete_server_snapshot(app_data_dir, server_id).is_err();
    if snapshot_cleanup_warning {
        tracing::warn!("could not remove server inventory snapshot after unpair");
    }
    Ok(UnpairServerResult {
        history_deleted: record.history_deleted,
        credential_cleanup_warning,
        snapshot_cleanup_warning,
    })
}

fn delete_credential(store: &dyn CredentialStore, reference: &str, credential_kind: &str) -> bool {
    match store.delete_with_outcome(reference) {
        Ok(CredentialDeleteOutcome::Deleted) => true,
        Ok(CredentialDeleteOutcome::Missing) => {
            tracing::info!(
                credential_kind,
                "credential was already absent during server unpair"
            );
            true
        }
        Err(error) => {
            tracing::warn!(
                credential_kind,
                error = %redact_text(&format!("{error:?}" )).text,
                "could not remove credential after server unpair"
            );
            false
        }
    }
}

#[cfg(test)]
#[path = "servers_tests.rs"]
mod tests;

#[tauri::command]
pub async fn collect_server_inventory(
    state: State<'_, AppState>,
    asset_id: String,
    transfer_approved: bool,
) -> Result<CollectionSummary, String> {
    if !transfer_approved {
        return Err("permission_denied".to_owned());
    }
    let asset = state
        .database
        .repository::<Asset>()
        .get(&asset_id)
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?
        .ok_or_else(|| "server_not_found".to_owned())?;
    if asset.removed_at.is_some() {
        return Err("server_not_found".to_owned());
    }
    let target_ref = asset
        .ssh_target_ref
        .as_deref()
        .ok_or_else(|| "collection_failed".to_owned())?;
    let fingerprint = asset
        .host_key_fingerprint
        .as_deref()
        .ok_or_else(|| "collection_failed".to_owned())?;
    let store = OsCredentialStore;
    let target_bytes = store
        .get(target_ref)
        .map_err(|error| opaque(error, "collection_failed"))?;
    let stored: StoredSshTarget = serde_json::from_slice(&target_bytes)
        .map_err(|error| opaque(error, "collection_failed"))?;
    let target = to_ssh_target(stored.target)?;
    let approved_at = Utc::now();
    let target_identity = SshIdentity::PrivateKeyRef(stored.private_key_ref);
    let approval = InventoryCollectionApproval::after_explicit_user_confirmation(approved_at);
    let collection_result = if let Some(jump_spec) = target.proxy_jump.as_deref() {
        let (jump, jump_identity) =
            resolve_pinned_proxy_jump(&state.database, &store, jump_spec, &target.alias).await?;
        collect_agent_via_jump_with_identities(
            &target,
            fingerprint,
            &jump,
            &jump_identity,
            &target_identity,
            &store,
            approval,
        )
        .await
    } else {
        collect_agent(&target, fingerprint, &target_identity, &store, approval).await
    };
    let collection = match collection_result {
        Ok(collection) => collection,
        Err(error) => {
            return handle_collection_failure(&state.database, &state.app_data_dir, &asset, error)
                .await;
        }
    };
    collection
        .inventory
        .validate()
        .map_err(|error| opaque(error, "collection_failed"))?;
    persist_server_snapshot(&state.app_data_dir, &asset.id, &collection.inventory)?;
    let evaluation = evaluate_server_os_packages(
        state.app_data_dir.join("advisories").join("osv"),
        collection.inventory.clone(),
    )
    .await?;
    refresh_linked_projects(&state, &asset.id).await?;
    let mut updated_asset = asset.clone();
    updated_asset.last_seen_at = Some(collection.inventory.captured_at);
    if collection.inventory.complete {
        updated_asset.last_success_at = Some(collection.inventory.captured_at);
    }
    updated_asset.updated_at = Utc::now();
    state
        .database
        .repository::<Asset>()
        .update(&updated_asset)
        .await
        .map_err(|error| opaque(error, "storage_unavailable"))?;
    write_audit_event(
        &state.database,
        "server_inventory_collection_approved",
        "asset",
        Some(asset.id.clone()),
        collection.approval.approved_at(),
        AuditResult::Succeeded,
    )
    .await?;
    Ok(collection_summary(
        asset.id,
        &collection.inventory,
        collection.approval.approved_at(),
        evaluation,
    ))
}

pub(super) async fn evaluate_server_os_packages(
    cache_root: PathBuf,
    inventory: AgentInventory,
) -> Result<super::os_packages::OsPackageEvaluation, String> {
    tokio::task::spawn_blocking(move || evaluate_os_packages(&cache_root, &inventory))
        .await
        .map_err(|error| opaque(error, "collection_failed"))
}

async fn handle_collection_failure(
    database: &Database,
    app_data_dir: &Path,
    asset: &Asset,
    error: CollectionError,
) -> Result<CollectionSummary, String> {
    if matches!(error, CollectionError::HostKeyChanged) {
        let _ = delete_server_snapshot(app_data_dir, &asset.id);
        let mut updated_asset = asset.clone();
        updated_asset.last_success_at = None;
        updated_asset.updated_at = Utc::now();
        let _ = database.repository::<Asset>().update(&updated_asset).await;
        let _ = write_audit_event(
            database,
            "server_host_key_changed",
            "asset",
            Some(asset.id.clone()),
            Utc::now(),
            AuditResult::Failed,
        )
        .await;
        return Err(opaque(error, "host_key_changed"));
    }
    Err(opaque(error, "collection_failed"))
}
