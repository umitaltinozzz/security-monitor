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
        })
        .collect())
}

#[tauri::command]
pub async fn inspect_server_host_key(input: SshTargetInput) -> Result<String, String> {
    let target = to_ssh_target(input)?;
    let candidate = inspect_host_key(&target)
        .await
        .map_err(|error| opaque(error, "host_key_failed"))?;
    Ok(candidate.fingerprint)
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
    let target = to_ssh_target(input.clone())?;
    let candidate = inspect_host_key(&target)
        .await
        .map_err(|error| opaque(error, "host_key_failed"))?;
    if candidate.fingerprint != confirmed_fingerprint {
        return Err("host_key_changed".to_owned());
    }
    let store = OsCredentialStore;
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
    let collection = collect_agent(
        &target,
        fingerprint,
        &SshIdentity::PrivateKeyRef(stored.private_key_ref),
        &store,
        InventoryCollectionApproval::after_explicit_user_confirmation(approved_at),
    )
    .await
    .map_err(|error| opaque(error, "collection_failed"))?;
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
