use super::*;
use std::sync::Mutex;
use zeroize::Zeroizing;

const TARGET_REF: &str = "secmon-keyring:v1:00000000-0000-4000-8000-000000000001";
const PRIVATE_KEY_REF: &str = "secmon-keyring:v1:00000000-0000-4000-8000-000000000002";

#[derive(Default)]
struct FailingDeleteStore {
    delete_attempts: Mutex<Vec<String>>,
    fail_delete: bool,
}

impl CredentialStore for FailingDeleteStore {
    fn put(
        &self,
        _secret: &[u8],
    ) -> Result<String, security_monitor_agent_transport::CredentialError> {
        Err(security_monitor_agent_transport::CredentialError::StoreUnavailable)
    }

    fn get(
        &self,
        reference: &str,
    ) -> Result<Zeroizing<Vec<u8>>, security_monitor_agent_transport::CredentialError> {
        if reference != TARGET_REF {
            return Err(security_monitor_agent_transport::CredentialError::StoreUnavailable);
        }
        let stored = StoredSshTarget {
            target: SshTargetInput {
                alias: "fixture".to_owned(),
                hostname: "example.invalid".to_owned(),
                username: "secmon".to_owned(),
                port: 22,
                environment: security_monitor_core::Environment::Production,
            },
            private_key_ref: PRIVATE_KEY_REF.to_owned(),
        };
        serde_json::to_vec(&stored)
            .map(Zeroizing::new)
            .map_err(|_| security_monitor_agent_transport::CredentialError::StoreUnavailable)
    }

    fn delete(
        &self,
        reference: &str,
    ) -> Result<(), security_monitor_agent_transport::CredentialError> {
        self.delete_with_outcome(reference).map(|_| ())
    }

    fn delete_with_outcome(
        &self,
        reference: &str,
    ) -> Result<CredentialDeleteOutcome, security_monitor_agent_transport::CredentialError> {
        self.delete_attempts
            .lock()
            .unwrap()
            .push(reference.to_owned());
        if self.fail_delete {
            Err(security_monitor_agent_transport::CredentialError::StoreUnavailable)
        } else {
            Ok(CredentialDeleteOutcome::Missing)
        }
    }
}

#[tokio::test]
async fn unpair_returns_a_warning_when_keyring_deletion_fails_after_commit() {
    let database = Database::in_memory().await.unwrap();
    let now = Utc::now();
    let asset = Asset {
        id: Uuid::new_v4().to_string(),
        asset_type: AssetType::Server,
        hostname_alias: "fixture".to_owned(),
        environment: security_monitor_core::Environment::Production,
        ssh_target_ref: Some(TARGET_REF.to_owned()),
        host_key_fingerprint: Some("SHA256:fixture".to_owned()),
        last_seen_at: None,
        last_success_at: None,
        removed_at: None,
        created_at: now,
        updated_at: now,
    };
    database.repository::<Asset>().create(&asset).await.unwrap();
    let app_data_dir = tempfile::tempdir().unwrap();
    let store = FailingDeleteStore {
        fail_delete: true,
        ..FailingDeleteStore::default()
    };

    let result = unpair_server_with_store(&database, app_data_dir.path(), &asset.id, false, &store)
        .await
        .unwrap();

    assert!(result.credential_cleanup_warning);
    assert!(!result.snapshot_cleanup_warning);
    assert_eq!(store.delete_attempts.lock().unwrap().len(), 2);
    let removed_asset = database
        .repository::<Asset>()
        .get(&asset.id)
        .await
        .unwrap()
        .unwrap();
    assert!(removed_asset.removed_at.is_some());
    assert!(removed_asset.ssh_target_ref.is_none());
    assert!(removed_asset.host_key_fingerprint.is_none());
}

#[tokio::test]
async fn unpair_treats_missing_keyring_entries_as_cleaned_up() {
    let database = Database::in_memory().await.unwrap();
    let now = Utc::now();
    let asset = Asset {
        id: Uuid::new_v4().to_string(),
        asset_type: AssetType::Server,
        hostname_alias: "fixture".to_owned(),
        environment: security_monitor_core::Environment::Production,
        ssh_target_ref: Some(TARGET_REF.to_owned()),
        host_key_fingerprint: Some("SHA256:fixture".to_owned()),
        last_seen_at: None,
        last_success_at: None,
        removed_at: None,
        created_at: now,
        updated_at: now,
    };
    database.repository::<Asset>().create(&asset).await.unwrap();
    let app_data_dir = tempfile::tempdir().unwrap();
    let store = FailingDeleteStore::default();

    let result = unpair_server_with_store(&database, app_data_dir.path(), &asset.id, false, &store)
        .await
        .unwrap();

    assert!(!result.credential_cleanup_warning);
    assert_eq!(store.delete_attempts.lock().unwrap().len(), 2);
}
