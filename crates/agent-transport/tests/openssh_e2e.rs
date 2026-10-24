#![cfg(target_os = "linux")]

use std::{
    collections::BTreeMap,
    process::{Command, Output, Stdio},
    sync::Mutex,
    time::Duration,
};

use chrono::{TimeZone, Utc};
use security_monitor_agent_transport::{
    CredentialError, CredentialStore, InventoryCollectionApproval, SshIdentity, SshTarget,
    collect_agent, create_pairing_instructions, inspect_host_key,
};
use tokio::time::sleep;
use zeroize::Zeroizing;

#[derive(Default)]
struct MemoryStore(Mutex<BTreeMap<String, Vec<u8>>>);

impl CredentialStore for MemoryStore {
    fn put(&self, secret: &[u8]) -> Result<String, CredentialError> {
        let reference = "secmon-keyring:v1:00000000-0000-4000-8000-000000000001".to_owned();
        self.0
            .lock()
            .map_err(|_| CredentialError::StoreUnavailable)?
            .insert(reference.clone(), secret.to_vec());
        Ok(reference)
    }

    fn get(&self, reference: &str) -> Result<Zeroizing<Vec<u8>>, CredentialError> {
        self.0
            .lock()
            .map_err(|_| CredentialError::StoreUnavailable)?
            .get(reference)
            .cloned()
            .map(Zeroizing::new)
            .ok_or(CredentialError::InvalidReference)
    }

    fn delete(&self, reference: &str) -> Result<(), CredentialError> {
        self.0
            .lock()
            .map_err(|_| CredentialError::StoreUnavailable)?
            .remove(reference);
        Ok(())
    }
}

struct Container(String);

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "--force", self.0.as_str()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[tokio::test]
async fn forced_command_collects_from_an_unprivileged_openssh_user() {
    let Ok(image) = std::env::var("SECMON_OPENSSH_E2E_IMAGE") else {
        return;
    };
    let temp = tempfile::tempdir().expect("temporary E2E directory");
    let host_key = temp.path().join("ssh_host_ed25519_key");
    let key_status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&host_key)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("ssh-keygen must be installed for the container test");
    assert!(
        key_status.success(),
        "the test host key should be generated"
    );

    let store = MemoryStore::default();
    let pairing = create_pairing_instructions(&store, "openssh-e2e").expect("dedicated client key");
    let authorized_keys = temp.path().join("authorized_keys");
    std::fs::write(&authorized_keys, pairing.authorized_keys_line).expect("authorized key file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&authorized_keys, std::fs::Permissions::from_mode(0o600))
            .expect("restrict authorized key fixture");
    }

    let created = docker_output([
        "create",
        "--rm",
        "--publish",
        "127.0.0.1::22",
        image.as_str(),
    ]);
    assert!(
        created.status.success(),
        "the OpenSSH container should be created"
    );
    let container_id = String::from_utf8(created.stdout)
        .expect("container id is UTF-8")
        .trim()
        .to_owned();
    assert!(!container_id.is_empty(), "Docker returned a container id");
    let _container = Container(container_id.clone());

    for (source, destination) in [
        (host_key.as_path(), "/etc/ssh/ssh_host_ed25519_key"),
        (&authorized_keys, "/home/secmon/.ssh/authorized_keys"),
    ] {
        let copied = Command::new("docker")
            .arg("cp")
            .arg(source)
            .arg(format!("{container_id}:{destination}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("Docker CLI should copy the fixture file");
        assert!(
            copied.success(),
            "fixture files should be copied into the container"
        );
    }

    let started = docker_output(["start", container_id.as_str()]);
    assert!(
        started.status.success(),
        "the OpenSSH container should start"
    );
    let published = docker_output(["port", container_id.as_str(), "22/tcp"]);
    assert!(
        published.status.success(),
        "Docker should publish the local SSH port: {}",
        String::from_utf8_lossy(&published.stderr)
    );
    let address = String::from_utf8(published.stdout).expect("published address is UTF-8");
    let port = address
        .trim()
        .rsplit(':')
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .expect("published port should be numeric");
    let target = SshTarget::new("openssh-e2e", "127.0.0.1", "secmon", port, None)
        .expect("loopback target should be valid");

    let mut candidate = None;
    for _ in 0..50 {
        match inspect_host_key(&target).await {
            Ok(observed) => {
                candidate = Some(observed);
                break;
            }
            Err(_) => sleep(Duration::from_millis(100)).await,
        }
    }
    let candidate = candidate.expect("OpenSSH should become reachable within five seconds");
    let changed_fingerprint = format!("SHA256:{}", "A".repeat(43));
    let approval = InventoryCollectionApproval::after_explicit_user_confirmation(
        Utc.with_ymd_and_hms(2026, 10, 24, 12, 0, 0)
            .single()
            .expect("fixed approval time"),
    );
    let rejected = collect_agent(
        &target,
        &changed_fingerprint,
        &SshIdentity::PrivateKeyRef(pairing.private_key_ref.clone()),
        &store,
        approval,
    )
    .await;
    assert!(
        matches!(
            rejected,
            Err(security_monitor_agent_transport::CollectionError::HostKeyChanged)
        ),
        "a changed host key must be rejected before authentication"
    );
    let collection = collect_agent(
        &target,
        &candidate.fingerprint,
        &SshIdentity::PrivateKeyRef(pairing.private_key_ref),
        &store,
        approval,
    )
    .await;
    let inventory = match collection {
        Ok(inventory) => inventory,
        Err(error) => {
            let logs = docker_output(["logs", container_id.as_str()]);
            panic!(
                "forced command should return a valid agent inventory: {error}; sshd logs: {}",
                String::from_utf8_lossy(&logs.stdout)
            );
        }
    };
    inventory
        .inventory
        .validate()
        .expect("remote inventory must validate");
    assert!(
        inventory
            .inventory
            .processes
            .iter()
            .any(|process| process.user_name.as_deref() == Some("secmon")),
        "agent collection should observe its own unprivileged process"
    );
    assert_eq!(
        inventory.approval.approved_at(),
        Utc.with_ymd_and_hms(2026, 10, 24, 12, 0, 0)
            .single()
            .expect("fixed approval time")
    );
}

fn docker_output<const N: usize>(args: [&str; N]) -> Output {
    Command::new("docker")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Docker CLI should be installed")
}
