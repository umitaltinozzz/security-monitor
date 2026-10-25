use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
};

use chrono::Utc;
use russh::{
    Channel, ChannelId,
    keys::{Algorithm, PrivateKey, ssh_key::PublicKey},
    server::{self, Auth, Msg, Server as _, Session},
};
use security_monitor_agent_transport::{
    CollectionError, CredentialError, CredentialStore, InventoryCollectionApproval, SshIdentity,
    SshTarget, collect_agent, create_pairing_instructions, inspect_host_key,
};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const FIXTURE_INVENTORY: &[u8] = include_bytes!("../../../tests/fixtures/agent/single-node.json");
const AGENT_COMMAND: &[u8] = b"secmon-agent collect";

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

#[derive(Clone)]
struct FixtureServer {
    authorized_key: PublicKey,
    commands: Arc<Mutex<Vec<Vec<u8>>>>,
    exit_status: Arc<AtomicU32>,
}

impl server::Server for FixtureServer {
    type Handler = Self;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self {
        self.clone()
    }
}

impl server::Handler for FixtureServer {
    type Error = russh::Error;

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(if user == "secmon" && key == &self.authorized_key {
            Auth::Accept
        } else {
            Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            }
        })
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Ok(mut commands) = self.commands.lock() {
            commands.push(command.to_vec());
        }
        if command != AGENT_COMMAND {
            session.channel_failure(channel)?;
            return Ok(());
        }
        session.channel_success(channel)?;
        session.data(channel, FIXTURE_INVENTORY)?;
        session.exit_status_request(channel, self.exit_status.load(Ordering::Relaxed))?;
        session.eof(channel)?;
        Ok(())
    }
}

#[tokio::test]
async fn pinned_ssh_transport_rejects_host_key_mismatch_and_nonzero_exit_status() {
    let store = MemoryStore::default();
    let pairing = create_pairing_instructions(&store, "loopback-e2e").expect("client key");
    let fields = pairing
        .authorized_keys_line
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    let key_type = fields
        .iter()
        .position(|field| *field == "ssh-ed25519")
        .expect("authorized key type");
    let authorized_key =
        PublicKey::from_openssh(&format!("{} {}", fields[key_type], fields[key_type + 1]))
            .expect("pairing public key");
    let commands = Arc::new(Mutex::new(Vec::new()));
    let exit_status = Arc::new(AtomicU32::new(0));
    let server = FixtureServer {
        authorized_key,
        commands: Arc::clone(&commands),
        exit_status: Arc::clone(&exit_status),
    };
    let config = Arc::new(server::Config {
        keys: vec![
            PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("loopback host key"),
        ],
        ..Default::default()
    });
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("loopback listener");
    let address = listener.local_addr().expect("listener address");
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let server_join = tokio::spawn(async move {
        let mut server = server;
        let server_task = server.run_on_socket(config, &listener);
        let _ = started_tx.send(server_task.handle());
        server_task.await
    });
    let server_handle = started_rx.await.expect("SSH fixture server should start");

    let target = SshTarget::new("loopback-e2e", "127.0.0.1", "secmon", address.port(), None)
        .expect("valid loopback SSH target");
    let fingerprint = inspect_host_key(&target)
        .await
        .expect("loopback host key should be readable")
        .fingerprint;
    let identity = SshIdentity::PrivateKeyRef(pairing.private_key_ref);
    let approval = InventoryCollectionApproval::after_explicit_user_confirmation(Utc::now());
    let mut wrong_fingerprint = fingerprint.as_bytes().to_vec();
    let first_encoded_byte = b"SHA256:".len();
    wrong_fingerprint[first_encoded_byte] = if wrong_fingerprint[first_encoded_byte] == b'A' {
        b'B'
    } else {
        b'A'
    };
    let wrong_fingerprint = String::from_utf8(wrong_fingerprint).expect("ASCII fingerprint");
    assert!(matches!(
        collect_agent(&target, &wrong_fingerprint, &identity, &store, approval).await,
        Err(CollectionError::HostKeyChanged)
    ));
    assert!(commands.lock().expect("command lock").is_empty());

    let collection = collect_agent(&target, &fingerprint, &identity, &store, approval)
        .await
        .expect("agent inventory should be collected over SSH");

    assert_eq!(collection.inventory.hostname, "fixture-app-1");
    collection
        .inventory
        .validate()
        .expect("fixture inventory should satisfy the protocol");
    exit_status.store(1, Ordering::Relaxed);
    assert!(matches!(
        collect_agent(&target, &fingerprint, &identity, &store, approval).await,
        Err(CollectionError::RemoteCommandFailed)
    ));
    assert_eq!(
        commands.lock().expect("command lock").clone(),
        vec![AGENT_COMMAND.to_vec(), AGENT_COMMAND.to_vec()]
    );

    server_handle.shutdown("test complete".to_owned());
    server_join
        .await
        .expect("SSH fixture server task should stop")
        .expect("SSH fixture server should exit cleanly");
}
