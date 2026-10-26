use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};

use chrono::{DateTime, Utc};
use russh::{
    ChannelMsg, ChannelStream, Disconnect,
    client::{self, Handle, Handler},
    keys::{HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate, decode_secret_key},
};
use security_monitor_agent_protocol::{
    AgentInventory, CheckKind, CheckStatus, CollectionCheck, ContainerRecord, DiagnosticCode,
    PackageSource, ProcessRecord, RuntimeRecord, ServiceRecord, decode_inventory, parse_os_release,
    parse_package_output, valid_container_id,
};
use thiserror::Error;
use tokio::time::timeout;

use crate::{
    CredentialError, CredentialStore, SshTarget, host::proxy_jump_matches, validate_fingerprint,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(12);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const COLLECTION_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_COMMAND_OUTPUT: usize = 16 * 1024 * 1024;
const MAX_AGENT_COMMAND: &[u8] = b"secmon-agent collect";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyCandidate {
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedProxyJump {
    pub target: SshTarget,
    pub confirmed_fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    Online,
    Offline,
    NeedsReview,
}

pub fn server_state_for_inventory(
    inventory: &AgentInventory,
    now: DateTime<Utc>,
    max_age: chrono::Duration,
) -> ServerState {
    let age = now.signed_duration_since(inventory.captured_at);
    if !inventory.complete || age < chrono::Duration::zero() || age > max_age {
        ServerState::NeedsReview
    } else {
        ServerState::Online
    }
}

pub fn server_state_for_error(error: &CollectionError) -> ServerState {
    match error {
        CollectionError::Ssh | CollectionError::Timeout => ServerState::Offline,
        _ => ServerState::NeedsReview,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshIdentity {
    /// The opaque reference resolves only through the operating-system credential store.
    PrivateKeyRef(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentlessApproval {
    pub confirmed_at: DateTime<Utc>,
    pub full_access_key_notice_shown: bool,
    pub docker_inspection_approved: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryCollectionApproval {
    approved_at: DateTime<Utc>,
}

impl InventoryCollectionApproval {
    /// Construct only after the user approves sending this server inventory to the local device.
    pub fn after_explicit_user_confirmation(approved_at: DateTime<Utc>) -> Self {
        Self { approved_at }
    }

    pub fn approved_at(&self) -> DateTime<Utc> {
        self.approved_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCollection {
    pub inventory: AgentInventory,
    pub approval: InventoryCollectionApproval,
}

impl AgentlessApproval {
    /// Call only after the UI has shown that the existing SSH key has the user's full SSH rights.
    pub fn after_explicit_user_confirmation(
        confirmed_at: DateTime<Utc>,
        docker_inspection_approved: bool,
    ) -> Self {
        Self {
            confirmed_at,
            full_access_key_notice_shown: true,
            docker_inspection_approved,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentlessCommand {
    OsRelease,
    DpkgPackages,
    RpmPackages,
    ApkPackages,
    NodeVersion,
    PhpVersion,
    Python3Version,
    DockerPs,
}

impl AgentlessCommand {
    pub fn label(&self) -> &'static str {
        match self {
            Self::OsRelease => "os_release",
            Self::DpkgPackages => "dpkg_packages",
            Self::RpmPackages => "rpm_packages",
            Self::ApkPackages => "apk_packages",
            Self::NodeVersion => "node_version",
            Self::PhpVersion => "php_version",
            Self::Python3Version => "python3_version",
            Self::DockerPs => "docker_ps",
        }
    }

    fn command(&self) -> &'static [u8] {
        match self {
            Self::OsRelease => b"cat /etc/os-release",
            Self::DpkgPackages => {
                b"dpkg-query -W -f='${binary:Package}\\t${Version}\\t${Architecture}\\t${Status}\\n'"
            }
            Self::RpmPackages => b"rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n'",
            Self::ApkPackages => b"apk info -v",
            Self::NodeVersion => b"node --version",
            Self::PhpVersion => b"php --version",
            Self::Python3Version => b"python3 --version",
            Self::DockerPs => b"docker ps --no-trunc --format '{{json .}}'",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentlessCollection {
    pub inventory: AgentInventory,
    pub approval: AgentlessApproval,
    pub executed_commands: Vec<AgentlessCommand>,
}

#[derive(Debug, Error)]
pub enum CollectionError {
    #[error("SSH target is invalid")]
    InvalidTarget,
    #[error("the recorded SSH host key does not match the server")]
    HostKeyChanged,
    #[error("host-key fingerprint must be explicitly confirmed before collection")]
    HostKeyNotConfirmed,
    #[error("the user must approve agentless collection after seeing the full-access-key notice")]
    AgentlessNotApproved,
    #[error("SSH connection timed out")]
    Timeout,
    #[error("SSH connection or collection failed")]
    Ssh,
    #[error("SSH authentication failed")]
    Authentication,
    #[error("SSH identity could not be read from the credential store")]
    Credential(#[from] CredentialError),
    #[error("SSH private key is invalid")]
    InvalidPrivateKey,
    #[error("remote agent output is invalid or incomplete")]
    Protocol,
    #[error("remote response exceeded the size limit")]
    OutputTooLarge,
    #[error("remote command failed or did not return a successful exit status")]
    RemoteCommandFailed,
    #[error("server key fingerprint is invalid")]
    InvalidFingerprint,
}

#[derive(Clone)]
struct KeyHandler {
    expected_fingerprint: Option<String>,
    observed_fingerprint: Arc<Mutex<Option<String>>>,
}

struct SshConnection {
    target: Handle<KeyHandler>,
    _jump: Option<Handle<KeyHandler>>,
}

impl Handler for KeyHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let fingerprint = server_public_key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string();
        if let Ok(mut observed) = self.observed_fingerprint.lock() {
            *observed = Some(fingerprint.clone());
        }
        Ok(self
            .expected_fingerprint
            .as_ref()
            .is_none_or(|expected| expected == &fingerprint))
    }
}

pub async fn inspect_host_key(target: &SshTarget) -> Result<HostKeyCandidate, CollectionError> {
    with_collection_timeout(async {
        target
            .validate()
            .map_err(|_| CollectionError::InvalidTarget)?;
        if target.proxy_jump.is_some() {
            return Err(CollectionError::InvalidTarget);
        }
        let observed = Arc::new(Mutex::new(None));
        let handler = KeyHandler {
            expected_fingerprint: None,
            observed_fingerprint: Arc::clone(&observed),
        };
        let session = timeout(CONNECT_TIMEOUT, connect_direct(target, handler))
            .await
            .map_err(|_| CollectionError::Timeout)??;
        let fingerprint = observed
            .lock()
            .map_err(|_| CollectionError::Ssh)?
            .clone()
            .ok_or(CollectionError::Ssh)?;
        session
            .disconnect(Disconnect::ByApplication, "host key inspected", "en")
            .await
            .map_err(|_| CollectionError::Ssh)?;
        Ok(HostKeyCandidate { fingerprint })
    })
    .await
}

pub async fn inspect_host_key_via_jump(
    target: &SshTarget,
    jump: &PinnedProxyJump,
    identity: &SshIdentity,
    store: &dyn CredentialStore,
) -> Result<HostKeyCandidate, CollectionError> {
    with_collection_timeout(async {
        validate_route(target, Some(jump))?;
        validate_fingerprint(&jump.confirmed_fingerprint)
            .map_err(|_| CollectionError::InvalidFingerprint)?;
        let mut jump_session =
            connect_pinned_host(&jump.target, &jump.confirmed_fingerprint).await?;
        authenticate(&mut jump_session, &jump.target.username, identity, store).await?;
        let channel = timeout(
            CONNECT_TIMEOUT,
            jump_session.channel_open_direct_tcpip(
                target.hostname.clone(),
                target.port.into(),
                "127.0.0.1".to_owned(),
                0,
            ),
        )
        .await
        .map_err(|_| CollectionError::Timeout)?
        .map_err(|_| CollectionError::Ssh)?;
        let stream: ChannelStream<_> = channel.into_stream();
        let observed = Arc::new(Mutex::new(None));
        let handler = KeyHandler {
            expected_fingerprint: None,
            observed_fingerprint: Arc::clone(&observed),
        };
        let config = ssh_client_config();
        let session = timeout(
            CONNECT_TIMEOUT,
            client::connect_stream(config, stream, handler),
        )
        .await
        .map_err(|_| CollectionError::Timeout)?
        .map_err(|_| CollectionError::Ssh)?;
        let fingerprint = observed
            .lock()
            .map_err(|_| CollectionError::Ssh)?
            .clone()
            .ok_or(CollectionError::Ssh)?;
        session
            .disconnect(Disconnect::ByApplication, "host key inspected", "en")
            .await
            .map_err(|_| CollectionError::Ssh)?;
        Ok(HostKeyCandidate { fingerprint })
    })
    .await
}

pub async fn collect_agent(
    target: &SshTarget,
    confirmed_fingerprint: &str,
    identity: &SshIdentity,
    store: &dyn CredentialStore,
    approval: InventoryCollectionApproval,
) -> Result<AgentCollection, CollectionError> {
    with_collection_timeout(async {
        let mut connection =
            connect_for_target(target, confirmed_fingerprint, identity, store, None).await?;
        let output = run_remote(&mut connection.target, MAX_AGENT_COMMAND).await?;
        let inventory = decode_inventory(&output).map_err(|_| CollectionError::Protocol)?;
        Ok(AgentCollection {
            inventory,
            approval,
        })
    })
    .await
}

pub async fn collect_agent_via_jump(
    target: &SshTarget,
    confirmed_fingerprint: &str,
    jump: &PinnedProxyJump,
    identity: &SshIdentity,
    store: &dyn CredentialStore,
    approval: InventoryCollectionApproval,
) -> Result<AgentCollection, CollectionError> {
    with_collection_timeout(async {
        let mut connection =
            connect_for_target(target, confirmed_fingerprint, identity, store, Some(jump)).await?;
        let output = run_remote(&mut connection.target, MAX_AGENT_COMMAND).await?;
        let inventory = decode_inventory(&output).map_err(|_| CollectionError::Protocol)?;
        Ok(AgentCollection {
            inventory,
            approval,
        })
    })
    .await
}

pub async fn collect_agentless(
    target: &SshTarget,
    confirmed_fingerprint: &str,
    identity: &SshIdentity,
    store: &dyn CredentialStore,
    approval: AgentlessApproval,
) -> Result<AgentlessCollection, CollectionError> {
    with_collection_timeout(async {
        validate_fingerprint(confirmed_fingerprint)
            .map_err(|_| CollectionError::InvalidFingerprint)?;
        if !approval.full_access_key_notice_shown {
            return Err(CollectionError::AgentlessNotApproved);
        }

        let mut connection =
            connect_for_target(target, confirmed_fingerprint, identity, store, None).await?;
        let commands = [
            AgentlessCommand::OsRelease,
            AgentlessCommand::DpkgPackages,
            AgentlessCommand::RpmPackages,
            AgentlessCommand::ApkPackages,
            AgentlessCommand::NodeVersion,
            AgentlessCommand::PhpVersion,
            AgentlessCommand::Python3Version,
            AgentlessCommand::DockerPs,
        ];
        let mut outputs = Vec::with_capacity(commands.len());
        for command in &commands {
            if *command == AgentlessCommand::DockerPs && !approval.docker_inspection_approved {
                continue;
            }
            outputs.push((
                command.clone(),
                run_remote(&mut connection.target, command.command()).await,
            ));
        }
        let inventory = agentless_inventory(
            target,
            outputs,
            Utc::now(),
            approval.docker_inspection_approved,
        );
        Ok(AgentlessCollection {
            inventory,
            approval,
            executed_commands: commands
                .into_iter()
                .filter(|command| {
                    *command != AgentlessCommand::DockerPs || approval.docker_inspection_approved
                })
                .collect(),
        })
    })
    .await
}

pub async fn collect_agentless_via_jump(
    target: &SshTarget,
    confirmed_fingerprint: &str,
    jump: &PinnedProxyJump,
    identity: &SshIdentity,
    store: &dyn CredentialStore,
    approval: AgentlessApproval,
) -> Result<AgentlessCollection, CollectionError> {
    with_collection_timeout(async {
        validate_fingerprint(confirmed_fingerprint)
            .map_err(|_| CollectionError::InvalidFingerprint)?;
        if !approval.full_access_key_notice_shown {
            return Err(CollectionError::AgentlessNotApproved);
        }
        let mut connection =
            connect_for_target(target, confirmed_fingerprint, identity, store, Some(jump)).await?;
        let commands = [
            AgentlessCommand::OsRelease,
            AgentlessCommand::DpkgPackages,
            AgentlessCommand::RpmPackages,
            AgentlessCommand::ApkPackages,
            AgentlessCommand::NodeVersion,
            AgentlessCommand::PhpVersion,
            AgentlessCommand::Python3Version,
            AgentlessCommand::DockerPs,
        ];
        let mut outputs = Vec::with_capacity(commands.len());
        for command in &commands {
            if *command == AgentlessCommand::DockerPs && !approval.docker_inspection_approved {
                continue;
            }
            outputs.push((
                command.clone(),
                run_remote(&mut connection.target, command.command()).await,
            ));
        }
        let inventory = agentless_inventory(
            target,
            outputs,
            Utc::now(),
            approval.docker_inspection_approved,
        );
        let executed_commands = commands
            .into_iter()
            .filter(|command| {
                *command != AgentlessCommand::DockerPs || approval.docker_inspection_approved
            })
            .collect();
        Ok(AgentlessCollection {
            inventory,
            approval,
            executed_commands,
        })
    })
    .await
}

async fn with_collection_timeout<T>(
    future: impl Future<Output = Result<T, CollectionError>>,
) -> Result<T, CollectionError> {
    with_timeout(COLLECTION_TIMEOUT, future).await
}

async fn with_timeout<T>(
    limit: Duration,
    future: impl Future<Output = Result<T, CollectionError>>,
) -> Result<T, CollectionError> {
    timeout(limit, future)
        .await
        .map_err(|_| CollectionError::Timeout)?
}

async fn connect_pinned_host(
    target: &SshTarget,
    fingerprint: &str,
) -> Result<Handle<KeyHandler>, CollectionError> {
    target
        .validate()
        .map_err(|_| CollectionError::InvalidTarget)?;
    if target.proxy_jump.is_some() {
        return Err(CollectionError::InvalidTarget);
    }
    connect_pinned_host_allow_jump_target(target, fingerprint).await
}

async fn connect_pinned_host_allow_jump_target(
    target: &SshTarget,
    fingerprint: &str,
) -> Result<Handle<KeyHandler>, CollectionError> {
    let observed = Arc::new(Mutex::new(None));
    let handler = KeyHandler {
        expected_fingerprint: Some(fingerprint.to_owned()),
        observed_fingerprint: Arc::clone(&observed),
    };
    let result = timeout(CONNECT_TIMEOUT, connect_direct(target, handler))
        .await
        .map_err(|_| CollectionError::Timeout)?;
    result.map_err(|_| {
        if observed
            .lock()
            .ok()
            .and_then(|fingerprint| fingerprint.clone())
            .is_some_and(|actual| actual != fingerprint)
        {
            CollectionError::HostKeyChanged
        } else {
            CollectionError::Ssh
        }
    })
}

async fn connect_for_target(
    target: &SshTarget,
    fingerprint: &str,
    identity: &SshIdentity,
    store: &dyn CredentialStore,
    jump: Option<&PinnedProxyJump>,
) -> Result<SshConnection, CollectionError> {
    validate_fingerprint(fingerprint).map_err(|_| CollectionError::InvalidFingerprint)?;
    validate_route(target, jump)?;
    let (mut target_session, jump_session) = if let Some(jump) = jump {
        validate_fingerprint(&jump.confirmed_fingerprint)
            .map_err(|_| CollectionError::InvalidFingerprint)?;
        let mut jump_session =
            connect_pinned_host(&jump.target, &jump.confirmed_fingerprint).await?;
        authenticate(&mut jump_session, &jump.target.username, identity, store).await?;
        let channel = timeout(
            CONNECT_TIMEOUT,
            jump_session.channel_open_direct_tcpip(
                target.hostname.clone(),
                target.port.into(),
                "127.0.0.1".to_owned(),
                0,
            ),
        )
        .await
        .map_err(|_| CollectionError::Timeout)?
        .map_err(|_| CollectionError::Ssh)?;
        let stream: ChannelStream<_> = channel.into_stream();
        let observed = Arc::new(Mutex::new(None));
        let handler = KeyHandler {
            expected_fingerprint: Some(fingerprint.to_owned()),
            observed_fingerprint: Arc::clone(&observed),
        };
        let target_session = timeout(
            CONNECT_TIMEOUT,
            client::connect_stream(ssh_client_config(), stream, handler),
        )
        .await
        .map_err(|_| CollectionError::Timeout)?
        .map_err(|_| {
            if observed
                .lock()
                .ok()
                .and_then(|observed| observed.clone())
                .is_some_and(|actual| actual != fingerprint)
            {
                CollectionError::HostKeyChanged
            } else {
                CollectionError::Ssh
            }
        })?;
        (target_session, Some(jump_session))
    } else {
        (
            connect_pinned_host_allow_jump_target(target, fingerprint).await?,
            None,
        )
    };
    authenticate(&mut target_session, &target.username, identity, store).await?;
    Ok(SshConnection {
        target: target_session,
        _jump: jump_session,
    })
}

fn validate_route(
    target: &SshTarget,
    jump: Option<&PinnedProxyJump>,
) -> Result<(), CollectionError> {
    target
        .validate()
        .map_err(|_| CollectionError::InvalidTarget)?;
    match (target.proxy_jump.as_deref(), jump) {
        (None, None) => Ok(()),
        (Some(alias), Some(jump))
            if proxy_jump_matches(alias, &jump.target)
                && jump.target.proxy_jump.is_none()
                && jump.target.alias != target.alias =>
        {
            jump.target
                .validate()
                .map_err(|_| CollectionError::InvalidTarget)
        }
        _ => Err(CollectionError::InvalidTarget),
    }
}

async fn connect_direct<H: Handler<Error = russh::Error> + Send + 'static>(
    target: &SshTarget,
    handler: H,
) -> Result<Handle<H>, CollectionError> {
    client::connect(
        ssh_client_config(),
        (target.hostname.as_str(), target.port),
        handler,
    )
    .await
    .map_err(|_| CollectionError::Ssh)
}

fn ssh_client_config() -> Arc<client::Config> {
    Arc::new(client::Config {
        inactivity_timeout: Some(COMMAND_TIMEOUT),
        ..client::Config::default()
    })
}

async fn authenticate(
    session: &mut Handle<KeyHandler>,
    username: &str,
    identity: &SshIdentity,
    store: &dyn CredentialStore,
) -> Result<(), CollectionError> {
    let SshIdentity::PrivateKeyRef(reference) = identity;
    let private_key_pem = store.get(reference)?;
    let pem =
        std::str::from_utf8(&private_key_pem).map_err(|_| CollectionError::InvalidPrivateKey)?;
    let private_key =
        decode_secret_key(pem, None).map_err(|_| CollectionError::InvalidPrivateKey)?;
    let auth = timeout(
        COMMAND_TIMEOUT,
        session.authenticate_publickey(
            username.to_owned(),
            PrivateKeyWithHashAlg::new(Arc::new(private_key), None),
        ),
    )
    .await
    .map_err(|_| CollectionError::Timeout)?
    .map_err(|_| CollectionError::Authentication)?;
    if auth.success() {
        Ok(())
    } else {
        Err(CollectionError::Authentication)
    }
}

async fn run_remote(
    session: &mut Handle<KeyHandler>,
    command: &[u8],
) -> Result<Vec<u8>, CollectionError> {
    timeout(COMMAND_TIMEOUT, async {
        let channel = session
            .channel_open_session()
            .await
            .map_err(|_| CollectionError::Ssh)?;
        channel
            .exec(true, command)
            .await
            .map_err(|_| CollectionError::Ssh)?;
        let mut output = Vec::new();
        let mut exit_status = None;
        let mut channel = channel;
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => {
                    if output.len().saturating_add(data.len()) > MAX_COMMAND_OUTPUT {
                        return Err(CollectionError::OutputTooLarge);
                    }
                    output.extend_from_slice(&data);
                }
                ChannelMsg::ExitStatus {
                    exit_status: status,
                } => {
                    if exit_status.replace(status).is_some() {
                        return Err(CollectionError::RemoteCommandFailed);
                    }
                }
                ChannelMsg::Eof => {}
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        if exit_status != Some(0) {
            return Err(CollectionError::RemoteCommandFailed);
        }
        Ok(output)
    })
    .await
    .map_err(|_| CollectionError::Timeout)?
}

fn agentless_inventory(
    target: &SshTarget,
    outputs: Vec<(AgentlessCommand, Result<Vec<u8>, CollectionError>)>,
    captured_at: DateTime<Utc>,
    docker_inspection_approved: bool,
) -> AgentInventory {
    let mut operating_system = None;
    let mut packages = Vec::new();
    let mut runtimes = Vec::new();
    let mut containers = Vec::new();
    let mut os_attempted = false;
    let mut os_succeeded = false;
    let mut os_command_failed = false;
    let mut package_commands_succeeded = 0usize;
    let mut package_output_invalid = false;
    let mut package_command_failed = false;
    let mut runtime_commands_attempted = 0usize;
    let mut runtime_commands_succeeded = 0usize;
    let mut runtime_output_invalid = false;
    let mut runtime_command_failed = false;
    let mut docker_attempted = false;
    let mut docker_succeeded = false;
    let mut docker_output_invalid = false;
    let mut docker_command_failed = false;

    for (command, result) in outputs {
        match command {
            AgentlessCommand::OsRelease => os_attempted = true,
            AgentlessCommand::DpkgPackages
            | AgentlessCommand::RpmPackages
            | AgentlessCommand::ApkPackages => {}
            AgentlessCommand::NodeVersion
            | AgentlessCommand::PhpVersion
            | AgentlessCommand::Python3Version => runtime_commands_attempted += 1,
            AgentlessCommand::DockerPs => docker_attempted = true,
        }
        let output = match result {
            Ok(output) => output,
            Err(error) => {
                if matches!(error, CollectionError::RemoteCommandFailed) {
                    match &command {
                        AgentlessCommand::OsRelease => os_command_failed = true,
                        AgentlessCommand::DpkgPackages
                        | AgentlessCommand::RpmPackages
                        | AgentlessCommand::ApkPackages => package_command_failed = true,
                        AgentlessCommand::NodeVersion
                        | AgentlessCommand::PhpVersion
                        | AgentlessCommand::Python3Version => runtime_command_failed = true,
                        AgentlessCommand::DockerPs => docker_command_failed = true,
                    }
                }
                continue;
            }
        };
        let text = String::from_utf8_lossy(&output);
        match command {
            AgentlessCommand::OsRelease => {
                operating_system = parse_os_release(&text);
                os_succeeded = operating_system.is_some();
            }
            AgentlessCommand::DpkgPackages => {
                let found = parse_package_output(&output, "deb", PackageSource::Dpkg);
                package_commands_succeeded += 1;
                package_output_invalid |= found.partial || found.records.is_empty();
                packages.extend(found.records);
            }
            AgentlessCommand::RpmPackages => {
                let found = parse_package_output(&output, "rpm", PackageSource::Rpm);
                package_commands_succeeded += 1;
                package_output_invalid |= found.partial || found.records.is_empty();
                packages.extend(found.records);
            }
            AgentlessCommand::ApkPackages => {
                let found = parse_package_output(&output, "apk", PackageSource::Apk);
                package_commands_succeeded += 1;
                package_output_invalid |= found.partial || found.records.is_empty();
                packages.extend(found.records);
            }
            AgentlessCommand::NodeVersion => {
                let succeeded = add_runtime(&mut runtimes, "node", &text, "/usr/bin/node");
                runtime_commands_succeeded += usize::from(succeeded);
                runtime_output_invalid |= !succeeded;
            }
            AgentlessCommand::PhpVersion => {
                let succeeded = add_runtime(&mut runtimes, "php", &text, "/usr/bin/php");
                runtime_commands_succeeded += usize::from(succeeded);
                runtime_output_invalid |= !succeeded;
            }
            AgentlessCommand::Python3Version => {
                let succeeded = add_runtime(&mut runtimes, "python3", &text, "/usr/bin/python3");
                runtime_commands_succeeded += usize::from(succeeded);
                runtime_output_invalid |= !succeeded;
            }
            AgentlessCommand::DockerPs => {
                docker_succeeded = parse_docker_ps(&text, &mut containers);
                docker_output_invalid = !docker_succeeded;
            }
        }
    }

    let os_status = if os_succeeded {
        CheckStatus::Complete
    } else {
        CheckStatus::Partial
    };
    let package_status = if package_commands_succeeded == 0 || package_output_invalid {
        CheckStatus::Partial
    } else {
        CheckStatus::Complete
    };
    let runtime_status = if runtime_commands_succeeded == runtime_commands_attempted
        && runtime_commands_attempted == 3
    {
        CheckStatus::Complete
    } else {
        CheckStatus::Partial
    };
    let docker_status = if !docker_inspection_approved {
        CheckStatus::Unavailable
    } else if !docker_attempted {
        CheckStatus::Partial
    } else if docker_succeeded && !docker_output_invalid {
        CheckStatus::Complete
    } else if docker_succeeded || docker_output_invalid {
        CheckStatus::Partial
    } else {
        CheckStatus::Unavailable
    };
    let mut checks = vec![
        collection_check(
            CheckKind::OperatingSystem,
            os_status,
            (!os_succeeded).then_some(if os_attempted {
                if os_command_failed {
                    DiagnosticCode::CommandFailed
                } else {
                    DiagnosticCode::InvalidOutput
                }
            } else {
                DiagnosticCode::CommandUnavailable
            }),
            usize::from(os_succeeded),
        ),
        collection_check(
            CheckKind::PackageInventory,
            package_status,
            (package_status != CheckStatus::Complete).then_some(
                if package_commands_succeeded == 0 {
                    if package_command_failed {
                        DiagnosticCode::CommandFailed
                    } else {
                        DiagnosticCode::CommandUnavailable
                    }
                } else {
                    DiagnosticCode::InvalidOutput
                },
            ),
            packages.len(),
        ),
        collection_check(
            CheckKind::Runtimes,
            runtime_status,
            (runtime_status != CheckStatus::Complete).then_some(if runtime_command_failed {
                DiagnosticCode::CommandFailed
            } else if runtime_output_invalid {
                DiagnosticCode::InvalidOutput
            } else {
                DiagnosticCode::CommandUnavailable
            }),
            runtimes.len(),
        ),
        collection_check(
            CheckKind::Processes,
            CheckStatus::Partial,
            Some(DiagnosticCode::UnsupportedPlatform),
            0,
        ),
        collection_check(
            CheckKind::Services,
            CheckStatus::Partial,
            Some(DiagnosticCode::UnsupportedPlatform),
            0,
        ),
        collection_check(
            CheckKind::Containers,
            docker_status,
            (docker_status != CheckStatus::Complete).then_some(if !docker_inspection_approved {
                DiagnosticCode::PermissionDenied
            } else if docker_command_failed {
                DiagnosticCode::CommandFailed
            } else if docker_output_invalid {
                DiagnosticCode::InvalidOutput
            } else {
                DiagnosticCode::CommandUnavailable
            }),
            containers.len(),
        ),
        collection_check(
            CheckKind::Deployments,
            CheckStatus::Partial,
            Some(DiagnosticCode::StaleObservation),
            0,
        ),
        collection_check(
            CheckKind::DependencyFiles,
            CheckStatus::Partial,
            Some(DiagnosticCode::UnsupportedPlatform),
            0,
        ),
    ];
    checks.sort_by_key(|check| check.kind);
    let complete = checks
        .iter()
        .all(|check| check.status == CheckStatus::Complete);
    AgentInventory {
        protocol_version: security_monitor_agent_protocol::PROTOCOL_VERSION,
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        captured_at,
        hostname: target.alias.clone(),
        operating_system,
        packages,
        runtimes,
        processes: Vec::<ProcessRecord>::new(),
        services: Vec::<ServiceRecord>::new(),
        containers,
        deployments: Vec::new(),
        checks,
        complete,
    }
}

fn collection_check(
    kind: CheckKind,
    status: CheckStatus,
    diagnostic: Option<DiagnosticCode>,
    count: usize,
) -> CollectionCheck {
    CollectionCheck {
        kind,
        status,
        diagnostic: if status == CheckStatus::Complete {
            None
        } else {
            diagnostic
        },
        item_count: count.min(u32::MAX as usize) as u32,
    }
}

fn add_runtime(runtimes: &mut Vec<RuntimeRecord>, name: &str, output: &str, path: &str) -> bool {
    let Some(version) = output
        .lines()
        .find(|line| line.contains(|character: char| character.is_ascii_digit()))
    else {
        return false;
    };
    runtimes.push(RuntimeRecord {
        name: name.to_owned(),
        version: version.trim().to_owned(),
        binary_path: path.to_owned(),
    });
    true
}

fn parse_docker_ps(output: &str, containers: &mut Vec<ContainerRecord>) -> bool {
    let mut valid = true;
    let mut saw_row = false;
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        saw_row = true;
        let row: Result<serde_json::Value, _> = serde_json::from_str(line);
        let Ok(row) = row else {
            valid = false;
            continue;
        };
        let id = row
            .get("ID")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let name = row
            .get("Names")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let image = row
            .get("Image")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if !valid_container_id(id) || name.is_empty() || image.is_empty() {
            valid = false;
            continue;
        }
        containers.push(ContainerRecord {
            id: id.to_owned(),
            name: name.to_owned(),
            image: image.to_owned(),
            image_digest: None,
            oci_revision: None,
            oci_version: None,
            oci_source: None,
        });
    }
    valid && saw_row
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone, Utc};
    use security_monitor_agent_protocol::{CheckKind, CheckStatus, decode_inventory};

    use super::{
        AgentlessApproval, AgentlessCommand, CollectionError, DiagnosticCode, ServerState,
        agentless_inventory, parse_docker_ps, parse_os_release, parse_package_output,
        server_state_for_error, server_state_for_inventory, with_timeout,
    };
    use crate::SshTarget;

    #[tokio::test]
    async fn collection_deadline_returns_timeout_when_a_step_never_finishes() {
        let result = with_timeout(
            std::time::Duration::from_millis(1),
            std::future::pending::<Result<(), CollectionError>>(),
        )
        .await;
        assert!(matches!(result, Err(CollectionError::Timeout)));
    }

    #[test]
    fn remote_command_allowlist_is_a_fixed_static_set() {
        let commands = [
            AgentlessCommand::OsRelease,
            AgentlessCommand::DpkgPackages,
            AgentlessCommand::RpmPackages,
            AgentlessCommand::ApkPackages,
            AgentlessCommand::NodeVersion,
            AgentlessCommand::PhpVersion,
            AgentlessCommand::Python3Version,
            AgentlessCommand::DockerPs,
        ];
        assert_eq!(
            commands
                .iter()
                .map(AgentlessCommand::label)
                .collect::<Vec<_>>(),
            vec![
                "os_release",
                "dpkg_packages",
                "rpm_packages",
                "apk_packages",
                "node_version",
                "php_version",
                "python3_version",
                "docker_ps"
            ]
        );
        assert!(
            commands
                .iter()
                .all(|command| !command.command().contains(&b'\n'))
        );
        assert!(
            String::from_utf8_lossy(AgentlessCommand::DpkgPackages.command()).contains("${Status}")
        );
    }

    #[test]
    fn os_release_and_package_output_are_normalized_without_raw_errors() {
        let os = parse_os_release("ID=debian\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=12\n")
            .expect("OS should parse");
        assert_eq!(os.id.as_deref(), Some("debian"));
        let packages = parse_package_output(
            b"libssl3\t3.0.11\tamd64\tinstall ok installed\nold-package\t1.0\tall\tdeinstall ok config-files\ninvalid\n",
            "deb",
            security_monitor_agent_protocol::PackageSource::Dpkg,
        );
        assert_eq!(packages.records.len(), 1);
        assert_eq!(packages.records[0].name, "libssl3");
        assert!(packages.partial);
    }

    #[test]
    fn docker_output_requires_hex_ids_and_preserves_distinct_digests_when_present() {
        let mut containers = Vec::new();
        assert!(!parse_docker_ps("", &mut containers));
        assert!(!parse_docker_ps(
            "{\"ID\":\"bad;id\",\"Names\":\"web\",\"Image\":\"web:latest\"}\n",
            &mut containers
        ));
        assert!(containers.is_empty());
    }

    #[test]
    fn agentless_output_always_marks_unavailable_inventory_partial() {
        let target = SshTarget::new("fixture", "127.0.0.1", "app", 22, None).expect("target valid");
        let now = Utc
            .timestamp_opt(1_792_820_000, 0)
            .single()
            .expect("timestamp");
        let approval = AgentlessApproval::after_explicit_user_confirmation(now, false);
        let inventory = agentless_inventory(&target, Vec::new(), now, false);
        assert!(!inventory.complete);
        assert!(inventory.checks.iter().any(
            |check| check.kind == CheckKind::Processes && check.status == CheckStatus::Partial
        ));
        assert!(approval.full_access_key_notice_shown);
        assert!(inventory.validate().is_ok());
        assert_eq!(
            server_state_for_inventory(&inventory, now, Duration::minutes(5)),
            ServerState::NeedsReview
        );
    }

    #[test]
    fn empty_docker_output_is_not_reported_as_a_complete_inventory() {
        let target = SshTarget::new("fixture", "127.0.0.1", "app", 22, None).expect("target valid");
        let now = Utc
            .timestamp_opt(1_792_820_000, 0)
            .single()
            .expect("timestamp");
        let inventory = agentless_inventory(
            &target,
            vec![(AgentlessCommand::DockerPs, Ok(Vec::new()))],
            now,
            true,
        );
        let check = inventory
            .checks
            .iter()
            .find(|check| check.kind == CheckKind::Containers)
            .expect("container check");

        assert_eq!(check.status, CheckStatus::Partial);
        assert_eq!(check.diagnostic, Some(DiagnosticCode::InvalidOutput));
        assert!(inventory.validate().is_ok());
    }

    #[test]
    fn agentless_aggregation_has_one_check_per_category_and_keeps_missing_runtimes_partial() {
        let target = SshTarget::new("fixture", "127.0.0.1", "app", 22, None).expect("target valid");
        let now = Utc
            .timestamp_opt(1_792_820_000, 0)
            .single()
            .expect("timestamp");
        let inventory = agentless_inventory(
            &target,
            vec![
                (
                    AgentlessCommand::OsRelease,
                    Ok(b"ID=debian\nNAME=Debian\n".to_vec()),
                ),
                (AgentlessCommand::DpkgPackages, Err(CollectionError::Ssh)),
                (AgentlessCommand::RpmPackages, Err(CollectionError::Ssh)),
                (
                    AgentlessCommand::ApkPackages,
                    Ok(b"libssl-3.0.0-r0\n".to_vec()),
                ),
                (AgentlessCommand::NodeVersion, Ok(b"v20.0.0\n".to_vec())),
                (AgentlessCommand::PhpVersion, Err(CollectionError::Ssh)),
                (AgentlessCommand::Python3Version, Err(CollectionError::Ssh)),
            ],
            now,
            false,
        );
        assert!(inventory.validate().is_ok());
        assert_eq!(inventory.checks.len(), CheckKind::ALL.len());
        assert_eq!(
            inventory
                .checks
                .iter()
                .filter(|check| check.kind == CheckKind::Runtimes)
                .count(),
            1
        );
        assert_eq!(
            inventory
                .checks
                .iter()
                .find(|check| check.kind == CheckKind::Runtimes)
                .map(|check| check.status),
            Some(CheckStatus::Partial)
        );
        assert_eq!(
            inventory
                .checks
                .iter()
                .find(|check| check.kind == CheckKind::Containers)
                .map(|check| check.status),
            Some(CheckStatus::Unavailable)
        );
        assert!(inventory.packages.iter().any(|package| {
            package.name == "libssl" && package.version.as_deref() == Some("3.0.0-r0")
        }));
    }

    #[test]
    fn stale_or_future_inventories_need_review_and_connection_failures_are_offline() {
        let stale = decode_inventory(include_bytes!(
            "../../../tests/fixtures/agent/stale-inventory.json"
        ))
        .expect("stale inventory fixture is valid");
        let now = Utc
            .with_ymd_and_hms(2026, 10, 24, 12, 0, 0)
            .single()
            .expect("fixed test time");
        assert_eq!(
            server_state_for_inventory(&stale, now, Duration::minutes(5)),
            ServerState::NeedsReview
        );
        assert_eq!(
            server_state_for_error(&CollectionError::Ssh),
            ServerState::Offline
        );
        assert_eq!(
            server_state_for_error(&CollectionError::HostKeyChanged),
            ServerState::NeedsReview
        );
    }
}
