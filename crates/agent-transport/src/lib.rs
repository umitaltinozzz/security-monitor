mod association;
mod credentials;
mod host;
mod pairing;
mod ssh_config;
mod transport;

pub use association::{
    AssociationMatch, LocalProjectIdentity, ProjectAssociationSuggestion,
    suggest_project_associations,
};
pub use credentials::{CredentialError, CredentialStore, OsCredentialStore};
pub use host::{SshTarget, TargetError, validate_fingerprint};
pub use pairing::{PairingInstructions, create_pairing_instructions};
pub use ssh_config::{
    SshConfigError, SshConfigWarning, SshHost, load_ssh_hosts_from, load_user_ssh_hosts,
    parse_ssh_config,
};
pub use transport::{
    AgentCollection, AgentlessApproval, AgentlessCollection, AgentlessCommand, CollectionError,
    HostKeyCandidate, InventoryCollectionApproval, PinnedProxyJump, ServerState, SshIdentity,
    collect_agent, collect_agent_via_jump, collect_agentless, collect_agentless_via_jump,
    inspect_host_key, inspect_host_key_via_jump, server_state_for_error,
    server_state_for_inventory,
};
