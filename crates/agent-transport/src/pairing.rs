use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{CredentialError, CredentialStore};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingInstructions {
    pub private_key_ref: String,
    pub authorized_keys_line: String,
    pub forced_command: &'static str,
}

#[derive(Debug, Error)]
pub enum PairingError {
    #[error("device label is invalid")]
    InvalidLabel,
    #[error("could not generate a dedicated SSH key")]
    KeyGeneration,
    #[error("could not store the dedicated SSH key in the operating-system credential store")]
    Credential(#[from] CredentialError),
}

pub fn create_pairing_instructions(
    store: &dyn CredentialStore,
    device_label: &str,
) -> Result<PairingInstructions, PairingError> {
    if device_label.is_empty()
        || device_label.len() > 64
        || !device_label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(PairingError::InvalidLabel);
    }

    let private_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .map_err(|_| PairingError::KeyGeneration)?;
    let pem = Zeroizing::new(
        private_key
            .to_openssh(LineEnding::LF)
            .map_err(|_| PairingError::KeyGeneration)?,
    );
    let key_bytes = Zeroizing::new(pem.as_bytes().to_vec());
    let public_key = private_key
        .public_key()
        .to_openssh()
        .map_err(|_| PairingError::KeyGeneration)?;
    if !public_key.starts_with("ssh-ed25519 ") {
        return Err(PairingError::KeyGeneration);
    }
    let private_key_ref = store.put(&key_bytes)?;
    let forced_command = "/usr/local/bin/secmon-agent collect";
    let authorized_keys_line = format!(
        "command=\"{forced_command}\",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,restrict {public_key} secmon@{device_label}"
    );
    Ok(PairingInstructions {
        private_key_ref,
        authorized_keys_line,
        forced_command,
    })
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Mutex};

    use zeroize::Zeroizing;

    use crate::{CredentialError, CredentialStore};

    use super::{PairingError, create_pairing_instructions};

    #[derive(Default)]
    struct MemoryStore(Mutex<BTreeMap<String, Vec<u8>>>);

    impl CredentialStore for MemoryStore {
        fn put(&self, secret: &[u8]) -> Result<String, CredentialError> {
            let id = format!(
                "secmon-keyring:v1:00000000-0000-4000-8000-{:012x}",
                self.0
                    .lock()
                    .map_err(|_| CredentialError::StoreUnavailable)?
                    .len()
                    + 1
            );
            self.0
                .lock()
                .map_err(|_| CredentialError::StoreUnavailable)?
                .insert(id.clone(), secret.to_vec());
            Ok(id)
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

    #[test]
    fn pairing_key_is_private_and_authorized_key_is_forced_and_restricted() {
        let store = MemoryStore::default();
        let instructions =
            create_pairing_instructions(&store, "laptop-1").expect("key should be generated");
        assert!(instructions.authorized_keys_line.starts_with("command=\"/usr/local/bin/secmon-agent collect\",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,restrict ssh-ed25519 "));
        assert!(
            instructions
                .authorized_keys_line
                .ends_with(" secmon@laptop-1")
        );
        assert!(
            store
                .get(&instructions.private_key_ref)
                .expect("key should be stored")
                .starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----")
        );
    }

    #[test]
    fn device_label_cannot_inject_authorized_key_options() {
        let store = MemoryStore::default();
        assert!(matches!(
            create_pairing_instructions(&store, "laptop\" command=\"id"),
            Err(PairingError::InvalidLabel)
        ));
    }
}
