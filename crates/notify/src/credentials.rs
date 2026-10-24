use keyring::Entry;
use thiserror::Error;
use uuid::Uuid;

const SERVICE: &str = "security-monitor";
const CREDENTIAL_REF_PREFIX: &str = "secmon-keyring:v1:";

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("credential reference is invalid")]
    InvalidReference,
    #[error("operating-system credential store is unavailable")]
    StoreUnavailable,
}

pub trait CredentialStore: Send + Sync {
    fn put(&self, secret: &str) -> Result<String, CredentialError>;
    fn get(&self, reference: &str) -> Result<String, CredentialError>;
    fn delete(&self, reference: &str) -> Result<(), CredentialError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct OsCredentialStore;

impl CredentialStore for OsCredentialStore {
    fn put(&self, secret: &str) -> Result<String, CredentialError> {
        let reference = format!("{CREDENTIAL_REF_PREFIX}{}", Uuid::new_v4());
        let entry =
            Entry::new(SERVICE, &reference).map_err(|_| CredentialError::StoreUnavailable)?;
        entry
            .set_password(secret)
            .map_err(|_| CredentialError::StoreUnavailable)?;
        Ok(reference)
    }

    fn get(&self, reference: &str) -> Result<String, CredentialError> {
        validate_reference(reference)?;
        let entry =
            Entry::new(SERVICE, reference).map_err(|_| CredentialError::StoreUnavailable)?;
        entry
            .get_password()
            .map_err(|_| CredentialError::StoreUnavailable)
    }

    fn delete(&self, reference: &str) -> Result<(), CredentialError> {
        validate_reference(reference)?;
        let entry =
            Entry::new(SERVICE, reference).map_err(|_| CredentialError::StoreUnavailable)?;
        entry
            .delete_credential()
            .map_err(|_| CredentialError::StoreUnavailable)
    }
}

fn validate_reference(reference: &str) -> Result<(), CredentialError> {
    let Some(identifier) = reference.strip_prefix(CREDENTIAL_REF_PREFIX) else {
        return Err(CredentialError::InvalidReference);
    };
    if Uuid::parse_str(identifier).is_ok()
        && identifier == identifier.to_ascii_lowercase()
        && identifier.len() == 36
    {
        Ok(())
    } else {
        Err(CredentialError::InvalidReference)
    }
}
