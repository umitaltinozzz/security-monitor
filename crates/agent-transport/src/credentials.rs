use keyring::Entry;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

const SERVICE: &str = "security-monitor";
const KEY_REF_PREFIX: &str = "secmon-keyring:v1:";

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("credential reference is invalid")]
    InvalidReference,
    #[error("operating-system credential store is unavailable")]
    StoreUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialDeleteOutcome {
    Deleted,
    Missing,
}

pub trait CredentialStore: Send + Sync {
    fn put(&self, secret: &[u8]) -> Result<String, CredentialError>;
    fn get(&self, reference: &str) -> Result<Zeroizing<Vec<u8>>, CredentialError>;
    fn get_optional(&self, reference: &str) -> Result<Option<Zeroizing<Vec<u8>>>, CredentialError> {
        self.get(reference).map(Some)
    }
    fn delete(&self, reference: &str) -> Result<(), CredentialError>;

    fn delete_with_outcome(
        &self,
        reference: &str,
    ) -> Result<CredentialDeleteOutcome, CredentialError> {
        self.delete(reference)?;
        Ok(CredentialDeleteOutcome::Deleted)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct OsCredentialStore;

impl CredentialStore for OsCredentialStore {
    fn put(&self, secret: &[u8]) -> Result<String, CredentialError> {
        let reference = format!("{KEY_REF_PREFIX}{}", Uuid::new_v4());
        let entry =
            Entry::new(SERVICE, &reference).map_err(|_| CredentialError::StoreUnavailable)?;
        entry
            .set_secret(secret)
            .map_err(|_| CredentialError::StoreUnavailable)?;
        Ok(reference)
    }

    fn get(&self, reference: &str) -> Result<Zeroizing<Vec<u8>>, CredentialError> {
        self.get_optional(reference)?
            .ok_or(CredentialError::StoreUnavailable)
    }

    fn get_optional(&self, reference: &str) -> Result<Option<Zeroizing<Vec<u8>>>, CredentialError> {
        validate_reference(reference)?;
        let entry =
            Entry::new(SERVICE, reference).map_err(|_| CredentialError::StoreUnavailable)?;
        match entry.get_secret() {
            Ok(value) => Ok(Some(Zeroizing::new(value))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(CredentialError::StoreUnavailable),
        }
    }

    fn delete(&self, reference: &str) -> Result<(), CredentialError> {
        self.delete_with_outcome(reference).map(|_| ())
    }

    fn delete_with_outcome(
        &self,
        reference: &str,
    ) -> Result<CredentialDeleteOutcome, CredentialError> {
        validate_reference(reference)?;
        let entry =
            Entry::new(SERVICE, reference).map_err(|_| CredentialError::StoreUnavailable)?;
        match entry.delete_credential() {
            Ok(()) => Ok(CredentialDeleteOutcome::Deleted),
            Err(keyring::Error::NoEntry) => Ok(CredentialDeleteOutcome::Missing),
            Err(_) => Err(CredentialError::StoreUnavailable),
        }
    }
}

pub(crate) fn validate_reference(reference: &str) -> Result<(), CredentialError> {
    let Some(identifier) = reference.strip_prefix(KEY_REF_PREFIX) else {
        return Err(CredentialError::InvalidReference);
    };
    if Uuid::parse_str(identifier).is_ok()
        && identifier.len() == 36
        && identifier == identifier.to_ascii_lowercase()
    {
        Ok(())
    } else {
        Err(CredentialError::InvalidReference)
    }
}
