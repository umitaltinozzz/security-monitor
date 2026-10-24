mod credentials;
mod dispatcher;
mod transport;

pub use credentials::{CredentialError, CredentialStore, OsCredentialStore};
pub use dispatcher::{
    ChannelTransport, DeliveryResult, DeliveryStatus, NotificationError, NotificationEvent,
    NotificationService, NotificationSettings,
};
pub use transport::{
    ChannelSecretConfig, ConfiguredTransport, SmtpTlsMode, approved_http_destination,
    approved_smtp_destination, store_channel_config,
};

#[cfg(test)]
mod tests;
