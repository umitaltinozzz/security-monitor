use std::sync::Arc;

use async_trait::async_trait;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::header::ContentType,
    transport::smtp::authentication::Credentials,
};
use security_monitor_advisory_providers::{HttpPolicy, PublicDataHttp};
use security_monitor_core::{NotificationChannel, NotificationChannelKind};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::info;
use url::Url;

use crate::{
    CredentialStore,
    dispatcher::{ChannelTransport, NotificationError, NotificationEvent},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChannelSecretConfig {
    Webhook {
        url: String,
    },
    Slack {
        url: String,
    },
    Discord {
        url: String,
    },
    Smtp {
        host: String,
        port: u16,
        tls: SmtpTlsMode,
        username: Option<String>,
        password: Option<String>,
        from: String,
        to: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpTlsMode {
    ImplicitTls,
    StartTls,
}

pub struct ConfiguredTransport {
    http: PublicDataHttp,
    credentials: Arc<dyn CredentialStore>,
}

impl ConfiguredTransport {
    pub fn new(http: PublicDataHttp, credentials: Arc<dyn CredentialStore>) -> Self {
        Self { http, credentials }
    }

    pub fn with_public_data_http(
        credentials: Arc<dyn CredentialStore>,
    ) -> Result<Self, NotificationError> {
        let http = PublicDataHttp::new(HttpPolicy {
            public_downloads_enabled: false,
        })
        .map_err(|_| NotificationError::DeliveryFailed)?;
        Ok(Self::new(http, credentials))
    }

    fn load_config(
        &self,
        channel: &NotificationChannel,
    ) -> Result<ChannelSecretConfig, NotificationError> {
        let reference = channel
            .config_ref
            .as_deref()
            .ok_or(NotificationError::InvalidConfiguration)?;
        let secret = self
            .credentials
            .get(reference)
            .map_err(|_| NotificationError::CredentialStore)?;
        serde_json::from_str(&secret).map_err(|_| NotificationError::InvalidConfiguration)
    }
}

#[async_trait]
impl ChannelTransport for ConfiguredTransport {
    async fn deliver(
        &self,
        channel: &NotificationChannel,
        event: &NotificationEvent,
        outbound_notifications_enabled: bool,
    ) -> Result<(), NotificationError> {
        match channel.kind {
            NotificationChannelKind::Desktop => deliver_desktop(event),
            NotificationChannelKind::Webhook
            | NotificationChannelKind::Slack
            | NotificationChannelKind::Discord
            | NotificationChannelKind::Smtp => {
                if !outbound_notifications_enabled || channel.network_approved_at.is_none() {
                    return Err(NotificationError::ApprovalRequired);
                }
                let destination = channel
                    .network_approved_destination
                    .as_deref()
                    .ok_or(NotificationError::ApprovalRequired)?;
                match (channel.kind, self.load_config(channel)?) {
                    (NotificationChannelKind::Webhook, ChannelSecretConfig::Webhook { url }) => {
                        let payload = event_payload(event);
                        self.http
                            .post_user_approved_json(
                                &url,
                                destination,
                                &payload,
                                outbound_notifications_enabled,
                            )
                            .await
                            .map_err(|_| NotificationError::DeliveryFailed)
                    }
                    (NotificationChannelKind::Slack, ChannelSecretConfig::Slack { url }) => {
                        let payload = json!({ "text": event_summary(event) });
                        self.http
                            .post_user_approved_json(
                                &url,
                                destination,
                                &payload,
                                outbound_notifications_enabled,
                            )
                            .await
                            .map_err(|_| NotificationError::DeliveryFailed)
                    }
                    (NotificationChannelKind::Discord, ChannelSecretConfig::Discord { url }) => {
                        let payload = json!({ "content": event_summary(event) });
                        self.http
                            .post_user_approved_json(
                                &url,
                                destination,
                                &payload,
                                outbound_notifications_enabled,
                            )
                            .await
                            .map_err(|_| NotificationError::DeliveryFailed)
                    }
                    (
                        NotificationChannelKind::Smtp,
                        ChannelSecretConfig::Smtp {
                            host,
                            port,
                            tls,
                            username,
                            password,
                            from,
                            to,
                        },
                    ) => {
                        send_email(
                            destination,
                            host,
                            port,
                            tls,
                            username,
                            password,
                            from,
                            to,
                            event,
                        )
                        .await
                    }
                    _ => Err(NotificationError::InvalidConfiguration),
                }
            }
        }
    }
}

fn deliver_desktop(event: &NotificationEvent) -> Result<(), NotificationError> {
    notify_rust::Notification::new()
        .summary("Security Monitor")
        .body(&event_summary(event))
        .show()
        .map(|_| ())
        .map_err(|_| NotificationError::DeliveryFailed)
}

fn event_payload(event: &NotificationEvent) -> Value {
    json!({
        "event": "security_finding",
        "finding_id": event.finding_id,
        "advisory_id": event.advisory_id,
        "asset_alias": event.asset_alias,
        "priority": event.priority_score,
        "severity": event.severity,
    })
}

fn event_summary(event: &NotificationEvent) -> String {
    let asset = event.asset_alias.as_deref().unwrap_or("local project");
    format!(
        "{} finding {} affects {} (priority {}/100).",
        event.advisory_id, event.finding_id, asset, event.priority_score
    )
}

#[allow(clippy::too_many_arguments)]
async fn send_email(
    approved_destination: &str,
    host: String,
    port: u16,
    tls: SmtpTlsMode,
    username: Option<String>,
    password: Option<String>,
    from: String,
    to: Vec<String>,
    event: &NotificationEvent,
) -> Result<(), NotificationError> {
    if host.is_empty()
        || host.chars().any(char::is_control)
        || port == 0
        || to.is_empty()
        || to.len() > 10
        || username.is_some() != password.is_some()
    {
        return Err(NotificationError::InvalidConfiguration);
    }
    let expected_destination = approved_smtp_destination(&host, port, tls)?;
    if expected_destination != approved_destination {
        return Err(NotificationError::ApprovalRequired);
    }
    let mut builder = match tls {
        SmtpTlsMode::ImplicitTls => AsyncSmtpTransport::<Tokio1Executor>::relay(&host),
        SmtpTlsMode::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host),
    }
    .map_err(|_| NotificationError::InvalidConfiguration)?
    .port(port);
    if let (Some(username), Some(password)) = (username, password) {
        builder = builder.credentials(Credentials::new(username, password));
    }
    let transport = builder.build();
    info!(destination_host = %host, "sending user-approved notification email");
    let mut message = Message::builder()
        .from(
            from.parse()
                .map_err(|_| NotificationError::InvalidConfiguration)?,
        )
        .subject(format!(
            "Security Monitor: {} priority {}",
            event.advisory_id, event.priority_score
        ))
        .header(ContentType::TEXT_PLAIN);
    for recipient in to {
        message = message.to(recipient
            .parse()
            .map_err(|_| NotificationError::InvalidConfiguration)?);
    }
    let message = message
        .body(event_summary(event))
        .map_err(|_| NotificationError::InvalidConfiguration)?;
    transport
        .send(message)
        .await
        .map(|_| ())
        .map_err(|_| NotificationError::DeliveryFailed)
}

pub fn approved_http_destination(address: &str) -> Result<String, NotificationError> {
    let url = Url::parse(address).map_err(|_| NotificationError::InvalidConfiguration)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(NotificationError::InvalidConfiguration);
    }
    Ok(url.origin().ascii_serialization())
}

pub fn approved_smtp_destination(
    host: &str,
    port: u16,
    tls: SmtpTlsMode,
) -> Result<String, NotificationError> {
    if host.is_empty() || host.chars().any(char::is_control) || port == 0 {
        return Err(NotificationError::InvalidConfiguration);
    }
    let scheme = match tls {
        SmtpTlsMode::ImplicitTls => "smtps",
        SmtpTlsMode::StartTls => "smtp",
    };
    let authority_host = if host.starts_with('[') && host.ends_with(']') {
        host.to_owned()
    } else if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let parsed = Url::parse(&format!("{scheme}://{authority_host}:{port}/"))
        .map_err(|_| NotificationError::InvalidConfiguration)?;
    if parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.port() != Some(port)
    {
        return Err(NotificationError::InvalidConfiguration);
    }
    let normalized_host = parsed
        .host_str()
        .ok_or(NotificationError::InvalidConfiguration)?;
    let formatted_host = if normalized_host.contains(':') && !normalized_host.starts_with('[') {
        format!("[{normalized_host}]")
    } else {
        normalized_host.to_owned()
    };
    Ok(format!("{scheme}://{formatted_host}:{port}"))
}

pub fn store_channel_config(
    credentials: &dyn CredentialStore,
    config: &ChannelSecretConfig,
) -> Result<String, NotificationError> {
    let serialized =
        serde_json::to_string(config).map_err(|_| NotificationError::InvalidConfiguration)?;
    credentials
        .put(&serialized)
        .map_err(|_| NotificationError::CredentialStore)
}
