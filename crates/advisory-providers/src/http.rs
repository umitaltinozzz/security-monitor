use std::{net::IpAddr, net::SocketAddr};
use std::{path::Path, time::Duration};

use futures_util::{Stream, StreamExt};
use reqwest::{StatusCode, header::RETRY_AFTER};
use thiserror::Error;
use tokio::{
    fs::File,
    io::{AsyncWrite, AsyncWriteExt},
};
use url::Url;

const MAX_BUFFERED_RESPONSE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_NOTIFICATION_RESPONSE_BYTES: u64 = 16 * 1024;
const MAX_AI_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_NEWS_FEED_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct HttpPolicy {
    pub public_downloads_enabled: bool,
}

#[derive(Clone)]
pub struct PublicDataHttp {
    client: reqwest::Client,
    approved_destination_client: reqwest::Client,
    policy: HttpPolicy,
    allow_loopback: bool,
}

/// Build the updater plugin's HTTP client with the same host logging and redirect
/// restrictions as the public data client.
pub fn configure_updater_client(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    builder
        .user_agent(concat!("secmon/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 {
                return attempt.stop();
            }
            if is_allowed_updater_url(attempt.url()) {
                if let Some(host) = attempt.url().host_str() {
                    tracing::info!(destination_host = %host, "following updater redirect");
                }
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
}

/// Authorize and log an updater destination before the updater plugin sends a request.
pub fn authorize_updater_destination(
    address: &str,
    policy: HttpPolicy,
) -> Result<String, ProviderError> {
    if !policy.public_downloads_enabled {
        return Err(ProviderError::NetworkDisabled);
    }
    let url = Url::parse(address).map_err(|_| ProviderError::InvalidUrl)?;
    if !is_allowed_updater_url(&url) {
        return Err(ProviderError::DestinationNotAllowed);
    }
    let host = url.host_str().ok_or(ProviderError::InvalidUrl)?.to_owned();
    tracing::info!(destination_host = %host, "requesting signed application update");
    Ok(host)
}

pub struct ApprovedAiRequest<'a> {
    pub address: &'a str,
    pub approved_origin: &'a str,
    pub payload: &'a serde_json::Value,
    pub credential: Option<&'a str>,
    pub anthropic_auth: bool,
    pub local_endpoint: bool,
    pub transfer_approved: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct HttpResponse {
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(crate) struct ConditionalFeedResponse {
    pub not_modified: bool,
    pub body: Vec<u8>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

impl PublicDataHttp {
    pub fn new(policy: HttpPolicy) -> Result<Self, ProviderError> {
        Self::build(policy, false)
    }

    #[cfg(feature = "test-support")]
    pub fn for_notification_tests() -> Result<Self, ProviderError> {
        Self::build(
            HttpPolicy {
                public_downloads_enabled: false,
            },
            true,
        )
    }

    fn build(policy: HttpPolicy, allow_loopback: bool) -> Result<Self, ProviderError> {
        ensure_rustls_crypto_provider()?;
        let redirect_loopback = allow_loopback;
        let client = reqwest::Client::builder()
            .user_agent(concat!("secmon/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(45))
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() >= 5 {
                    return attempt.stop();
                }
                if is_allowed_url(attempt.url(), redirect_loopback, true) {
                    if let Some(host) = attempt.url().host_str() {
                        tracing::info!(destination_host = %host, "following public provider redirect");
                    }
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            }))
            .build()
            .map_err(|_| ProviderError::HttpClient)?;
        let approved_destination_client = reqwest::Client::builder()
            .user_agent(concat!("secmon/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(90))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ProviderError::HttpClient)?;
        Ok(Self {
            client,
            approved_destination_client,
            policy,
            allow_loopback,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        Self::for_tests_with_policy(HttpPolicy {
            public_downloads_enabled: true,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_tests_with_policy(policy: HttpPolicy) -> Self {
        Self::build(policy, true).expect("test HTTP client")
    }

    pub(crate) async fn get(&self, address: &str) -> Result<HttpResponse, ProviderError> {
        self.ensure_enabled()?;
        let url = Url::parse(address).map_err(|_| ProviderError::InvalidUrl)?;
        if !is_allowed_url(&url, self.allow_loopback, false) {
            return Err(ProviderError::DestinationNotAllowed);
        }
        let host = url.host_str().ok_or(ProviderError::InvalidUrl)?.to_owned();
        tracing::info!(destination_host = %host, "fetching public advisory data");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| ProviderError::Network { host: host.clone() })?;
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            return Err(rate_limited_error(&response, host));
        }
        let status = response.status();
        if !status.is_success() {
            return Err(ProviderError::HttpStatus {
                host,
                status: status.as_u16(),
            });
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_BUFFERED_RESPONSE_BYTES)
        {
            return Err(ProviderError::DownloadTooLarge);
        }
        let body = collect_bounded_body(response.bytes_stream(), MAX_BUFFERED_RESPONSE_BYTES, host)
            .await?;
        Ok(HttpResponse { body })
    }

    pub(crate) async fn get_conditional_feed(
        &self,
        address: &str,
        etag: Option<&str>,
        last_modified: Option<&str>,
    ) -> Result<ConditionalFeedResponse, ProviderError> {
        self.ensure_enabled()?;
        let url = Url::parse(address).map_err(|_| ProviderError::InvalidUrl)?;
        if !is_valid_feed_url(&url, self.allow_loopback) {
            return Err(ProviderError::DestinationNotAllowed);
        }
        let host = url.host_str().ok_or(ProviderError::InvalidUrl)?.to_owned();
        tracing::info!(destination_host = %host, "fetching configured security news feed");
        let mut request = self.feed_client(&url, &host).await?.get(url.clone());
        if let Some(etag) = etag.filter(|value| valid_conditional_header(value)) {
            request = request.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = last_modified.filter(|value| valid_conditional_header(value)) {
            request = request.header(reqwest::header::IF_MODIFIED_SINCE, last_modified);
        }
        let response = request
            .send()
            .await
            .map_err(|_| ProviderError::Network { host: host.clone() })?;
        let status = response.status();
        if status == StatusCode::NOT_MODIFIED {
            return Ok(ConditionalFeedResponse {
                not_modified: true,
                body: Vec::new(),
                etag: response_header(&response, reqwest::header::ETAG),
                last_modified: response_header(&response, reqwest::header::LAST_MODIFIED),
            });
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(rate_limited_error(&response, host));
        }
        if !status.is_success() {
            return Err(ProviderError::HttpStatus {
                host,
                status: status.as_u16(),
            });
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_NEWS_FEED_BYTES)
        {
            return Err(ProviderError::DownloadTooLarge);
        }
        let etag = response_header(&response, reqwest::header::ETAG);
        let last_modified = response_header(&response, reqwest::header::LAST_MODIFIED);
        let body = collect_bounded_body(response.bytes_stream(), MAX_NEWS_FEED_BYTES, host).await?;
        Ok(ConditionalFeedResponse {
            not_modified: false,
            body,
            etag,
            last_modified,
        })
    }

    async fn feed_client(&self, url: &Url, host: &str) -> Result<reqwest::Client, ProviderError> {
        pinned_destination_client(
            url,
            host,
            self.allow_loopback && url.scheme() == "http",
            Duration::from_secs(30),
        )
        .await
    }

    pub async fn download_to(
        &self,
        address: &str,
        destination: &Path,
        max_bytes: u64,
    ) -> Result<u64, ProviderError> {
        let mut file = File::create(destination).await.map_err(ProviderError::Io)?;
        self.download_to_writer(address, &mut file, max_bytes).await
    }

    pub async fn download_to_writer<W>(
        &self,
        address: &str,
        writer: &mut W,
        max_bytes: u64,
    ) -> Result<u64, ProviderError>
    where
        W: AsyncWrite + Unpin,
    {
        self.ensure_enabled()?;
        let url = Url::parse(address).map_err(|_| ProviderError::InvalidUrl)?;
        if !is_allowed_url(&url, self.allow_loopback, false) {
            return Err(ProviderError::DestinationNotAllowed);
        }
        let host = url.host_str().ok_or(ProviderError::InvalidUrl)?.to_owned();
        tracing::info!(destination_host = %host, "downloading public advisory data");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| ProviderError::Network { host: host.clone() })?;
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            return Err(rate_limited_error(&response, host));
        }
        let status = response.status();
        if !status.is_success() {
            return Err(ProviderError::HttpStatus {
                host,
                status: status.as_u16(),
            });
        }
        let mut stream = response.bytes_stream();
        let mut total = 0_u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| ProviderError::Network { host: host.clone() })?;
            total = total
                .checked_add(chunk.len() as u64)
                .ok_or(ProviderError::DownloadTooLarge)?;
            if total > max_bytes {
                return Err(ProviderError::DownloadTooLarge);
            }
            writer.write_all(&chunk).await.map_err(ProviderError::Io)?;
        }
        writer.flush().await.map_err(ProviderError::Io)?;
        Ok(total)
    }

    /// Sends a small notification to the exact HTTPS origin approved by the user. The complete
    /// destination, including webhook secrets in its path, is never logged or returned in errors.
    pub async fn post_user_approved_json(
        &self,
        address: &str,
        approved_origin: &str,
        payload: &serde_json::Value,
        outbound_notifications_enabled: bool,
    ) -> Result<(), ProviderError> {
        self.post_user_approved_json_with_bearer(
            address,
            approved_origin,
            payload,
            None,
            outbound_notifications_enabled,
        )
        .await
    }

    /// Sends a small notification to an approved HTTPS origin. An optional bearer token remains
    /// in memory and is sent only in the HTTP authorization header.
    pub async fn post_user_approved_json_with_bearer(
        &self,
        address: &str,
        approved_origin: &str,
        payload: &serde_json::Value,
        bearer_token: Option<&str>,
        outbound_notifications_enabled: bool,
    ) -> Result<(), ProviderError> {
        if !outbound_notifications_enabled {
            return Err(ProviderError::NetworkDisabled);
        }
        let url = Url::parse(address).map_err(|_| ProviderError::InvalidUrl)?;
        let approved = Url::parse(approved_origin).map_err(|_| ProviderError::InvalidUrl)?;
        let host = url.host_str().ok_or(ProviderError::InvalidUrl)?.to_owned();
        let loopback_http = self.allow_loopback
            && url.scheme() == "http"
            && matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]");
        if url.origin().ascii_serialization() != approved.origin().ascii_serialization()
            || approved.path() != "/"
            || approved.query().is_some()
            || approved.fragment().is_some()
            || (!loopback_http && url.scheme() != "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(ProviderError::DestinationNotAllowed);
        }
        tracing::info!(destination_host = %host, "sending user-approved notification summary");
        let client =
            pinned_destination_client(&url, &host, loopback_http, Duration::from_secs(90)).await?;
        let mut request = client.post(url).json(payload);
        if let Some(token) = bearer_token.filter(|token| !token.is_empty()) {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|_| ProviderError::Network { host: host.clone() })?;
        let status = response.status();
        if !status.is_success() {
            return Err(ProviderError::HttpStatus {
                host,
                status: status.as_u16(),
            });
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_NOTIFICATION_RESPONSE_BYTES)
        {
            return Err(ProviderError::DownloadTooLarge);
        }
        let _ = collect_bounded_body(
            response.bytes_stream(),
            MAX_NOTIFICATION_RESPONSE_BYTES,
            host,
        )
        .await?;
        Ok(())
    }

    /// Sends one AI request to the exact authority the user approved. Redirects are disabled so
    /// approval for one provider can never silently send prompt data to another destination.
    pub async fn post_user_approved_ai_json(
        &self,
        request: ApprovedAiRequest<'_>,
    ) -> Result<Vec<u8>, ProviderError> {
        let ApprovedAiRequest {
            address,
            approved_origin,
            payload,
            credential,
            anthropic_auth,
            local_endpoint,
            transfer_approved,
        } = request;
        if !transfer_approved {
            return Err(ProviderError::NetworkDisabled);
        }
        let url = Url::parse(address).map_err(|_| ProviderError::InvalidUrl)?;
        let approved = Url::parse(approved_origin).map_err(|_| ProviderError::InvalidUrl)?;
        let host = url.host_str().ok_or(ProviderError::InvalidUrl)?.to_owned();
        let loopback_http = local_endpoint
            && url.scheme() == "http"
            && matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]");
        if url.origin().ascii_serialization() != approved.origin().ascii_serialization()
            || approved.path() != "/"
            || approved.query().is_some()
            || approved.fragment().is_some()
            || (!loopback_http && url.scheme() != "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || (local_endpoint && !loopback_http)
        {
            return Err(ProviderError::DestinationNotAllowed);
        }
        tracing::info!(destination_host = %host, "sending explicitly approved AI request");
        let mut request = self.approved_destination_client.post(url).json(payload);
        if let Some(credential) = credential {
            request = if anthropic_auth {
                request
                    .header("x-api-key", credential)
                    .header("anthropic-version", "2023-06-01")
            } else {
                request.bearer_auth(credential)
            };
        }
        let response = request
            .send()
            .await
            .map_err(|_| ProviderError::Network { host: host.clone() })?;
        let status = response.status();
        if !status.is_success() {
            return Err(ProviderError::HttpStatus {
                host,
                status: status.as_u16(),
            });
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_AI_RESPONSE_BYTES)
        {
            return Err(ProviderError::DownloadTooLarge);
        }
        collect_bounded_body(response.bytes_stream(), MAX_AI_RESPONSE_BYTES, host).await
    }

    fn ensure_enabled(&self) -> Result<(), ProviderError> {
        if self.policy.public_downloads_enabled {
            Ok(())
        } else {
            Err(ProviderError::NetworkDisabled)
        }
    }
}

async fn pinned_destination_client(
    url: &Url,
    host: &str,
    allow_loopback: bool,
    timeout: Duration,
) -> Result<reqwest::Client, ProviderError> {
    let port = url
        .port_or_known_default()
        .ok_or(ProviderError::InvalidUrl)?;
    let lookup_host = host.trim_start_matches('[').trim_end_matches(']');
    let addresses = tokio::net::lookup_host((lookup_host, port))
        .await
        .map_err(|_| ProviderError::DestinationNotAllowed)?
        .collect::<Vec<SocketAddr>>();
    if !resolved_addresses_allowed(&addresses, allow_loopback) {
        return Err(ProviderError::DestinationNotAllowed);
    }
    reqwest::Client::builder()
        .user_agent(concat!("secmon/", env!("CARGO_PKG_VERSION")))
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(lookup_host, &addresses)
        .build()
        .map_err(|_| ProviderError::HttpClient)
}

fn resolved_addresses_allowed(addresses: &[SocketAddr], allow_loopback: bool) -> bool {
    !addresses.is_empty()
        && addresses.iter().all(|address| {
            is_public_ip(address.ip()) || (allow_loopback && address.ip().is_loopback())
        })
}

fn ensure_rustls_crypto_provider() -> Result<(), ProviderError> {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return Ok(());
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        Ok(())
    } else {
        Err(ProviderError::HttpClient)
    }
}

async fn collect_bounded_body<S, C, E>(
    mut stream: S,
    max_bytes: u64,
    host: String,
) -> Result<Vec<u8>, ProviderError>
where
    S: Stream<Item = Result<C, E>> + Unpin,
    C: AsRef<[u8]>,
{
    let mut body = Vec::new();
    let mut total = 0_u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ProviderError::Network { host: host.clone() })?;
        total = total
            .checked_add(chunk.as_ref().len() as u64)
            .ok_or(ProviderError::DownloadTooLarge)?;
        if total > max_bytes {
            return Err(ProviderError::DownloadTooLarge);
        }
        body.extend_from_slice(chunk.as_ref());
    }
    Ok(body)
}

fn rate_limited_error(response: &reqwest::Response, host: String) -> ProviderError {
    let retry_after = response
        .headers()
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    ProviderError::RateLimited { host, retry_after }
}

fn is_allowed_url(url: &Url, allow_loopback: bool, allow_release_asset_redirect: bool) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    if allow_loopback && (host == "127.0.0.1" || host == "localhost" || host == "[::1]") {
        return url.scheme() == "http";
    }
    if url.scheme() != "https" {
        return false;
    }
    let github_release = host == "github.com"
        && (url
            .path()
            .starts_with("/google/osv-scanner/releases/download/")
            || url
                .path()
                .starts_with("/aquasecurity/trivy/releases/download/"));
    host == "cve.now"
        || host.ends_with(".cve.now")
        || host == "api.github.com"
        || github_release
        || (allow_release_asset_redirect && host == "release-assets.githubusercontent.com")
        || host == "osv-vulnerabilities.storage.googleapis.com"
        || host == "www.cisa.gov"
        || host == "cisa.gov"
        || host == "api.first.org"
        || host == "epss.empiricalsecurity.com"
}

fn is_allowed_updater_url(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    (host == "github.com"
        && url
            .path()
            .starts_with("/umitaltinozzz/security-monitor/releases/"))
        || host == "release-assets.githubusercontent.com"
}

fn is_valid_feed_url(url: &Url, allow_loopback: bool) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let local_test_url = allow_loopback
        && url.scheme() == "http"
        && matches!(host, "localhost" | "127.0.0.1" | "[::1]");
    (url.scheme() == "https" || local_test_url)
        && !host.ends_with(".local")
        && host != "localhost"
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path().len() <= 2048
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [a, b, c, d] = address.octets();
            !(address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_unspecified()
                || address.is_multicast()
                || a == 0
                || (a == 100 && (64..=127).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 0 && c == 2)
                || (a == 198 && matches!(b, 18 | 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113)
                || a >= 224
                || (a == 255 && b == 255 && c == 255 && d == 255))
        }
        IpAddr::V6(address) => {
            !(address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || address.is_unique_local()
                || address.is_unicast_link_local()
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| !is_public_ip(IpAddr::V4(mapped))))
        }
    }
}

fn valid_conditional_header(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn response_header(
    response: &reqwest::Response,
    name: reqwest::header::HeaderName,
) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| valid_conditional_header(value))
        .map(str::to_owned)
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("public advisory downloads are disabled by privacy settings")]
    NetworkDisabled,
    #[error("HTTP destination is not an approved public data provider")]
    DestinationNotAllowed,
    #[error("HTTP client could not be initialized")]
    HttpClient,
    #[error("HTTP address is invalid")]
    InvalidUrl,
    #[error("request to {host} failed")]
    Network { host: String },
    #[error("{host} returned HTTP {status}")]
    HttpStatus { host: String, status: u16 },
    #[error("{host} rate limited the request")]
    RateLimited {
        host: String,
        retry_after: Option<String>,
    },
    #[error("provider polling is delayed by the retry backoff")]
    BackoffActive,
    #[error("cve.now polling interval must be between five minutes and 24 hours")]
    InvalidPollInterval,
    #[error("provider returned invalid data")]
    InvalidData,
    #[error("provider cache operation failed")]
    Io(#[source] std::io::Error),
    #[error("provider cache JSON could not be read or written")]
    Json(#[source] serde_json::Error),
    #[error("provider CSV could not be parsed")]
    Csv(#[source] csv::Error),
    #[error("OSV archive is invalid")]
    Zip(#[source] zip::result::ZipError),
    #[error("provider download exceeded its size limit")]
    DownloadTooLarge,
    #[error("database operation failed")]
    Database(#[from] security_monitor_database::DatabaseError),
}

impl From<std::io::Error> for ProviderError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for ProviderError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<csv::Error> for ProviderError {
    fn from(error: csv::Error) -> Self {
        Self::Csv(error)
    }
}

impl From<zip::result::ZipError> for ProviderError {
    fn from(error: zip::result::ZipError) -> Self {
        Self::Zip(error)
    }
}

#[cfg(test)]
mod tests {
    use futures_util::stream;
    use serde_json::json;
    use std::net::SocketAddr;
    use url::Url;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path},
    };

    use super::{
        HttpPolicy, ProviderError, PublicDataHttp, authorize_updater_destination,
        collect_bounded_body, configure_updater_client, is_allowed_updater_url, is_allowed_url,
        resolved_addresses_allowed,
    };

    #[test]
    fn shared_http_client_installs_the_ring_crypto_provider() {
        let _http = PublicDataHttp::new(HttpPolicy {
            public_downloads_enabled: false,
        })
        .expect("shared HTTP client initializes");
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }

    #[test]
    fn updater_requests_require_download_consent_and_stay_on_release_hosts() {
        let endpoint = "https://github.com/umitaltinozzz/security-monitor/releases/latest/download/latest.json";
        let asset = "https://release-assets.githubusercontent.com/downloads/release";
        let other_repository = "https://github.com/another/project/releases/download/v1/update";
        let insecure =
            "http://github.com/umitaltinozzz/security-monitor/releases/latest/download/latest.json";

        assert!(matches!(
            authorize_updater_destination(
                endpoint,
                HttpPolicy {
                    public_downloads_enabled: false
                }
            ),
            Err(ProviderError::NetworkDisabled)
        ));
        assert_eq!(
            authorize_updater_destination(
                endpoint,
                HttpPolicy {
                    public_downloads_enabled: true
                }
            )
            .unwrap(),
            "github.com"
        );
        assert!(is_allowed_updater_url(&Url::parse(asset).unwrap()));
        assert!(!is_allowed_updater_url(
            &Url::parse(other_repository).unwrap()
        ));
        assert!(!is_allowed_updater_url(&Url::parse(insecure).unwrap()));
    }

    #[tokio::test]
    async fn disabled_public_downloads_send_no_http_request() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/feed.xml"))
            .respond_with(ResponseTemplate::new(200).set_body_string("unexpected"))
            .expect(0)
            .mount(&server)
            .await;

        let http = PublicDataHttp::for_tests_with_policy(HttpPolicy {
            public_downloads_enabled: false,
        });
        assert!(matches!(
            http.get(&format!("{}/feed.xml", server.uri())).await,
            Err(ProviderError::NetworkDisabled)
        ));
        assert!(
            server
                .received_requests()
                .await
                .expect("wiremock records requests")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn updater_client_stops_redirects_to_unapproved_hosts() {
        let origin = MockServer::start().await;
        let target = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/manifest"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/asset", target.uri())),
            )
            .expect(1)
            .mount(&origin)
            .await;
        Mock::given(method("GET"))
            .and(path("/asset"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&target)
            .await;

        let client = configure_updater_client(reqwest::Client::builder())
            .build()
            .expect("configured updater client");
        let response = client
            .get(format!("{}/manifest", origin.uri()))
            .send()
            .await
            .expect("initial response is returned without following an unapproved redirect");
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        assert_eq!(
            target
                .received_requests()
                .await
                .expect("wiremock records target requests")
                .len(),
            0
        );
    }

    #[test]
    fn github_downloads_are_restricted_to_the_two_pinned_scanner_repositories() {
        let osv = Url::parse(
            "https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_amd64",
        )
        .unwrap();
        let trivy = Url::parse(
            "https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-64bit.tar.gz",
        )
        .unwrap();
        let other_repository =
            Url::parse("https://github.com/attacker/tool/releases/download/v1/tool").unwrap();
        let source_code =
            Url::parse("https://github.com/google/osv-scanner/archive/main.zip").unwrap();

        assert!(is_allowed_url(&osv, false, false));
        assert!(is_allowed_url(&trivy, false, false));
        assert!(!is_allowed_url(&other_repository, false, false));
        assert!(!is_allowed_url(&source_code, false, false));
        let asset_host =
            Url::parse("https://release-assets.githubusercontent.com/downloads/asset").unwrap();
        assert!(!is_allowed_url(&asset_host, false, false));
        assert!(is_allowed_url(&asset_host, false, true));
    }

    #[tokio::test]
    async fn streamed_response_without_a_length_header_is_bounded() {
        let response = stream::iter([Ok::<_, ()>(vec![1_u8, 2, 3]), Ok::<_, ()>(vec![4, 5, 6])]);

        let error = collect_bounded_body(response, 5, "fixture.invalid".to_owned())
            .await
            .unwrap_err();

        assert!(matches!(error, ProviderError::DownloadTooLarge));
    }

    #[tokio::test]
    async fn streamed_response_at_the_limit_is_collected() {
        let response = stream::iter([Ok::<_, ()>(vec![1_u8, 2, 3]), Ok::<_, ()>(vec![4, 5, 6])]);

        let body = collect_bounded_body(response, 6, "fixture.invalid".to_owned())
            .await
            .unwrap();

        assert_eq!(body, [1, 2, 3, 4, 5, 6]);
    }

    #[tokio::test]
    async fn approved_notification_post_requires_global_privacy_and_exact_origin() {
        let server = MockServer::start().await;
        let payload = json!({ "event": "security_finding", "priority": 80 });
        Mock::given(method("POST"))
            .and(path("/hooks/private-token"))
            .and(body_json(payload.clone()))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        let http = PublicDataHttp::for_tests();
        let destination = format!("{}/hooks/private-token", server.uri());

        assert!(matches!(
            http.post_user_approved_json(&destination, &server.uri(), &payload, false)
                .await,
            Err(ProviderError::NetworkDisabled)
        ));
        assert!(matches!(
            http.post_user_approved_json(
                &destination,
                "https://different.example.test",
                &payload,
                true
            )
            .await,
            Err(ProviderError::DestinationNotAllowed)
        ));
        http.post_user_approved_json(&destination, &server.uri(), &payload, true)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn approved_notification_post_does_not_follow_redirects() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(302).insert_header("Location", "/target"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/target"))
            .respond_with(ResponseTemplate::new(204))
            .expect(0)
            .mount(&server)
            .await;
        let http = PublicDataHttp::for_tests();
        let destination = format!("{}/hook", server.uri());
        let error = http
            .post_user_approved_json(
                &destination,
                &server.uri(),
                &json!({"event":"security_finding"}),
                true,
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            ProviderError::HttpStatus { status: 302, .. }
        ));
    }

    #[test]
    fn notification_destinations_reject_private_and_link_local_dns_answers() {
        let address = |value: &str| value.parse::<SocketAddr>().unwrap();

        for blocked in [
            address("10.0.0.1:443"),
            address("169.254.1.2:443"),
            address("127.0.0.1:443"),
            address("[fc00::1]:443"),
            address("[fe80::1]:443"),
        ] {
            assert!(!resolved_addresses_allowed(&[blocked], false));
        }
        assert!(resolved_addresses_allowed(&[address("8.8.8.8:443")], false));
        assert!(resolved_addresses_allowed(
            &[address("127.0.0.1:8080")],
            true
        ));
    }

    #[tokio::test]
    async fn conditional_feed_304_returns_no_body_and_sends_both_validators() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/feed.xml"))
            .respond_with(
                ResponseTemplate::new(304)
                    .insert_header("ETag", "\"feed-v1\"")
                    .insert_header("Last-Modified", "Sat, 24 Oct 2026 12:00:00 GMT"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let response = PublicDataHttp::for_tests()
            .get_conditional_feed(
                &format!("{}/feed.xml", server.uri()),
                Some("\"feed-v1\""),
                Some("Sat, 24 Oct 2026 12:00:00 GMT"),
            )
            .await
            .expect("304 is a valid conditional response");
        assert!(response.not_modified);
        assert!(response.body.is_empty());
        assert_eq!(response.etag.as_deref(), Some("\"feed-v1\""));
        let requests = server
            .received_requests()
            .await
            .expect("wiremock records the request");
        let headers = &requests[0].headers;
        assert_eq!(headers.get("if-none-match").unwrap(), "\"feed-v1\"");
        assert_eq!(
            headers.get("if-modified-since").unwrap(),
            "Sat, 24 Oct 2026 12:00:00 GMT"
        );
    }
}
