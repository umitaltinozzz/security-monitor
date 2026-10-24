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

#[derive(Debug, Clone, Copy)]
pub struct HttpPolicy {
    pub public_downloads_enabled: bool,
}

#[derive(Clone)]
pub struct PublicDataHttp {
    client: reqwest::Client,
    policy: HttpPolicy,
    allow_loopback: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct HttpResponse {
    pub body: Vec<u8>,
}

impl PublicDataHttp {
    pub fn new(policy: HttpPolicy) -> Result<Self, ProviderError> {
        Self::build(policy, false)
    }

    fn build(policy: HttpPolicy, allow_loopback: bool) -> Result<Self, ProviderError> {
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
        Ok(Self {
            client,
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

    fn ensure_enabled(&self) -> Result<(), ProviderError> {
        if self.policy.public_downloads_enabled {
            Ok(())
        } else {
            Err(ProviderError::NetworkDisabled)
        }
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

    use url::Url;

    use super::{ProviderError, collect_bounded_body, is_allowed_url};

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
}
