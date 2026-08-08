//! Generic HTTP Basic Auth login and concurrent spray module.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::{Client, StatusCode};

use crate::cli::HttpUrlScheme;

use super::{AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule};

/// HTTP Basic Auth module configuration.
///
/// Performs a single GET with `Authorization: Basic` against
/// `{scheme}://<host>:<port><path>`. Default scheme is `http`, default port is
/// 80, default path is `/`. HTTPS skips TLS certificate verification.
#[derive(Debug, Clone)]
pub struct HttpBasicModule {
    scheme: HttpUrlScheme,
}

impl HttpBasicModule {
    /// Creates a new HTTP Basic Auth module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Reserved for API symmetry with other modules; the live
    ///   attempt uses `AttemptContext::timeout()` from CLI `--timeout-ms`.
    /// - `scheme`: CLI `--protocol` value (`http` or `https`).
    ///
    /// # Returns
    ///
    /// A module ready for concurrent credential sprays via global `--threads`.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::cli::HttpUrlScheme;
    /// use brute::protocol::http::HttpBasicModule;
    /// let _module = HttpBasicModule::new(5_000, HttpUrlScheme::Http);
    /// ```
    pub fn new(_timeout_ms: u64, scheme: HttpUrlScheme) -> Self {
        Self { scheme }
    }
}

#[async_trait]
impl BruteModule for HttpBasicModule {
    fn name(&self) -> &'static str {
        "http"
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        let username = ctx.credential.username.clone().unwrap_or_default();
        let password = ctx.credential.password.clone().unwrap_or_default();
        let path = normalize_path(ctx.path.as_deref().unwrap_or("/"));
        let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
        let url = build_http_basic_url(self.scheme, &ctx.target_host, port, &path);

        let client =
            match build_http_basic_client(ctx.timeout(), self.scheme, ctx.target.proxy.as_ref()) {
                Ok(client) => client,
                Err(err) => {
                    return AttemptOutcome::Error(format!("http client build failed: {err}"));
                }
            };

        match client
            .get(&url)
            .basic_auth(username, Some(password))
            .send()
            .await
        {
            Ok(response) => classify_http_basic_status(response.status()),
            Err(err) => AttemptOutcome::Error(format!("http request failed: {err}")),
        }
    }
}

/// Ensures the request path is absolute (leading `/`).
///
/// # Parameters
///
/// - `path`: CLI `--path` value or module default.
///
/// # Returns
///
/// Path with a leading `/`. Empty input becomes `/`.
///
/// # Examples
///
/// ```
/// use brute::protocol::http::normalize_path;
/// assert_eq!(normalize_path("/manager/html"), "/manager/html");
/// assert_eq!(normalize_path("login"), "/login");
/// assert_eq!(normalize_path(""), "/");
/// ```
pub fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

/// Builds the request URL used for a Basic Auth attempt.
///
/// # Parameters
///
/// - `scheme`: CLI `--protocol` (`http` or `https`).
/// - `host`: Target hostname or IP.
/// - `port`: Service port (module default 80 when CLI omits `--port`).
/// - `path`: Absolute path from [`normalize_path`].
///
/// # Returns
///
/// `{scheme}://host:port/path` URL string.
///
/// # Examples
///
/// ```
/// use brute::cli::HttpUrlScheme;
/// use brute::protocol::http::build_http_basic_url;
/// assert_eq!(
///     build_http_basic_url(HttpUrlScheme::Http, "10.10.50.30", 8080, "/manager/html"),
///     "http://10.10.50.30:8080/manager/html"
/// );
/// assert_eq!(
///     build_http_basic_url(HttpUrlScheme::Https, "10.10.50.30", 8443, "/"),
///     "https://10.10.50.30:8443/"
/// );
/// ```
pub fn build_http_basic_url(scheme: HttpUrlScheme, host: &str, port: u16, path: &str) -> String {
    format!("{}://{host}:{port}{path}", scheme.as_str())
}

/// Returns whether the shipped HTTP Basic client must skip TLS certificate verification.
///
/// HTTPS always skips verification by default (self-signed / invalid certs). Plain
/// HTTP does not negotiate TLS; the flag is false so the policy is explicit.
///
/// # Parameters
///
/// - `scheme`: CLI `--protocol` value.
///
/// # Returns
///
/// `true` when the client builder must call `danger_accept_invalid_certs(true)`.
///
/// # Examples
///
/// ```
/// use brute::cli::HttpUrlScheme;
/// use brute::protocol::http::scheme_skips_cert_verification;
/// assert!(!scheme_skips_cert_verification(HttpUrlScheme::Http));
/// assert!(scheme_skips_cert_verification(HttpUrlScheme::Https));
/// ```
pub fn scheme_skips_cert_verification(scheme: HttpUrlScheme) -> bool {
    matches!(scheme, HttpUrlScheme::Https)
}

/// Builds the `reqwest` client used by the shipped HTTP Basic attempt path.
///
/// When `scheme` is `https`, certificate verification is disabled by default.
/// When `proxy` is set, all requests are routed through that proxy.
///
/// # Parameters
///
/// - `timeout`: Per-attempt timeout from CLI `--timeout-ms`.
/// - `scheme`: CLI `--protocol` value.
/// - `proxy`: Optional outbound proxy from CLI `--proxy`.
///
/// # Returns
///
/// Configured [`Client`] on success.
///
/// # Errors
///
/// Returns `reqwest::Error` when the client cannot be constructed.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use brute::cli::HttpUrlScheme;
/// use brute::protocol::http::build_http_basic_client;
/// let client = build_http_basic_client(Duration::from_secs(5), HttpUrlScheme::Https, None)
///     .expect("client builds");
/// let _ = client;
/// ```
pub fn build_http_basic_client(
    timeout: Duration,
    scheme: HttpUrlScheme,
    proxy: Option<&crate::proxy::ProxyConfig>,
) -> Result<Client, reqwest::Error> {
    let mut builder = Client::builder().timeout(timeout);
    // HTTPS: always accept invalid/self-signed certificates by default.
    // Plain HTTP: no TLS; keep prior lenient builder if a hop redirects to TLS.
    if scheme_skips_cert_verification(scheme) || matches!(scheme, HttpUrlScheme::Http) {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if let Some(proxy) = proxy {
        builder = builder.proxy(proxy.to_reqwest_proxy()?);
    }
    builder.build()
}

/// Maps an HTTP response status to a credential attempt outcome.
///
/// Classification for Basic-protected resources:
/// - `2xx`: authentication succeeded
/// - `401 Unauthorized`: wrong credentials
/// - `403 Forbidden`: credentials accepted but resource denied (still a hit for spray)
/// - other statuses: transport/application error (not a clean auth decision)
///
/// # Parameters
///
/// - `status`: HTTP status from the Basic Auth GET response.
///
/// # Returns
///
/// [`AttemptOutcome::Success`], [`AttemptOutcome::Failure`], or [`AttemptOutcome::Error`].
///
/// # Examples
///
/// ```
/// use brute::protocol::http::classify_http_basic_status;
/// use brute::protocol::AttemptOutcome;
/// use reqwest::StatusCode;
///
/// assert!(matches!(
///     classify_http_basic_status(StatusCode::OK),
///     AttemptOutcome::Success(_)
/// ));
/// assert!(matches!(
///     classify_http_basic_status(StatusCode::UNAUTHORIZED),
///     AttemptOutcome::Failure(_)
/// ));
/// ```
pub fn classify_http_basic_status(status: StatusCode) -> AttemptOutcome {
    if status.is_success() {
        AttemptOutcome::Success(AttemptSuccess::new("HTTP Basic access!"))
    } else if status == StatusCode::UNAUTHORIZED {
        AttemptOutcome::Failure("http basic auth rejected credentials".to_string())
    } else if status == StatusCode::FORBIDDEN {
        // Valid Basic credentials often still receive 403 when the principal lacks
        // a role (e.g. Tomcat Manager). Treat as a successful credential hit.
        AttemptOutcome::Success(AttemptSuccess::new(
            "Credentials accepted but access forbidden (HTTP 403)",
        ))
    } else {
        AttemptOutcome::Error(format!("unexpected HTTP status: {status}"))
    }
}
