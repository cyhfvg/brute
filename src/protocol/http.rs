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

        let client = match build_http_basic_client(ctx.timeout(), self.scheme) {
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
///
/// # Parameters
///
/// - `timeout`: Per-attempt timeout from CLI `--timeout-ms`.
/// - `scheme`: CLI `--protocol` value.
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
/// let client = build_http_basic_client(Duration::from_secs(5), HttpUrlScheme::Https)
///     .expect("client builds");
/// let _ = client;
/// ```
pub fn build_http_basic_client(
    timeout: Duration,
    scheme: HttpUrlScheme,
) -> Result<Client, reqwest::Error> {
    let mut builder = Client::builder().timeout(timeout);
    // HTTPS: always accept invalid/self-signed certificates by default.
    // Plain HTTP: no TLS; keep prior lenient builder if a hop redirects to TLS.
    if scheme_skips_cert_verification(scheme) || matches!(scheme, HttpUrlScheme::Http) {
        builder = builder.danger_accept_invalid_certs(true);
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

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };

    use reqwest::StatusCode;

    use super::*;
    use crate::{
        cli::{CommonArgs, Protocol},
        credentials::CredentialSet,
        protocol::{AttemptContext, AttemptOutcome, BruteModule},
    };

    /// Minimal RFC 4648 Base64 encoder for test-only Authorization checks (no extra crate).
    fn encode_basic_token(user: &str, pass: &str) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let raw = format!("{user}:{pass}");
        let bytes = raw.as_bytes();
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        let mut i = 0;
        while i < bytes.len() {
            let b0 = bytes[i];
            let b1 = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
            let b2 = if i + 2 < bytes.len() { bytes[i + 2] } else { 0 };
            out.push(TABLE[(b0 >> 2) as usize] as char);
            out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
            if i + 1 < bytes.len() {
                out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
            } else {
                out.push('=');
            }
            if i + 2 < bytes.len() {
                out.push(TABLE[(b2 & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
            i += 3;
        }
        out
    }

    /// Verifies path normalization used when building the request URL.
    #[test]
    fn normalizes_request_paths() {
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/manager/html"), "/manager/html");
        assert_eq!(normalize_path("manager/html"), "/manager/html");
        assert_eq!(normalize_path("login"), "/login");
    }

    /// Verifies URL scheme selection for default http and explicit https.
    #[test]
    fn builds_basic_auth_url_with_scheme() {
        assert_eq!(
            build_http_basic_url(HttpUrlScheme::Http, "127.0.0.1", 8080, "/"),
            "http://127.0.0.1:8080/"
        );
        assert_eq!(
            build_http_basic_url(HttpUrlScheme::Http, "10.10.50.30", 8080, "/manager/html"),
            "http://10.10.50.30:8080/manager/html"
        );
        assert_eq!(
            build_http_basic_url(HttpUrlScheme::Https, "10.10.50.30", 8443, "/secure"),
            "https://10.10.50.30:8443/secure"
        );
        assert_eq!(
            build_http_basic_url(HttpUrlScheme::Https, "127.0.0.1", 443, "/"),
            "https://127.0.0.1:443/"
        );
    }

    /// Verifies HTTPS requires cert-verification skip; plain HTTP does not (no TLS).
    #[test]
    fn https_scheme_skips_cert_verification() {
        assert!(!scheme_skips_cert_verification(HttpUrlScheme::Http));
        assert!(scheme_skips_cert_verification(HttpUrlScheme::Https));
    }

    /// Verifies the shipped client builder constructs for both schemes (HTTPS path
    /// exercises accept-invalid-certs configuration).
    #[test]
    fn builds_client_for_http_and_https_schemes() {
        let http_client = build_http_basic_client(Duration::from_secs(2), HttpUrlScheme::Http)
            .expect("http client");
        let https_client = build_http_basic_client(Duration::from_secs(2), HttpUrlScheme::Https)
            .expect("https client with invalid-cert accept");
        let _ = (http_client, https_client);

        // Production attempt path must call the shared builder (not a parallel reimplementation).
        let source = include_str!("http.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production http source");
        assert!(
            production.contains("build_http_basic_client"),
            "attempt path must use build_http_basic_client"
        );
        assert!(
            production.contains("scheme_skips_cert_verification")
                || production.contains("danger_accept_invalid_certs"),
            "HTTPS path must configure accept-invalid-certs"
        );
        assert!(
            production.contains("build_http_basic_url(self.scheme")
                || production.contains("build_http_basic_url(self.scheme,"),
            "attempt path must pass module scheme into URL builder"
        );
    }

    /// Verifies status → outcome mapping for success, failure, and non-auth errors.
    #[test]
    fn classifies_http_basic_status_codes() {
        assert!(matches!(
            classify_http_basic_status(StatusCode::OK),
            AttemptOutcome::Success(_)
        ));
        assert!(matches!(
            classify_http_basic_status(StatusCode::NO_CONTENT),
            AttemptOutcome::Success(_)
        ));
        assert!(matches!(
            classify_http_basic_status(StatusCode::UNAUTHORIZED),
            AttemptOutcome::Failure(_)
        ));
        assert!(matches!(
            classify_http_basic_status(StatusCode::FORBIDDEN),
            AttemptOutcome::Success(_)
        ));
        assert!(matches!(
            classify_http_basic_status(StatusCode::INTERNAL_SERVER_ERROR),
            AttemptOutcome::Error(_)
        ));
        assert!(matches!(
            classify_http_basic_status(StatusCode::NOT_FOUND),
            AttemptOutcome::Error(_)
        ));
    }

    /// Spawns a real HTTP Basic responder on an ephemeral port.
    ///
    /// Accepts only `user`/`pass` with the expected request path; wrong auth → 401,
    /// wrong path → 404. Handles a bounded number of connections then exits.
    fn spawn_basic_auth_server(
        expected_path: &'static str,
        valid_user: &'static str,
        valid_pass: &'static str,
        max_connections: usize,
    ) -> (u16, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let port = listener.local_addr().expect("local addr").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_clone = Arc::clone(&hits);
        let expected_token = encode_basic_token(valid_user, valid_pass);

        thread::spawn(move || {
            for _ in 0..max_connections {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                hits_clone.fetch_add(1, Ordering::SeqCst);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

                let mut buf = [0u8; 4096];
                let n = match stream.read(&mut buf) {
                    Ok(n) if n > 0 => n,
                    _ => continue,
                };
                let request = String::from_utf8_lossy(&buf[..n]);
                let first_line = request.lines().next().unwrap_or("");
                // Request-target may be path or path?query; match the configured path.
                let path_ok = first_line.split_whitespace().nth(1).is_some_and(|target| {
                    target == expected_path || target.starts_with(&format!("{expected_path}?"))
                });

                let auth_ok = request
                    .lines()
                    .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
                    .map(|line| {
                        let rest = line.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");
                        let mut parts = rest.split_whitespace();
                        let scheme = parts.next().unwrap_or("");
                        let token = parts.next().unwrap_or("");
                        scheme.eq_ignore_ascii_case("Basic") && token == expected_token
                    })
                    .unwrap_or(false);

                let response = if !path_ok {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else if auth_ok {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                } else {
                    "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"test\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                };
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });

        // Brief settle so accept loop is ready.
        thread::sleep(Duration::from_millis(20));
        (port, hits)
    }

    fn attempt_ctx(
        host: &str,
        port: u16,
        path: &str,
        username: &str,
        password: &str,
        timeout_ms: u64,
    ) -> AttemptContext {
        AttemptContext {
            protocol: Protocol::Http,
            target_host: host.to_string(),
            target: CommonArgs {
                targets: vec![host.to_string()],
                usernames: vec![username.to_string()],
                passwords: vec![password.to_string()],
                credential_id: None,
                port: Some(port),
                threads: 1,
                retries: 0,
                timeout_ms,
                continue_on_success: false,
            },
            path: Some(path.to_string()),
            execute: None,
            credential: CredentialSet {
                username: Some(username.to_string()),
                password: Some(password.to_string()),
                service_name: None,
                sid: None,
            },
        }
    }

    /// End-to-end attempt against a real HTTP Basic listener (valid credentials).
    #[tokio::test]
    async fn attempt_succeeds_with_valid_basic_credentials() {
        let (port, _hits) = spawn_basic_auth_server("/manager/html", "admin", "admin123", 4);
        let module = HttpBasicModule::new(2_000, HttpUrlScheme::Http);
        let ctx = attempt_ctx(
            "127.0.0.1",
            port,
            "/manager/html",
            "admin",
            "admin123",
            2_000,
        );

        let outcome = module.attempt(&ctx).await;
        match outcome {
            AttemptOutcome::Success(success) => {
                assert!(
                    success.message.contains("HTTP Basic"),
                    "unexpected success message: {}",
                    success.message
                );
            }
            other => panic!("expected Success, got {other:?}"),
        }
    }

    /// End-to-end attempt: wrong password maps to Failure (not Error / not stub).
    #[tokio::test]
    async fn attempt_fails_with_invalid_basic_credentials() {
        let (port, _hits) = spawn_basic_auth_server("/secret", "admin", "admin123", 4);
        let module = HttpBasicModule::new(2_000, HttpUrlScheme::Http);
        let ctx = attempt_ctx("127.0.0.1", port, "/secret", "admin", "wrong", 2_000);

        let outcome = module.attempt(&ctx).await;
        match outcome {
            AttemptOutcome::Failure(msg) => {
                assert!(
                    msg.to_ascii_lowercase().contains("reject")
                        || msg.to_ascii_lowercase().contains("auth"),
                    "unexpected failure message: {msg}"
                );
            }
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    /// Wrong path on an otherwise live server yields Error (non-auth status), not Failure.
    #[tokio::test]
    async fn attempt_errors_on_non_auth_http_status() {
        let (port, _hits) = spawn_basic_auth_server("/ok", "u", "p", 4);
        let module = HttpBasicModule::new(2_000, HttpUrlScheme::Http);
        let ctx = attempt_ctx("127.0.0.1", port, "/missing", "u", "p", 2_000);

        let outcome = module.attempt(&ctx).await;
        assert!(
            matches!(outcome, AttemptOutcome::Error(_)),
            "expected Error for 404 path, got {outcome:?}"
        );
    }

    /// Default path `/` is applied when context path is absent.
    #[tokio::test]
    async fn attempt_uses_default_root_path_when_path_omitted() {
        let (port, _hits) = spawn_basic_auth_server("/", "root", "toor", 4);
        let module = HttpBasicModule::new(2_000, HttpUrlScheme::Http);
        let mut ctx = attempt_ctx("127.0.0.1", port, "/", "root", "toor", 2_000);
        ctx.path = None;

        let outcome = module.attempt(&ctx).await;
        assert!(
            matches!(outcome, AttemptOutcome::Success(_)),
            "default path / should hit the root Basic resource: {outcome:?}"
        );
    }

    /// Closed port produces a request Error, never the scaffold stub message.
    #[tokio::test]
    async fn attempt_errors_on_connection_failure() {
        let module = HttpBasicModule::new(500, HttpUrlScheme::Http);
        // Port 1 is typically closed on loopback.
        let ctx = attempt_ctx("127.0.0.1", 1, "/", "admin", "secret", 500);
        let outcome = module.attempt(&ctx).await;
        match outcome {
            AttemptOutcome::Error(msg) => {
                assert!(
                    !msg.contains("scaffolded but not implemented"),
                    "must not use stub: {msg}"
                );
                assert!(
                    msg.contains("http request failed") || msg.contains("error"),
                    "expected transport error text: {msg}"
                );
            }
            other => panic!("expected Error on closed port, got {other:?}"),
        }
    }

    /// HTTPS scheme builds `https://` URLs and reports transport error on closed port.
    #[tokio::test]
    async fn attempt_https_scheme_uses_https_url_on_closed_port() {
        let module = HttpBasicModule::new(500, HttpUrlScheme::Https);
        let ctx = attempt_ctx("127.0.0.1", 1, "/manager/html", "admin", "secret", 500);
        let outcome = module.attempt(&ctx).await;
        match outcome {
            AttemptOutcome::Error(msg) => {
                assert!(
                    !msg.contains("scaffolded but not implemented"),
                    "must not use stub: {msg}"
                );
                assert!(
                    msg.contains("https://127.0.0.1:1/manager/html")
                        || msg.contains("http request failed"),
                    "expected https URL or request failure, got: {msg}"
                );
            }
            other => panic!("expected Error on closed HTTPS port, got {other:?}"),
        }
    }
}
