//! Shared timeout, outcome mapping, and HTTP request construction.
//!
//! Client, URL, and Basic Auth construction live in [`super::http_request`]
//! and are re-exported here. This is not a second 401/403 table. Status
//! classification stays in [`super::http_auth`]. [`classify_basic_status`]
//! calls that table with the shared Basic Auth wording. It does not copy the
//! 2xx/401/403 rules. Callers still map [`HttpAttemptFailure`] onto the
//! existing outcome wording.

use std::time::Duration;

use reqwest::StatusCode;

use super::http::build_http_no_redirect_client;
use super::http_auth::{HttpForbiddenPolicy, require_http_auth};
use super::{AttemptContext, AttemptOutcome, AttemptSuccess};

pub use super::http_request::{
    attempt_http_client, credentials_absent, http_attempt_url, http_service_url, http_target_url,
    target_http_client, with_basic_auth,
};

/// Classified failure from one protocol attempt.
///
/// The detail string is the module's own message. This type does not add or
/// strip a protocol prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpAttemptFailure {
    /// Credentials were rejected.
    Auth(String),
    /// Connect, protocol, or other non-auth failure.
    Transport(String),
    /// Login succeeded and the follow-up command failed.
    Command(String),
}

/// Maps a string error that uses the `auth:` prefix into [`HttpAttemptFailure`].
///
/// Modules whose auth predicate is wider than this prefix, such as Kafka and
/// Kibana, must not use this function.
///
/// # Parameters
///
/// - `err`: Module error. A leading `auth:` prefix is an authentication failure
///   and is removed, including a repeated prefix.
///
/// # Returns
///
/// [`HttpAttemptFailure::Auth`] when `err` starts with `auth:`, otherwise
/// [`HttpAttemptFailure::Transport`] with the original string.
///
/// # Errors
///
/// Does not return [`Result`].
///
/// # Examples
///
/// ```
/// use brute::protocol::http_attempt::{HttpAttemptFailure, classify_auth_prefix};
///
/// assert_eq!(
///     classify_auth_prefix("auth:denied".to_string()),
///     HttpAttemptFailure::Auth("denied".to_string())
/// );
/// assert_eq!(
///     classify_auth_prefix("connection reset".to_string()),
///     HttpAttemptFailure::Transport("connection reset".to_string())
/// );
/// ```
pub fn classify_auth_prefix(err: String) -> HttpAttemptFailure {
    let trimmed = err.trim_start_matches("auth:");
    if trimmed.len() != err.len() {
        HttpAttemptFailure::Auth(trimmed.to_string())
    } else {
        HttpAttemptFailure::Transport(err)
    }
}

/// Runs one attempt under `timeout` and maps Auth, Transport, and Command failures.
///
/// # Parameters
///
/// - `timeout`: Per-attempt deadline. Elapsed time becomes `attempt timed out`.
/// - `protocol`: Lowercase protocol name used in outcome messages.
/// - `success_banner`: Banner used only when a command fails after authentication. `&str` or `String`.
/// - `attempt`: Future returning success or a classified failure.
///
/// # Returns
///
/// [`AttemptOutcome::Success`] for a successful attempt or a post-auth command
/// error. Auth failures and transport errors use `{protocol} auth failed` and
/// `{protocol} transport failed`.
///
/// # Errors
///
/// Does not return [`Result`]. Timeout and classified failures are
/// [`AttemptOutcome`] values.
///
/// # Examples
///
/// ```ignore
/// let outcome = run_http_attempt(
///     ctx.timeout(),
///     "elasticsearch",
///     || success_message(is_unauthenticated(ctx)),
///     attempt_once(ctx),
/// )
/// .await;
/// ```
pub async fn run_http_attempt<F, B>(
    timeout: Duration,
    protocol: &str,
    success_banner: impl FnOnce() -> B,
    attempt: F,
) -> AttemptOutcome
where
    F: Future<Output = Result<AttemptSuccess, HttpAttemptFailure>>,
    B: Into<String>,
{
    match tokio::time::timeout(timeout, attempt).await {
        Ok(Ok(success)) => AttemptOutcome::Success(success),
        Ok(Err(HttpAttemptFailure::Auth(err))) => {
            AttemptOutcome::failure(format!("{protocol} auth failed: {err}"))
        }
        Ok(Err(HttpAttemptFailure::Transport(err))) => {
            AttemptOutcome::error(format!("{protocol} transport failed: {err}"))
        }
        Ok(Err(HttpAttemptFailure::Command(err))) => {
            AttemptOutcome::Success(AttemptSuccess::with_command_error(
                success_banner(),
                format!("{protocol} command execution failed: {err}"),
            ))
        }
        Err(_) => AttemptOutcome::error("attempt timed out".to_string()),
    }
}

/// Maps a client build failure onto [`HttpAttemptFailure::Transport`].
///
/// # Parameters
///
/// - `result`: `reqwest` client builder result.
///
/// # Returns
///
/// The built client.
///
/// # Errors
///
/// Returns [`HttpAttemptFailure::Transport`] with `err.to_string()` when the
/// client cannot be built.
///
/// # Examples
///
/// ```ignore
/// let client = client_build_failure(attempt_http_client(ctx))?;
/// ```
fn client_build_failure(
    result: Result<reqwest::Client, reqwest::Error>,
) -> Result<reqwest::Client, HttpAttemptFailure> {
    result.map_err(|err| HttpAttemptFailure::Transport(err.to_string()))
}

/// Builds the attempt client and maps build failure to Transport.
///
/// # Parameters
///
/// - `ctx`: Attempt timeout, scheme, and proxy.
///
/// # Returns
///
/// Configured client.
///
/// # Errors
///
/// Returns [`HttpAttemptFailure::Transport`] with `err.to_string()`.
///
/// # Examples
///
/// ```ignore
/// let client = open_attempt_client(ctx)?;
/// ```
pub fn open_attempt_client(ctx: &AttemptContext) -> Result<reqwest::Client, HttpAttemptFailure> {
    client_build_failure(attempt_http_client(ctx))
}

/// Builds a no-redirect attempt client and maps build failure to Transport.
///
/// Form-login modules inspect `Location` and `Set-Cookie`, so redirects stay
/// visible.
///
/// # Parameters
///
/// - `ctx`: Attempt timeout, scheme, and proxy.
///
/// # Returns
///
/// Client that does not follow redirects.
///
/// # Errors
///
/// Returns [`HttpAttemptFailure::Transport`] with `err.to_string()`.
///
/// # Examples
///
/// ```ignore
/// let client = open_attempt_client_no_redirect(ctx)?;
/// ```
pub fn open_attempt_client_no_redirect(
    ctx: &AttemptContext,
) -> Result<reqwest::Client, HttpAttemptFailure> {
    client_build_failure(build_http_no_redirect_client(
        ctx.timeout(),
        ctx.url_scheme,
        ctx.target.proxy.as_ref(),
    ))
}

/// Classifies a Basic Auth HTTP status with the shared wording.
///
/// Calls [`require_http_auth`]. It does not reimplement the 2xx/401/403 table.
///
/// # Parameters
///
/// - `status`: Response status.
/// - `policy`: How HTTP 403 is classified for this protocol.
///
/// # Returns
///
/// `Ok(())` when the status is a credential hit.
///
/// # Errors
///
/// Returns [`HttpAttemptFailure::Auth`] with `invalid username or password`,
/// or [`HttpAttemptFailure::Transport`] with `unexpected HTTP status: {status}`.
///
/// # Examples
///
/// ```
/// use brute::protocol::http_attempt::{HttpAttemptFailure, classify_basic_status};
/// use brute::protocol::http_auth::HttpForbiddenPolicy;
/// use reqwest::StatusCode;
///
/// let err = classify_basic_status(StatusCode::UNAUTHORIZED, HttpForbiddenPolicy::AuthFailure)
///     .expect_err("401 is an auth failure");
/// assert_eq!(
///     err,
///     HttpAttemptFailure::Auth("invalid username or password".to_string())
/// );
/// ```
pub fn classify_basic_status(
    status: StatusCode,
    policy: HttpForbiddenPolicy,
) -> Result<(), HttpAttemptFailure> {
    require_http_auth(
        status,
        policy,
        || HttpAttemptFailure::Auth("invalid username or password".to_string()),
        |status| HttpAttemptFailure::Transport(format!("unexpected HTTP status: {status}")),
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use reqwest::StatusCode;

    use crate::cli::{HttpUrlScheme, Protocol};
    use crate::protocol::PostAuthResult;
    use crate::protocol::http_auth::HttpForbiddenPolicy;

    use super::*;

    #[tokio::test]
    async fn maps_auth_transport_command_and_timeout() {
        let auth = run_http_attempt(
            Duration::from_secs(1),
            "elasticsearch",
            || "banner".to_string(),
            async { Err(HttpAttemptFailure::Auth("denied".to_string())) },
        )
        .await;
        match auth {
            AttemptOutcome::Failure(fault) => {
                assert_eq!(fault.message, "elasticsearch auth failed: denied");
            }
            other => panic!("expected auth failure, got {other:?}"),
        }

        let transport = run_http_attempt(
            Duration::from_secs(1),
            "etcd",
            || "unused".to_string(),
            async { Err(classify_auth_prefix("connection reset by peer".to_string())) },
        )
        .await;
        match transport {
            AttemptOutcome::Error(fault) => {
                assert_eq!(
                    fault.message,
                    "etcd transport failed: connection reset by peer"
                );
            }
            other => panic!("expected transport error, got {other:?}"),
        }

        let prefixed = run_http_attempt(
            Duration::from_secs(1),
            "grafana",
            || "unused".to_string(),
            async { Err(classify_auth_prefix("auth:auth:bad".to_string())) },
        )
        .await;
        match prefixed {
            AttemptOutcome::Failure(fault) => {
                assert_eq!(fault.message, "grafana auth failed: bad");
            }
            other => panic!("expected stripped auth failure, got {other:?}"),
        }

        let command = run_http_attempt(
            Duration::from_secs(1),
            "ftp",
            || "FTP access!".to_string(),
            async { Err(HttpAttemptFailure::Command("550".to_string())) },
        )
        .await;
        match command {
            AttemptOutcome::Success(success) => {
                assert_eq!(success.message, "FTP access!");
                match success.post_auth_result {
                    Some(PostAuthResult::Failed(error)) => {
                        assert_eq!(error, "ftp command execution failed: 550");
                    }
                    other => panic!("expected command error, got {other:?}"),
                }
            }
            other => panic!("expected command success, got {other:?}"),
        }

        let timed_out = run_http_attempt(
            Duration::from_millis(1),
            "kibana",
            || "unused".to_string(),
            async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok(AttemptSuccess::new("late"))
            },
        )
        .await;
        match timed_out {
            AttemptOutcome::Error(fault) => {
                assert_eq!(fault.message, "attempt timed out");
            }
            other => panic!("expected timeout, got {other:?}"),
        }
    }

    fn sample_ctx(
        username: Option<&str>,
        password: Option<&str>,
        port: Option<u16>,
    ) -> AttemptContext {
        use crate::cli::{CommonArgs, Protocol};
        use crate::credentials::CredentialSet;

        AttemptContext {
            protocol: Protocol::Jenkins,
            target_host: "10.0.0.5".into(),
            url_scheme: HttpUrlScheme::Http,
            target: CommonArgs {
                targets: vec!["10.0.0.5".into()],
                usernames: vec!["user".into()],
                passwords: vec!["pass".into()],
                credential_id: None,
                port,
                threads: 1,
                retries: 0,
                timeout_ms: 1000,
                delay_ms: 0,
                jitter_ms: 0,
                continue_on_success: false,
                proxy: None,
            },
            path: None,
            execute: None,
            credential: CredentialSet {
                username: username.map(str::to_string),
                password: password.map(str::to_string),
                service_name: None,
                sid: None,
            },
        }
    }

    #[test]
    fn basic_auth_header_and_status_wording_stay_shared() {
        use reqwest::header::AUTHORIZATION;

        let client = reqwest::Client::new();
        let empty = sample_ctx(None, None, Some(8080));
        let authed = sample_ctx(Some("user"), Some("pass"), Some(8080));
        let bare = client
            .get("http://127.0.0.1/")
            .build()
            .expect("request builds");
        let omitted = with_basic_auth(client.get("http://127.0.0.1/"), &empty)
            .build()
            .expect("request builds");
        assert_eq!(
            omitted.headers().get(AUTHORIZATION),
            bare.headers().get(AUTHORIZATION)
        );
        assert!(omitted.headers().get(AUTHORIZATION).is_none());

        let applied = with_basic_auth(client.get("http://127.0.0.1/"), &authed)
            .build()
            .expect("request builds");
        let manual = client
            .get("http://127.0.0.1/")
            .basic_auth("user", Some("pass"))
            .build()
            .expect("request builds");
        assert_eq!(
            applied.headers().get(AUTHORIZATION),
            manual.headers().get(AUTHORIZATION)
        );

        let password_only = sample_ctx(Some(""), Some("x"), Some(8080));
        let password_header = with_basic_auth(client.get("http://127.0.0.1/"), &password_only)
            .build()
            .expect("request builds");
        let password_manual = client
            .get("http://127.0.0.1/")
            .basic_auth("", Some("x"))
            .build()
            .expect("request builds");
        assert_eq!(
            password_header.headers().get(AUTHORIZATION),
            password_manual.headers().get(AUTHORIZATION)
        );

        assert!(credentials_absent(&empty));
        assert!(!credentials_absent(&authed));
        assert!(credentials_absent(&sample_ctx(
            Some(""),
            Some(""),
            Some(8080)
        )));
        assert!(!credentials_absent(&password_only));

        assert!(classify_basic_status(StatusCode::OK, HttpForbiddenPolicy::AuthFailure).is_ok());
        assert_eq!(
            classify_basic_status(StatusCode::UNAUTHORIZED, HttpForbiddenPolicy::CredentialHit),
            Err(HttpAttemptFailure::Auth(
                "invalid username or password".to_string()
            ))
        );
        assert!(
            classify_basic_status(StatusCode::FORBIDDEN, HttpForbiddenPolicy::CredentialHit)
                .is_ok()
        );
        assert_eq!(
            classify_basic_status(StatusCode::FORBIDDEN, HttpForbiddenPolicy::AuthFailure),
            Err(HttpAttemptFailure::Auth(
                "invalid username or password".to_string()
            ))
        );
        assert_eq!(
            classify_basic_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                HttpForbiddenPolicy::AuthFailure
            ),
            Err(HttpAttemptFailure::Transport(
                "unexpected HTTP status: 500 Internal Server Error".to_string()
            ))
        );
        assert_eq!(
            http_attempt_url(&authed, "/api/json"),
            "http://10.0.0.5:8080/api/json"
        );
        assert_eq!(
            http_attempt_url(&sample_ctx(None, None, None), "/api/json"),
            http_service_url(
                HttpUrlScheme::Http,
                "10.0.0.5",
                Protocol::Jenkins.default_port(),
                "/api/json"
            )
        );
    }
}
