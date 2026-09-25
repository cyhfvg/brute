//! Shared timeout and Auth/Transport/Command mapping for protocol attempts.
//!
//! This is not a second 401/403 table. Status classification stays in
//! [`super::http_auth`]. Callers classify their own error type into
//! [`HttpAttemptFailure`], then this module maps that class onto the existing
//! outcome wording.

use std::time::Duration;

use super::{AttemptOutcome, AttemptSuccess};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::PostAuthResult;

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
}
