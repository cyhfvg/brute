//! Shared HTTP authentication status classification.
//!
//! Credential sprays must not invent a private meaning for 401/403 in each
//! module. [`classify_http_auth_status`] is the only status table. Each
//! protocol selects a [`HttpForbiddenPolicy`] and keeps its own error type.

use reqwest::StatusCode;

/// How HTTP 403 is interpreted after a credentialed request.
///
/// 401 is always an authentication failure. 2xx is always a hit. Other
/// statuses are transport or application errors, not a clean auth decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpForbiddenPolicy {
    /// 403 means the credentials were accepted and the resource was denied.
    ///
    /// Used by generic HTTP Basic, Tomcat Manager, Elasticsearch, Docker,
    /// CouchDB, Kubelet, and Prometheus.
    CredentialHit,
    /// 403 means the service rejected the credentials.
    ///
    /// Used by Jenkins, Grafana, GitLab, Harbor, Hadoop, ClickHouse, InfluxDB,
    /// Druid, Neo4j, Nexus, Solr, Spark, WebLogic, WebSphere, Kibana, JBoss,
    /// MinIO, and Nacos.
    AuthFailure,
}

/// Credential decision produced from an HTTP status alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpAuthDecision {
    /// Credentials were accepted.
    Success,
    /// Credentials were rejected.
    AuthFailure,
    /// Status is not an authentication decision.
    Transport,
}

/// Classifies an HTTP status with the shared spray policy.
///
/// # Parameters
///
/// - `status`: Response status from the credentialed request.
/// - `policy`: Protocol-specific meaning of HTTP 403.
///
/// # Returns
///
/// [`HttpAuthDecision::Success`] for 2xx, and for 403 when `policy` is
/// [`HttpForbiddenPolicy::CredentialHit`]. [`HttpAuthDecision::AuthFailure`]
/// for 401, and for 403 when `policy` is [`HttpForbiddenPolicy::AuthFailure`].
/// Every other status is [`HttpAuthDecision::Transport`].
///
/// # Examples
///
/// ```
/// use brute::protocol::http_auth::{
///     HttpAuthDecision, HttpForbiddenPolicy, classify_http_auth_status,
/// };
/// use reqwest::StatusCode;
///
/// assert_eq!(
///     classify_http_auth_status(StatusCode::FORBIDDEN, HttpForbiddenPolicy::CredentialHit),
///     HttpAuthDecision::Success
/// );
/// assert_eq!(
///     classify_http_auth_status(StatusCode::FORBIDDEN, HttpForbiddenPolicy::AuthFailure),
///     HttpAuthDecision::AuthFailure
/// );
/// assert_eq!(
///     classify_http_auth_status(StatusCode::UNAUTHORIZED, HttpForbiddenPolicy::CredentialHit),
///     HttpAuthDecision::AuthFailure
/// );
/// ```
pub fn classify_http_auth_status(
    status: StatusCode,
    policy: HttpForbiddenPolicy,
) -> HttpAuthDecision {
    if status.is_success() {
        return HttpAuthDecision::Success;
    }
    if status == StatusCode::UNAUTHORIZED {
        return HttpAuthDecision::AuthFailure;
    }
    if status == StatusCode::FORBIDDEN {
        return match policy {
            HttpForbiddenPolicy::CredentialHit => HttpAuthDecision::Success,
            HttpForbiddenPolicy::AuthFailure => HttpAuthDecision::AuthFailure,
        };
    }
    HttpAuthDecision::Transport
}

/// Applies [`classify_http_auth_status`] to a module-specific error type.
///
/// # Parameters
///
/// - `status`: Response status from the credentialed request.
/// - `policy`: Protocol-specific meaning of HTTP 403.
/// - `auth_error`: Constructor for a rejected-credential error.
/// - `transport_error`: Constructor for a non-auth status. Receives `status`.
///
/// # Returns
///
/// `Ok(())` when the decision is success.
///
/// # Errors
///
/// Returns `auth_error()` for an authentication failure and
/// `transport_error(status)` for every other non-success status.
///
/// # Examples
///
/// ```
/// use brute::protocol::http_auth::{HttpForbiddenPolicy, require_http_auth};
/// use reqwest::StatusCode;
///
/// let decision: Result<(), &str> = require_http_auth(
///     StatusCode::UNAUTHORIZED,
///     HttpForbiddenPolicy::AuthFailure,
///     || "auth",
///     |_| "transport",
/// );
/// assert_eq!(decision, Err("auth"));
/// ```
pub fn require_http_auth<E>(
    status: StatusCode,
    policy: HttpForbiddenPolicy,
    auth_error: impl FnOnce() -> E,
    transport_error: impl FnOnce(StatusCode) -> E,
) -> Result<(), E> {
    match classify_http_auth_status(status, policy) {
        HttpAuthDecision::Success => Ok(()),
        HttpAuthDecision::AuthFailure => Err(auth_error()),
        HttpAuthDecision::Transport => Err(transport_error(status)),
    }
}

#[cfg(test)]
mod tests {
    use super::{HttpAuthDecision, HttpForbiddenPolicy, classify_http_auth_status};
    use reqwest::StatusCode;

    #[test]
    fn forbidden_policy_is_the_only_split() {
        let cases = [
            (
                StatusCode::OK,
                HttpForbiddenPolicy::CredentialHit,
                HttpAuthDecision::Success,
            ),
            (
                StatusCode::OK,
                HttpForbiddenPolicy::AuthFailure,
                HttpAuthDecision::Success,
            ),
            (
                StatusCode::UNAUTHORIZED,
                HttpForbiddenPolicy::CredentialHit,
                HttpAuthDecision::AuthFailure,
            ),
            (
                StatusCode::UNAUTHORIZED,
                HttpForbiddenPolicy::AuthFailure,
                HttpAuthDecision::AuthFailure,
            ),
            (
                StatusCode::FORBIDDEN,
                HttpForbiddenPolicy::CredentialHit,
                HttpAuthDecision::Success,
            ),
            (
                StatusCode::FORBIDDEN,
                HttpForbiddenPolicy::AuthFailure,
                HttpAuthDecision::AuthFailure,
            ),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                HttpForbiddenPolicy::CredentialHit,
                HttpAuthDecision::Transport,
            ),
            (
                StatusCode::BAD_GATEWAY,
                HttpForbiddenPolicy::AuthFailure,
                HttpAuthDecision::Transport,
            ),
        ];

        for (status, policy, expected) in cases {
            assert_eq!(
                classify_http_auth_status(status, policy),
                expected,
                "{status} / {policy:?}"
            );
        }
    }
}
