//! Prometheus login, unauthorized access, and post-auth HTTP API (`-x`).
//!
//! Empty username and password probe `GET /api/v1/status/buildinfo` without
//! Authorization. Non-empty credentials use HTTP Basic Auth.

use async_trait::async_trait;
use reqwest::StatusCode;

use crate::protocol::http::normalize_path;

use super::http_attempt::{
    classify_basic_status, credentials_absent, http_attempt_url, http_target_url,
    open_attempt_client, target_http_client, with_basic_auth,
};
use super::http_auth::HttpForbiddenPolicy;
use super::{AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext};

/// Prometheus attempt errors split auth failures from post-auth command failures.
type PromAttemptError = crate::protocol::http_attempt::HttpAttemptFailure;

/// Prometheus module configuration.
#[derive(Debug, Clone)]
pub struct PrometheusModule;

impl PrometheusModule {
    /// Creates a new Prometheus module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`PrometheusModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::prometheus::PrometheusModule;
    ///
    /// let _module = PrometheusModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for PrometheusModule {
    fn name(&self) -> &'static str {
        "prometheus"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> Option<String> {
        match tokio::time::timeout(ctx.timeout(), probe_buildinfo(ctx)).await {
            Ok(Some(message)) => Some(message),
            _ => None,
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        crate::protocol::http_attempt::run_http_attempt(
            ctx.timeout(),
            "prometheus",
            || success_message(credentials_absent(ctx)),
            attempt_once(ctx),
        )
        .await
    }
}

/// Runs one Prometheus login or unauthorized probe, then optional `-x`.
///
/// # Parameters
///
/// - `ctx`: Target, credential, timeout, proxy, and optional execute path.
///
/// # Returns
///
/// [`AttemptSuccess`] when buildinfo accepts the credentials (or anonymous access).
///
/// # Errors
///
/// Returns [`PromAttemptError::Auth`] on HTTP 401, [`PromAttemptError::Transport`]
/// on connect failures, and [`PromAttemptError::Command`] for post-auth API errors.
///
/// # Examples
///
/// ```ignore
/// let success = attempt_once(&ctx).await?;
/// ```
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, PromAttemptError> {
    let unauthenticated = credentials_absent(ctx);
    let client = open_attempt_client(ctx)?;
    let url = http_attempt_url(ctx, "/api/v1/status/buildinfo");
    let mut request = client.get(&url);
    request = with_basic_auth(request, ctx);
    let response = request
        .send()
        .await
        .map_err(|err| PromAttemptError::Transport(err.to_string()))?;
    classify_basic_status(response.status(), HttpForbiddenPolicy::CredentialHit)?;
    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => execute_command(&client, ctx, command, message).await,
        None => Ok(AttemptSuccess::new(message)),
    }
}

async fn execute_command(
    client: &reqwest::Client,
    ctx: &AttemptContext,
    command: &str,
    success_message: &str,
) -> Result<AttemptSuccess, PromAttemptError> {
    let path = execute_path(command);
    let url = http_attempt_url(ctx, &path);
    let mut request = client.get(&url);
    request = with_basic_auth(request, ctx);
    let response = request
        .send()
        .await
        .map_err(|err| PromAttemptError::Command(err.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| PromAttemptError::Command(err.to_string()))?;
    if status.is_success() {
        Ok(AttemptSuccess::with_command(
            success_message,
            trim_body(&body),
        ))
    } else {
        Err(PromAttemptError::Command(format!(
            "HTTP {status}: {}",
            trim_body(&body)
        )))
    }
}

/// Normalizes `-x` text into a Prometheus API path.
///
/// # Parameters
///
/// - `command`: CLI `-x` value (`query`, `targets`, `metrics`, or a path).
///
/// # Returns
///
/// Absolute path.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::prometheus::execute_path;
///
/// assert_eq!(execute_path("query"), "/api/v1/query?query=up");
/// assert_eq!(execute_path("/metrics"), "/metrics");
/// ```
pub fn execute_path(command: &str) -> String {
    let trimmed = command.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "query" | "up" => "/api/v1/query?query=up".to_string(),
        "targets" => "/api/v1/targets".to_string(),
        "config" => "/api/v1/status/config".to_string(),
        "buildinfo" | "version" => "/api/v1/status/buildinfo".to_string(),
        "metrics" => "/metrics".to_string(),
        other => normalize_path(other),
    }
}

/// Extracts `Prometheus <version>` from buildinfo JSON.
///
/// # Parameters
///
/// - `body`: `/api/v1/status/buildinfo` response body.
///
/// # Returns
///
/// Banner such as `Prometheus 2.54.1`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::prometheus::parse_buildinfo_banner;
///
/// let body = r#"{"status":"success","data":{"version":"2.54.1"}}"#;
/// assert_eq!(
///     parse_buildinfo_banner(body).as_deref(),
///     Some("Prometheus 2.54.1")
/// );
/// ```
pub fn parse_buildinfo_banner(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let version = value
        .get("data")
        .and_then(|data| data.get("version"))
        .and_then(serde_json::Value::as_str)?;
    if version.is_empty() {
        None
    } else {
        Some(format!("Prometheus {version}"))
    }
}

async fn probe_buildinfo(ctx: &TargetContext) -> Option<String> {
    let client = target_http_client(ctx).ok()?;
    let url = http_target_url(ctx, "/api/v1/status/buildinfo");
    let response = client.get(&url).send().await.ok()?;
    let status = response.status();
    let body = response.text().await.ok()?;
    if let Some(banner) = parse_buildinfo_banner(&body) {
        return Some(banner);
    }
    if status.is_success() || status == StatusCode::UNAUTHORIZED {
        Some("Prometheus".to_string())
    } else {
        None
    }
}

fn trim_body(body: &str) -> String {
    const MAX: usize = 8192;
    let trimmed = body.trim();
    if trimmed.len() > MAX {
        format!("{}\n...", &trimmed[..MAX])
    } else {
        trimmed.to_string()
    }
}

fn success_message(unauthenticated: bool) -> &'static str {
    if unauthenticated {
        "Prometheus unauthorized access!"
    } else {
        "Prometheus access!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_path_maps_shorthand() {
        assert_eq!(execute_path("query"), "/api/v1/query?query=up");
        assert_eq!(execute_path("/metrics"), "/metrics");
    }

    #[test]
    fn parse_buildinfo_banner_reads_version() {
        let body = r#"{"status":"success","data":{"version":"2.54.1"}}"#;
        assert_eq!(
            parse_buildinfo_banner(body).as_deref(),
            Some("Prometheus 2.54.1")
        );
        assert_eq!(parse_buildinfo_banner("not-json"), None);
    }
}
