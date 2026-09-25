//! Prometheus login, unauthorized access, and post-auth HTTP API (`-x`).
//!
//! Empty username and password probe `GET /api/v1/status/buildinfo` without
//! Authorization. Non-empty credentials use HTTP Basic Auth.

use async_trait::async_trait;
use reqwest::StatusCode;

use crate::cli::HttpUrlScheme;
use crate::protocol::http::{build_http_basic_client, normalize_path};

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

/// Prometheus attempt errors split auth failures from post-auth command failures.
#[derive(Debug)]
enum PromAttemptError {
    Auth(String),
    Transport(String),
    Command(String),
}

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

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_buildinfo(ctx)).await {
            Ok(Some(message)) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        match tokio::time::timeout(ctx.timeout(), attempt_once(ctx)).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(PromAttemptError::Auth(err))) => {
                AttemptOutcome::Failure(format!("prometheus auth failed: {err}"))
            }
            Ok(Err(PromAttemptError::Transport(err))) => {
                AttemptOutcome::Error(format!("prometheus transport failed: {err}"))
            }
            Ok(Err(PromAttemptError::Command(err))) => {
                let message = success_message(is_unauthenticated(ctx));
                AttemptOutcome::Success(AttemptSuccess::with_command_error(
                    message,
                    format!("prometheus command execution failed: {err}"),
                ))
            }
            Err(_) => AttemptOutcome::Error("attempt timed out".to_string()),
        }
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
    let unauthenticated = is_unauthenticated(ctx);
    let client = build_http_basic_client(
        ctx.timeout(),
        HttpUrlScheme::Http,
        ctx.target.proxy.as_ref(),
    )
    .map_err(|err| PromAttemptError::Transport(err.to_string()))?;
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let url = api_url(&ctx.target_host, port, "/api/v1/status/buildinfo");
    let mut request = client.get(&url);
    if !unauthenticated {
        request = request.basic_auth(
            ctx.credential.username.as_deref().unwrap_or(""),
            Some(ctx.credential.password.as_deref().unwrap_or("")),
        );
    }
    let response = request
        .send()
        .await
        .map_err(|err| PromAttemptError::Transport(err.to_string()))?;
    classify_status(response.status())?;
    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => execute_command(&client, ctx, command, unauthenticated, message).await,
        None => Ok(AttemptSuccess::new(message)),
    }
}

fn classify_status(status: StatusCode) -> Result<(), PromAttemptError> {
    super::http_auth::require_http_auth(
        status,
        super::http_auth::HttpForbiddenPolicy::CredentialHit,
        || PromAttemptError::Auth("invalid username or password".to_string()),
        |status| PromAttemptError::Transport(format!("unexpected HTTP status: {status}")),
    )
}

async fn execute_command(
    client: &reqwest::Client,
    ctx: &AttemptContext,
    command: &str,
    unauthenticated: bool,
    success_message: &str,
) -> Result<AttemptSuccess, PromAttemptError> {
    let path = execute_path(command);
    let url = api_url(
        &ctx.target_host,
        ctx.target.port.unwrap_or(ctx.protocol.default_port()),
        &path,
    );
    let mut request = client.get(&url);
    if !unauthenticated {
        request = request.basic_auth(
            ctx.credential.username.as_deref().unwrap_or(""),
            Some(ctx.credential.password.as_deref().unwrap_or("")),
        );
    }
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

/// Builds `http://host:port{path}` for Prometheus HTTP.
///
/// # Parameters
///
/// - `host`: Target host.
/// - `port`: Service port.
/// - `path`: Absolute path.
///
/// # Returns
///
/// URL string.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::prometheus::api_url;
///
/// assert_eq!(
///     api_url("10.0.0.5", 9090, "/metrics"),
///     "http://10.0.0.5:9090/metrics"
/// );
/// ```
pub fn api_url(host: &str, port: u16, path: &str) -> String {
    format!("http://{host}:{port}{path}")
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
    let client = build_http_basic_client(
        ctx.timeout(),
        HttpUrlScheme::Http,
        ctx.target.proxy.as_ref(),
    )
    .ok()?;
    let url = api_url(&ctx.target_host, ctx.port(), "/api/v1/status/buildinfo");
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

fn is_unauthenticated(ctx: &AttemptContext) -> bool {
    ctx.credential.username.as_deref().unwrap_or("").is_empty()
        && ctx.credential.password.as_deref().unwrap_or("").is_empty()
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
