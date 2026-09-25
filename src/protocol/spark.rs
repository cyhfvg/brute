//! Spark master UI login, unauthorized probe, and post-auth HTTP API (`-x`).
//!
//! Empty credentials probe `GET /json/` without Authorization. Non-empty
//! credentials use HTTP Basic Auth against the same endpoint.

use async_trait::async_trait;
use reqwest::StatusCode;

use crate::cli::HttpUrlScheme;
use crate::protocol::http::{build_http_basic_client, normalize_path};

use super::{AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext};

/// Spark attempt errors split auth failures from post-auth command failures.
type SparkAttemptError = crate::protocol::http_attempt::HttpAttemptFailure;

/// Spark module configuration.
#[derive(Debug, Clone)]
pub struct SparkModule;

impl SparkModule {
    /// Creates a new Spark module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`SparkModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::spark::SparkModule;
    ///
    /// let _module = SparkModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for SparkModule {
    fn name(&self) -> &'static str {
        "spark"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> Option<String> {
        match tokio::time::timeout(ctx.timeout(), probe_json(ctx)).await {
            Ok(Some(message)) => Some(message),
            _ => None,
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        crate::protocol::http_attempt::run_http_attempt(
            ctx.timeout(),
            "spark",
            || success_message(is_unauthenticated(ctx)),
            attempt_once(ctx),
        )
        .await
    }
}

/// Runs one Spark master UI login or unauthorized probe, then optional `-x`.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, SparkAttemptError> {
    let unauthenticated = is_unauthenticated(ctx);
    let client = build_http_basic_client(ctx.timeout(), ctx.url_scheme, ctx.target.proxy.as_ref())
        .map_err(|err| SparkAttemptError::Transport(err.to_string()))?;
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let url = api_url(ctx.url_scheme, &ctx.target_host, port, "/json/");
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
        .map_err(|err| SparkAttemptError::Transport(err.to_string()))?;
    classify_status(response.status())?;
    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => execute_command(&client, ctx, command, unauthenticated, message).await,
        None => Ok(AttemptSuccess::new(message)),
    }
}

fn classify_status(status: StatusCode) -> Result<(), SparkAttemptError> {
    super::http_auth::require_http_auth(
        status,
        super::http_auth::HttpForbiddenPolicy::AuthFailure,
        || SparkAttemptError::Auth("invalid username or password".to_string()),
        |status| SparkAttemptError::Transport(format!("unexpected HTTP status: {status}")),
    )
}

async fn execute_command(
    client: &reqwest::Client,
    ctx: &AttemptContext,
    command: &str,
    unauthenticated: bool,
    success_message: &str,
) -> Result<AttemptSuccess, SparkAttemptError> {
    let path = execute_path(command);
    let url = api_url(
        ctx.url_scheme,
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
        .map_err(|err| SparkAttemptError::Command(err.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| SparkAttemptError::Command(err.to_string()))?;
    if status.is_success() {
        Ok(AttemptSuccess::with_command(
            success_message,
            trim_body(&body),
        ))
    } else {
        Err(SparkAttemptError::Command(format!(
            "HTTP {status}: {}",
            trim_body(&body)
        )))
    }
}

/// Builds `http://host:port{path}` for Spark HTTP.
///
/// # Parameters
///
/// - `scheme`: URL scheme (`http` or `https`).
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
/// use brute::protocol::spark::api_url;
///
/// assert_eq!(api_url(brute::cli::HttpUrlScheme::Http, "10.0.0.5", 8080, "/json/"), "http://10.0.0.5:8080/json/");
/// ```
pub fn api_url(scheme: HttpUrlScheme, host: &str, port: u16, path: &str) -> String {
    super::http::build_http_basic_url(scheme, host, port, path)
}

/// Normalizes `-x` text into a Spark master UI path.
///
/// # Parameters
///
/// - `command`: CLI `-x` value (`json`, `env`, or a path).
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
/// use brute::protocol::spark::execute_path;
///
/// assert_eq!(execute_path("json"), "/json/");
/// assert_eq!(execute_path("env"), "/environment/");
/// ```
pub fn execute_path(command: &str) -> String {
    let trimmed = command.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "json" | "status" => "/json/".to_string(),
        "env" | "environment" => "/environment/".to_string(),
        "apps" | "applications" => "/api/v1/applications".to_string(),
        other => normalize_path(other),
    }
}

async fn probe_json(ctx: &TargetContext) -> Option<String> {
    let client =
        build_http_basic_client(ctx.timeout(), ctx.url_scheme, ctx.target.proxy.as_ref()).ok()?;
    let url = api_url(ctx.url_scheme, &ctx.target_host, ctx.port(), "/json/");
    let response = client.get(&url).send().await.ok()?;
    let status = response.status();
    if status.is_success() || status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN
    {
        Some("Spark".to_string())
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
        "Spark unauthorized access!"
    } else {
        "Spark access!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_path_maps_shorthand() {
        assert_eq!(execute_path("json"), "/json/");
        assert_eq!(execute_path("env"), "/environment/");
    }
}
