//! Druid login, unauthorized probe, and post-auth SQL (`-x`).
//!
//! Empty credentials POST `/druid/v2/sql` without Authorization. Non-empty
//! credentials use HTTP Basic Auth against the same endpoint.

use async_trait::async_trait;
use reqwest::StatusCode;
use reqwest::header::CONTENT_TYPE;

use crate::cli::HttpUrlScheme;
use crate::protocol::http::{build_http_basic_client, normalize_path};

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

/// Druid attempt errors split auth failures from post-auth command failures.
type DruidAttemptError = crate::protocol::http_attempt::HttpAttemptFailure;

/// Druid module configuration.
#[derive(Debug, Clone)]
pub struct DruidModule;

impl DruidModule {
    /// Creates a new Druid module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`DruidModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::druid::DruidModule;
    ///
    /// let _module = DruidModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for DruidModule {
    fn name(&self) -> &'static str {
        "druid"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_status(ctx)).await {
            Ok(Some(message)) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        crate::protocol::http_attempt::run_http_attempt(
            ctx.timeout(),
            "druid",
            || success_message(is_unauthenticated(ctx)),
            attempt_once(ctx),
        )
        .await
    }
}

/// Runs one Druid SQL login or unauthorized probe, then optional `-x`.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, DruidAttemptError> {
    let unauthenticated = is_unauthenticated(ctx);
    let client = build_http_basic_client(ctx.timeout(), ctx.url_scheme, ctx.target.proxy.as_ref())
        .map_err(|err| DruidAttemptError::Transport(err.to_string()))?;
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let url = api_url(
        ctx.url_scheme,
        &ctx.target_host,
        port,
        "/druid/coordinator/v1/isLeader",
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
        .map_err(|err| DruidAttemptError::Transport(err.to_string()))?;
    classify_status(response.status())?;
    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => execute_command(&client, ctx, command, unauthenticated, message).await,
        None => Ok(AttemptSuccess::new(message)),
    }
}

fn classify_status(status: StatusCode) -> Result<(), DruidAttemptError> {
    super::http_auth::require_http_auth(
        status,
        super::http_auth::HttpForbiddenPolicy::AuthFailure,
        || DruidAttemptError::Auth("invalid username or password".to_string()),
        |status| DruidAttemptError::Transport(format!("unexpected HTTP status: {status}")),
    )
}

async fn execute_command(
    client: &reqwest::Client,
    ctx: &AttemptContext,
    command: &str,
    unauthenticated: bool,
    success_message: &str,
) -> Result<AttemptSuccess, DruidAttemptError> {
    let (method, path, body) = execute_request(command);
    let url = api_url(
        ctx.url_scheme,
        &ctx.target_host,
        ctx.target.port.unwrap_or(ctx.protocol.default_port()),
        &path,
    );
    let mut request = if method == "POST" {
        client
            .post(&url)
            .header(CONTENT_TYPE, "application/json")
            .body(body)
    } else {
        client.get(&url)
    };
    if !unauthenticated {
        request = request.basic_auth(
            ctx.credential.username.as_deref().unwrap_or(""),
            Some(ctx.credential.password.as_deref().unwrap_or("")),
        );
    }
    let response = request
        .send()
        .await
        .map_err(|err| DruidAttemptError::Command(err.to_string()))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|err| DruidAttemptError::Command(err.to_string()))?;
    if status.is_success() {
        Ok(AttemptSuccess::with_command(
            success_message,
            trim_body(&text),
        ))
    } else {
        Err(DruidAttemptError::Command(format!(
            "HTTP {status}: {}",
            trim_body(&text)
        )))
    }
}

/// Builds `http://host:port{path}` for Druid HTTP.
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
/// use brute::protocol::druid::api_url;
///
/// assert_eq!(
///     api_url(brute::cli::HttpUrlScheme::Http, "10.0.0.5", 8888, "/status"),
///     "http://10.0.0.5:8888/status"
/// );
/// ```
pub fn api_url(scheme: HttpUrlScheme, host: &str, port: u16, path: &str) -> String {
    super::http::build_http_basic_url(scheme, host, port, path)
}

/// Maps `-x` text to an HTTP method, path, and optional JSON body.
///
/// # Parameters
///
/// - `command`: CLI `-x` value (`status`, `sql`, or a path).
///
/// # Returns
///
/// `(method, path, body)`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::druid::execute_request;
///
/// let (method, path, body) = execute_request("status");
/// assert_eq!(method, "GET");
/// assert_eq!(path, "/status");
/// assert!(body.is_empty());
/// ```
pub fn execute_request(command: &str) -> (&'static str, String, String) {
    let trimmed = command.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "status" => ("GET", "/status".to_string(), String::new()),
        "sql" | "select" => (
            "POST",
            "/druid/v2/sql".to_string(),
            r#"{"query":"SELECT 1"}"#.to_string(),
        ),
        other if other.to_ascii_lowercase().starts_with("select ") => (
            "POST",
            "/druid/v2/sql".to_string(),
            format!(r#"{{"query":{}}}"#, json_string(trimmed)),
        ),
        other => ("GET", normalize_path(other), String::new()),
    }
}

async fn probe_status(ctx: &TargetContext) -> Option<String> {
    let client =
        build_http_basic_client(ctx.timeout(), ctx.url_scheme, ctx.target.proxy.as_ref()).ok()?;
    let url = api_url(ctx.url_scheme, &ctx.target_host, ctx.port(), "/status");
    let response = client.get(&url).send().await.ok()?;
    let status = response.status();
    if status.is_success() || status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN
    {
        Some("Druid".to_string())
    } else {
        None
    }
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| format!("\"{value}\""))
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
        "Druid unauthorized access!"
    } else {
        "Druid access!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_request_maps_status() {
        let (method, path, body) = execute_request("status");
        assert_eq!(method, "GET");
        assert_eq!(path, "/status");
        assert!(body.is_empty());
    }

    #[test]
    fn execute_request_maps_sql() {
        let (method, path, body) = execute_request("SELECT 1");
        assert_eq!(method, "POST");
        assert_eq!(path, "/druid/v2/sql");
        assert!(body.contains("SELECT 1"));
    }
}
