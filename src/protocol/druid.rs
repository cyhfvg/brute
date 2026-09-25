//! Druid login, unauthorized probe, and post-auth SQL (`-x`).
//!
//! Empty credentials POST `/druid/v2/sql` without Authorization. Non-empty
//! credentials use HTTP Basic Auth against the same endpoint.

use async_trait::async_trait;
use reqwest::StatusCode;
use reqwest::header::CONTENT_TYPE;

use crate::protocol::http::normalize_path;

use super::http_attempt::{
    classify_basic_status, credentials_absent, http_attempt_url, http_target_url,
    open_attempt_client, target_http_client, with_basic_auth,
};
use super::http_auth::HttpForbiddenPolicy;
use super::{AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext};

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

    async fn probe_target(&self, ctx: &TargetContext) -> Option<String> {
        match tokio::time::timeout(ctx.timeout(), probe_status(ctx)).await {
            Ok(Some(message)) => Some(message),
            _ => None,
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        crate::protocol::http_attempt::run_http_attempt(
            ctx.timeout(),
            "druid",
            || success_message(credentials_absent(ctx)),
            attempt_once(ctx),
        )
        .await
    }
}

/// Runs one Druid SQL login or unauthorized probe, then optional `-x`.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, DruidAttemptError> {
    let unauthenticated = credentials_absent(ctx);
    let client = open_attempt_client(ctx)?;
    let url = http_attempt_url(ctx, "/druid/coordinator/v1/isLeader");
    let mut request = client.get(&url);
    request = with_basic_auth(request, ctx);
    let response = request
        .send()
        .await
        .map_err(|err| DruidAttemptError::Transport(err.to_string()))?;
    classify_basic_status(response.status(), HttpForbiddenPolicy::AuthFailure)?;
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
) -> Result<AttemptSuccess, DruidAttemptError> {
    let (method, path, body) = execute_request(command);
    let url = http_attempt_url(ctx, &path);
    let mut request = if method == "POST" {
        client
            .post(&url)
            .header(CONTENT_TYPE, "application/json")
            .body(body)
    } else {
        client.get(&url)
    };
    request = with_basic_auth(request, ctx);
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
    let client = target_http_client(ctx).ok()?;
    let url = http_target_url(ctx, "/status");
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
