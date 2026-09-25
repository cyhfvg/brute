//! Jenkins login, unauthorized access, and post-auth HTTP API (`-x`).
//!
//! Empty username and password probe `GET /api/json` without Authorization.
//! Non-empty credentials use HTTP Basic Auth against the same endpoint.

use async_trait::async_trait;
use reqwest::StatusCode;

use crate::protocol::http::normalize_path;

use super::http_attempt::{
    classify_basic_status, credentials_absent, http_attempt_url, http_target_url,
    open_attempt_client, target_http_client, with_basic_auth,
};
use super::http_auth::HttpForbiddenPolicy;
use super::{AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext};

/// Jenkins attempt errors split auth failures from post-auth command failures.
type JenkinsAttemptError = crate::protocol::http_attempt::HttpAttemptFailure;

/// Jenkins module configuration.
#[derive(Debug, Clone)]
pub struct JenkinsModule;

impl JenkinsModule {
    /// Creates a new Jenkins module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`JenkinsModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::jenkins::JenkinsModule;
    ///
    /// let _module = JenkinsModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for JenkinsModule {
    fn name(&self) -> &'static str {
        "jenkins"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> Option<String> {
        match tokio::time::timeout(ctx.timeout(), probe_api(ctx)).await {
            Ok(Some(message)) => Some(message),
            _ => None,
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        crate::protocol::http_attempt::run_http_attempt(
            ctx.timeout(),
            "jenkins",
            || success_message(credentials_absent(ctx)),
            attempt_once(ctx),
        )
        .await
    }
}

/// Runs one Jenkins login or unauthorized probe, then optional `-x`.
///
/// # Parameters
///
/// - `ctx`: Target, credential, timeout, proxy, and optional execute path.
///
/// # Returns
///
/// [`AttemptSuccess`] when `/api/json` accepts the credentials (or anonymous access).
///
/// # Errors
///
/// Returns [`JenkinsAttemptError::Auth`] on HTTP 401/403, transport errors otherwise.
///
/// # Examples
///
/// ```ignore
/// let success = attempt_once(&ctx).await?;
/// ```
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, JenkinsAttemptError> {
    let unauthenticated = credentials_absent(ctx);
    let client = open_attempt_client(ctx)?;
    let url = http_attempt_url(ctx, "/api/json");
    let mut request = client.get(&url);
    request = with_basic_auth(request, ctx);
    let response = request
        .send()
        .await
        .map_err(|err| JenkinsAttemptError::Transport(err.to_string()))?;
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
) -> Result<AttemptSuccess, JenkinsAttemptError> {
    let path = execute_path(command);
    let url = http_attempt_url(ctx, &path);
    let mut request = client.get(&url);
    request = with_basic_auth(request, ctx);
    let response = request
        .send()
        .await
        .map_err(|err| JenkinsAttemptError::Command(err.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| JenkinsAttemptError::Command(err.to_string()))?;
    if status.is_success() {
        Ok(AttemptSuccess::with_command(
            success_message,
            trim_body(&body),
        ))
    } else {
        Err(JenkinsAttemptError::Command(format!(
            "HTTP {status}: {}",
            trim_body(&body)
        )))
    }
}

/// Normalizes `-x` text into a Jenkins API path.
///
/// # Parameters
///
/// - `command`: CLI `-x` value (`api`, `whoami`, `queue`, or a path).
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
/// use brute::protocol::jenkins::execute_path;
///
/// assert_eq!(execute_path("whoami"), "/whoAmI/api/json");
/// assert_eq!(execute_path("/api/json"), "/api/json");
/// ```
pub fn execute_path(command: &str) -> String {
    let trimmed = command.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "api" | "json" => "/api/json".to_string(),
        "whoami" => "/whoAmI/api/json".to_string(),
        "queue" => "/queue/api/json".to_string(),
        "computers" | "nodes" => "/computer/api/json".to_string(),
        other => normalize_path(other),
    }
}

/// Extracts `Jenkins <version>` from `/api/json`.
///
/// # Parameters
///
/// - `body`: API JSON body.
///
/// # Returns
///
/// Banner such as `Jenkins 2.462.3`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::jenkins::parse_api_banner;
///
/// let body = r#"{"mode":"NORMAL","nodeName":"","version":"2.462.3"}"#;
/// assert_eq!(parse_api_banner(body).as_deref(), Some("Jenkins 2.462.3"));
/// ```
pub fn parse_api_banner(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let version = value.get("version").and_then(serde_json::Value::as_str)?;
    if version.is_empty() {
        None
    } else {
        Some(format!("Jenkins {version}"))
    }
}

async fn probe_api(ctx: &TargetContext) -> Option<String> {
    let client = target_http_client(ctx).ok()?;
    let url = http_target_url(ctx, "/api/json");
    let response = client.get(&url).send().await.ok()?;
    let status = response.status();
    let body = response.text().await.ok()?;
    if let Some(banner) = parse_api_banner(&body) {
        return Some(banner);
    }
    if status.is_success() || status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN
    {
        Some("Jenkins".to_string())
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
        "Jenkins unauthorized access!"
    } else {
        "Jenkins access!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_path_maps_shorthand() {
        assert_eq!(execute_path("whoami"), "/whoAmI/api/json");
        assert_eq!(execute_path("/api/json"), "/api/json");
    }

    #[test]
    fn parse_api_banner_reads_version() {
        let body = r#"{"mode":"NORMAL","version":"2.462.3"}"#;
        assert_eq!(parse_api_banner(body).as_deref(), Some("Jenkins 2.462.3"));
        assert_eq!(parse_api_banner("not-json"), None);
    }
}
