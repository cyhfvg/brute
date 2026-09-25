//! Kubelet HTTPS login, unauthorized probe, and post-auth API (`-x`).
//!
//! Empty credentials probe `GET /runningpods` without Authorization. Non-empty
//! credentials send `Authorization: Bearer <password>` (token in `-p`).

use async_trait::async_trait;
use reqwest::StatusCode;
use reqwest::header::AUTHORIZATION;

use crate::protocol::http::normalize_path;

use super::http_attempt::{
    classify_basic_status, credentials_absent, http_attempt_url, http_target_url,
    open_attempt_client, target_http_client,
};
use super::http_auth::HttpForbiddenPolicy;
use super::{AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext};

/// Kubelet attempt errors split auth failures from post-auth command failures.
type KubeletAttemptError = crate::protocol::http_attempt::HttpAttemptFailure;

/// Kubelet module configuration.
#[derive(Debug, Clone)]
pub struct KubeletModule;

impl KubeletModule {
    /// Creates a new kubelet module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`KubeletModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::kubelet::KubeletModule;
    ///
    /// let _module = KubeletModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for KubeletModule {
    fn name(&self) -> &'static str {
        "kubelet"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> Option<String> {
        match tokio::time::timeout(ctx.timeout(), probe_healthz(ctx)).await {
            Ok(Some(message)) => Some(message),
            _ => None,
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        crate::protocol::http_attempt::run_http_attempt(
            ctx.timeout(),
            "kubelet",
            || success_message(credentials_absent(ctx)),
            attempt_once(ctx),
        )
        .await
    }
}

/// Runs one kubelet login or unauthorized probe, then optional `-x`.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, KubeletAttemptError> {
    let unauthenticated = credentials_absent(ctx);
    let client = open_attempt_client(ctx)?;
    let url = http_attempt_url(ctx, "/runningpods/");
    let mut request = client.get(&url);
    if !unauthenticated {
        request = authorize(request, ctx);
    }
    let response = request
        .send()
        .await
        .map_err(|err| KubeletAttemptError::Transport(err.to_string()))?;
    classify_basic_status(response.status(), HttpForbiddenPolicy::CredentialHit)?;
    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => execute_command(&client, ctx, command, unauthenticated, message).await,
        None => Ok(AttemptSuccess::new(message)),
    }
}

fn authorize(request: reqwest::RequestBuilder, ctx: &AttemptContext) -> reqwest::RequestBuilder {
    let username = ctx.credential.username.as_deref().unwrap_or("");
    let password = ctx.credential.password.as_deref().unwrap_or("");
    if username.is_empty() {
        request.header(AUTHORIZATION, format!("Bearer {password}"))
    } else {
        request.basic_auth(username, Some(password))
    }
}

async fn execute_command(
    client: &reqwest::Client,
    ctx: &AttemptContext,
    command: &str,
    unauthenticated: bool,
    success_message: &str,
) -> Result<AttemptSuccess, KubeletAttemptError> {
    let path = execute_path(command);
    let url = http_attempt_url(ctx, &path);
    let mut request = client.get(&url);
    if !unauthenticated {
        request = authorize(request, ctx);
    }
    let response = request
        .send()
        .await
        .map_err(|err| KubeletAttemptError::Command(err.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| KubeletAttemptError::Command(err.to_string()))?;
    if status.is_success() || status == StatusCode::FORBIDDEN {
        Ok(AttemptSuccess::with_command(
            success_message,
            trim_body(&body),
        ))
    } else {
        Err(KubeletAttemptError::Command(format!(
            "HTTP {status}: {}",
            trim_body(&body)
        )))
    }
}

/// Normalizes `-x` text into a kubelet path.
///
/// # Parameters
///
/// - `command`: CLI `-x` value (`pods`, `healthz`, or a path).
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
/// use brute::protocol::kubelet::execute_path;
///
/// assert_eq!(execute_path("pods"), "/runningpods/");
/// assert_eq!(execute_path("healthz"), "/healthz");
/// ```
pub fn execute_path(command: &str) -> String {
    let trimmed = command.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "pods" | "runningpods" => "/runningpods/".to_string(),
        "healthz" | "health" => "/healthz".to_string(),
        "spec" => "/spec/".to_string(),
        other => normalize_path(other),
    }
}

async fn probe_healthz(ctx: &TargetContext) -> Option<String> {
    let client = target_http_client(ctx).ok()?;
    let url = http_target_url(ctx, "/healthz");
    let response = client.get(&url).send().await.ok()?;
    let status = response.status();
    if status.is_success() || status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN
    {
        Some("Kubelet".to_string())
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
        "Kubelet unauthorized access!"
    } else {
        "Kubelet access!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_path_maps_shorthand() {
        assert_eq!(execute_path("pods"), "/runningpods/");
        assert_eq!(execute_path("healthz"), "/healthz");
    }
}
