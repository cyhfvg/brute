//! Docker Engine API login, unauthorized access, and post-auth HTTP commands.
//!
//! Empty username and password probe `GET /version` without Authorization.
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

/// Docker API attempt errors split auth failures from post-auth command failures.
type DockerAttemptError = crate::protocol::http_attempt::HttpAttemptFailure;

/// Docker Engine API module configuration.
#[derive(Debug, Clone)]
pub struct DockerModule;

impl DockerModule {
    /// Creates a new Docker API module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Per-attempt timeout in milliseconds. Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`DockerModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::docker::DockerModule;
    ///
    /// let _module = DockerModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for DockerModule {
    fn name(&self) -> &'static str {
        "docker"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> Option<String> {
        match tokio::time::timeout(ctx.timeout(), probe_version(ctx)).await {
            Ok(Some(message)) => Some(message),
            _ => None,
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        crate::protocol::http_attempt::run_http_attempt(
            ctx.timeout(),
            "docker",
            || success_message(credentials_absent(ctx)),
            attempt_once(ctx),
        )
        .await
    }
}

/// Runs one Docker API login or unauthorized probe, then optional `-x`.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, DockerAttemptError> {
    let unauthenticated = credentials_absent(ctx);
    let client = open_attempt_client(ctx)?;
    let url = http_attempt_url(ctx, "/version");
    let mut request = client.get(&url);
    request = with_basic_auth(request, ctx);
    let response = request
        .send()
        .await
        .map_err(|err| DockerAttemptError::Transport(err.to_string()))?;
    classify_basic_status(response.status(), HttpForbiddenPolicy::CredentialHit)?;

    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => execute_docker_command(&client, ctx, command, message).await,
        None => Ok(AttemptSuccess::new(message)),
    }
}

/// Executes a post-auth Docker Engine API GET.
async fn execute_docker_command(
    client: &reqwest::Client,
    ctx: &AttemptContext,
    command: &str,
    success_message: &str,
) -> Result<AttemptSuccess, DockerAttemptError> {
    let path = execute_path(command);
    let url = http_attempt_url(ctx, &path);
    let mut request = client.get(&url);
    request = with_basic_auth(request, ctx);
    let response = request
        .send()
        .await
        .map_err(|err| DockerAttemptError::Command(err.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| DockerAttemptError::Command(err.to_string()))?;
    if status.is_success() {
        Ok(AttemptSuccess::with_command(
            success_message,
            trim_body(&body),
        ))
    } else {
        Err(DockerAttemptError::Command(format!(
            "HTTP {status}: {}",
            trim_body(&body)
        )))
    }
}

/// Normalizes `-x` text into a Docker Engine API path.
///
/// # Parameters
///
/// - `command`: CLI `-x` value (`info`, `containers`, `images`, or a path).
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
/// use brute::protocol::docker::execute_path;
///
/// assert_eq!(execute_path("containers"), "/containers/json?all=true");
/// assert_eq!(execute_path("/info"), "/info");
/// ```
pub fn execute_path(command: &str) -> String {
    let trimmed = command.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "info" => "/info".to_string(),
        "version" => "/version".to_string(),
        "containers" | "ps" => "/containers/json?all=true".to_string(),
        "images" => "/images/json".to_string(),
        other => normalize_path(other),
    }
}

/// Probes `GET /version` without credentials.
async fn probe_version(ctx: &TargetContext) -> Option<String> {
    let client = target_http_client(ctx).ok()?;
    let url = http_target_url(ctx, "/version");
    let response = client.get(&url).send().await.ok()?;
    let status = response.status();
    let body = response.text().await.ok()?;
    if let Some(banner) = parse_version_banner(&body) {
        return Some(banner);
    }
    if status.is_success() || status == StatusCode::UNAUTHORIZED {
        Some("Docker API".to_string())
    } else {
        None
    }
}

/// Extracts `Docker <version>` from `/version` JSON.
///
/// # Parameters
///
/// - `body`: `/version` response body.
///
/// # Returns
///
/// Banner such as `Docker 27.3.1`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::docker::parse_version_banner;
///
/// let body = r#"{"Version":"27.3.1","ApiVersion":"1.47"}"#;
/// assert_eq!(parse_version_banner(body).as_deref(), Some("Docker 27.3.1"));
/// ```
pub fn parse_version_banner(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let version = value.get("Version").and_then(serde_json::Value::as_str)?;
    if version.is_empty() {
        None
    } else {
        Some(format!("Docker {version}"))
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
        "Docker unauthorized access!"
    } else {
        "Docker access!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_path_maps_shorthand() {
        assert_eq!(execute_path("containers"), "/containers/json?all=true");
        assert_eq!(execute_path("info"), "/info");
    }

    #[test]
    fn parse_version_banner_reads_engine_version() {
        let body = r#"{"Version":"27.3.1","ApiVersion":"1.47"}"#;
        assert_eq!(parse_version_banner(body).as_deref(), Some("Docker 27.3.1"));
        assert_eq!(parse_version_banner("not-json"), None);
    }
}
