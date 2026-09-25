//! Docker Engine API login, unauthorized access, and post-auth HTTP commands.
//!
//! Empty username and password probe `GET /version` without Authorization.
//! Non-empty credentials use HTTP Basic Auth against the same endpoint.

use async_trait::async_trait;
use reqwest::StatusCode;

use crate::cli::HttpUrlScheme;
use crate::protocol::http::{build_http_basic_client, normalize_path};

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

/// Docker API attempt errors split auth failures from post-auth command failures.
#[derive(Debug)]
enum DockerAttemptError {
    Auth(String),
    Transport(String),
    Command(String),
}

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

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_version(ctx)).await {
            Ok(Some(message)) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        match tokio::time::timeout(ctx.timeout(), attempt_once(ctx)).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(DockerAttemptError::Auth(err))) => {
                AttemptOutcome::Failure(format!("docker auth failed: {err}"))
            }
            Ok(Err(DockerAttemptError::Transport(err))) => {
                AttemptOutcome::Error(format!("docker transport failed: {err}"))
            }
            Ok(Err(DockerAttemptError::Command(err))) => {
                let message = success_message(is_unauthenticated(ctx));
                AttemptOutcome::Success(AttemptSuccess::with_command_error(
                    message,
                    format!("docker command execution failed: {err}"),
                ))
            }
            Err(_) => AttemptOutcome::Error("attempt timed out".to_string()),
        }
    }
}

/// Runs one Docker API login or unauthorized probe, then optional `-x`.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, DockerAttemptError> {
    let unauthenticated = is_unauthenticated(ctx);
    let client = build_http_basic_client(
        ctx.timeout(),
        HttpUrlScheme::Http,
        ctx.target.proxy.as_ref(),
    )
    .map_err(|err| DockerAttemptError::Transport(err.to_string()))?;
    let url = api_url(
        &ctx.target_host,
        ctx.target.port.unwrap_or(ctx.protocol.default_port()),
        "/version",
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
        .map_err(|err| DockerAttemptError::Transport(err.to_string()))?;
    classify_status(response.status())?;

    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => {
            execute_docker_command(&client, ctx, command, unauthenticated, message).await
        }
        None => Ok(AttemptSuccess::new(message)),
    }
}

/// Classifies Docker API status into auth success or failure.
fn classify_status(status: StatusCode) -> Result<(), DockerAttemptError> {
    super::http_auth::require_http_auth(
        status,
        super::http_auth::HttpForbiddenPolicy::CredentialHit,
        || DockerAttemptError::Auth("invalid username or password".to_string()),
        |status| DockerAttemptError::Transport(format!("unexpected HTTP status: {status}")),
    )
}

/// Executes a post-auth Docker Engine API GET.
async fn execute_docker_command(
    client: &reqwest::Client,
    ctx: &AttemptContext,
    command: &str,
    unauthenticated: bool,
    success_message: &str,
) -> Result<AttemptSuccess, DockerAttemptError> {
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

/// Builds `http://host:port{path}` for the Docker Engine API.
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
/// use brute::protocol::docker::api_url;
///
/// assert_eq!(
///     api_url("10.0.0.5", 2375, "/version"),
///     "http://10.0.0.5:2375/version"
/// );
/// ```
pub fn api_url(host: &str, port: u16, path: &str) -> String {
    format!("http://{host}:{port}{path}")
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
    let client = build_http_basic_client(
        ctx.timeout(),
        HttpUrlScheme::Http,
        ctx.target.proxy.as_ref(),
    )
    .ok()?;
    let url = api_url(&ctx.target_host, ctx.port(), "/version");
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

fn is_unauthenticated(ctx: &AttemptContext) -> bool {
    ctx.credential.username.as_deref().unwrap_or("").is_empty()
        && ctx.credential.password.as_deref().unwrap_or("").is_empty()
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
