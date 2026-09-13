//! Kubelet HTTPS login, unauthorized probe, and post-auth API (`-x`).
//!
//! Empty credentials probe `GET /runningpods` without Authorization. Non-empty
//! credentials send `Authorization: Bearer <password>` (token in `-p`).

use async_trait::async_trait;
use reqwest::StatusCode;
use reqwest::header::AUTHORIZATION;

use crate::cli::HttpUrlScheme;
use crate::protocol::http::{build_http_basic_client, normalize_path};

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

/// Kubelet attempt errors split auth failures from post-auth command failures.
#[derive(Debug)]
enum KubeletAttemptError {
    Auth(String),
    Transport(String),
    Command(String),
}

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

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_healthz(ctx)).await {
            Ok(Some(message)) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        match tokio::time::timeout(ctx.timeout(), attempt_once(ctx)).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(KubeletAttemptError::Auth(err))) => {
                AttemptOutcome::Failure(format!("kubelet auth failed: {err}"))
            }
            Ok(Err(KubeletAttemptError::Transport(err))) => {
                AttemptOutcome::Error(format!("kubelet transport failed: {err}"))
            }
            Ok(Err(KubeletAttemptError::Command(err))) => {
                let message = success_message(is_unauthenticated(ctx));
                AttemptOutcome::Success(AttemptSuccess::with_command_error(
                    message,
                    format!("kubelet command execution failed: {err}"),
                ))
            }
            Err(_) => AttemptOutcome::Error("attempt timed out".to_string()),
        }
    }
}

/// Runs one kubelet login or unauthorized probe, then optional `-x`.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, KubeletAttemptError> {
    let unauthenticated = is_unauthenticated(ctx);
    let client = build_http_basic_client(
        ctx.timeout(),
        HttpUrlScheme::Https,
        ctx.target.proxy.as_ref(),
    )
    .map_err(|err| KubeletAttemptError::Transport(err.to_string()))?;
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let url = api_url(&ctx.target_host, port, "/runningpods/");
    let mut request = client.get(&url);
    if !unauthenticated {
        request = authorize(request, ctx);
    }
    let response = request
        .send()
        .await
        .map_err(|err| KubeletAttemptError::Transport(err.to_string()))?;
    classify_status(response.status())?;
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
fn classify_status(status: StatusCode) -> Result<(), KubeletAttemptError> {
    if status.is_success() || status == StatusCode::FORBIDDEN {
        Ok(())
    } else if status == StatusCode::UNAUTHORIZED {
        Err(KubeletAttemptError::Auth(
            "invalid token or credentials".to_string(),
        ))
    } else {
        Err(KubeletAttemptError::Transport(format!(
            "unexpected HTTP status: {status}"
        )))
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
    let url = api_url(
        &ctx.target_host,
        ctx.target.port.unwrap_or(ctx.protocol.default_port()),
        &path,
    );
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

/// Builds `https://host:port{path}` for kubelet HTTPS.
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
/// use brute::protocol::kubelet::api_url;
///
/// assert_eq!(
///     api_url("10.0.0.5", 10250, "/healthz"),
///     "https://10.0.0.5:10250/healthz"
/// );
/// ```
pub fn api_url(host: &str, port: u16, path: &str) -> String {
    format!("https://{host}:{port}{path}")
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
    let client = build_http_basic_client(
        ctx.timeout(),
        HttpUrlScheme::Https,
        ctx.target.proxy.as_ref(),
    )
    .ok()?;
    let url = api_url(&ctx.target_host, ctx.port(), "/healthz");
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

fn is_unauthenticated(ctx: &AttemptContext) -> bool {
    ctx.credential.username.as_deref().unwrap_or("").is_empty()
        && ctx.credential.password.as_deref().unwrap_or("").is_empty()
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
