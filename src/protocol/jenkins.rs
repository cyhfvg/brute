//! Jenkins login, unauthorized access, and post-auth HTTP API (`-x`).
//!
//! Empty username and password probe `GET /api/json` without Authorization.
//! Non-empty credentials use HTTP Basic Auth against the same endpoint.

use async_trait::async_trait;
use reqwest::StatusCode;

use crate::cli::HttpUrlScheme;
use crate::protocol::http::{build_http_basic_client, normalize_path};

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

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

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_api(ctx)).await {
            Ok(Some(message)) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        crate::protocol::http_attempt::run_http_attempt(
            ctx.timeout(),
            "jenkins",
            || success_message(is_unauthenticated(ctx)),
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
    let unauthenticated = is_unauthenticated(ctx);
    let client = build_http_basic_client(ctx.timeout(), ctx.url_scheme, ctx.target.proxy.as_ref())
        .map_err(|err| JenkinsAttemptError::Transport(err.to_string()))?;
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let url = api_url(ctx.url_scheme, &ctx.target_host, port, "/api/json");
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
        .map_err(|err| JenkinsAttemptError::Transport(err.to_string()))?;
    classify_status(response.status())?;
    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => execute_command(&client, ctx, command, unauthenticated, message).await,
        None => Ok(AttemptSuccess::new(message)),
    }
}

fn classify_status(status: StatusCode) -> Result<(), JenkinsAttemptError> {
    super::http_auth::require_http_auth(
        status,
        super::http_auth::HttpForbiddenPolicy::AuthFailure,
        || JenkinsAttemptError::Auth("invalid username or password".to_string()),
        |status| JenkinsAttemptError::Transport(format!("unexpected HTTP status: {status}")),
    )
}

async fn execute_command(
    client: &reqwest::Client,
    ctx: &AttemptContext,
    command: &str,
    unauthenticated: bool,
    success_message: &str,
) -> Result<AttemptSuccess, JenkinsAttemptError> {
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

/// Builds `http://host:port{path}` for Jenkins HTTP.
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
/// use brute::protocol::jenkins::api_url;
///
/// assert_eq!(
///     api_url(brute::cli::HttpUrlScheme::Http, "10.0.0.5", 8080, "/api/json"),
///     "http://10.0.0.5:8080/api/json"
/// );
/// ```
pub fn api_url(scheme: HttpUrlScheme, host: &str, port: u16, path: &str) -> String {
    super::http::build_http_basic_url(scheme, host, port, path)
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
    let client =
        build_http_basic_client(ctx.timeout(), ctx.url_scheme, ctx.target.proxy.as_ref()).ok()?;
    let url = api_url(ctx.url_scheme, &ctx.target_host, ctx.port(), "/api/json");
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

fn is_unauthenticated(ctx: &AttemptContext) -> bool {
    ctx.credential.username.as_deref().unwrap_or("").is_empty()
        && ctx.credential.password.as_deref().unwrap_or("").is_empty()
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
