//! GitLab login, unauthorized probe, and post-auth HTTP API (`-x`).
//!
//! Empty credentials probe `GET /api/v4/user` without a token. Non-empty
//! credentials POST `/oauth/token` with password grant.

use async_trait::async_trait;
use reqwest::StatusCode;
use reqwest::header::CONTENT_TYPE;
use serde_json::Value;

use crate::cli::HttpUrlScheme;
use crate::protocol::http::{build_http_basic_client, normalize_path};

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

/// GitLab attempt errors split auth failures from post-auth command failures.
#[derive(Debug)]
enum GitlabAttemptError {
    Auth(String),
    Transport(String),
    Command(String),
}

/// GitLab module configuration.
#[derive(Debug, Clone)]
pub struct GitlabModule;

impl GitlabModule {
    /// Creates a new GitLab module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`GitlabModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::gitlab::GitlabModule;
    ///
    /// let _module = GitlabModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for GitlabModule {
    fn name(&self) -> &'static str {
        "gitlab"
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
            Ok(Err(GitlabAttemptError::Auth(err))) => {
                AttemptOutcome::failure(format!("gitlab auth failed: {err}"))
            }
            Ok(Err(GitlabAttemptError::Transport(err))) => {
                AttemptOutcome::error(format!("gitlab transport failed: {err}"))
            }
            Ok(Err(GitlabAttemptError::Command(err))) => {
                let message = success_message(is_unauthenticated(ctx));
                AttemptOutcome::Success(AttemptSuccess::with_command_error(
                    message,
                    format!("gitlab command execution failed: {err}"),
                ))
            }
            Err(_) => AttemptOutcome::error("attempt timed out".to_string()),
        }
    }
}

/// Runs one GitLab OAuth login or unauthorized probe, then optional `-x`.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, GitlabAttemptError> {
    let unauthenticated = is_unauthenticated(ctx);
    let client = build_http_basic_client(ctx.timeout(), ctx.url_scheme, ctx.target.proxy.as_ref())
        .map_err(|err| GitlabAttemptError::Transport(err.to_string()))?;
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let token = if unauthenticated {
        let url = api_url(ctx.url_scheme, &ctx.target_host, port, "/api/v4/user");
        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|err| GitlabAttemptError::Transport(err.to_string()))?;
        if super::http_auth::classify_http_auth_status(
            response.status(),
            super::http_auth::HttpForbiddenPolicy::AuthFailure,
        ) == super::http_auth::HttpAuthDecision::AuthFailure
        {
            return Err(GitlabAttemptError::Auth(
                "anonymous access is disabled".to_string(),
            ));
        }
        if !response.status().is_success() {
            return Err(GitlabAttemptError::Transport(format!(
                "unexpected HTTP status: {}",
                response.status()
            )));
        }
        None
    } else {
        let url = api_url(ctx.url_scheme, &ctx.target_host, port, "/oauth/token");
        let form = format!(
            "grant_type=password&username={}&password={}",
            encode_form(ctx.credential.username.as_deref().unwrap_or("")),
            encode_form(ctx.credential.password.as_deref().unwrap_or("")),
        );
        let response = client
            .post(&url)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form)
            .send()
            .await
            .map_err(|err| GitlabAttemptError::Transport(err.to_string()))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|err| GitlabAttemptError::Transport(err.to_string()))?;
        if super::http_auth::classify_http_auth_status(
            status,
            super::http_auth::HttpForbiddenPolicy::AuthFailure,
        ) == super::http_auth::HttpAuthDecision::AuthFailure
            || status == StatusCode::BAD_REQUEST
            || body.to_ascii_lowercase().contains("invalid_grant")
        {
            return Err(GitlabAttemptError::Auth(
                "invalid username or password".to_string(),
            ));
        }
        if !status.is_success() {
            return Err(GitlabAttemptError::Transport(format!(
                "unexpected HTTP status: {status}: {}",
                trim_body(&body)
            )));
        }
        Some(parse_access_token(&body).ok_or_else(|| {
            GitlabAttemptError::Auth("login succeeded without access_token".to_string())
        })?)
    };
    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => execute_command(&client, ctx, command, token.as_deref(), message).await,
        None => Ok(AttemptSuccess::new(message)),
    }
}

async fn execute_command(
    client: &reqwest::Client,
    ctx: &AttemptContext,
    command: &str,
    token: Option<&str>,
    success_message: &str,
) -> Result<AttemptSuccess, GitlabAttemptError> {
    let path = execute_path(command);
    let url = api_url(
        ctx.url_scheme,
        &ctx.target_host,
        ctx.target.port.unwrap_or(ctx.protocol.default_port()),
        &path,
    );
    let mut request = client.get(&url);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = request
        .send()
        .await
        .map_err(|err| GitlabAttemptError::Command(err.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| GitlabAttemptError::Command(err.to_string()))?;
    if status.is_success() {
        Ok(AttemptSuccess::with_command(
            success_message,
            trim_body(&body),
        ))
    } else {
        Err(GitlabAttemptError::Command(format!(
            "HTTP {status}: {}",
            trim_body(&body)
        )))
    }
}

/// Builds `http://host:port{path}` for GitLab HTTP.
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
/// use brute::protocol::gitlab::api_url;
///
/// assert_eq!(
///     api_url(brute::cli::HttpUrlScheme::Http, "10.0.0.5", 80, "/oauth/token"),
///     "http://10.0.0.5:80/oauth/token"
/// );
/// ```
pub fn api_url(scheme: HttpUrlScheme, host: &str, port: u16, path: &str) -> String {
    super::http::build_http_basic_url(scheme, host, port, path)
}

/// Normalizes `-x` text into a GitLab API path.
///
/// # Parameters
///
/// - `command`: CLI `-x` value (`user`, `projects`, or a path).
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
/// use brute::protocol::gitlab::execute_path;
///
/// assert_eq!(execute_path("user"), "/api/v4/user");
/// assert_eq!(execute_path("projects"), "/api/v4/projects");
/// ```
pub fn execute_path(command: &str) -> String {
    let trimmed = command.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "user" | "whoami" => "/api/v4/user".to_string(),
        "projects" => "/api/v4/projects".to_string(),
        "version" => "/api/v4/version".to_string(),
        other => normalize_path(other),
    }
}

/// Extracts `access_token` from an OAuth JSON body.
///
/// # Parameters
///
/// - `body`: `/oauth/token` response.
///
/// # Returns
///
/// Token string when present.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::gitlab::parse_access_token;
///
/// assert_eq!(
///     parse_access_token(r#"{"access_token":"abc"}"#).as_deref(),
///     Some("abc")
/// );
/// ```
pub fn parse_access_token(body: &str) -> Option<String> {
    let value: Value = serde_json::from_str(body).ok()?;
    value
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
}

fn encode_form(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

async fn probe_version(ctx: &TargetContext) -> Option<String> {
    let client =
        build_http_basic_client(ctx.timeout(), ctx.url_scheme, ctx.target.proxy.as_ref()).ok()?;
    let url = api_url(
        ctx.url_scheme,
        &ctx.target_host,
        ctx.port(),
        "/api/v4/version",
    );
    let response = client.get(&url).send().await.ok()?;
    if response.status().is_success()
        || response.status() == StatusCode::UNAUTHORIZED
        || response.status() == StatusCode::FORBIDDEN
    {
        Some("GitLab".to_string())
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
        "GitLab unauthorized access!"
    } else {
        "GitLab access!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_path_maps_shorthand() {
        assert_eq!(execute_path("user"), "/api/v4/user");
        assert_eq!(execute_path("projects"), "/api/v4/projects");
    }

    #[test]
    fn parse_access_token_reads_json() {
        assert_eq!(
            parse_access_token(r#"{"access_token":"tok"}"#).as_deref(),
            Some("tok")
        );
    }
}
