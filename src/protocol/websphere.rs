//! WebSphere Application Server admin console login and post-auth console page (`-x`).
//!
//! Credentials are posted as `j_username`/`j_password` to
//! `/ibm/console/j_security_check`. The admin console serves HTTPS on 9043 by
//! default, so TLS certificate verification is skipped like other HTTPS modules.

use async_trait::async_trait;
use reqwest::StatusCode;
use reqwest::header::CONTENT_TYPE;

use crate::cli::HttpUrlScheme;
use crate::protocol::http::{
    build_http_basic_client, build_http_no_redirect_client, normalize_path,
};

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

/// WebSphere attempt errors split auth failures from post-auth command failures.
#[derive(Debug)]
enum WebsphereAttemptError {
    Auth(String),
    Transport(String),
    Command(String),
}

/// WebSphere module configuration.
#[derive(Debug, Clone)]
pub struct WebsphereModule;

impl WebsphereModule {
    /// Creates a new WebSphere module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`WebsphereModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::websphere::WebsphereModule;
    ///
    /// let _module = WebsphereModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for WebsphereModule {
    fn name(&self) -> &'static str {
        "websphere"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_logon(ctx)).await {
            Ok(Some(message)) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        match tokio::time::timeout(ctx.timeout(), attempt_once(ctx)).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(WebsphereAttemptError::Auth(err))) => {
                AttemptOutcome::failure(format!("websphere auth failed: {err}"))
            }
            Ok(Err(WebsphereAttemptError::Transport(err))) => {
                AttemptOutcome::error(format!("websphere transport failed: {err}"))
            }
            Ok(Err(WebsphereAttemptError::Command(err))) => {
                AttemptOutcome::Success(AttemptSuccess::with_command_error(
                    "WebSphere access!",
                    format!("websphere command execution failed: {err}"),
                ))
            }
            Err(_) => AttemptOutcome::error("attempt timed out".to_string()),
        }
    }
}

/// Runs one WebSphere console login, then optional `-x`.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, WebsphereAttemptError> {
    let client =
        build_http_no_redirect_client(ctx.timeout(), ctx.url_scheme, ctx.target.proxy.as_ref())
            .map_err(|err| WebsphereAttemptError::Transport(err.to_string()))?;
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let username = ctx.credential.username.as_deref().unwrap_or("");
    let password = ctx.credential.password.as_deref().unwrap_or("");
    let url = api_url(
        ctx.url_scheme,
        &ctx.target_host,
        port,
        "/ibm/console/j_security_check",
    );
    let form = format!(
        "j_username={}&j_password={}",
        encode_form(username),
        encode_form(password),
    );
    let response = client
        .post(&url)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(form)
        .send()
        .await
        .map_err(|err| WebsphereAttemptError::Transport(err.to_string()))?;
    let status = response.status();
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
    let cookie = session_cookie(&response);
    classify_login(status, &location)?;
    match ctx.execute.as_deref() {
        Some(command) => execute_command(&client, ctx, command, &cookie).await,
        None => Ok(AttemptSuccess::new("WebSphere access!")),
    }
}

fn classify_login(status: StatusCode, location: &str) -> Result<(), WebsphereAttemptError> {
    let lower = location.to_ascii_lowercase();
    let bounced = lower.contains("logon") || lower.contains("j_security_check");
    if bounced {
        return Err(WebsphereAttemptError::Auth(
            "invalid username or password".to_string(),
        ));
    }
    if status.is_success() || status.is_redirection() {
        return Ok(());
    }
    super::http_auth::require_http_auth(
        status,
        super::http_auth::HttpForbiddenPolicy::AuthFailure,
        || WebsphereAttemptError::Auth("invalid username or password".to_string()),
        |status| WebsphereAttemptError::Transport(format!("unexpected HTTP status: {status}")),
    )
}

async fn execute_command(
    client: &reqwest::Client,
    ctx: &AttemptContext,
    command: &str,
    cookie: &str,
) -> Result<AttemptSuccess, WebsphereAttemptError> {
    let path = execute_path(command);
    let url = api_url(
        ctx.url_scheme,
        &ctx.target_host,
        ctx.target.port.unwrap_or(ctx.protocol.default_port()),
        &path,
    );
    let mut request = client.get(&url);
    if !cookie.is_empty() {
        request = request.header(reqwest::header::COOKIE, cookie);
    }
    let response = request
        .send()
        .await
        .map_err(|err| WebsphereAttemptError::Command(err.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| WebsphereAttemptError::Command(err.to_string()))?;
    if status.is_success() {
        Ok(AttemptSuccess::with_command(
            "WebSphere access!",
            trim_body(&body),
        ))
    } else {
        Err(WebsphereAttemptError::Command(format!(
            "HTTP {status}: {}",
            trim_body(&body)
        )))
    }
}

/// Builds `https://host:port{path}` for the WebSphere admin console.
///
/// # Parameters
///
/// - `scheme`: URL scheme (`http` or `https`).
/// - `host`: Target host.
/// - `port`: Console port.
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
/// use brute::protocol::websphere::api_url;
///
/// assert_eq!(
///     api_url(brute::cli::HttpUrlScheme::Https, "10.0.0.5", 9043, "/ibm/console/"),
///     "https://10.0.0.5:9043/ibm/console/"
/// );
/// ```
pub fn api_url(scheme: HttpUrlScheme, host: &str, port: u16, path: &str) -> String {
    super::http::build_http_basic_url(scheme, host, port, path)
}

/// Normalizes `-x` text into an admin console path.
///
/// # Parameters
///
/// - `command`: CLI `-x` value (`console`, `serverinfo`, or a path).
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
/// use brute::protocol::websphere::execute_path;
///
/// assert_eq!(execute_path("console"), "/ibm/console/login.do?action=secure");
/// ```
pub fn execute_path(command: &str) -> String {
    let trimmed = command.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "console" | "home" | "serverinfo" | "info" => {
            "/ibm/console/login.do?action=secure".to_string()
        }
        other => normalize_path(other),
    }
}

fn session_cookie(response: &reqwest::Response) -> String {
    response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or(value).trim())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
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

async fn probe_logon(ctx: &TargetContext) -> Option<String> {
    let client =
        build_http_basic_client(ctx.timeout(), ctx.url_scheme, ctx.target.proxy.as_ref()).ok()?;
    let url = api_url(
        ctx.url_scheme,
        &ctx.target_host,
        ctx.port(),
        "/ibm/console/logon.jsp",
    );
    let response = client.get(&url).send().await.ok()?;
    if response.status().is_success() || response.status() == StatusCode::FORBIDDEN {
        Some("WebSphere".to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_path_maps_shorthand() {
        assert_eq!(
            execute_path("console"),
            "/ibm/console/login.do?action=secure"
        );
    }

    #[test]
    fn classify_login_rejects_bounce_to_logon() {
        assert!(classify_login(StatusCode::FOUND, "/ibm/console/logon.jsp").is_err());
        assert!(classify_login(StatusCode::OK, "").is_ok());
    }
}
