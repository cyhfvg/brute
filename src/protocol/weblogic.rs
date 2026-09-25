//! WebLogic Server admin console login and post-auth console page (`-x`).
//!
//! Credentials are posted as `j_username`/`j_password` to
//! `/console/j_security_check`. The admin console serves HTTP on 7001 by default.

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

/// WebLogic attempt errors split auth failures from post-auth command failures.
#[derive(Debug)]
enum WeblogicAttemptError {
    Auth(String),
    Transport(String),
    Command(String),
}

/// WebLogic module configuration.
#[derive(Debug, Clone)]
pub struct WeblogicModule;

impl WeblogicModule {
    /// Creates a new WebLogic module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`WeblogicModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::weblogic::WeblogicModule;
    ///
    /// let _module = WeblogicModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for WeblogicModule {
    fn name(&self) -> &'static str {
        "weblogic"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_login_page(ctx)).await {
            Ok(Some(message)) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        match tokio::time::timeout(ctx.timeout(), attempt_once(ctx)).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(WeblogicAttemptError::Auth(err))) => {
                AttemptOutcome::failure(format!("weblogic auth failed: {err}"))
            }
            Ok(Err(WeblogicAttemptError::Transport(err))) => {
                AttemptOutcome::error(format!("weblogic transport failed: {err}"))
            }
            Ok(Err(WeblogicAttemptError::Command(err))) => {
                AttemptOutcome::Success(AttemptSuccess::with_command_error(
                    "WebLogic access!",
                    format!("weblogic command execution failed: {err}"),
                ))
            }
            Err(_) => AttemptOutcome::error("attempt timed out".to_string()),
        }
    }
}

/// Runs one WebLogic console login, then optional `-x`.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, WeblogicAttemptError> {
    let client =
        build_http_no_redirect_client(ctx.timeout(), ctx.url_scheme, ctx.target.proxy.as_ref())
            .map_err(|err| WeblogicAttemptError::Transport(err.to_string()))?;
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let username = ctx.credential.username.as_deref().unwrap_or("");
    let password = ctx.credential.password.as_deref().unwrap_or("");
    let url = api_url(
        ctx.url_scheme,
        &ctx.target_host,
        port,
        "/console/j_security_check",
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
        .map_err(|err| WeblogicAttemptError::Transport(err.to_string()))?;
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
        None => Ok(AttemptSuccess::new("WebLogic access!")),
    }
}

fn classify_login(status: StatusCode, location: &str) -> Result<(), WeblogicAttemptError> {
    let lower = location.to_ascii_lowercase();
    let bounced = lower.contains("loginform") || lower.contains("j_security_check");
    if bounced {
        return Err(WeblogicAttemptError::Auth(
            "invalid username or password".to_string(),
        ));
    }
    if status.is_success() || status.is_redirection() {
        return Ok(());
    }
    super::http_auth::require_http_auth(
        status,
        super::http_auth::HttpForbiddenPolicy::AuthFailure,
        || WeblogicAttemptError::Auth("invalid username or password".to_string()),
        |status| WeblogicAttemptError::Transport(format!("unexpected HTTP status: {status}")),
    )
}

async fn execute_command(
    client: &reqwest::Client,
    ctx: &AttemptContext,
    command: &str,
    cookie: &str,
) -> Result<AttemptSuccess, WeblogicAttemptError> {
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
        .map_err(|err| WeblogicAttemptError::Command(err.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| WeblogicAttemptError::Command(err.to_string()))?;
    if status.is_success() {
        Ok(AttemptSuccess::with_command(
            "WebLogic access!",
            trim_body(&body),
        ))
    } else {
        Err(WeblogicAttemptError::Command(format!(
            "HTTP {status}: {}",
            trim_body(&body)
        )))
    }
}

/// Builds `http://host:port{path}` for the WebLogic admin console.
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
/// use brute::protocol::weblogic::api_url;
///
/// assert_eq!(
///     api_url(brute::cli::HttpUrlScheme::Http, "10.0.0.5", 7001, "/console/"),
///     "http://10.0.0.5:7001/console/"
/// );
/// ```
pub fn api_url(scheme: HttpUrlScheme, host: &str, port: u16, path: &str) -> String {
    super::http::build_http_basic_url(scheme, host, port, path)
}

/// Normalizes `-x` text into an admin console path.
///
/// # Parameters
///
/// - `command`: CLI `-x` value (`console`, `server`, or a path).
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
/// use brute::protocol::weblogic::execute_path;
///
/// assert_eq!(execute_path("console"), "/console/console.portal");
/// ```
pub fn execute_path(command: &str) -> String {
    let trimmed = command.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "console" | "home" | "portal" => "/console/console.portal".to_string(),
        "server" | "servers" => {
            "/console/console.portal?_nfpb=true&_pageLabel=ServerTablePage".to_string()
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

async fn probe_login_page(ctx: &TargetContext) -> Option<String> {
    let client =
        build_http_basic_client(ctx.timeout(), ctx.url_scheme, ctx.target.proxy.as_ref()).ok()?;
    let url = api_url(
        ctx.url_scheme,
        &ctx.target_host,
        ctx.port(),
        "/console/login/LoginForm.jsp",
    );
    let response = client.get(&url).send().await.ok()?;
    if response.status().is_success() || response.status() == StatusCode::FORBIDDEN {
        Some("WebLogic".to_string())
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
        assert_eq!(execute_path("console"), "/console/console.portal");
    }

    #[test]
    fn classify_login_rejects_bounce_to_login_form() {
        assert!(classify_login(StatusCode::FOUND, "/console/login/LoginForm.jsp").is_err());
        assert!(classify_login(StatusCode::FOUND, "/console/console.portal").is_ok());
    }
}
