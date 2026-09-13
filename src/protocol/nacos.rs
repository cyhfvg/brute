//! Nacos login, unauthorized probe, and post-auth HTTP API (`-x`).
//!
//! Empty credentials probe `GET /nacos/v1/console/health/readiness` without a
//! token. Non-empty credentials POST `/nacos/v1/auth/login`.

use async_trait::async_trait;
use reqwest::StatusCode;
use reqwest::header;
use serde_json::Value;

use crate::cli::HttpUrlScheme;
use crate::protocol::http::{build_http_basic_client, normalize_path};

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

/// Nacos attempt errors split auth failures from post-auth command failures.
#[derive(Debug)]
enum NacosAttemptError {
    Auth(String),
    Transport(String),
    Command(String),
}

/// Nacos module configuration.
#[derive(Debug, Clone)]
pub struct NacosModule;

impl NacosModule {
    /// Creates a new Nacos module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`NacosModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::nacos::NacosModule;
    ///
    /// let _module = NacosModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for NacosModule {
    fn name(&self) -> &'static str {
        "nacos"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_health(ctx)).await {
            Ok(Some(message)) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        match tokio::time::timeout(ctx.timeout(), attempt_once(ctx)).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(NacosAttemptError::Auth(err))) => {
                AttemptOutcome::Failure(format!("nacos auth failed: {err}"))
            }
            Ok(Err(NacosAttemptError::Transport(err))) => {
                AttemptOutcome::Error(format!("nacos transport failed: {err}"))
            }
            Ok(Err(NacosAttemptError::Command(err))) => {
                let message = success_message(is_unauthenticated(ctx));
                AttemptOutcome::Success(AttemptSuccess::with_command_error(
                    message,
                    format!("nacos command execution failed: {err}"),
                ))
            }
            Err(_) => AttemptOutcome::Error("attempt timed out".to_string()),
        }
    }
}

/// Runs one Nacos login or anonymous probe, then optional `-x`.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, NacosAttemptError> {
    let unauthenticated = is_unauthenticated(ctx);
    let client = build_http_basic_client(
        ctx.timeout(),
        HttpUrlScheme::Http,
        ctx.target.proxy.as_ref(),
    )
    .map_err(|err| NacosAttemptError::Transport(err.to_string()))?;
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let token = if unauthenticated {
        let url = api_url(
            &ctx.target_host,
            port,
            "/nacos/v1/cs/configs?search=accurate&dataId=&group=&pageNo=1&pageSize=1",
        );
        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|err| NacosAttemptError::Transport(err.to_string()))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|err| NacosAttemptError::Transport(err.to_string()))?;
        if is_nacos_auth_error(status, &body) {
            return Err(NacosAttemptError::Auth(
                "anonymous access is disabled".to_string(),
            ));
        }
        if !status.is_success() {
            return Err(NacosAttemptError::Transport(format!(
                "unexpected HTTP status: {status}"
            )));
        }
        None
    } else {
        let url = api_url(&ctx.target_host, port, "/nacos/v1/auth/login");
        let form = format!(
            "username={}&password={}",
            encode_form_component(ctx.credential.username.as_deref().unwrap_or("")),
            encode_form_component(ctx.credential.password.as_deref().unwrap_or("")),
        );
        let response = client
            .post(&url)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form)
            .send()
            .await
            .map_err(|err| NacosAttemptError::Transport(err.to_string()))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|err| NacosAttemptError::Transport(err.to_string()))?;
        if is_nacos_auth_error(status, &body) || status.is_server_error() {
            return Err(NacosAttemptError::Auth(
                "invalid username or password".to_string(),
            ));
        }
        if !status.is_success() {
            return Err(NacosAttemptError::Transport(format!(
                "unexpected HTTP status: {status}: {}",
                trim_body(&body)
            )));
        }
        Some(parse_access_token(&body).ok_or_else(|| {
            NacosAttemptError::Auth("login succeeded without accessToken".to_string())
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
) -> Result<AttemptSuccess, NacosAttemptError> {
    let path = execute_path(command);
    let mut url = api_url(
        &ctx.target_host,
        ctx.target.port.unwrap_or(ctx.protocol.default_port()),
        &path,
    );
    if let Some(token) = token {
        let sep = if url.contains('?') { '&' } else { '?' };
        url.push_str(&format!(
            "{sep}accessToken={}",
            encode_form_component(token)
        ));
    }
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|err| NacosAttemptError::Command(err.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| NacosAttemptError::Command(err.to_string()))?;
    if status.is_success() {
        Ok(AttemptSuccess::with_command(
            success_message,
            trim_body(&body),
        ))
    } else {
        Err(NacosAttemptError::Command(format!(
            "HTTP {status}: {}",
            trim_body(&body)
        )))
    }
}

/// Builds `http://host:port{path}` for Nacos HTTP.
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
/// use brute::protocol::nacos::api_url;
///
/// assert_eq!(
///     api_url("10.0.0.5", 8848, "/nacos/v1/auth/login"),
///     "http://10.0.0.5:8848/nacos/v1/auth/login"
/// );
/// ```
pub fn api_url(host: &str, port: u16, path: &str) -> String {
    format!("http://{host}:{port}{path}")
}

/// Normalizes `-x` text into a Nacos API path.
///
/// # Parameters
///
/// - `command`: CLI `-x` value (`namespaces`, `configs`, or a path).
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
/// use brute::protocol::nacos::execute_path;
///
/// assert_eq!(execute_path("namespaces"), "/nacos/v1/console/namespaces");
/// ```
pub fn execute_path(command: &str) -> String {
    let trimmed = command.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "namespaces" | "ns" => "/nacos/v1/console/namespaces".to_string(),
        "configs" => {
            "/nacos/v1/cs/configs?search=accurate&dataId=&group=&pageNo=1&pageSize=10".to_string()
        }
        other => normalize_path(other),
    }
}

/// Extracts `accessToken` from a Nacos login JSON body.
///
/// # Parameters
///
/// - `body`: `/nacos/v1/auth/login` response.
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
/// use brute::protocol::nacos::parse_access_token;
///
/// assert_eq!(
///     parse_access_token(r#"{"accessToken":"abc"}"#).as_deref(),
///     Some("abc")
/// );
/// ```
pub fn parse_access_token(body: &str) -> Option<String> {
    let value: Value = serde_json::from_str(body).ok()?;
    value
        .get("accessToken")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
}

/// Returns whether a Nacos HTTP response indicates an authentication failure.
///
/// # Parameters
///
/// - `status`: HTTP status.
/// - `body`: Response body.
///
/// # Returns
///
/// `true` for auth failures.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::nacos::is_nacos_auth_error;
/// use reqwest::StatusCode;
///
/// assert!(is_nacos_auth_error(StatusCode::FORBIDDEN, "user not found!"));
/// assert!(is_nacos_auth_error(
///     StatusCode::INTERNAL_SERVER_ERROR,
///     "caused: User nacos not found;"
/// ));
/// ```
pub fn is_nacos_auth_error(status: StatusCode, body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return true;
    }
    lower.contains("user not found")
        || lower.contains("unknown user")
        || lower.contains("invalid username")
        || lower.contains("access denied")
        || (lower.contains("auth") && lower.contains("fail"))
}

async fn probe_health(ctx: &TargetContext) -> Option<String> {
    let client = build_http_basic_client(
        ctx.timeout(),
        HttpUrlScheme::Http,
        ctx.target.proxy.as_ref(),
    )
    .ok()?;
    let url = api_url(
        &ctx.target_host,
        ctx.port(),
        "/nacos/v1/console/health/readiness",
    );
    let response = client.get(&url).send().await.ok()?;
    if response.status().is_success()
        || response.status() == StatusCode::UNAUTHORIZED
        || response.status() == StatusCode::FORBIDDEN
    {
        Some("Nacos".to_string())
    } else {
        None
    }
}

/// Percent-encodes a form or query component.
///
/// # Parameters
///
/// - `input`: Raw username, password, or token.
///
/// # Returns
///
/// Percent-encoded ASCII string.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::nacos::encode_form_component;
///
/// assert_eq!(encode_form_component("a b"), "a%20b");
/// ```
pub fn encode_form_component(input: &str) -> String {
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
        "Nacos unauthorized access!"
    } else {
        "Nacos access!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_path_maps_shorthand() {
        assert_eq!(execute_path("namespaces"), "/nacos/v1/console/namespaces");
    }

    #[test]
    fn parse_access_token_reads_json() {
        assert_eq!(
            parse_access_token(r#"{"accessToken":"tok"}"#).as_deref(),
            Some("tok")
        );
    }
}
