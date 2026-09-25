//! etcd v3 HTTP login, unauthorized KV probe, and post-auth API (`-x`).
//!
//! Empty credentials POST `/v3/kv/range` without a token. Non-empty credentials
//! POST `/v3/auth/authenticate` then reuse the token.

use async_trait::async_trait;
use reqwest::{StatusCode, header};

use crate::cli::HttpUrlScheme;
use crate::protocol::http::normalize_path;

use super::http_attempt::{
    attempt_http_client, credentials_absent, http_attempt_url, http_service_url, http_target_url,
    target_http_client,
};
use super::{AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext};

/// etcd module configuration.
#[derive(Debug, Clone)]
pub struct EtcdModule;

impl EtcdModule {
    /// Creates a new etcd module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`EtcdModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::etcd::EtcdModule;
    ///
    /// let _module = EtcdModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for EtcdModule {
    fn name(&self) -> &'static str {
        "etcd"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> Option<String> {
        match tokio::time::timeout(ctx.timeout(), probe_version(ctx)).await {
            Ok(Some(message)) => Some(message),
            _ => None,
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        crate::protocol::http_attempt::run_http_attempt(ctx.timeout(), "etcd", String::new, async {
            attempt_once(ctx)
                .await
                .map_err(crate::protocol::http_attempt::classify_auth_prefix)
        })
        .await
    }
}

/// Runs one etcd login or unauthorized KV probe, then optional `-x`.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, String> {
    let unauthenticated = credentials_absent(ctx);
    let client = attempt_http_client(ctx).map_err(|err| err.to_string())?;
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let token = if unauthenticated {
        kv_range(&client, ctx.url_scheme, &ctx.target_host, port, None).await?;
        None
    } else {
        Some(authenticate(&client, &ctx.target_host, port, ctx).await?)
    };
    let message = success_message(unauthenticated);
    if let Some(command) = ctx.execute.as_deref() {
        let path = execute_path(command);
        let url = http_attempt_url(ctx, &path);
        let mut req = if path.contains("/v3/") {
            client
                .post(&url)
                .header(header::CONTENT_TYPE, "application/json")
                .body("{}")
        } else {
            client.get(&url)
        };
        if let Some(token) = token.as_deref() {
            req = req.header(header::AUTHORIZATION, token);
        }
        let response = req.send().await.map_err(|err| err.to_string())?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if status.is_success() && !is_etcd_error(&body) {
            return Ok(AttemptSuccess::with_command(message, trim_body(&body)));
        }
        return Ok(AttemptSuccess::with_command_error(
            message,
            format!("etcd command failed: {status} {}", trim_body(&body)),
        ));
    }
    Ok(AttemptSuccess::new(message))
}

async fn authenticate(
    client: &reqwest::Client,
    host: &str,
    port: u16,
    ctx: &AttemptContext,
) -> Result<String, String> {
    let url = http_service_url(ctx.url_scheme, host, port, "/v3/auth/authenticate");
    let body = serde_json::json!({
        "name": ctx.credential.username.as_deref().unwrap_or(""),
        "password": ctx.credential.password.as_deref().unwrap_or(""),
    });
    let response = client
        .post(&url)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|err| err.to_string())?;
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if is_etcd_auth_error(&text) || status == StatusCode::UNAUTHORIZED {
        return Err(format!("auth:{text}"));
    }
    if !status.is_success() {
        return Err(format!("auth:authenticate {status} {text}"));
    }
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|err| format!("auth:{err}"))?;
    value
        .get("token")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("auth:no token in {text}"))
}

/// Posts one etcd KV range request.
///
/// # Parameters
///
/// - `client`: HTTP client for this attempt.
/// - `scheme`: URL scheme from the attempt context.
/// - `host`: Target host.
/// - `port`: Service port.
/// - `token`: Optional authenticate token. `None` probes unauthorized access.
///
/// # Returns
///
/// `Ok(())` when the range request is accepted.
///
/// # Errors
///
/// Returns an `auth:` error for authentication failures and a status error otherwise.
///
/// # Examples
///
/// ```ignore
/// kv_range(&client, scheme, host, port, None).await?;
/// ```
async fn kv_range(
    client: &reqwest::Client,
    scheme: HttpUrlScheme,
    host: &str,
    port: u16,
    token: Option<&str>,
) -> Result<(), String> {
    let url = http_service_url(scheme, host, port, "/v3/kv/range");
    let mut req = client
        .post(&url)
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"key":"AA=="}"#);
    if let Some(token) = token {
        req = req.header(header::AUTHORIZATION, token);
    }
    let response = req.send().await.map_err(|err| err.to_string())?;
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if is_etcd_auth_error(&text) || status == StatusCode::UNAUTHORIZED {
        return Err(format!("auth:{text}"));
    }
    if !status.is_success() {
        return Err(format!("kv range {status} {text}"));
    }
    Ok(())
}

/// Normalizes `-x` text into an etcd HTTP path.
///
/// # Parameters
///
/// - `command`: CLI `-x` value (`version`, `range`, or a path).
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
/// use brute::protocol::etcd::execute_path;
///
/// assert_eq!(execute_path("version"), "/version");
/// assert_eq!(execute_path("range"), "/v3/kv/range");
/// ```
pub fn execute_path(command: &str) -> String {
    let trimmed = command.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "version" => "/version".to_string(),
        "range" | "kv" => "/v3/kv/range".to_string(),
        "auth" => "/v3/auth/status".to_string(),
        other => normalize_path(other),
    }
}

/// Extracts `etcd <version>` from `/version` JSON.
///
/// # Parameters
///
/// - `body`: `/version` response body.
///
/// # Returns
///
/// Banner such as `etcd 3.5.16`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::etcd::parse_version_banner;
///
/// let body = r#"{"etcdserver":"3.5.16","etcdcluster":"3.5.0"}"#;
/// assert_eq!(parse_version_banner(body).as_deref(), Some("etcd 3.5.16"));
/// ```
pub fn parse_version_banner(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let version = value
        .get("etcdserver")
        .and_then(serde_json::Value::as_str)?;
    if version.is_empty() {
        None
    } else {
        Some(format!("etcd {version}"))
    }
}

/// Returns whether etcd JSON indicates an authentication failure.
///
/// # Parameters
///
/// - `body`: Response body.
///
/// # Returns
///
/// `true` for auth-related error text.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::etcd::is_etcd_auth_error;
///
/// assert!(is_etcd_auth_error(r#"{"error":"etcdserver: authentication failed, invalid user ID or password"}"#));
/// assert!(!is_etcd_auth_error(r#"{"header":{}}"#));
/// ```
pub fn is_etcd_auth_error(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("authentication failed")
        || lower.contains("invalid auth token")
        || lower.contains("user doesn't exist")
        || lower.contains("permission denied")
        || lower.contains("user name is empty")
}

fn is_etcd_error(body: &str) -> bool {
    body.contains("\"error\"")
}

async fn probe_version(ctx: &TargetContext) -> Option<String> {
    let client = target_http_client(ctx).ok()?;
    let url = http_target_url(ctx, "/version");
    let response = client.get(&url).send().await.ok()?;
    let body = response.text().await.ok()?;
    parse_version_banner(&body).or(Some("etcd".to_string()))
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
        "etcd unauthorized access!"
    } else {
        "etcd access!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_path_maps_shorthand() {
        assert_eq!(execute_path("version"), "/version");
        assert_eq!(execute_path("range"), "/v3/kv/range");
    }

    #[test]
    fn parse_version_banner_reads_etcdserver() {
        let body = r#"{"etcdserver":"3.5.16","etcdcluster":"3.5.0"}"#;
        assert_eq!(parse_version_banner(body).as_deref(), Some("etcd 3.5.16"));
    }
}
