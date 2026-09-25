//! Kibana login, unauthorized status probe, and post-auth HTTP API (`-x`).
//!
//! Empty credentials probe `GET /api/status` without cookies. Non-empty
//! credentials POST `/internal/security/login` (Kibana 7.10+/8).

use async_trait::async_trait;
use reqwest::{StatusCode, header};

use crate::cli::HttpUrlScheme;
use crate::protocol::http::build_http_basic_client;

use super::{AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext};

/// Kibana module configuration.
#[derive(Debug, Clone)]
pub struct KibanaModule;

impl KibanaModule {
    /// Creates a new Kibana module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`KibanaModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::kibana::KibanaModule;
    ///
    /// let _module = KibanaModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for KibanaModule {
    fn name(&self) -> &'static str {
        "kibana"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> Option<String> {
        match tokio::time::timeout(ctx.timeout(), probe_status(ctx)).await {
            Ok(Some(message)) => Some(message),
            _ => None,
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        crate::protocol::http_attempt::run_http_attempt(
            ctx.timeout(),
            "kibana",
            String::new,
            async {
                attempt_once(ctx).await.map_err(|err| {
                    if is_auth_error(&err) {
                        crate::protocol::http_attempt::HttpAttemptFailure::Auth(err)
                    } else {
                        crate::protocol::http_attempt::HttpAttemptFailure::Transport(err)
                    }
                })
            },
        )
        .await
    }
}

/// Runs one Kibana login or anonymous status probe, then optional `-x`.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, String> {
    let unauthenticated = ctx.credential.username.as_deref().unwrap_or("").is_empty()
        && ctx.credential.password.as_deref().unwrap_or("").is_empty();
    let client = build_http_basic_client(ctx.timeout(), ctx.url_scheme, ctx.target.proxy.as_ref())
        .map_err(|err| err.to_string())?;
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let cookie = if unauthenticated {
        let url = status_url(ctx.url_scheme, &ctx.target_host, port);
        let response = client
            .get(&url)
            .header("kbn-xsrf", "true")
            .send()
            .await
            .map_err(|err| err.to_string())?;
        if super::http_auth::classify_http_auth_status(
            response.status(),
            super::http_auth::HttpForbiddenPolicy::AuthFailure,
        ) == super::http_auth::HttpAuthDecision::AuthFailure
        {
            return Err(format!("auth:anonymous status {}", response.status()));
        }
        if !response.status().is_success() {
            return Err(format!("kibana status probe failed: {}", response.status()));
        }
        None
    } else {
        Some(login(&client, &ctx.target_host, port, ctx).await?)
    };
    let message = if unauthenticated {
        "Kibana unauthorized access!"
    } else {
        "Kibana access!"
    };
    if let Some(command) = ctx.execute.as_deref() {
        let path = execute_path(command);
        let url = super::http::build_http_basic_url(ctx.url_scheme, &ctx.target_host, port, &path);
        let mut req = client.get(&url).header("kbn-xsrf", "true");
        if let Some(cookie) = cookie.as_deref() {
            req = req.header(header::COOKIE, cookie);
        }
        let response = req.send().await.map_err(|err| err.to_string())?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if status.is_success() {
            return Ok(AttemptSuccess::with_command(message, trim_body(&body)));
        }
        return Ok(AttemptSuccess::with_command_error(
            message,
            format!("kibana command failed: {status} {}", trim_body(&body)),
        ));
    }
    Ok(AttemptSuccess::new(message))
}

async fn login(
    client: &reqwest::Client,
    host: &str,
    port: u16,
    ctx: &AttemptContext,
) -> Result<String, String> {
    let user = ctx.credential.username.as_deref().unwrap_or("");
    let pass = ctx.credential.password.as_deref().unwrap_or("");
    let url =
        super::http::build_http_basic_url(ctx.url_scheme, host, port, "/internal/security/login");
    let body = serde_json::json!({
        "providerType": "basic",
        "providerName": "basic",
        "currentURL": "/login",
        "params": {"username": user, "password": pass}
    });
    let response = client
        .post(&url)
        .header("kbn-xsrf", "true")
        .header("x-elastic-internal-origin", "Kibana")
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|err| err.to_string())?;
    let status = response.status();
    let cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or(value).to_string())
        .collect::<Vec<_>>()
        .join("; ");
    if super::http_auth::classify_http_auth_status(
        status,
        super::http_auth::HttpForbiddenPolicy::AuthFailure,
    ) == super::http_auth::HttpAuthDecision::AuthFailure
    {
        return Err(format!("auth:login {status}"));
    }
    if !status.is_success() {
        return Err(format!("kibana login failed: {status}"));
    }
    Ok(cookie)
}

/// Builds the Kibana status URL.
///
/// # Parameters
///
/// - `scheme`: URL scheme (`http` or `https`).
/// - `host`: Target host.
/// - `port`: Service port.
///
/// # Returns
///
/// `http://host:port/api/status`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::kibana::status_url;
///
/// assert_eq!(status_url(brute::cli::HttpUrlScheme::Http, "10.0.0.5", 5601), "http://10.0.0.5:5601/api/status");
/// ```
pub fn status_url(scheme: HttpUrlScheme, host: &str, port: u16) -> String {
    super::http::build_http_basic_url(scheme, host, port, "/api/status")
}

/// Normalizes `-x` text into an absolute Kibana API path.
///
/// # Parameters
///
/// - `command`: CLI `-x` value.
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
/// use brute::protocol::kibana::execute_path;
///
/// assert_eq!(execute_path("status"), "/api/status");
/// assert_eq!(execute_path("/api/status"), "/api/status");
/// ```
pub fn execute_path(command: &str) -> String {
    let trimmed = command.trim();
    match trimmed {
        "" | "status" => "/api/status".to_string(),
        path if path.starts_with('/') => path.to_string(),
        other => format!("/{other}"),
    }
}

/// Classifies Kibana login failures versus transport errors.
///
/// # Parameters
///
/// - `err`: HTTP error text.
///
/// # Returns
///
/// `true` for 401/403 / login wording.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::kibana::is_auth_error;
///
/// assert!(is_auth_error("auth:login 401 Unauthorized"));
/// assert!(!is_auth_error("connection refused"));
/// ```
pub fn is_auth_error(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("auth:")
        || lower.contains("401")
        || lower.contains("403")
        || lower.contains("unauthorized")
}

async fn probe_status(ctx: &TargetContext) -> Option<String> {
    let client =
        build_http_basic_client(ctx.timeout(), ctx.url_scheme, ctx.target.proxy.as_ref()).ok()?;
    let url = status_url(ctx.url_scheme, &ctx.target_host, ctx.port());
    let response = client
        .get(&url)
        .header("kbn-xsrf", "true")
        .send()
        .await
        .ok()?;
    if response.status().is_success() || response.status() == StatusCode::UNAUTHORIZED {
        Some("Kibana".to_string())
    } else {
        None
    }
}

fn trim_body(body: &str) -> String {
    const MAX: usize = 512;
    let compact = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.len() <= MAX {
        compact
    } else {
        format!("{}…", &compact[..MAX])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_path_normalizes_status() {
        assert_eq!(execute_path("status"), "/api/status");
        assert_eq!(execute_path("/api/status"), "/api/status");
    }

    #[test]
    fn is_auth_error_detects_401() {
        assert!(is_auth_error("auth:login 401 Unauthorized"));
        assert!(!is_auth_error("connection refused"));
    }
}
