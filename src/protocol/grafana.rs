//! Grafana login, anonymous org probe, and post-auth HTTP API (`-x`).
//!
//! Empty credentials probe `GET /api/org` without a session. Non-empty
//! credentials POST `/login` and reuse the session cookie.

use async_trait::async_trait;
use reqwest::header;

use crate::cli::HttpUrlScheme;
use crate::protocol::http::{build_http_basic_client, normalize_path};

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

/// Grafana module configuration.
#[derive(Debug, Clone)]
pub struct GrafanaModule;

impl GrafanaModule {
    /// Creates a new Grafana module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`GrafanaModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::grafana::GrafanaModule;
    ///
    /// let _module = GrafanaModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for GrafanaModule {
    fn name(&self) -> &'static str {
        "grafana"
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
            Ok(Err(err)) if err.starts_with("auth:") => AttemptOutcome::Failure(format!(
                "grafana auth failed: {}",
                err.trim_start_matches("auth:")
            )),
            Ok(Err(err)) => AttemptOutcome::Error(format!("grafana transport failed: {err}")),
            Err(_) => AttemptOutcome::Error("attempt timed out".to_string()),
        }
    }
}

/// Runs one Grafana login or anonymous org probe, then optional `-x`.
///
/// # Parameters
///
/// - `ctx`: Target, credential, timeout, proxy, and optional execute path.
///
/// # Returns
///
/// [`AttemptSuccess`] when login or anonymous access is accepted.
///
/// # Errors
///
/// Returns `auth:...` on 401/403 and a transport string otherwise.
///
/// # Examples
///
/// ```ignore
/// let success = attempt_once(&ctx).await?;
/// ```
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, String> {
    let unauthenticated = is_unauthenticated(ctx);
    let client = build_http_basic_client(ctx.timeout(), ctx.url_scheme, ctx.target.proxy.as_ref())
        .map_err(|err| err.to_string())?;
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let cookie = if unauthenticated {
        let url = api_url(ctx.url_scheme, &ctx.target_host, port, "/api/org");
        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|err| err.to_string())?;
        if super::http_auth::classify_http_auth_status(
            response.status(),
            super::http_auth::HttpForbiddenPolicy::AuthFailure,
        ) == super::http_auth::HttpAuthDecision::AuthFailure
        {
            return Err(format!("auth:anonymous org {}", response.status()));
        }
        if !response.status().is_success() {
            return Err(format!("grafana org probe failed: {}", response.status()));
        }
        None
    } else {
        Some(login(&client, &ctx.target_host, port, ctx).await?)
    };
    let message = success_message(unauthenticated);
    if let Some(command) = ctx.execute.as_deref() {
        let path = execute_path(command);
        let url = api_url(ctx.url_scheme, &ctx.target_host, port, &path);
        let mut req = client.get(&url);
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
            format!("grafana command failed: {status} {}", trim_body(&body)),
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
    let url = api_url(ctx.url_scheme, host, port, "/login");
    let body = serde_json::json!({ "user": user, "password": pass });
    let response = client
        .post(&url)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|err| err.to_string())?;
    let status = response.status();
    let cookie = cookie_header(response.headers());
    if super::http_auth::classify_http_auth_status(
        status,
        super::http_auth::HttpForbiddenPolicy::AuthFailure,
    ) == super::http_auth::HttpAuthDecision::AuthFailure
    {
        return Err(format!("auth:login {status}"));
    }
    if !status.is_success() {
        return Err(format!("grafana login failed: {status}"));
    }
    Ok(cookie)
}

fn cookie_header(headers: &header::HeaderMap) -> String {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or(value).to_string())
        .collect::<Vec<_>>()
        .join("; ")
}

/// Builds `http://host:port{path}` for Grafana HTTP.
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
/// use brute::protocol::grafana::api_url;
///
/// assert_eq!(
///     api_url(brute::cli::HttpUrlScheme::Http, "10.0.0.5", 3000, "/api/org"),
///     "http://10.0.0.5:3000/api/org"
/// );
/// ```
pub fn api_url(scheme: HttpUrlScheme, host: &str, port: u16, path: &str) -> String {
    super::http::build_http_basic_url(scheme, host, port, path)
}

/// Normalizes `-x` text into a Grafana API path.
///
/// # Parameters
///
/// - `command`: CLI `-x` value (`org`, `datasources`, `health`, or a path).
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
/// use brute::protocol::grafana::execute_path;
///
/// assert_eq!(execute_path("org"), "/api/org");
/// assert_eq!(execute_path("/api/health"), "/api/health");
/// ```
pub fn execute_path(command: &str) -> String {
    let trimmed = command.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "org" => "/api/org".to_string(),
        "datasources" | "ds" => "/api/datasources".to_string(),
        "health" => "/api/health".to_string(),
        "users" => "/api/org/users".to_string(),
        other => normalize_path(other),
    }
}

/// Extracts `Grafana <version>` from `/api/health` JSON.
///
/// # Parameters
///
/// - `body`: Health response body.
///
/// # Returns
///
/// Banner such as `Grafana 11.1.0`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::grafana::parse_health_banner;
///
/// let body = r#"{"commit":"abc","database":"ok","version":"11.1.0"}"#;
/// assert_eq!(parse_health_banner(body).as_deref(), Some("Grafana 11.1.0"));
/// ```
pub fn parse_health_banner(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let version = value.get("version").and_then(serde_json::Value::as_str)?;
    if version.is_empty() {
        None
    } else {
        Some(format!("Grafana {version}"))
    }
}

async fn probe_health(ctx: &TargetContext) -> Option<String> {
    let client =
        build_http_basic_client(ctx.timeout(), ctx.url_scheme, ctx.target.proxy.as_ref()).ok()?;
    let url = api_url(ctx.url_scheme, &ctx.target_host, ctx.port(), "/api/health");
    let response = client.get(&url).send().await.ok()?;
    let status = response.status();
    let body = response.text().await.ok()?;
    if let Some(banner) = parse_health_banner(&body) {
        return Some(banner);
    }
    if status.is_success() {
        Some("Grafana".to_string())
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
        "Grafana unauthorized access!"
    } else {
        "Grafana access!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_path_maps_shorthand() {
        assert_eq!(execute_path("org"), "/api/org");
        assert_eq!(execute_path("datasources"), "/api/datasources");
        assert_eq!(execute_path("/api/health"), "/api/health");
    }

    #[test]
    fn parse_health_banner_reads_version() {
        let body = r#"{"commit":"abc","database":"ok","version":"11.1.0"}"#;
        assert_eq!(parse_health_banner(body).as_deref(), Some("Grafana 11.1.0"));
        assert_eq!(parse_health_banner("not-json"), None);
    }
}
