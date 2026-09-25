//! InfluxDB 1.x HTTP login and post-auth query (`-x`).
//!
//! Empty credentials probe `GET /query?q=SHOW DATABASES` without Authorization.
//! Non-empty credentials use HTTP Basic Auth.

use async_trait::async_trait;
use reqwest::StatusCode;

use crate::cli::HttpUrlScheme;
use crate::protocol::http::{build_http_basic_client, normalize_path};

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

/// InfluxDB attempt errors split auth failures from post-auth command failures.
type InfluxAttemptError = crate::protocol::http_attempt::HttpAttemptFailure;

/// InfluxDB module configuration.
#[derive(Debug, Clone)]
pub struct InfluxDbModule;

impl InfluxDbModule {
    /// Creates a new InfluxDB module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`InfluxDbModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::influxdb::InfluxDbModule;
    ///
    /// let _module = InfluxDbModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for InfluxDbModule {
    fn name(&self) -> &'static str {
        "influxdb"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_ping(ctx)).await {
            Ok(Some(())) => TargetProbe::Ready(Some("InfluxDB".to_string())),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        crate::protocol::http_attempt::run_http_attempt(
            ctx.timeout(),
            "influxdb",
            || success_message(is_unauthenticated(ctx)),
            attempt_once(ctx),
        )
        .await
    }
}

/// Runs one InfluxDB login or unauthorized probe, then optional `-x`.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, InfluxAttemptError> {
    let unauthenticated = is_unauthenticated(ctx);
    let client = build_http_basic_client(ctx.timeout(), ctx.url_scheme, ctx.target.proxy.as_ref())
        .map_err(|err| InfluxAttemptError::Transport(err.to_string()))?;
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let url = api_url(
        ctx.url_scheme,
        &ctx.target_host,
        port,
        "/query?q=SHOW%20DATABASES",
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
        .map_err(|err| InfluxAttemptError::Transport(err.to_string()))?;
    classify_status(response.status())?;
    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => execute_command(&client, ctx, command, unauthenticated, message).await,
        None => Ok(AttemptSuccess::new(message)),
    }
}

fn classify_status(status: StatusCode) -> Result<(), InfluxAttemptError> {
    super::http_auth::require_http_auth(
        status,
        super::http_auth::HttpForbiddenPolicy::AuthFailure,
        || InfluxAttemptError::Auth("invalid username or password".to_string()),
        |status| InfluxAttemptError::Transport(format!("unexpected HTTP status: {status}")),
    )
}

async fn execute_command(
    client: &reqwest::Client,
    ctx: &AttemptContext,
    command: &str,
    unauthenticated: bool,
    success_message: &str,
) -> Result<AttemptSuccess, InfluxAttemptError> {
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
        .map_err(|err| InfluxAttemptError::Command(err.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| InfluxAttemptError::Command(err.to_string()))?;
    if status.is_success() {
        Ok(AttemptSuccess::with_command(
            success_message,
            trim_body(&body),
        ))
    } else {
        Err(InfluxAttemptError::Command(format!(
            "HTTP {status}: {}",
            trim_body(&body)
        )))
    }
}

/// Builds `http://host:port{path}` for InfluxDB HTTP.
///
/// # Parameters
///
/// - `scheme`: URL scheme (`http` or `https`).
/// - `host`: Target host.
/// - `port`: Service port.
/// - `path`: Absolute path or query.
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
/// use brute::protocol::influxdb::api_url;
///
/// assert_eq!(
///     api_url(brute::cli::HttpUrlScheme::Http, "10.0.0.5", 8086, "/ping"),
///     "http://10.0.0.5:8086/ping"
/// );
/// ```
pub fn api_url(scheme: HttpUrlScheme, host: &str, port: u16, path: &str) -> String {
    super::http::build_http_basic_url(scheme, host, port, path)
}

/// Normalizes `-x` text into an InfluxDB HTTP path.
///
/// # Parameters
///
/// - `command`: CLI `-x` value (`dbs`, `ping`, or InfluxQL).
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
/// use brute::protocol::influxdb::execute_path;
///
/// assert_eq!(execute_path("dbs"), "/query?q=SHOW%20DATABASES");
/// assert_eq!(execute_path("ping"), "/ping");
/// ```
pub fn execute_path(command: &str) -> String {
    let trimmed = command.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "dbs" | "databases" => "/query?q=SHOW%20DATABASES".to_string(),
        "ping" => "/ping".to_string(),
        "users" => "/query?q=SHOW%20USERS".to_string(),
        _ if trimmed.starts_with('/') => normalize_path(trimmed),
        _ => format!("/query?q={}", trimmed.replace(' ', "%20")),
    }
}

async fn probe_ping(ctx: &TargetContext) -> Option<()> {
    let client =
        build_http_basic_client(ctx.timeout(), ctx.url_scheme, ctx.target.proxy.as_ref()).ok()?;
    let url = api_url(ctx.url_scheme, &ctx.target_host, ctx.port(), "/ping");
    let response = client.get(&url).send().await.ok()?;
    response.status().is_success().then_some(())
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
        "InfluxDB unauthorized access!"
    } else {
        "InfluxDB access!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_path_maps_shorthand() {
        assert_eq!(execute_path("dbs"), "/query?q=SHOW%20DATABASES");
        assert_eq!(execute_path("SHOW USERS"), "/query?q=SHOW%20USERS");
    }
}
