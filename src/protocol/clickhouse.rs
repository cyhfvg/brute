//! ClickHouse HTTP login and post-auth SQL (`-x`).
//!
//! Empty username and password probe `GET /ping` without Authorization.
//! Non-empty credentials use HTTP Basic Auth against `GET /?query=SELECT 1`.

use async_trait::async_trait;
use reqwest::StatusCode;

use crate::cli::HttpUrlScheme;
use crate::protocol::http::build_http_basic_client;

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

/// ClickHouse attempt errors split auth failures from post-auth command failures.
#[derive(Debug)]
enum ChAttemptError {
    Auth(String),
    Transport(String),
    Command(String),
}

/// ClickHouse module configuration.
#[derive(Debug, Clone)]
pub struct ClickHouseModule;

impl ClickHouseModule {
    /// Creates a new ClickHouse module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`ClickHouseModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::clickhouse::ClickHouseModule;
    ///
    /// let _module = ClickHouseModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for ClickHouseModule {
    fn name(&self) -> &'static str {
        "clickhouse"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_ping(ctx)).await {
            Ok(Some(())) => TargetProbe::Ready(Some("ClickHouse".to_string())),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        match tokio::time::timeout(ctx.timeout(), attempt_once(ctx)).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(ChAttemptError::Auth(err))) => {
                AttemptOutcome::Failure(format!("clickhouse auth failed: {err}"))
            }
            Ok(Err(ChAttemptError::Transport(err))) => {
                AttemptOutcome::Error(format!("clickhouse transport failed: {err}"))
            }
            Ok(Err(ChAttemptError::Command(err))) => {
                let message = success_message(is_unauthenticated(ctx));
                AttemptOutcome::Success(AttemptSuccess::with_command_error(
                    message,
                    format!("clickhouse command execution failed: {err}"),
                ))
            }
            Err(_) => AttemptOutcome::Error("attempt timed out".to_string()),
        }
    }
}

/// Runs one ClickHouse login or unauthorized probe, then optional `-x` SQL.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, ChAttemptError> {
    let unauthenticated = is_unauthenticated(ctx);
    let client = build_http_basic_client(
        ctx.timeout(),
        HttpUrlScheme::Http,
        ctx.target.proxy.as_ref(),
    )
    .map_err(|err| ChAttemptError::Transport(err.to_string()))?;
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let url = query_url(&ctx.target_host, port, "SELECT 1");
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
        .map_err(|err| ChAttemptError::Transport(err.to_string()))?;
    classify_status(response.status(), unauthenticated)?;
    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => execute_sql(&client, ctx, command, unauthenticated, message).await,
        None => Ok(AttemptSuccess::new(message)),
    }
}

fn classify_status(status: StatusCode, unauthenticated: bool) -> Result<(), ChAttemptError> {
    match super::http_auth::classify_http_auth_status(
        status,
        super::http_auth::HttpForbiddenPolicy::AuthFailure,
    ) {
        super::http_auth::HttpAuthDecision::Success => Ok(()),
        super::http_auth::HttpAuthDecision::AuthFailure => Err(ChAttemptError::Auth(
            "invalid username or password".to_string(),
        )),
        super::http_auth::HttpAuthDecision::Transport if unauthenticated => Err(
            ChAttemptError::Auth(format!("anonymous ping rejected: {status}")),
        ),
        super::http_auth::HttpAuthDecision::Transport => Err(ChAttemptError::Transport(format!(
            "unexpected HTTP status: {status}"
        ))),
    }
}

async fn execute_sql(
    client: &reqwest::Client,
    ctx: &AttemptContext,
    command: &str,
    unauthenticated: bool,
    success_message: &str,
) -> Result<AttemptSuccess, ChAttemptError> {
    let sql = execute_sql_text(command);
    let url = query_url(
        &ctx.target_host,
        ctx.target.port.unwrap_or(ctx.protocol.default_port()),
        &sql,
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
        .map_err(|err| ChAttemptError::Command(err.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| ChAttemptError::Command(err.to_string()))?;
    if status.is_success() {
        Ok(AttemptSuccess::with_command(
            success_message,
            trim_body(&body),
        ))
    } else {
        Err(ChAttemptError::Command(format!(
            "HTTP {status}: {}",
            trim_body(&body)
        )))
    }
}

/// Builds `http://host:port{path}` for ClickHouse HTTP.
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
/// use brute::protocol::clickhouse::api_url;
///
/// assert_eq!(api_url("10.0.0.5", 8123, "/ping"), "http://10.0.0.5:8123/ping");
/// ```
pub fn api_url(host: &str, port: u16, path: &str) -> String {
    format!("http://{host}:{port}{path}")
}

/// Builds a ClickHouse HTTP query URL.
///
/// # Parameters
///
/// - `host`: Target host.
/// - `port`: Service port.
/// - `sql`: SQL text.
///
/// # Returns
///
/// `http://host:port/?query=...` URL.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::clickhouse::query_url;
///
/// assert!(query_url("10.0.0.5", 8123, "SELECT 1").contains("query=SELECT"));
/// ```
pub fn query_url(host: &str, port: u16, sql: &str) -> String {
    let encoded: String = sql
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            b' ' => "+".to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect();
    format!("http://{host}:{port}/?query={encoded}")
}

/// Normalizes `-x` text into ClickHouse SQL.
///
/// # Parameters
///
/// - `command`: CLI `-x` value (`version`, `databases`, or SQL).
///
/// # Returns
///
/// SQL string.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::clickhouse::execute_sql_text;
///
/// assert_eq!(execute_sql_text("version"), "SELECT version()");
/// assert_eq!(execute_sql_text("SELECT 1"), "SELECT 1");
/// ```
pub fn execute_sql_text(command: &str) -> String {
    let trimmed = command.trim().trim_end_matches(';');
    match trimmed.to_ascii_lowercase().as_str() {
        "version" => "SELECT version()".to_string(),
        "databases" | "dbs" => "SHOW DATABASES".to_string(),
        "tables" => "SHOW TABLES".to_string(),
        _ => trimmed.to_string(),
    }
}

async fn probe_ping(ctx: &TargetContext) -> Option<()> {
    let client = build_http_basic_client(
        ctx.timeout(),
        HttpUrlScheme::Http,
        ctx.target.proxy.as_ref(),
    )
    .ok()?;
    let url = api_url(&ctx.target_host, ctx.port(), "/ping");
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
        "ClickHouse unauthorized access!"
    } else {
        "ClickHouse access!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_sql_text_maps_shorthand() {
        assert_eq!(execute_sql_text("version"), "SELECT version()");
        assert_eq!(execute_sql_text("SELECT 1;"), "SELECT 1");
    }
}
