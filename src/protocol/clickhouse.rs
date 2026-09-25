//! ClickHouse HTTP login and post-auth SQL (`-x`).
//!
//! Empty username and password probe `GET /ping` without Authorization.
//! Non-empty credentials use HTTP Basic Auth against `GET /?query=SELECT 1`.

use async_trait::async_trait;
use reqwest::StatusCode;

use crate::cli::HttpUrlScheme;

use super::http_attempt::{
    credentials_absent, http_service_url, http_target_url, open_attempt_client, target_http_client,
    with_basic_auth,
};
use super::{AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext};

/// ClickHouse attempt errors split auth failures from post-auth command failures.
type ChAttemptError = crate::protocol::http_attempt::HttpAttemptFailure;

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

    async fn probe_target(&self, ctx: &TargetContext) -> Option<String> {
        match tokio::time::timeout(ctx.timeout(), probe_ping(ctx)).await {
            Ok(Some(())) => Some("ClickHouse".to_string()),
            _ => None,
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        crate::protocol::http_attempt::run_http_attempt(
            ctx.timeout(),
            "clickhouse",
            || success_message(credentials_absent(ctx)),
            attempt_once(ctx),
        )
        .await
    }
}

/// Runs one ClickHouse login or unauthorized probe, then optional `-x` SQL.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, ChAttemptError> {
    let unauthenticated = credentials_absent(ctx);
    let client = open_attempt_client(ctx)?;
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let url = query_url(ctx.url_scheme, &ctx.target_host, port, "SELECT 1");
    let mut request = client.get(&url);
    request = with_basic_auth(request, ctx);
    let response = request
        .send()
        .await
        .map_err(|err| ChAttemptError::Transport(err.to_string()))?;
    classify_status(response.status(), unauthenticated)?;
    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => execute_sql(&client, ctx, command, message).await,
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
    success_message: &str,
) -> Result<AttemptSuccess, ChAttemptError> {
    let sql = execute_sql_text(command);
    let url = query_url(
        ctx.url_scheme,
        &ctx.target_host,
        ctx.target.port.unwrap_or(ctx.protocol.default_port()),
        &sql,
    );
    let mut request = client.get(&url);
    request = with_basic_auth(request, ctx);
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

/// Builds a ClickHouse HTTP query URL.
///
/// # Parameters
///
/// - `scheme`: URL scheme (`http` or `https`).
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
/// assert!(query_url(brute::cli::HttpUrlScheme::Http, "10.0.0.5", 8123, "SELECT 1").contains("query=SELECT"));
/// ```
pub fn query_url(scheme: HttpUrlScheme, host: &str, port: u16, sql: &str) -> String {
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
    let base = http_service_url(scheme, host, port, "/");
    format!("{base}?query={encoded}")
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
    let client = target_http_client(ctx).ok()?;
    let url = http_target_url(ctx, "/ping");
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
