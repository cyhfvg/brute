//! InfluxDB 1.x HTTP login and post-auth query (`-x`).
//!
//! Empty credentials probe `GET /query?q=SHOW DATABASES` without Authorization.
//! Non-empty credentials use HTTP Basic Auth.

use async_trait::async_trait;

use crate::protocol::http::normalize_path;

use super::http_attempt::{
    classify_basic_status, credentials_absent, http_attempt_url, http_target_url,
    open_attempt_client, target_http_client, with_basic_auth,
};
use super::http_auth::HttpForbiddenPolicy;
use super::{AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext};

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

    async fn probe_target(&self, ctx: &TargetContext) -> Option<String> {
        match tokio::time::timeout(ctx.timeout(), probe_ping(ctx)).await {
            Ok(Some(())) => Some("InfluxDB".to_string()),
            _ => None,
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        crate::protocol::http_attempt::run_http_attempt(
            ctx.timeout(),
            "influxdb",
            || success_message(credentials_absent(ctx)),
            attempt_once(ctx),
        )
        .await
    }
}

/// Runs one InfluxDB login or unauthorized probe, then optional `-x`.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, InfluxAttemptError> {
    let unauthenticated = credentials_absent(ctx);
    let client = open_attempt_client(ctx)?;
    let url = http_attempt_url(ctx, "/query?q=SHOW%20DATABASES");
    let mut request = client.get(&url);
    request = with_basic_auth(request, ctx);
    let response = request
        .send()
        .await
        .map_err(|err| InfluxAttemptError::Transport(err.to_string()))?;
    classify_basic_status(response.status(), HttpForbiddenPolicy::AuthFailure)?;
    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => execute_command(&client, ctx, command, message).await,
        None => Ok(AttemptSuccess::new(message)),
    }
}

async fn execute_command(
    client: &reqwest::Client,
    ctx: &AttemptContext,
    command: &str,
    success_message: &str,
) -> Result<AttemptSuccess, InfluxAttemptError> {
    let path = execute_path(command);
    let url = http_attempt_url(ctx, &path);
    let mut request = client.get(&url);
    request = with_basic_auth(request, ctx);
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
