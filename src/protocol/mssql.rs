//! Microsoft SQL Server login and post-auth SQL (`-x`).
//!
//! Empty username and password are treated as an unauthenticated probe and fail
//! unless the instance accepts them. Host:port clients use the shared TCP proxy bridge.

use async_trait::async_trait;
use tiberius::{AuthMethod, Client, Config};
use tokio::net::TcpStream;
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

/// MSSQL module configuration.
#[derive(Debug, Clone)]
pub struct MssqlModule;

impl MssqlModule {
    /// Creates a new MSSQL module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`MssqlModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::mssql::MssqlModule;
    ///
    /// let _module = MssqlModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for MssqlModule {
    fn name(&self) -> &'static str {
        "mssql"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_tcp(ctx)).await {
            Ok(true) => TargetProbe::Ready(Some("MSSQL TDS".to_string())),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        match tokio::time::timeout(ctx.timeout(), attempt_once(ctx)).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(err)) if is_auth_error(&err) => {
                AttemptOutcome::failure(format!("mssql auth failed: {err}"))
            }
            Ok(Err(err)) => AttemptOutcome::error(format!("mssql transport failed: {err}")),
            Err(_) => AttemptOutcome::error("attempt timed out".to_string()),
        }
    }
}

/// Runs one TDS login, then optional SQL.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, String> {
    let username = ctx.credential.username.as_deref().unwrap_or("");
    let password = ctx.credential.password.as_deref().unwrap_or("");
    let host = ctx.target_host.as_str();
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let endpoint =
        crate::proxy::resolve_tcp_endpoint(ctx.target.proxy.as_ref(), host, port).await?;
    let (connect_host, connect_port, _bridge) = endpoint;
    let mut config = Config::new();
    config.host(&connect_host);
    config.port(connect_port);
    config.authentication(AuthMethod::sql_server(username, password));
    config.trust_cert();
    let tcp = TcpStream::connect((connect_host.as_str(), connect_port))
        .await
        .map_err(|err| err.to_string())?;
    tcp.set_nodelay(true).map_err(|err| err.to_string())?;
    let mut client: Client<Compat<TcpStream>> = Client::connect(config, tcp.compat_write())
        .await
        .map_err(|err| err.to_string())?;
    let message = "MSSQL access!";
    if let Some(command) = ctx.execute.as_deref() {
        let output = run_sql(&mut client, command).await;
        let _ = client.close().await;
        return Ok(match output {
            Ok(text) => AttemptSuccess::with_command(message, text),
            Err(err) => AttemptSuccess::with_command_error(message, err),
        });
    }
    let _ = client.close().await;
    Ok(AttemptSuccess::new(message))
}

async fn run_sql(client: &mut Client<Compat<TcpStream>>, command: &str) -> Result<String, String> {
    let sql = command.trim().trim_end_matches(';');
    if sql.is_empty() {
        return Ok("(empty query)".to_string());
    }
    let rows = client
        .simple_query(sql)
        .await
        .map_err(|err| err.to_string())?
        .into_first_result()
        .await
        .map_err(|err| err.to_string())?;
    let mut lines = Vec::new();
    for row in rows.iter().take(10) {
        let mut cols = Vec::new();
        for i in 0..row.columns().len() {
            let value = row
                .try_get::<&str, _>(i)
                .ok()
                .flatten()
                .map(ToOwned::to_owned)
                .or_else(|| {
                    row.try_get::<i32, _>(i)
                        .ok()
                        .flatten()
                        .map(|v| v.to_string())
                })
                .or_else(|| {
                    row.try_get::<i64, _>(i)
                        .ok()
                        .flatten()
                        .map(|v| v.to_string())
                })
                .unwrap_or_else(|| "NULL".to_string());
            cols.push(value);
        }
        lines.push(cols.join(" | "));
    }
    if lines.is_empty() {
        Ok("(no rows)".to_string())
    } else {
        Ok(lines.join("\n"))
    }
}

/// Classifies tiberius login failures versus transport errors.
///
/// # Parameters
///
/// - `err`: Driver error text.
///
/// # Returns
///
/// `true` for login/password wording.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::mssql::is_auth_error;
///
/// assert!(is_auth_error("Login failed for user 'sa'"));
/// assert!(!is_auth_error("connection refused"));
/// ```
pub fn is_auth_error(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("login failed")
        || lower.contains("login failed for user")
        || lower.contains("password")
        || lower.contains("18456")
        || lower.contains("authentication")
}

async fn probe_tcp(ctx: &TargetContext) -> bool {
    tokio::net::TcpStream::connect((ctx.target_host.as_str(), ctx.port()))
        .await
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_auth_error_detects_login_failed() {
        assert!(is_auth_error("Login failed for user 'sa'."));
        assert!(is_auth_error("error 18456"));
        assert!(!is_auth_error("connection refused"));
    }
}
