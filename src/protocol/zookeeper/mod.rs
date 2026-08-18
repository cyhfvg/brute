//! ZooKeeper login, unauthorized access, and post-auth command execution.
//!
//! Empty username and password probe unauthenticated `getChildren("/")`.
//! Non-empty credentials use SASL DIGEST-MD5 (JAAS DigestLoginModule).

use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zookeeper_client::{Client, Error as ZkError, SaslOptions};

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};
use crate::proxy::ProxyTcpBridge;

mod command;

pub use command::{execute_zookeeper_command, join_zk_path, split_command};

/// ZooKeeper attempt errors split auth failures from post-auth command failures.
#[derive(Debug)]
enum ZkAttemptError {
    Auth(String),
    Transport(String),
    Command(String),
}

/// ZooKeeper module configuration.
#[derive(Debug, Clone)]
pub struct ZookeeperModule;

impl ZookeeperModule {
    /// Creates a new ZooKeeper module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused constructor argument kept for parity with other modules.
    ///
    /// # Returns
    ///
    /// A stateless [`ZookeeperModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::zookeeper::ZookeeperModule;
    ///
    /// let _module = ZookeeperModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for ZookeeperModule {
    fn name(&self) -> &'static str {
        "zookeeper"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_srvr(ctx)).await {
            Ok(Some(message)) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        match tokio::time::timeout(ctx.timeout(), attempt_once(ctx)).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(ZkAttemptError::Auth(err))) => {
                AttemptOutcome::Failure(format!("zookeeper auth failed: {err}"))
            }
            Ok(Err(ZkAttemptError::Transport(err))) => {
                AttemptOutcome::Error(format!("zookeeper transport failed: {err}"))
            }
            Ok(Err(ZkAttemptError::Command(err))) => {
                let message = success_message(is_unauthenticated(ctx));
                AttemptOutcome::Success(AttemptSuccess::with_command_error(
                    message,
                    format!("zookeeper command execution failed: {err}"),
                ))
            }
            Err(_) => AttemptOutcome::Error("attempt timed out".to_string()),
        }
    }
}

/// Runs one ZooKeeper login or unauthorized probe, then optional `-x`.
///
/// # Parameters
///
/// - `ctx`: Target, credential, timeout, proxy, and optional execute command.
///
/// # Returns
///
/// [`AttemptSuccess`] when the session is established and any command succeeds.
///
/// # Errors
///
/// Returns [`ZkAttemptError::Auth`] for SASL/ACL rejection, [`ZkAttemptError::Transport`]
/// for connect failures, and [`ZkAttemptError::Command`] for post-auth command errors.
///
/// # Examples
///
/// ```ignore
/// let success = attempt_once(&ctx).await?;
/// ```
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, ZkAttemptError> {
    let host = ctx.target_host.clone();
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let timeout = ctx.timeout();
    let unauthenticated = is_unauthenticated(ctx);
    let sasl = if unauthenticated {
        None
    } else {
        Some((
            ctx.credential.username.clone().unwrap_or_default(),
            ctx.credential.password.clone().unwrap_or_default(),
        ))
    };

    let (client, _bridge) =
        connect_client(&host, port, ctx.target.proxy.as_ref(), timeout, sasl).await?;

    if unauthenticated {
        client
            .list_children("/")
            .await
            .map_err(classify_unauth_error)?;
    }

    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => execute_zookeeper_command(&client, command, message)
            .await
            .map_err(ZkAttemptError::Command),
        None => Ok(AttemptSuccess::new(message)),
    }
}

/// Opens a ZooKeeper session, optionally with SASL DIGEST-MD5.
///
/// # Parameters
///
/// - `host`: Real destination host (used when no proxy is configured).
/// - `port`: Real destination port.
/// - `proxy`: Optional outbound proxy; when set, a local TCP bridge is started.
/// - `timeout`: Session and connection timeout budget.
/// - `sasl`: `Some((username, password))` for DIGEST-MD5; `None` for anonymous.
///
/// # Returns
///
/// Connected [`Client`] plus an optional bridge guard that must outlive the client.
///
/// # Errors
///
/// Returns [`ZkAttemptError::Auth`] on SASL/auth failure and
/// [`ZkAttemptError::Transport`] on proxy or TCP failure.
///
/// # Examples
///
/// ```ignore
/// let (client, _bridge) = connect_client("192.168.5.10", 2181, None, timeout, None).await?;
/// ```
async fn connect_client(
    host: &str,
    port: u16,
    proxy: Option<&crate::proxy::ProxyConfig>,
    timeout: Duration,
    sasl: Option<(String, String)>,
) -> Result<(Client, Option<ProxyTcpBridge>), ZkAttemptError> {
    let (connect_host, connect_port, bridge) =
        crate::proxy::resolve_tcp_endpoint(proxy, host, port)
            .await
            .map_err(|err| ZkAttemptError::Transport(format!("proxy bridge failed: {err}")))?;
    let cluster = format!("{connect_host}:{connect_port}");
    // ZooKeeper 协商 session timeout 下限通常为 4s; 过短会被服务端抬升.
    let session_timeout = timeout.max(Duration::from_millis(4_000));
    let mut connector = Client::connector()
        .with_session_timeout(session_timeout)
        .with_connection_timeout(timeout)
        .with_fail_eagerly()
        .with_server_version(3, 9, 0);
    if let Some((username, password)) = sasl {
        connector = connector.with_sasl(SaslOptions::digest_md5(username, password));
    }
    let client = connector
        .connect(&cluster)
        .await
        .map_err(classify_connect_error)?;
    Ok((client, bridge))
}

/// Classifies a connect-time ZooKeeper error as auth versus transport.
///
/// # Parameters
///
/// - `err`: Error returned by [`Connector::connect`](zookeeper_client::Connector::connect).
///
/// # Returns
///
/// [`ZkAttemptError::Auth`] for SASL/auth rejection; otherwise transport.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// let classified = classify_connect_error(err);
/// ```
fn classify_connect_error(err: ZkError) -> ZkAttemptError {
    if is_auth_error(&err) {
        ZkAttemptError::Auth(err.to_string())
    } else {
        ZkAttemptError::Transport(err.to_string())
    }
}

/// Classifies an unauthenticated `getChildren` error.
///
/// # Parameters
///
/// - `err`: Error from listing `/` without credentials.
///
/// # Returns
///
/// Auth failure when the cluster rejects anonymous access; transport otherwise.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// let classified = classify_unauth_error(err);
/// ```
fn classify_unauth_error(err: ZkError) -> ZkAttemptError {
    if is_auth_error(&err) {
        ZkAttemptError::Auth(err.to_string())
    } else {
        ZkAttemptError::Transport(err.to_string())
    }
}

/// Returns whether a ZooKeeper error represents authentication failure.
///
/// # Parameters
///
/// - `err`: Client error to inspect.
///
/// # Returns
///
/// `true` for `AuthFailed` / `NoAuth` or SASL-related messages.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// assert!(is_auth_error(&ZkError::AuthFailed));
/// ```
fn is_auth_error(err: &ZkError) -> bool {
    matches!(err, ZkError::AuthFailed | ZkError::NoAuth) || {
        let lower = err.to_string().to_ascii_lowercase();
        lower.contains("auth") || lower.contains("sasl")
    }
}

/// Returns whether this attempt is an anonymous unauthorized probe.
///
/// # Parameters
///
/// - `ctx`: Attempt whose username and password may be empty/`None`.
///
/// # Returns
///
/// `true` when both username and password are absent or empty.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// assert!(is_unauthenticated(&ctx));
/// ```
fn is_unauthenticated(ctx: &AttemptContext) -> bool {
    ctx.credential
        .username
        .as_deref()
        .unwrap_or_default()
        .is_empty()
        && ctx
            .credential
            .password
            .as_deref()
            .unwrap_or_default()
            .is_empty()
}

/// Returns the success banner for authenticated versus unauthorized access.
///
/// # Parameters
///
/// - `unauthenticated`: Whether the session used empty credentials.
///
/// # Returns
///
/// Operator-facing success message.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(success_message(true), "ZooKeeper unauthorized access!");
/// ```
fn success_message(unauthenticated: bool) -> &'static str {
    if unauthenticated {
        "ZooKeeper unauthorized access!"
    } else {
        "ZooKeeper access!"
    }
}

/// Sends the `srvr` four-letter word and formats a short probe line.
///
/// # Parameters
///
/// - `ctx`: Target host, port, timeout, and optional proxy.
///
/// # Returns
///
/// `Some` version/mode summary when the peer speaks ZooKeeper four-letter words.
///
/// # Errors
///
/// This function does not return errors; I/O failures become `None`.
///
/// # Examples
///
/// ```ignore
/// let banner = probe_srvr(&ctx).await;
/// ```
async fn probe_srvr(ctx: &TargetContext) -> Option<String> {
    let host = ctx.target_host.as_str();
    let port = ctx.port();
    let mut stream = match ctx.target.proxy.as_ref() {
        Some(proxy) => crate::proxy::connect_async(proxy, host, port).await.ok()?,
        None => tokio::net::TcpStream::connect((host, port)).await.ok()?,
    };
    stream.write_all(b"srvr").await.ok()?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.ok()?;
    parse_srvr_banner(&String::from_utf8_lossy(&buf))
}

/// Extracts version and mode from a `srvr` four-letter response.
///
/// # Parameters
///
/// - `body`: Raw `srvr` text.
///
/// # Returns
///
/// Compact banner such as `ZooKeeper 3.9.5 (standalone)`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::zookeeper::parse_srvr_banner;
///
/// let body = "Zookeeper version: 3.9.5-abc, built on 2026-02-11\nMode: standalone\n";
/// assert_eq!(
///     parse_srvr_banner(body).as_deref(),
///     Some("ZooKeeper 3.9.5 (standalone)")
/// );
/// ```
pub fn parse_srvr_banner(body: &str) -> Option<String> {
    let mut version = None;
    let mut mode = None;
    for line in body.lines() {
        let line = line.trim();
        if let Some(rest) = line
            .strip_prefix("Zookeeper version:")
            .or_else(|| line.strip_prefix("ZooKeeper version:"))
        {
            let rest = rest.trim();
            let token = rest.split([',', ' ', '-']).find(|part| {
                !part.is_empty() && part.chars().next().is_some_and(|c| c.is_ascii_digit())
            })?;
            version = Some(token.to_string());
        } else if let Some(rest) = line.strip_prefix("Mode:") {
            let rest = rest.trim();
            if !rest.is_empty() {
                mode = Some(rest.to_string());
            }
        }
    }
    match (version, mode) {
        (Some(version), Some(mode)) => Some(format!("ZooKeeper {version} ({mode})")),
        (Some(version), None) => Some(format!("ZooKeeper {version}")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::parse_srvr_banner;

    /// Verifies `srvr` parsing keeps the numeric version and server mode.
    #[test]
    fn parse_srvr_banner_extracts_version_and_mode() {
        let body = "Zookeeper version: 3.9.5-293c895a, built on 2026-02-11 20:18 UTC\n\
                    Latency min/avg/max: 0/0/0\n\
                    Mode: standalone\n\
                    Node count: 5\n";
        assert_eq!(
            parse_srvr_banner(body).as_deref(),
            Some("ZooKeeper 3.9.5 (standalone)")
        );
    }

    /// Verifies unrecognized four-letter output is ignored.
    #[test]
    fn parse_srvr_banner_rejects_unrelated_text() {
        assert_eq!(parse_srvr_banner("imok"), None);
    }
}
