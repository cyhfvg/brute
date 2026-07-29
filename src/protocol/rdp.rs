//! RDP login attempts via pure-Rust `rdp-rs` (NLA/CredSSP + NTLM).
//!
//! ## Dependency choice
//!
//! IronRDP (`ironrdp-connector` 0.8+) cannot resolve against `smb2` because picky pins a
//! pre-release `aes-gcm` that conflicts with smb2's stable `aes-gcm`. Vendor-patching is
//! forbidden, so this module uses the mature pure-Rust protocol stack in `rdp-rs` instead.
//! TLS is provided by `native-tls` (via rdp-rs); OpenSSL is **vendored and linked
//! statically** (`openssl` crate with `vendored`) so release binaries stay single-file
//! without `libssl.so` / `libcrypto.so` runtime dependencies.

use std::{
    io,
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    time::Duration,
};

use async_trait::async_trait;
use rdp::core::client::Connector;
use rdp::model::error::{Error as RdpClientError, RdpErrorKind};

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
    run_blocking_with_timeout,
};

/// RDP module configuration.
#[derive(Debug, Clone)]
pub struct RdpModule;

impl RdpModule {
    /// Creates a new RDP module.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Reserved for API parity with other modules; per-attempt
    ///   timeouts are taken from each [`AttemptContext`] / [`TargetContext`].
    ///
    /// # Returns
    ///
    /// A configured [`RdpModule`] ready for the scheduler.
    ///
    /// # Errors
    ///
    /// This constructor does not fail.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let module = RdpModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for RdpModule {
    fn name(&self) -> &'static str {
        "rdp"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        let host = ctx.target_host.clone();
        let port = ctx.port();
        let timeout = ctx.timeout();

        let probe = tokio::task::spawn_blocking(move || probe_rdp_port(&host, port, timeout));
        match tokio::time::timeout(timeout, probe).await {
            Ok(Ok(Some(message))) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        let host = ctx.target_host.clone();
        let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
        let username = ctx.credential.username.clone().unwrap_or_default();
        let password = ctx.credential.password.clone().unwrap_or_default();
        let timeout = ctx.timeout();

        run_blocking_with_timeout(timeout, move || {
            try_rdp_login(&host, port, &username, &password, timeout)
        })
        .await
    }
}

/// Performs one RDP authentication attempt (X.224 + TLS + NLA/CredSSP).
///
/// # Parameters
///
/// - `host`: Target hostname or IP.
/// - `port`: RDP TCP port (typically 3389).
/// - `username`: Account name; may be `DOMAIN\\user` or `user@domain`.
/// - `password`: Account password.
/// - `timeout`: Connection and I/O timeout for the blocking client.
///
/// # Returns
///
/// [`AttemptOutcome::Success`] when CredSSP/NLA accepts the credentials,
/// [`AttemptOutcome::Failure`] for logon rejections, or [`AttemptOutcome::Error`]
/// for transport and other non-auth problems.
///
/// # Errors
///
/// Errors are mapped into [`AttemptOutcome`] variants rather than returned as `Result`.
///
/// # Examples
///
/// ```ignore
/// let outcome = try_rdp_login(
///     "10.10.50.10",
///     3389,
///     "admin",
///     "secret",
///     Duration::from_secs(5),
/// );
/// ```
pub fn try_rdp_login(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    timeout: Duration,
) -> AttemptOutcome {
    let (domain, user) = split_domain_user(username);

    let server_addr = match resolve_addr(host, port) {
        Ok(addr) => addr,
        Err(err) => {
            return AttemptOutcome::Error(format!("rdp resolve error: {err}"));
        }
    };

    let tcp_stream = match TcpStream::connect_timeout(&server_addr, timeout) {
        Ok(stream) => stream,
        Err(err) => {
            return AttemptOutcome::Error(format!("rdp transport error: {err}"));
        }
    };

    if let Err(err) = apply_socket_timeouts(&tcp_stream, timeout) {
        return AttemptOutcome::Error(format!("rdp socket setup error: {err}"));
    }

    let mut connector = Connector::new()
        .screen(800, 600)
        .credentials(domain, user, password.to_string())
        .use_nla(true)
        .check_certificate(false)
        .name("brute-rdp".to_string());

    match connector.connect(tcp_stream) {
        Ok(mut client) => {
            // Drop the session immediately; login success is enough for brute.
            let _ = client.shutdown();
            AttemptOutcome::Success(AttemptSuccess::new("RDP access!"))
        }
        Err(err) => classify_rdp_error(&err),
    }
}

/// Splits `DOMAIN\\user` or `user@domain` into `(domain, user)`.
///
/// # Parameters
///
/// - `username`: Raw username field from credentials.
///
/// # Returns
///
/// `(domain, user)` where `domain` is empty for unqualified names.
///
/// # Errors
///
/// This function does not fail.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(split_domain_user(r"LAB\alice"), ("LAB".into(), "alice".into()));
/// assert_eq!(split_domain_user("alice@lab.local"), ("lab.local".into(), "alice".into()));
/// assert_eq!(split_domain_user("alice"), ("".into(), "alice".into()));
/// ```
pub fn split_domain_user(username: &str) -> (String, String) {
    if let Some((domain, user)) = username.split_once('\\') {
        return (domain.to_string(), user.to_string());
    }
    if let Some((user, domain)) = username.split_once('@') {
        return (domain.to_string(), user.to_string());
    }
    (String::new(), username.to_string())
}

/// Maps an `rdp-rs` error into a high-level attempt outcome.
///
/// # Parameters
///
/// - `err`: Error returned by the RDP connection sequence.
///
/// # Returns
///
/// [`AttemptOutcome::Failure`] for credential / access rejections, otherwise
/// [`AttemptOutcome::Error`].
///
/// # Errors
///
/// This function does not fail.
///
/// # Examples
///
/// ```ignore
/// let outcome = classify_rdp_error(&err);
/// ```
pub fn classify_rdp_error(err: &RdpClientError) -> AttemptOutcome {
    let message = format!("{err:?}");
    if is_rdp_auth_failure(err) || looks_like_auth_failure_message(&message) {
        AttemptOutcome::Failure(format!("rdp auth failed: {message}"))
    } else if looks_like_transport_message(&message) {
        AttemptOutcome::Error(format!("rdp transport error: {message}"))
    } else {
        AttemptOutcome::Error(format!("rdp error: {message}"))
    }
}

/// Returns true when an rdp-rs error represents bad credentials or denied logon.
///
/// # Parameters
///
/// - `err`: Error from the RDP client stack.
///
/// # Returns
///
/// `true` for auth-style rejections that should print as `[-]`.
///
/// # Errors
///
/// This function does not fail.
///
/// # Examples
///
/// ```ignore
/// assert!(is_rdp_auth_failure(&err));
/// ```
pub fn is_rdp_auth_failure(err: &RdpClientError) -> bool {
    match err {
        RdpClientError::RdpError(inner) => {
            matches!(
                inner.kind(),
                RdpErrorKind::RejectedByServer
                    | RdpErrorKind::InvalidAutomata
                    | RdpErrorKind::PossibleMITM
                    | RdpErrorKind::InvalidChecksum
            ) || looks_like_auth_failure_message(&format!("{:?}", inner.kind()))
                || looks_like_auth_failure_message(&format!("{inner:?}"))
        }
        RdpClientError::Io(io_err) => {
            let text = format!("{io_err}");
            let debug = format!("{io_err:?}");
            // native-tls surfaces bad passwords as TLS "access denied" alert 49.
            looks_like_auth_failure_message(&text)
                || looks_like_auth_failure_message(&debug)
                || text.to_ascii_lowercase().contains("access denied")
                || debug.contains("alert number 49")
                || debug.contains("ssl3_read_bytes")
        }
        RdpClientError::SslError(ssl_err) => {
            let text = format!("{ssl_err}");
            looks_like_auth_failure_message(&text)
                || text.to_ascii_lowercase().contains("access denied")
        }
        RdpClientError::SslHandshakeError => true,
        _ => looks_like_auth_failure_message(&format!("{err:?}")),
    }
}

/// Heuristic for protocol errors that represent bad credentials.
fn looks_like_auth_failure_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("logon")
        || lower.contains("password")
        || lower.contains("credential")
        || lower.contains("authentication")
        || lower.contains("access denied")
        || lower.contains("logon_failure")
        || lower.contains("status_logon")
        || lower.contains("0xc000006d")
        || lower.contains("0xc000006a")
        || lower.contains("rejected")
        || lower.contains("alert number 49")
}

fn looks_like_transport_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("connection refused")
        || lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("network is unreachable")
        || lower.contains("no route to host")
        || lower.contains("os error")
}

/// Best-effort TCP readiness probe before credential spraying.
fn probe_rdp_port(host: &str, port: u16, timeout: Duration) -> Option<String> {
    let addr = resolve_addr(host, port).ok()?;
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_stream) => Some(format!("rdp port open on {host}:{port}")),
        Err(_) => None,
    }
}

fn resolve_addr(host: &str, port: u16) -> io::Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no socket address resolved"))
}

fn apply_socket_timeouts(stream: &TcpStream, timeout: Duration) -> io::Result<()> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.set_nodelay(true)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error as IoError, ErrorKind as IoErrorKind};

    use rdp::model::error::RdpError;

    /// Verifies domain/user splitting used before CredSSP.
    #[test]
    fn splits_domain_user_forms() {
        assert_eq!(
            split_domain_user(r"LAB\alice"),
            ("LAB".to_string(), "alice".to_string())
        );
        assert_eq!(
            split_domain_user("alice@lab.local"),
            ("lab.local".to_string(), "alice".to_string())
        );
        assert_eq!(
            split_domain_user("alice"),
            (String::new(), "alice".to_string())
        );
    }

    /// Verifies TLS access-denied style messages map to auth failure.
    #[test]
    fn classifies_tls_access_denied_as_auth_failure() {
        let io_err =
            IoError::other("ssl3_read_bytes: tlsv1 alert access denied (SSL alert number 49)");
        let err = RdpClientError::Io(io_err);
        assert!(is_rdp_auth_failure(&err));
        match classify_rdp_error(&err) {
            AttemptOutcome::Failure(message) => {
                assert!(message.contains("rdp auth failed"));
            }
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    /// Verifies protocol RejectedByServer maps to auth failure.
    #[test]
    fn classifies_rejected_by_server_as_auth_failure() {
        let err =
            RdpClientError::RdpError(RdpError::new(RdpErrorKind::RejectedByServer, "rejected"));
        assert!(is_rdp_auth_failure(&err));
        match classify_rdp_error(&err) {
            AttemptOutcome::Failure(message) => {
                assert!(message.contains("rdp auth failed"));
            }
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    /// Verifies transport-style messages stay Error.
    #[test]
    fn classifies_connection_refused_as_error() {
        let io_err = IoError::new(IoErrorKind::ConnectionRefused, "connection refused");
        let err = RdpClientError::Io(io_err);
        match classify_rdp_error(&err) {
            AttemptOutcome::Error(message) => {
                assert!(
                    message.contains("rdp transport error") || message.contains("rdp error"),
                    "{message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// Closed local port must surface transport Error, not the unimplemented stub.
    #[test]
    fn closed_port_is_transport_error_not_stub() {
        let outcome = try_rdp_login(
            "127.0.0.1",
            1,
            "admin",
            "not-a-real-password",
            Duration::from_millis(400),
        );
        match outcome {
            AttemptOutcome::Error(message) => {
                assert!(
                    message.contains("rdp transport error")
                        || message.contains("rdp resolve error")
                        || message.contains("Connection refused")
                        || message.contains("timed out")
                        || message.contains("os error")
                        || message.contains("rdp error"),
                    "unexpected error text: {message}"
                );
                assert!(
                    !message.contains("scaffolded but not implemented"),
                    "must not use stub: {message}"
                );
            }
            other => panic!("expected Error for closed port, got {other:?}"),
        }
    }

    /// Auth-failure heuristic covers logon NTSTATUS text used in console mapping.
    #[test]
    fn auth_heuristic_covers_logon_status() {
        assert!(looks_like_auth_failure_message(
            "STATUS_LOGON_FAILURE [0xc000006d]"
        ));
        assert!(!looks_like_auth_failure_message("connection refused"));
    }
}
