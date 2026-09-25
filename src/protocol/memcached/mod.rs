//! Memcached login, unauthorized access, SASL PLAIN auth, and post-auth commands.
//!
//! Empty username and password probe unauthenticated ASCII `stats`.
//! Non-empty credentials use the binary protocol SASL PLAIN mechanism.

mod codec;
mod command;

pub use codec::{
    OPCODE_VERSION, ascii_looks_successful, ascii_response_complete, encode_request,
    parse_binary_header, parse_version_banner, sasl_plain_payload,
};
pub use command::{execute_memcached_command, split_command};

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};
use codec::{
    OPCODE_SASL_AUTH, OPCODE_STAT, OPCODE_VERSION as BINARY_VERSION, STATUS_AUTH_ERROR, STATUS_OK,
    STATUS_UNKNOWN_COMMAND, encode_request as encode_bin, parse_version_banner as parse_banner,
    read_ascii_response, read_binary_response, sasl_plain_payload as plain_payload,
};

/// Memcached attempt errors split auth/connect failures from post-auth command failures.
type MemcachedAttemptError = crate::protocol::http_attempt::HttpAttemptFailure;

/// Memcached module configuration.
#[derive(Debug, Clone)]
pub struct MemcachedModule;

impl MemcachedModule {
    /// Creates a new Memcached module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Per-attempt timeout in milliseconds. Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`MemcachedModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::memcached::MemcachedModule;
    ///
    /// let _module = MemcachedModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for MemcachedModule {
    fn name(&self) -> &'static str {
        "memcached"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_version(ctx)).await {
            Ok(Some(message)) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        crate::protocol::http_attempt::run_http_attempt(
            ctx.timeout(),
            "memcached",
            || success_message(is_unauthenticated(ctx)),
            attempt_once(ctx),
        )
        .await
    }
}

/// Runs one Memcached login or unauthorized probe, then optional `-x`.
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
/// Returns [`MemcachedAttemptError::Auth`] for SASL/ASCII rejection,
/// [`MemcachedAttemptError::Transport`] for connect failures, and
/// [`MemcachedAttemptError::Command`] for post-auth command errors.
///
/// # Examples
///
/// ```ignore
/// let success = attempt_once(&ctx).await?;
/// ```
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, MemcachedAttemptError> {
    let host = ctx.target_host.as_str();
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let unauthenticated = is_unauthenticated(ctx);
    let mut stream = connect_stream(host, port, ctx.target.proxy.as_ref()).await?;

    if unauthenticated {
        binary_unauthorized_probe(&mut stream).await?;
    } else {
        sasl_plain_auth(
            &mut stream,
            ctx.credential.username.as_deref().unwrap_or(""),
            ctx.credential.password.as_deref().unwrap_or(""),
        )
        .await?;
    }

    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => execute_memcached_command(&mut stream, command, message)
            .await
            .map_err(MemcachedAttemptError::Command),
        None => Ok(AttemptSuccess::new(message)),
    }
}

/// Opens a TCP connection to Memcached, optionally through `--proxy`.
///
/// # Parameters
///
/// - `host`: Destination host.
/// - `port`: Destination port.
/// - `proxy`: Optional outbound proxy.
///
/// # Returns
///
/// Connected [`TcpStream`].
///
/// # Errors
///
/// Returns [`MemcachedAttemptError::Transport`] when the socket or proxy tunnel fails.
///
/// # Examples
///
/// ```ignore
/// let stream = connect_stream("127.0.0.1", 11211, None).await?;
/// ```
async fn connect_stream(
    host: &str,
    port: u16,
    proxy: Option<&crate::proxy::ProxyConfig>,
) -> Result<TcpStream, MemcachedAttemptError> {
    let stream = match proxy {
        Some(proxy) => crate::proxy::connect_async(proxy, host, port)
            .await
            .map_err(MemcachedAttemptError::Transport)?,
        None => TcpStream::connect((host, port))
            .await
            .map_err(|err| MemcachedAttemptError::Transport(err.to_string()))?,
    };
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Probes unauthorized access with binary `STAT` and drains the response.
///
/// # Parameters
///
/// - `stream`: Connected Memcached socket.
///
/// # Returns
///
/// `Ok(())` when the server returns STAT packets without requiring SASL.
///
/// # Errors
///
/// Returns [`MemcachedAttemptError::Auth`] on `AUTH_ERROR` and
/// [`MemcachedAttemptError::Transport`] on I/O failure.
///
/// # Examples
///
/// ```ignore
/// binary_unauthorized_probe(&mut stream).await?;
/// ```
async fn binary_unauthorized_probe(stream: &mut TcpStream) -> Result<(), MemcachedAttemptError> {
    stream
        .write_all(&encode_bin(OPCODE_STAT, b"", b"", b""))
        .await
        .map_err(|err| MemcachedAttemptError::Transport(err.to_string()))?;
    loop {
        let packet = read_binary_response(stream)
            .await
            .map_err(MemcachedAttemptError::Transport)?;
        match packet.status {
            STATUS_OK => {
                if packet.key.is_empty() && packet.value.is_empty() {
                    return Ok(());
                }
            }
            STATUS_AUTH_ERROR => {
                return Err(MemcachedAttemptError::Auth(
                    "authentication required".to_string(),
                ));
            }
            other => {
                return Err(MemcachedAttemptError::Auth(format!(
                    "stat status 0x{other:04x}: {}",
                    String::from_utf8_lossy(&packet.value)
                )));
            }
        }
    }
}

/// Authenticates with binary-protocol SASL PLAIN.
///
/// # Parameters
///
/// - `stream`: Connected Memcached socket.
/// - `username`: SASL authentication identity.
/// - `password`: SASL password.
///
/// # Returns
///
/// `Ok(())` when the server accepts the PLAIN exchange.
///
/// # Errors
///
/// Returns [`MemcachedAttemptError::Auth`] on `AUTH_ERROR` / unknown-command and
/// [`MemcachedAttemptError::Transport`] on I/O failure.
///
/// # Examples
///
/// ```ignore
/// sasl_plain_auth(&mut stream, "admin", "secret").await?;
/// ```
async fn sasl_plain_auth(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
) -> Result<(), MemcachedAttemptError> {
    let payload = plain_payload(username, password);
    let packet = encode_bin(OPCODE_SASL_AUTH, b"", b"PLAIN", &payload);
    stream
        .write_all(&packet)
        .await
        .map_err(|err| MemcachedAttemptError::Transport(err.to_string()))?;
    let response = read_binary_response(stream)
        .await
        .map_err(MemcachedAttemptError::Transport)?;
    match response.status {
        STATUS_OK => Ok(()),
        STATUS_AUTH_ERROR => Err(MemcachedAttemptError::Auth(
            "invalid username or password".to_string(),
        )),
        STATUS_UNKNOWN_COMMAND => Err(MemcachedAttemptError::Auth(
            "server does not support SASL".to_string(),
        )),
        other => Err(MemcachedAttemptError::Auth(format!(
            "sasl status 0x{other:04x}: {}",
            String::from_utf8_lossy(&response.value)
        ))),
    }
}

/// Sends binary VERSION (falling back to ASCII `version`) and formats a probe line.
///
/// # Parameters
///
/// - `ctx`: Target host, port, timeout, and optional proxy.
///
/// # Returns
///
/// `Some` version banner when the peer speaks Memcached.
///
/// # Errors
///
/// This function does not return errors; I/O failures become `None`.
///
/// # Examples
///
/// ```ignore
/// let banner = probe_version(&ctx).await;
/// ```
async fn probe_version(ctx: &TargetContext) -> Option<String> {
    let mut stream = connect_stream(&ctx.target_host, ctx.port(), ctx.target.proxy.as_ref())
        .await
        .ok()?;
    let packet = encode_bin(BINARY_VERSION, b"", b"", b"");
    if stream.write_all(&packet).await.is_ok()
        && let Ok(response) = read_binary_response(&mut stream).await
        && response.status == STATUS_OK
    {
        return parse_banner(&format!(
            "VERSION {}",
            String::from_utf8_lossy(&response.value)
        ));
    }

    let mut stream = connect_stream(&ctx.target_host, ctx.port(), ctx.target.proxy.as_ref())
        .await
        .ok()?;
    if stream.write_all(b"version\r\n").await.is_ok()
        && let Ok(body) = read_ascii_response(&mut stream).await
    {
        parse_banner(&body)
    } else {
        None
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
    ctx.credential.username.as_deref().unwrap_or("").is_empty()
        && ctx.credential.password.as_deref().unwrap_or("").is_empty()
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
/// assert_eq!(success_message(true), "Memcached unauthorized access!");
/// ```
fn success_message(unauthenticated: bool) -> &'static str {
    if unauthenticated {
        "Memcached unauthorized access!"
    } else {
        "Memcached access!"
    }
}
