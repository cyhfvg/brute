//! ActiveMQ login via STOMP CONNECT, plus post-auth SEND (`-x`).
//!
//! Empty username and password probe anonymous CONNECT. Non-empty credentials
//! send `login` / `passcode` headers.

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

/// ActiveMQ STOMP module configuration.
#[derive(Debug, Clone)]
pub struct ActiveMqModule;

impl ActiveMqModule {
    /// Creates a new ActiveMQ module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`ActiveMqModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::activemq::ActiveMqModule;
    ///
    /// let _module = ActiveMqModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for ActiveMqModule {
    fn name(&self) -> &'static str {
        "activemq"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_stomp(ctx)).await {
            Ok(Some(message)) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        match tokio::time::timeout(ctx.timeout(), attempt_once(ctx)).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(err)) if err.starts_with("auth:") => AttemptOutcome::failure(format!(
                "activemq auth failed: {}",
                err.trim_start_matches("auth:")
            )),
            Ok(Err(err)) => AttemptOutcome::error(format!("activemq transport failed: {err}")),
            Err(_) => AttemptOutcome::error("attempt timed out".to_string()),
        }
    }
}

/// Runs one STOMP CONNECT, then optional SEND.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, String> {
    let unauthenticated = is_unauthenticated(ctx);
    let mut stream = connect_stream(
        &ctx.target_host,
        ctx.target.port.unwrap_or(ctx.protocol.default_port()),
        ctx.target.proxy.as_ref(),
    )
    .await?;
    let frame = connect_frame(
        ctx.credential.username.as_deref().unwrap_or(""),
        ctx.credential.password.as_deref().unwrap_or(""),
    );
    stream
        .write_all(frame.as_bytes())
        .await
        .map_err(|err| err.to_string())?;
    let response = read_stomp_frame(&mut stream).await?;
    if !response.starts_with("CONNECTED") {
        return Err(format!("auth:{}", first_line(&response)));
    }
    let message = success_message(unauthenticated);
    let result = match ctx.execute.as_deref() {
        Some(command) => {
            let send = send_frame(command);
            if let Err(err) = stream.write_all(send.as_bytes()).await {
                return Ok(AttemptSuccess::with_command_error(
                    message,
                    format!("activemq command execution failed: {err}"),
                ));
            }
            match tokio::time::timeout(
                ctx.timeout() / 4 + std::time::Duration::from_millis(200),
                read_stomp_frame(&mut stream),
            )
            .await
            {
                Ok(Ok(reply)) if reply.starts_with("ERROR") => {
                    AttemptSuccess::with_command_error(message, first_line(&reply))
                }
                Ok(Ok(reply)) => AttemptSuccess::with_command(message, first_line(&reply)),
                _ => AttemptSuccess::with_command(message, "SENT".to_string()),
            }
        }
        None => AttemptSuccess::new(message),
    };
    let _ = stream.write_all(b"DISCONNECT\n\n\0").await;
    Ok(result)
}

async fn connect_stream(
    host: &str,
    port: u16,
    proxy: Option<&crate::proxy::ProxyConfig>,
) -> Result<TcpStream, String> {
    match proxy {
        Some(proxy) => crate::proxy::connect_async(proxy, host, port).await,
        None => TcpStream::connect((host, port))
            .await
            .map_err(|err| err.to_string()),
    }
}

/// Builds a STOMP CONNECT frame.
///
/// # Parameters
///
/// - `username`: STOMP `login` header; omitted when empty.
/// - `password`: STOMP `passcode` header; omitted when empty.
///
/// # Returns
///
/// NUL-terminated CONNECT frame.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::activemq::connect_frame;
///
/// let frame = connect_frame("admin", "secret");
/// assert!(frame.starts_with("CONNECT\n"));
/// assert!(frame.contains("login:admin"));
/// ```
pub fn connect_frame(username: &str, password: &str) -> String {
    let mut frame = String::from("CONNECT\naccept-version:1.0,1.1,1.2\nhost:localhost\n");
    if !username.is_empty() {
        frame.push_str("login:");
        frame.push_str(username);
        frame.push('\n');
    }
    if !password.is_empty() {
        frame.push_str("passcode:");
        frame.push_str(password);
        frame.push('\n');
    }
    frame.push('\n');
    frame.push('\0');
    frame
}

/// Builds a STOMP SEND frame to `/queue/brute`.
///
/// # Parameters
///
/// - `body`: Message body from `-x`.
///
/// # Returns
///
/// NUL-terminated SEND frame.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::activemq::send_frame;
///
/// let frame = send_frame("hello");
/// assert!(frame.starts_with("SEND\n"));
/// assert!(frame.contains("destination:/queue/brute"));
/// ```
pub fn send_frame(body: &str) -> String {
    format!("SEND\ndestination:/queue/brute\ncontent-type:text/plain\n\n{body}\0")
}

async fn read_stomp_frame(stream: &mut TcpStream) -> Result<String, String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream
            .read(&mut byte)
            .await
            .map_err(|err| err.to_string())?;
        if n == 0 {
            if buf.is_empty() {
                return Err("connection closed".to_string());
            }
            break;
        }
        if byte[0] == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.len() > 65_536 {
            return Err("STOMP frame too large".to_string());
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn first_line(frame: &str) -> String {
    frame.lines().next().unwrap_or(frame).trim().to_string()
}

async fn probe_stomp(ctx: &TargetContext) -> Option<String> {
    let mut stream = connect_stream(&ctx.target_host, ctx.port(), ctx.target.proxy.as_ref())
        .await
        .ok()?;
    stream
        .write_all(connect_frame("", "").as_bytes())
        .await
        .ok()?;
    let response = read_stomp_frame(&mut stream).await.ok()?;
    if response.starts_with("CONNECTED") {
        Some("ActiveMQ STOMP".to_string())
    } else if response.starts_with("ERROR") {
        Some("ActiveMQ STOMP (auth required)".to_string())
    } else {
        None
    }
}

fn is_unauthenticated(ctx: &AttemptContext) -> bool {
    ctx.credential.username.as_deref().unwrap_or("").is_empty()
        && ctx.credential.password.as_deref().unwrap_or("").is_empty()
}

fn success_message(unauthenticated: bool) -> &'static str {
    if unauthenticated {
        "ActiveMQ unauthorized access!"
    } else {
        "ActiveMQ access!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_frame_includes_credentials() {
        let frame = connect_frame("admin", "secret");
        assert!(frame.contains("login:admin"));
        assert!(frame.contains("passcode:secret"));
        assert!(frame.ends_with('\0'));
    }

    #[test]
    fn send_frame_targets_brute_queue() {
        let frame = send_frame("payload");
        assert!(frame.contains("destination:/queue/brute"));
        assert!(frame.contains("payload"));
    }
}
