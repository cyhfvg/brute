//! Kafka SASL/PLAIN login and optional topic metadata (`-x`).
//!
//! Empty username/password fail. Stream-injectable `--proxy`.

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

const API_SASL_HANDSHAKE: i16 = 17;
const API_API_VERSIONS: i16 = 18;
const API_SASL_AUTHENTICATE: i16 = 36;
const API_METADATA: i16 = 3;

/// Kafka module configuration.
#[derive(Debug, Clone)]
pub struct KafkaModule;

impl KafkaModule {
    /// Creates a new Kafka module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`KafkaModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::kafka::KafkaModule;
    ///
    /// let _module = KafkaModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for KafkaModule {
    fn name(&self) -> &'static str {
        "kafka"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_versions(ctx)).await {
            Ok(Some(message)) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        match tokio::time::timeout(ctx.timeout(), attempt_once(ctx)).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(err)) if is_auth_error(&err) => {
                AttemptOutcome::failure(format!("kafka auth failed: {err}"))
            }
            Ok(Err(err)) => AttemptOutcome::error(format!("kafka transport failed: {err}")),
            Err(_) => AttemptOutcome::error("attempt timed out".to_string()),
        }
    }
}

/// Runs SASL Handshake + PLAIN authenticate, then optional Metadata.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, String> {
    let user = ctx.credential.username.as_deref().unwrap_or("");
    let pass = ctx.credential.password.as_deref().unwrap_or("");
    let mut stream = connect_stream(
        &ctx.target_host,
        ctx.target.port.unwrap_or(ctx.protocol.default_port()),
        ctx.target.proxy.as_ref(),
    )
    .await?;
    let handshake = kafka_request(API_SASL_HANDSHAKE, 1, 1, &encode_string("PLAIN"));
    write_frame(&mut stream, &handshake).await?;
    let reply = read_frame(&mut stream).await?;
    let error = read_i16_at(&reply, 4)?;
    if error != 0 {
        return Err(format!("auth:SASL handshake error {error}"));
    }
    let auth_bytes = encode_plain(user, pass);
    let auth = kafka_request(API_SASL_AUTHENTICATE, 0, 2, &encode_bytes(&auth_bytes));
    write_frame(&mut stream, &auth).await?;
    let reply = read_frame(&mut stream).await?;
    let error = read_i16_at(&reply, 4)?;
    if error != 0 {
        let msg = read_nullable_string_at(&reply, 6).unwrap_or_default();
        return Err(format!("auth:SASL authenticate error {error} {msg}"));
    }
    if let Some(command) = ctx.execute.as_deref() {
        let body = encode_metadata_all();
        let meta = kafka_request(API_METADATA, 1, 3, &body);
        write_frame(&mut stream, &meta).await?;
        let reply = read_frame(&mut stream).await?;
        let output = format_metadata(&reply, command);
        return Ok(AttemptSuccess::with_command("Kafka access!", output));
    }
    Ok(AttemptSuccess::new("Kafka access!"))
}

fn encode_plain(user: &str, pass: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(user.len() + pass.len() + 2);
    out.push(0);
    out.extend_from_slice(user.as_bytes());
    out.push(0);
    out.extend_from_slice(pass.as_bytes());
    out
}

fn kafka_request(api_key: i16, api_version: i16, correlation: i32, body: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&api_key.to_be_bytes());
    inner.extend_from_slice(&api_version.to_be_bytes());
    inner.extend_from_slice(&correlation.to_be_bytes());
    inner.extend_from_slice(&encode_string("brute"));
    inner.extend_from_slice(body);
    let mut frame = Vec::with_capacity(4 + inner.len());
    frame.extend_from_slice(&(inner.len() as i32).to_be_bytes());
    frame.extend_from_slice(&inner);
    frame
}

fn encode_string(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + s.len());
    out.extend_from_slice(&(s.len() as i16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
    out
}

fn encode_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

fn encode_metadata_all() -> Vec<u8> {
    // Metadata v1: topics array null = all topics.
    (-1i32).to_be_bytes().to_vec()
}

async fn write_frame(stream: &mut TcpStream, frame: &[u8]) -> Result<(), String> {
    stream.write_all(frame).await.map_err(|err| err.to_string())
}

async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|err| err.to_string())?;
    let len = i32::from_be_bytes(len_buf);
    if len <= 0 || len > 1_000_000 {
        return Err(format!("invalid kafka frame length {len}"));
    }
    let mut body = vec![0u8; len as usize];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|err| err.to_string())?;
    Ok(body)
}

fn read_i16_at(buf: &[u8], offset: usize) -> Result<i16, String> {
    let slice = buf
        .get(offset..offset + 2)
        .ok_or_else(|| "truncated kafka response".to_string())?;
    Ok(i16::from_be_bytes([slice[0], slice[1]]))
}

fn read_nullable_string_at(buf: &[u8], offset: usize) -> Option<String> {
    let len = read_i16_at(buf, offset).ok()?;
    if len < 0 {
        return Some(String::new());
    }
    let start = offset + 2;
    let end = start + len as usize;
    buf.get(start..end)
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
}

fn format_metadata(reply: &[u8], command: &str) -> String {
    if command.trim().is_empty() || command.eq_ignore_ascii_case("metadata") {
        format!("metadata bytes={}", reply.len())
    } else {
        format!("executed {command}; metadata bytes={}", reply.len())
    }
}

/// Classifies Kafka SASL failures versus transport errors.
///
/// # Parameters
///
/// - `err`: Handshake/authenticate error text.
///
/// # Returns
///
/// `true` for SASL / auth wording.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::kafka::is_auth_error;
///
/// assert!(is_auth_error("auth:SASL authenticate error 58"));
/// assert!(!is_auth_error("connection refused"));
/// ```
pub fn is_auth_error(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("auth:")
        || lower.contains("sasl")
        || lower.contains("authentication")
        || lower.contains("58")
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

async fn probe_versions(ctx: &TargetContext) -> Option<String> {
    let mut stream = connect_stream(&ctx.target_host, ctx.port(), ctx.target.proxy.as_ref())
        .await
        .ok()?;
    let req = kafka_request(API_API_VERSIONS, 0, 1, &[]);
    write_frame(&mut stream, &req).await.ok()?;
    let reply = read_frame(&mut stream).await.ok()?;
    let error = read_i16_at(&reply, 4).ok()?;
    if error == 0 {
        Some("Kafka broker".to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_plain_uses_nul_separators() {
        assert_eq!(encode_plain("u", "p"), [0, b'u', 0, b'p']);
    }

    #[test]
    fn is_auth_error_detects_sasl() {
        assert!(is_auth_error("auth:SASL authenticate error 58"));
        assert!(!is_auth_error("connection refused"));
    }
}
