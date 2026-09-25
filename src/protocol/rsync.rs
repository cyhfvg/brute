//! rsync daemon module login (RSYNCD handshake + AUTHREQD MD5).
//!
//! Username/password authenticate against `--module` (default `files`).
//! Empty credentials probe unauthenticated module listing/access.

use async_trait::async_trait;
use openssl::hash::{MessageDigest, hash};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

/// rsync daemon module configuration.
#[derive(Debug, Clone)]
pub struct RsyncModule;

impl RsyncModule {
    /// Creates a new rsync module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`RsyncModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::rsync::RsyncModule;
    ///
    /// let _module = RsyncModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for RsyncModule {
    fn name(&self) -> &'static str {
        "rsync"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_greeting(ctx)).await {
            Ok(Some(message)) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        crate::protocol::http_attempt::run_http_attempt(
            ctx.timeout(),
            "rsync",
            String::new,
            async {
                attempt_once(ctx)
                    .await
                    .map_err(crate::protocol::http_attempt::classify_auth_prefix)
            },
        )
        .await
    }
}

/// Runs one rsync daemon module login.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, String> {
    let module = ctx
        .path
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("files");
    let unauthenticated = ctx.credential.username.as_deref().unwrap_or("").is_empty()
        && ctx.credential.password.as_deref().unwrap_or("").is_empty();
    let mut stream = connect_stream(
        &ctx.target_host,
        ctx.target.port.unwrap_or(ctx.protocol.default_port()),
        ctx.target.proxy.as_ref(),
    )
    .await?;
    let mut reader = BufReader::new(&mut stream);
    let greeting = read_line(&mut reader).await?;
    let protocol = parse_greeting(&greeting).ok_or_else(|| format!("bad greeting: {greeting}"))?;
    write_line(reader.get_mut(), &greeting).await?;
    write_line(reader.get_mut(), module).await?;
    let reply = read_line(&mut reader).await?;
    if reply.starts_with("@RSYNCD: OK") || reply.starts_with("@RSYNCD: EXIT") {
        if unauthenticated {
            return Ok(AttemptSuccess::new("rsync unauthorized access!"));
        }
        return Err("auth:module did not require a password".to_string());
    }
    if let Some(challenge) = reply.strip_prefix("@RSYNCD: AUTHREQD ") {
        if unauthenticated {
            return Err("auth:authentication required".to_string());
        }
        let user = ctx.credential.username.as_deref().unwrap_or("");
        let pass = ctx.credential.password.as_deref().unwrap_or("");
        let digest = rsync_auth_hash(pass, challenge.trim(), protocol)?;
        write_line(reader.get_mut(), &format!("{user} {digest}")).await?;
        let result = read_line(&mut reader).await?;
        if result.starts_with("@RSYNCD: OK") {
            return Ok(AttemptSuccess::new("rsync access!"));
        }
        return Err(format!("auth:{result}"));
    }
    if reply.starts_with("@ERROR") {
        return Err(format!("auth:{reply}"));
    }
    Err(format!("unexpected reply: {reply}"))
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

async fn read_line<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> Result<String, String> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(|err| err.to_string())?;
    if line.is_empty() {
        return Err("connection closed".to_string());
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

async fn write_line<W: AsyncWriteExt + Unpin>(writer: &mut W, line: &str) -> Result<(), String> {
    writer
        .write_all(format!("{line}\n").as_bytes())
        .await
        .map_err(|err| err.to_string())
}

/// Parses `@RSYNCD: 31.0` into the numeric protocol version used for hashing.
///
/// # Parameters
///
/// - `greeting`: First server line.
///
/// # Returns
///
/// Protocol major version, e.g. `31`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::rsync::parse_greeting;
///
/// assert_eq!(parse_greeting("@RSYNCD: 31.0"), Some(31));
/// ```
pub fn parse_greeting(greeting: &str) -> Option<i32> {
    let rest = greeting.strip_prefix("@RSYNCD:")?.trim();
    let major = rest.split(['.', ' ']).next()?;
    major.parse().ok()
}

/// Computes the rsync daemon AUTHREQD response digest.
///
/// Modern daemons negotiate MD5, then base64-encode MD5(password || challenge)
/// without padding.
///
/// # Parameters
///
/// - `password`: Module secret.
/// - `challenge`: AUTHREQD challenge string.
/// - `_protocol`: Negotiated daemon protocol (reserved).
///
/// # Returns
///
/// Unpadded base64 digest.
///
/// # Errors
///
/// Returns an error if OpenSSL hashing fails.
///
/// # Examples
///
/// ```
/// use brute::protocol::rsync::rsync_auth_hash;
///
/// let digest = rsync_auth_hash("secret", "challenge", 31).expect("hash");
/// assert!(!digest.is_empty());
/// ```
pub fn rsync_auth_hash(password: &str, challenge: &str, _protocol: i32) -> Result<String, String> {
    let mut data = Vec::with_capacity(password.len() + challenge.len());
    data.extend_from_slice(password.as_bytes());
    data.extend_from_slice(challenge.as_bytes());
    let digest = hash(MessageDigest::md5(), &data).map_err(|err| err.to_string())?;
    Ok(openssl::base64::encode_block(&digest)
        .chars()
        .filter(|ch| *ch != '=' && *ch != '\n')
        .collect())
}

async fn probe_greeting(ctx: &TargetContext) -> Option<String> {
    let mut stream = connect_stream(&ctx.target_host, ctx.port(), ctx.target.proxy.as_ref())
        .await
        .ok()?;
    let mut reader = BufReader::new(&mut stream);
    let greeting = read_line(&mut reader).await.ok()?;
    parse_greeting(&greeting).map(|ver| format!("rsync daemon protocol {ver}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_greeting_reads_major_version() {
        assert_eq!(parse_greeting("@RSYNCD: 31.0"), Some(31));
        assert_eq!(parse_greeting("SSH-2.0"), None);
    }

    #[test]
    fn rsync_auth_hash_is_stable() {
        let a = rsync_auth_hash("pw", "ch", 31).unwrap();
        let b = rsync_auth_hash("pw", "ch", 31).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 22);
    }
}
