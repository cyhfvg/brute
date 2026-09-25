//! NFSv3 ONC RPC login probe (AUTH_NULL / AUTH_UNIX) and export dump (`-x`).
//!
//! Empty credentials use AUTH_NULL. Non-empty usernames are treated as UNIX uids
//! when numeric, otherwise uid 0. NFS has no password; a rejected AUTH_UNIX is
//! reported as auth failure.

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

const RPC_CALL: u32 = 0;
const RPC_REPLY: u32 = 1;
const RPC_VERSION: u32 = 2;
const MSG_ACCEPTED: u32 = 0;
const SUCCESS: u32 = 0;
const AUTH_NULL: u32 = 0;
const AUTH_UNIX: u32 = 1;
const NFS_PROGRAM: u32 = 100_003;
const NFS_VERSION: u32 = 3;
const MOUNT_PROGRAM: u32 = 100_005;
const MOUNT_VERSION: u32 = 3;
const PROC_NULL: u32 = 0;
const MOUNT_DUMP: u32 = 2;

/// NFS module configuration.
#[derive(Debug, Clone)]
pub struct NfsModule;

impl NfsModule {
    /// Creates a new NFS module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`NfsModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::nfs::NfsModule;
    ///
    /// let _module = NfsModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for NfsModule {
    fn name(&self) -> &'static str {
        "nfs"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_null(ctx)).await {
            Ok(true) => TargetProbe::Ready(Some("NFSv3".to_string())),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        match tokio::time::timeout(ctx.timeout(), attempt_once(ctx)).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(err)) if err.starts_with("auth:") => AttemptOutcome::failure(format!(
                "nfs auth failed: {}",
                err.trim_start_matches("auth:")
            )),
            Ok(Err(err)) => AttemptOutcome::error(format!("nfs transport failed: {err}")),
            Err(_) => AttemptOutcome::error("attempt timed out".to_string()),
        }
    }
}

/// Runs NFS NULL with AUTH_NULL or AUTH_UNIX, then optional MOUNT DUMP.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, String> {
    let unauthenticated = ctx.credential.username.as_deref().unwrap_or("").is_empty()
        && ctx.credential.password.as_deref().unwrap_or("").is_empty();
    let mut stream = connect_stream(
        &ctx.target_host,
        ctx.target.port.unwrap_or(ctx.protocol.default_port()),
        ctx.target.proxy.as_ref(),
    )
    .await?;
    let cred = if unauthenticated {
        auth_null()
    } else {
        auth_unix(parse_uid(ctx.credential.username.as_deref().unwrap_or("")))
    };
    let call = rpc_call(1, NFS_PROGRAM, NFS_VERSION, PROC_NULL, &cred, &[]);
    write_record(&mut stream, &call).await?;
    let reply = read_record(&mut stream).await?;
    accept_rpc(&reply)?;
    let message = if unauthenticated {
        "NFS unauthorized access!"
    } else {
        "NFS access!"
    };
    if let Some(command) = ctx.execute.as_deref() {
        let dump = rpc_call(2, MOUNT_PROGRAM, MOUNT_VERSION, MOUNT_DUMP, &cred, &[]);
        match write_record(&mut stream, &dump).await {
            Ok(()) => match read_record(&mut stream).await {
                Ok(body) => {
                    let text = format!("{command}: mount dump {} bytes", body.len());
                    return Ok(AttemptSuccess::with_command(message, text));
                }
                Err(err) => {
                    return Ok(AttemptSuccess::with_command_error(message, err));
                }
            },
            Err(err) => return Ok(AttemptSuccess::with_command_error(message, err)),
        }
    }
    Ok(AttemptSuccess::new(message))
}

fn parse_uid(username: &str) -> u32 {
    username.parse().unwrap_or(0)
}

/// Builds AUTH_NULL credentials.
///
/// # Parameters
///
/// None.
///
/// # Returns
///
/// XDR credential bytes.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::nfs::auth_null;
///
/// assert_eq!(auth_null().len(), 8);
/// ```
pub fn auth_null() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&AUTH_NULL.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out
}

/// Builds AUTH_UNIX credentials for `uid`.
///
/// # Parameters
///
/// - `uid`: UNIX user id.
///
/// # Returns
///
/// XDR credential bytes.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::nfs::auth_unix;
///
/// assert!(!auth_unix(0).is_empty());
/// ```
pub fn auth_unix(uid: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_be_bytes()); // stamp
    body.extend_from_slice(&encode_xdr_string("brute"));
    body.extend_from_slice(&uid.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes()); // gid
    body.extend_from_slice(&0u32.to_be_bytes()); // gids count
    let mut out = Vec::new();
    out.extend_from_slice(&AUTH_UNIX.to_be_bytes());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

fn encode_xdr_string(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

fn rpc_call(
    xid: u32,
    program: u32,
    version: u32,
    procedure: u32,
    cred: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&xid.to_be_bytes());
    out.extend_from_slice(&RPC_CALL.to_be_bytes());
    out.extend_from_slice(&RPC_VERSION.to_be_bytes());
    out.extend_from_slice(&program.to_be_bytes());
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&procedure.to_be_bytes());
    out.extend_from_slice(cred);
    out.extend_from_slice(&AUTH_NULL.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn accept_rpc(reply: &[u8]) -> Result<(), String> {
    if reply.len() < 24 {
        return Err("truncated rpc reply".to_string());
    }
    let msg_type = u32::from_be_bytes(reply[4..8].try_into().unwrap());
    if msg_type != RPC_REPLY {
        return Err("not an rpc reply".to_string());
    }
    let reply_stat = u32::from_be_bytes(reply[8..12].try_into().unwrap());
    if reply_stat != MSG_ACCEPTED {
        return Err("auth:rpc denied".to_string());
    }
    // skip verifier flavor+len at 12, then accept_stat
    if reply.len() < 24 {
        return Err("truncated rpc accept".to_string());
    }
    let flavor = u32::from_be_bytes(reply[12..16].try_into().unwrap());
    let vlen = u32::from_be_bytes(reply[16..20].try_into().unwrap()) as usize;
    let accept_off = 20 + vlen + padding(vlen);
    let accept_stat = reply
        .get(accept_off..accept_off + 4)
        .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
        .unwrap_or(SUCCESS);
    if accept_stat != SUCCESS {
        return Err(format!(
            "auth:rpc accept_stat {accept_stat} flavor {flavor}"
        ));
    }
    Ok(())
}

fn padding(len: usize) -> usize {
    (4 - (len % 4)) % 4
}

async fn write_record(stream: &mut TcpStream, payload: &[u8]) -> Result<(), String> {
    let marker = 0x8000_0000u32 | payload.len() as u32;
    stream
        .write_all(&marker.to_be_bytes())
        .await
        .map_err(|err| err.to_string())?;
    stream
        .write_all(payload)
        .await
        .map_err(|err| err.to_string())
}

async fn read_record(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut marker = [0u8; 4];
    stream
        .read_exact(&mut marker)
        .await
        .map_err(|err| err.to_string())?;
    let marker = u32::from_be_bytes(marker);
    let len = (marker & 0x7fff_ffff) as usize;
    if len == 0 || len > 1_000_000 {
        return Err(format!("invalid rpc record length {len}"));
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|err| err.to_string())?;
    Ok(body)
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

async fn probe_null(ctx: &TargetContext) -> bool {
    let mut stream =
        match connect_stream(&ctx.target_host, ctx.port(), ctx.target.proxy.as_ref()).await {
            Ok(stream) => stream,
            Err(_) => return false,
        };
    let call = rpc_call(1, NFS_PROGRAM, NFS_VERSION, PROC_NULL, &auth_null(), &[]);
    if write_record(&mut stream, &call).await.is_err() {
        return false;
    }
    read_record(&mut stream).await.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_null_is_eight_bytes() {
        assert_eq!(auth_null(), [0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn parse_uid_falls_back_to_root() {
        assert_eq!(parse_uid("0"), 0);
        assert_eq!(parse_uid("1000"), 1000);
        assert_eq!(parse_uid("admin"), 0);
    }
}
