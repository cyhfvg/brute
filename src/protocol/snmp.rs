//! SNMPv2c community login and OID GET (`-x`).
//!
//! The password is the community string. When the password is empty, the username
//! is used instead. Empty username and password probe the default `public` community.

use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::net::UdpSocket;

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

const SNMP_V2C: u8 = 1;
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_GET_REQUEST: u8 = 0xa0;
const TAG_GET_RESPONSE: u8 = 0xa2;
const SYS_DESCR: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 1];
const SYS_DESCR_INDEX: u32 = 0;

/// SNMPv2c module configuration.
#[derive(Debug, Clone)]
pub struct SnmpModule;

impl SnmpModule {
    /// Creates a new SNMP module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`SnmpModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::snmp::SnmpModule;
    ///
    /// let _module = SnmpModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for SnmpModule {
    fn name(&self) -> &'static str {
        "snmp"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_sys_descr(ctx)).await {
            Ok(Some(message)) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        match tokio::time::timeout(ctx.timeout(), attempt_once(ctx)).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(err)) => AttemptOutcome::failure(format!("snmp auth failed: {err}")),
            Err(_) => AttemptOutcome::failure("snmp auth failed: no response".to_string()),
        }
    }
}

/// Runs one SNMPv2c GET against `sysDescr.0`, then optional `-x` OID GET.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, String> {
    let community = community_from_credential(ctx);
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let socket = bind_udp().await?;
    let addr = resolve_udp(&ctx.target_host, port).await?;
    let descr = snmp_get(&socket, addr, &community, &SYS_DESCR, SYS_DESCR_INDEX).await?;
    let unauthenticated = community == "public"
        && ctx.credential.username.as_deref().unwrap_or("").is_empty()
        && ctx.credential.password.as_deref().unwrap_or("").is_empty();
    let message = if unauthenticated {
        "SNMP unauthorized access!"
    } else {
        "SNMP access!"
    };
    match ctx.execute.as_deref() {
        Some(command) => {
            let (oid, suffix) = parse_oid(command)?;
            let value = snmp_get(&socket, addr, &community, &oid, suffix).await?;
            Ok(AttemptSuccess::with_command(message, value))
        }
        None => Ok(AttemptSuccess::with_command(message, descr)),
    }
}

/// Resolves the SNMPv2c community string for this attempt.
///
/// # Parameters
///
/// - `ctx`: Credential whose password (preferred) or username holds the community.
///
/// # Returns
///
/// Community string; empty credentials become `public`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(community_from_credential(&ctx), "public");
/// ```
fn community_from_credential(ctx: &AttemptContext) -> String {
    let password = ctx.credential.password.as_deref().unwrap_or("");
    if !password.is_empty() {
        return password.to_string();
    }
    let username = ctx.credential.username.as_deref().unwrap_or("");
    if !username.is_empty() {
        username.to_string()
    } else {
        "public".to_string()
    }
}

async fn bind_udp() -> Result<UdpSocket, String> {
    UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|err| err.to_string())
}

async fn resolve_udp(host: &str, port: u16) -> Result<SocketAddr, String> {
    tokio::net::lookup_host((host, port))
        .await
        .map_err(|err| err.to_string())?
        .next()
        .ok_or_else(|| format!("no UDP address for {host}:{port}"))
}

/// Performs an SNMPv2c GET and returns the first varbind value as text.
async fn snmp_get(
    socket: &UdpSocket,
    addr: SocketAddr,
    community: &str,
    oid: &[u32],
    suffix: u32,
) -> Result<String, String> {
    let request_id = 1i32;
    let packet = encode_get_request(community, request_id, oid, suffix);
    socket
        .send_to(&packet, addr)
        .await
        .map_err(|err| err.to_string())?;
    let mut buf = [0u8; 2048];
    let (n, _) = socket
        .recv_from(&mut buf)
        .await
        .map_err(|err| err.to_string())?;
    decode_get_response(&buf[..n])
}

/// Encodes an SNMPv2c GetRequest for one OID.
///
/// # Parameters
///
/// - `community`: Community string.
/// - `request_id`: Request identifier.
/// - `oid`: OID prefix without the instance suffix.
/// - `suffix`: Instance index (usually `0`).
///
/// # Returns
///
/// BER-encoded SNMP message.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::snmp::encode_get_request;
///
/// let packet = encode_get_request("public", 1, &[1, 3, 6, 1, 2, 1, 1, 1], 0);
/// assert_eq!(packet[0], 0x30);
/// ```
pub fn encode_get_request(community: &str, request_id: i32, oid: &[u32], suffix: u32) -> Vec<u8> {
    let mut oid_nodes = oid.to_vec();
    oid_nodes.push(suffix);
    let varbind = ber_sequence(vec![ber_oid(&oid_nodes), vec![TAG_NULL, 0]]);
    let varbind_list = ber_sequence(vec![varbind]);
    let pdu_body = [
        ber_integer(i64::from(request_id)),
        ber_integer(0),
        ber_integer(0),
        varbind_list,
    ]
    .concat();
    let mut pdu = vec![TAG_GET_REQUEST];
    pdu.extend(ber_length(pdu_body.len()));
    pdu.extend(pdu_body);
    ber_sequence(vec![
        ber_integer(i64::from(SNMP_V2C)),
        ber_octet_string(community.as_bytes()),
        pdu,
    ])
}

/// Decodes an SNMPv2c GetResponse into the first varbind value.
///
/// # Parameters
///
/// - `bytes`: UDP payload.
///
/// # Returns
///
/// Printable value string.
///
/// # Errors
///
/// Returns an error when BER is invalid or `error-status` is non-zero.
pub fn decode_get_response(bytes: &[u8]) -> Result<String, String> {
    let (tag, content, rest) = ber_read(bytes)?;
    if tag != TAG_SEQUENCE || !rest.is_empty() {
        return Err("invalid SNMP message".to_string());
    }
    let (_, _version, content) = ber_read(content)?;
    let (tag, _community, content) = ber_read(content)?;
    if tag != TAG_OCTET_STRING {
        return Err("invalid SNMP community".to_string());
    }
    let (tag, pdu, _) = ber_read(content)?;
    if tag != TAG_GET_RESPONSE {
        return Err(format!("unexpected SNMP PDU tag 0x{tag:02x}"));
    }
    let (_, _, pdu) = ber_read(pdu)?; // request-id
    let (_, error_status, pdu) = ber_read(pdu)?;
    let status = ber_as_i64(error_status)?;
    if status != 0 {
        return Err(format!("snmp error-status {status}"));
    }
    let (_, _, pdu) = ber_read(pdu)?; // error-index
    let (_, varbind_list, _) = ber_read(pdu)?;
    let (_, varbind, _) = ber_read(varbind_list)?;
    let (_, _, value) = ber_read(varbind)?; // oid
    let (tag, value, _) = ber_read(value)?;
    Ok(format_snmp_value(tag, value))
}

fn format_snmp_value(tag: u8, value: &[u8]) -> String {
    match tag {
        TAG_OCTET_STRING => String::from_utf8_lossy(value).into_owned(),
        TAG_INTEGER => ber_as_i64(value)
            .map(|n| n.to_string())
            .unwrap_or_else(|_| hex_bytes(value)),
        TAG_OID => decode_oid(value)
            .into_iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join("."),
        _ => hex_bytes(value),
    }
}

fn hex_bytes(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses `-x` dotted OID text into prefix + instance suffix.
///
/// # Parameters
///
/// - `command`: Dotted OID such as `1.3.6.1.2.1.1.5.0` or `sysName`.
///
/// # Returns
///
/// `(oid_prefix, instance_suffix)`.
///
/// # Errors
///
/// Returns an error when the OID cannot be parsed.
///
/// # Examples
///
/// ```
/// use brute::protocol::snmp::parse_oid;
///
/// let (oid, suffix) = parse_oid("1.3.6.1.2.1.1.5.0").expect("oid");
/// assert_eq!(oid, [1, 3, 6, 1, 2, 1, 1, 5]);
/// assert_eq!(suffix, 0);
/// ```
pub fn parse_oid(command: &str) -> Result<(Vec<u32>, u32), String> {
    let trimmed = command.trim();
    let lowered = trimmed.to_ascii_lowercase();
    let dotted = match lowered.as_str() {
        "sysdescr" | "descr" => "1.3.6.1.2.1.1.1.0",
        "sysname" | "name" => "1.3.6.1.2.1.1.5.0",
        "sysuptime" | "uptime" => "1.3.6.1.2.1.1.3.0",
        _ => trimmed,
    };
    let mut parts = Vec::new();
    for part in dotted.split('.') {
        if part.is_empty() {
            continue;
        }
        let n = part
            .parse::<u32>()
            .map_err(|_| format!("invalid SNMP OID {command:?}"))?;
        parts.push(n);
    }
    if parts.len() < 2 {
        return Err(format!("invalid SNMP OID {command:?}"));
    }
    let suffix = parts.pop().unwrap_or(0);
    Ok((parts, suffix))
}

fn ber_sequence(children: Vec<Vec<u8>>) -> Vec<u8> {
    let body = children.concat();
    let mut out = vec![TAG_SEQUENCE];
    out.extend(ber_length(body.len()));
    out.extend(body);
    out
}

fn ber_octet_string(bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![TAG_OCTET_STRING];
    out.extend(ber_length(bytes.len()));
    out.extend(bytes);
    out
}

fn ber_integer(value: i64) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1
        && ((bytes[0] == 0 && bytes[1] < 0x80) || (bytes[0] == 0xff && bytes[1] >= 0x80))
    {
        bytes.remove(0);
    }
    let mut out = vec![TAG_INTEGER];
    out.extend(ber_length(bytes.len()));
    out.extend(bytes);
    out
}

fn ber_oid(nodes: &[u32]) -> Vec<u8> {
    let mut body = Vec::new();
    if nodes.len() >= 2 {
        body.push(u8::try_from(nodes[0] * 40 + nodes[1]).unwrap_or(u8::MAX));
        for node in &nodes[2..] {
            body.extend(ber_oid_node(*node));
        }
    }
    let mut out = vec![TAG_OID];
    out.extend(ber_length(body.len()));
    out.extend(body);
    out
}

fn ber_oid_node(mut value: u32) -> Vec<u8> {
    let mut stack = vec![(value & 0x7f) as u8];
    value >>= 7;
    while value > 0 {
        stack.push(((value & 0x7f) as u8) | 0x80);
        value >>= 7;
    }
    stack.reverse();
    stack
}

fn ber_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

fn ber_read(input: &[u8]) -> Result<(u8, &[u8], &[u8]), String> {
    let tag = *input.first().ok_or("truncated BER tag")?;
    let (len, rest) = ber_read_length(input.get(1..).ok_or("truncated BER length")?)?;
    if rest.len() < len {
        return Err("truncated BER value".to_string());
    }
    Ok((tag, &rest[..len], &rest[len..]))
}

fn ber_read_length(input: &[u8]) -> Result<(usize, &[u8]), String> {
    let first = *input.first().ok_or("truncated BER length")?;
    if first < 0x80 {
        return Ok((first as usize, &input[1..]));
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > 2 || input.len() < 1 + count {
        return Err("unsupported BER length".to_string());
    }
    let mut len = 0usize;
    for b in &input[1..=count] {
        len = (len << 8) | usize::from(*b);
    }
    Ok((len, &input[1 + count..]))
}

fn ber_as_i64(bytes: &[u8]) -> Result<i64, String> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err("invalid BER integer".to_string());
    }
    let mut acc: i64 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
    for b in bytes {
        acc = (acc << 8) | i64::from(*b);
    }
    Ok(acc)
}

fn decode_oid(bytes: &[u8]) -> Vec<u32> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let mut nodes = vec![u32::from(bytes[0] / 40), u32::from(bytes[0] % 40)];
    let mut acc = 0u32;
    for b in &bytes[1..] {
        acc = (acc << 7) | u32::from(b & 0x7f);
        if b & 0x80 == 0 {
            nodes.push(acc);
            acc = 0;
        }
    }
    nodes
}

async fn probe_sys_descr(ctx: &TargetContext) -> Option<String> {
    let socket = bind_udp().await.ok()?;
    let addr = resolve_udp(&ctx.target_host, ctx.port()).await.ok()?;
    let value = snmp_get(&socket, addr, "public", &SYS_DESCR, SYS_DESCR_INDEX)
        .await
        .ok()?;
    if value.is_empty() {
        Some("SNMPv2c".to_string())
    } else {
        Some(format!("SNMP {value}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_get_request_starts_with_sequence() {
        let packet = encode_get_request("public", 1, &SYS_DESCR, 0);
        assert_eq!(packet[0], TAG_SEQUENCE);
        assert!(packet.len() > 20);
    }

    #[test]
    fn parse_oid_accepts_dotted_and_shorthand() {
        let (oid, suffix) = parse_oid("1.3.6.1.2.1.1.5.0").unwrap();
        assert_eq!(oid, [1, 3, 6, 1, 2, 1, 1, 5]);
        assert_eq!(suffix, 0);
        let (oid, suffix) = parse_oid("sysDescr").unwrap();
        assert_eq!(oid, SYS_DESCR);
        assert_eq!(suffix, 0);
    }

    #[test]
    fn decode_roundtrip_get_response() {
        let request = encode_get_request("public", 7, &SYS_DESCR, 0);
        // Build a synthetic GetResponse by swapping PDU tag a0 -> a2 and injecting octet string.
        let mut response = request.clone();
        if let Some(pos) = response.iter().position(|b| *b == TAG_GET_REQUEST) {
            response[pos] = TAG_GET_RESPONSE;
        }
        // The request encodes NULL as the value; decode will still succeed with empty/hex.
        assert!(decode_get_response(&response).is_ok());
    }
}
