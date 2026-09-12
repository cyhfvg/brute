//! ASCII and binary Memcached protocol helpers.

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

pub const OPCODE_GET: u8 = 0x00;
pub const OPCODE_SET: u8 = 0x01;
pub const OPCODE_DELETE: u8 = 0x04;
pub const OPCODE_FLUSH: u8 = 0x08;
pub const OPCODE_VERSION: u8 = 0x0b;
pub const OPCODE_STAT: u8 = 0x10;
pub const OPCODE_SASL_AUTH: u8 = 0x21;

pub const STATUS_OK: u16 = 0x0000;
pub const STATUS_NOT_FOUND: u16 = 0x0001;
pub const STATUS_AUTH_ERROR: u16 = 0x0020;
pub const STATUS_UNKNOWN_COMMAND: u16 = 0x0081;

const HEADER_LEN: usize = 24;
const ASCII_MAX_BODY: usize = 1_048_576;

/// One binary-protocol request or response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryPacket {
    pub opcode: u8,
    pub status: u16,
    pub extras: Vec<u8>,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// Extracts a compact banner from an ASCII `VERSION` response.
///
/// # Parameters
///
/// - `body`: Raw ASCII response, possibly including trailing `\\r\\n`.
///
/// # Returns
///
/// Compact banner such as `Memcached 1.6.37`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::memcached::parse_version_banner;
///
/// assert_eq!(
///     parse_version_banner("VERSION 1.6.37\r\n").as_deref(),
///     Some("Memcached 1.6.37")
/// );
/// ```
pub fn parse_version_banner(body: &str) -> Option<String> {
    let line = body.lines().next()?.trim();
    let version = line.strip_prefix("VERSION ")?.trim();
    if version.is_empty() {
        None
    } else {
        Some(format!("Memcached {version}"))
    }
}

/// Builds a SASL PLAIN payload (`NUL authzid NUL authcid NUL passwd` with empty authzid).
///
/// # Parameters
///
/// - `username`: SASL authentication identity.
/// - `password`: SASL password.
///
/// # Returns
///
/// Binary PLAIN payload bytes.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::memcached::sasl_plain_payload;
///
/// assert_eq!(sasl_plain_payload("admin", "secret"), b"\0admin\0secret");
/// ```
pub fn sasl_plain_payload(username: &str, password: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(username.len() + password.len() + 2);
    payload.push(0);
    payload.extend_from_slice(username.as_bytes());
    payload.push(0);
    payload.extend_from_slice(password.as_bytes());
    payload
}

/// Encodes a binary-protocol request packet.
///
/// # Parameters
///
/// - `opcode`: Memcached binary opcode.
/// - `extras`: Optional extras (for example SET flags/expiry).
/// - `key`: Command key bytes.
/// - `value`: Command value bytes.
///
/// # Returns
///
/// Wire bytes including the 24-byte header.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::memcached::{OPCODE_VERSION, encode_request};
///
/// let packet = encode_request(OPCODE_VERSION, b"", b"", b"");
/// assert_eq!(packet.len(), 24);
/// assert_eq!(packet[0], 0x80);
/// assert_eq!(packet[1], OPCODE_VERSION);
/// ```
pub fn encode_request(opcode: u8, extras: &[u8], key: &[u8], value: &[u8]) -> Vec<u8> {
    let body_len = extras.len() + key.len() + value.len();
    let mut buf = Vec::with_capacity(HEADER_LEN + body_len);
    buf.push(0x80);
    buf.push(opcode);
    buf.extend_from_slice(&(u16::try_from(key.len()).unwrap_or(u16::MAX)).to_be_bytes());
    buf.push(u8::try_from(extras.len()).unwrap_or(u8::MAX));
    buf.push(0);
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&(u32::try_from(body_len).unwrap_or(u32::MAX)).to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(&0u64.to_be_bytes());
    buf.extend_from_slice(extras);
    buf.extend_from_slice(key);
    buf.extend_from_slice(value);
    buf
}

/// Parses a 24-byte binary response header into lengths and status.
///
/// # Parameters
///
/// - `header`: Exactly 24 header bytes.
///
/// # Returns
///
/// `(opcode, status, extras_len, key_len, body_len)` when magic is `0x81`.
///
/// # Errors
///
/// Returns an error when the header is truncated or magic is not a response.
///
/// # Examples
///
/// ```
/// use brute::protocol::memcached::parse_binary_header;
///
/// let mut header = [0u8; 24];
/// header[0] = 0x81;
/// header[1] = 0x0b;
/// let parsed = parse_binary_header(&header).expect("header");
/// assert_eq!(parsed.0, 0x0b);
/// ```
pub fn parse_binary_header(header: &[u8]) -> Result<(u8, u16, usize, usize, usize), String> {
    if header.len() < HEADER_LEN {
        return Err("truncated memcached binary header".to_string());
    }
    if header[0] != 0x81 {
        return Err(format!("unexpected memcached magic 0x{:02x}", header[0]));
    }
    let opcode = header[1];
    let key_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    let extras_len = header[4] as usize;
    let status = u16::from_be_bytes([header[6], header[7]]);
    let body_len = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
    Ok((opcode, status, extras_len, key_len, body_len))
}

/// Reads one binary-protocol response.
///
/// # Parameters
///
/// - `stream`: Connected Memcached socket.
///
/// # Returns
///
/// Decoded [`BinaryPacket`].
///
/// # Errors
///
/// Returns a string error on I/O failure or a malformed header.
///
/// # Examples
///
/// ```ignore
/// let packet = read_binary_response(&mut stream).await?;
/// ```
pub async fn read_binary_response(stream: &mut TcpStream) -> Result<BinaryPacket, String> {
    let mut header = [0u8; HEADER_LEN];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|err| err.to_string())?;
    let (opcode, status, extras_len, key_len, body_len) = parse_binary_header(&header)?;
    if extras_len + key_len > body_len {
        return Err("memcached binary body shorter than extras+key".to_string());
    }
    let mut body = vec![0u8; body_len];
    if body_len > 0 {
        stream
            .read_exact(&mut body)
            .await
            .map_err(|err| err.to_string())?;
    }
    let extras = body.get(..extras_len).unwrap_or(&[]).to_vec();
    let key = body
        .get(extras_len..extras_len + key_len)
        .unwrap_or(&[])
        .to_vec();
    let value = body.get(extras_len + key_len..).unwrap_or(&[]).to_vec();
    Ok(BinaryPacket {
        opcode,
        status,
        extras,
        key,
        value,
    })
}

/// Reads an ASCII response until `END`, a one-line reply, or an error line.
///
/// # Parameters
///
/// - `stream`: Connected Memcached socket.
///
/// # Returns
///
/// UTF-8 (lossy) response text without a trailing terminator requirement.
///
/// # Errors
///
/// Returns a string error on I/O failure, empty peer close, or oversize body.
///
/// # Examples
///
/// ```ignore
/// let body = read_ascii_response(&mut stream).await?;
/// ```
pub async fn read_ascii_response(stream: &mut TcpStream) -> Result<String, String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|err| err.to_string())?;
        if n == 0 {
            if buf.is_empty() {
                return Err("connection closed".to_string());
            }
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > ASCII_MAX_BODY {
            return Err("memcached ASCII response too large".to_string());
        }
        if ascii_response_complete(&buf) {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Returns whether ASCII bytes form a complete Memcached reply.
///
/// # Parameters
///
/// - `buf`: Accumulated response bytes.
///
/// # Returns
///
/// `true` when a terminator (`END`, `ERROR`, `STORED`, `VERSION`, ...) is present.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::memcached::ascii_response_complete;
///
/// assert!(ascii_response_complete(b"VERSION 1.6.37\r\n"));
/// assert!(!ascii_response_complete(b"STAT pid 1\r\n"));
/// ```
pub fn ascii_response_complete(buf: &[u8]) -> bool {
    let text = String::from_utf8_lossy(buf);
    let trimmed = text.trim_end_matches(['\r', '\n']);
    if trimmed.ends_with("\nEND") || trimmed == "END" {
        return true;
    }
    let first = text.lines().next().unwrap_or("").trim_end();
    first.starts_with("VERSION ")
        || first.starts_with("ERROR")
        || first.starts_with("CLIENT_ERROR")
        || first.starts_with("SERVER_ERROR")
        || first == "STORED"
        || first == "DELETED"
        || first == "NOT_FOUND"
        || first == "EXISTS"
        || first == "NOT_STORED"
        || first == "TOUCHED"
        || first == "OK"
        || first.starts_with("VALUE ") && (trimmed.ends_with("\nEND") || trimmed == "END")
}

/// Returns whether an ASCII body indicates a successful unauthenticated probe.
///
/// # Parameters
///
/// - `body`: ASCII response text.
///
/// # Returns
///
/// `true` for `STAT`/`END`/`VERSION` success replies.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::memcached::ascii_looks_successful;
///
/// assert!(ascii_looks_successful("STAT pid 1\r\nEND\r\n"));
/// assert!(!ascii_looks_successful("ERROR\r\n"));
/// ```
pub fn ascii_looks_successful(body: &str) -> bool {
    let first = body.lines().next().unwrap_or("").trim_end();
    first.starts_with("STAT ") || first == "END" || first.starts_with("VERSION ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_banner_extracts_version() {
        assert_eq!(
            parse_version_banner("VERSION 1.6.37\r\n").as_deref(),
            Some("Memcached 1.6.37")
        );
        assert_eq!(parse_version_banner("ERROR\r\n"), None);
    }

    #[test]
    fn sasl_plain_payload_uses_empty_authzid() {
        assert_eq!(sasl_plain_payload("admin", "secret"), b"\0admin\0secret");
        assert_eq!(sasl_plain_payload("", "onlypass"), b"\0\0onlypass");
    }

    #[test]
    fn encode_request_sets_key_and_body_lengths() {
        let packet = encode_request(OPCODE_SASL_AUTH, b"", b"PLAIN", b"\0u\0p");
        assert_eq!(packet[0], 0x80);
        assert_eq!(packet[1], OPCODE_SASL_AUTH);
        assert_eq!(&packet[2..4], &5u16.to_be_bytes());
        assert_eq!(u32::from_be_bytes(packet[8..12].try_into().unwrap()), 9);
    }

    #[test]
    fn parse_binary_header_reads_status_and_body_len() {
        let mut header = [0u8; 24];
        header[0] = 0x81;
        header[1] = OPCODE_VERSION;
        header[7] = 0x20;
        header[11] = 4;
        let (opcode, status, extras, key, body) = parse_binary_header(&header).unwrap();
        assert_eq!(opcode, OPCODE_VERSION);
        assert_eq!(status, STATUS_AUTH_ERROR);
        assert_eq!((extras, key, body), (0, 0, 4));
    }
}
