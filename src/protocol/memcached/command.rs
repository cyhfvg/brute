//! Post-auth Memcached command execution for `-x`.

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::protocol::AttemptSuccess;

use super::codec::{
    OPCODE_DELETE, OPCODE_FLUSH, OPCODE_GET, OPCODE_SET, OPCODE_STAT, OPCODE_VERSION,
    STATUS_NOT_FOUND, STATUS_OK, encode_request, read_binary_response,
};

/// Executes a Memcached command after authentication succeeds.
///
/// Dispatches `stats`/`version`/`get`/`set`/`delete`/`flush_all` over the binary protocol.
///
/// # Parameters
///
/// - `stream`: Authenticated Memcached socket.
/// - `command`: CLI `-x` string.
/// - `success_message`: Login banner preserved when the command succeeds or fails.
///
/// # Returns
///
/// [`AttemptSuccess`] with command output on success.
///
/// # Errors
///
/// Returns a string error when the command is empty, unsupported, or rejected.
/// Authentication remains successful; callers wrap this as a command failure.
///
/// # Examples
///
/// ```ignore
/// let success = execute_memcached_command(&mut stream, "stats", "Memcached access!").await?;
/// ```
pub async fn execute_memcached_command(
    stream: &mut TcpStream,
    command: &str,
    success_message: &str,
) -> Result<AttemptSuccess, String> {
    let output = execute_binary_command(stream, command).await?;
    Ok(AttemptSuccess::with_command(success_message, output))
}

/// Dispatches a small set of binary-protocol commands after SASL auth.
///
/// # Parameters
///
/// - `stream`: SASL-authenticated Memcached socket.
/// - `command`: Shell-like command string (`stats`, `version`, `get`, `set`, `delete`, `flush_all`).
///
/// # Returns
///
/// Formatted command output.
///
/// # Errors
///
/// Returns an error when the command is empty, unknown, or the server rejects it.
///
/// # Examples
///
/// ```ignore
/// let body = execute_binary_command(&mut stream, "get mykey").await?;
/// ```
async fn execute_binary_command(stream: &mut TcpStream, command: &str) -> Result<String, String> {
    let parts = split_command(command);
    let Some((name, args)) = parts.split_first() else {
        return Err("empty memcached command".to_string());
    };
    match name.to_ascii_lowercase().as_str() {
        "stats" | "stat" => binary_stats(stream, args.first().map(String::as_str)).await,
        "version" => binary_version(stream).await,
        "get" | "gets" => {
            let key = args
                .first()
                .ok_or_else(|| "get requires a key".to_string())?;
            binary_get(stream, key).await
        }
        "set" | "add" => {
            let key = args
                .first()
                .ok_or_else(|| "set requires a key and value".to_string())?;
            let value = args
                .get(1)
                .ok_or_else(|| "set requires a key and value".to_string())?;
            binary_set(stream, key, value).await
        }
        "delete" => {
            let key = args
                .first()
                .ok_or_else(|| "delete requires a key".to_string())?;
            binary_delete(stream, key).await
        }
        "flush_all" | "flush" => binary_flush(stream).await,
        other => Err(format!(
            "unsupported memcached command {other:?}; expected stats, version, get, set, delete, flush_all"
        )),
    }
}

/// Reads all STAT packets until the empty terminator packet.
///
/// # Parameters
///
/// - `stream`: SASL-authenticated socket.
/// - `key`: Optional STAT subtree key (`items`, `settings`, ...).
///
/// # Returns
///
/// Newline-joined `STAT name value` lines, or `END` when empty.
///
/// # Errors
///
/// Returns an error on I/O failure or non-OK status.
async fn binary_stats(stream: &mut TcpStream, key: Option<&str>) -> Result<String, String> {
    let key_bytes = key.unwrap_or("").as_bytes();
    stream
        .write_all(&encode_request(OPCODE_STAT, b"", key_bytes, b""))
        .await
        .map_err(|err| err.to_string())?;
    let mut lines = Vec::new();
    loop {
        let packet = read_binary_response(stream).await?;
        if packet.status != STATUS_OK {
            return Err(format_status(packet.status, &packet.value));
        }
        if packet.key.is_empty() && packet.value.is_empty() {
            break;
        }
        lines.push(format!(
            "STAT {} {}",
            String::from_utf8_lossy(&packet.key),
            String::from_utf8_lossy(&packet.value)
        ));
    }
    if lines.is_empty() {
        Ok("END".to_string())
    } else {
        Ok(lines.join("\n"))
    }
}

/// Reads the binary VERSION value.
///
/// # Parameters
///
/// - `stream`: SASL-authenticated socket.
///
/// # Returns
///
/// `VERSION <semver>` text.
///
/// # Errors
///
/// Returns an error on I/O failure or non-OK status.
async fn binary_version(stream: &mut TcpStream) -> Result<String, String> {
    stream
        .write_all(&encode_request(OPCODE_VERSION, b"", b"", b""))
        .await
        .map_err(|err| err.to_string())?;
    let packet = read_binary_response(stream).await?;
    if packet.status != STATUS_OK {
        return Err(format_status(packet.status, &packet.value));
    }
    Ok(format!(
        "VERSION {}",
        String::from_utf8_lossy(&packet.value)
    ))
}

/// Fetches one key with binary GET.
///
/// # Parameters
///
/// - `stream`: SASL-authenticated socket.
/// - `key`: Cache key.
///
/// # Returns
///
/// Value text, or `NOT_FOUND`.
///
/// # Errors
///
/// Returns an error on I/O failure or unexpected status.
async fn binary_get(stream: &mut TcpStream, key: &str) -> Result<String, String> {
    stream
        .write_all(&encode_request(OPCODE_GET, b"", key.as_bytes(), b""))
        .await
        .map_err(|err| err.to_string())?;
    let packet = read_binary_response(stream).await?;
    match packet.status {
        STATUS_OK => Ok(bytes_as_text(&packet.value)),
        STATUS_NOT_FOUND => Ok("NOT_FOUND".to_string()),
        other => Err(format_status(other, &packet.value)),
    }
}

/// Stores one key with binary SET (flags=0, expiry=0).
///
/// # Parameters
///
/// - `stream`: SASL-authenticated socket.
/// - `key`: Cache key.
/// - `value`: Value string.
///
/// # Returns
///
/// `STORED` on success.
///
/// # Errors
///
/// Returns an error on I/O failure or non-OK status.
async fn binary_set(stream: &mut TcpStream, key: &str, value: &str) -> Result<String, String> {
    let mut extras = [0u8; 8];
    extras[..4].copy_from_slice(&0u32.to_be_bytes());
    extras[4..].copy_from_slice(&0u32.to_be_bytes());
    stream
        .write_all(&encode_request(
            OPCODE_SET,
            &extras,
            key.as_bytes(),
            value.as_bytes(),
        ))
        .await
        .map_err(|err| err.to_string())?;
    let packet = read_binary_response(stream).await?;
    if packet.status != STATUS_OK {
        return Err(format_status(packet.status, &packet.value));
    }
    Ok("STORED".to_string())
}

/// Deletes one key with binary DELETE.
///
/// # Parameters
///
/// - `stream`: SASL-authenticated socket.
/// - `key`: Cache key.
///
/// # Returns
///
/// `DELETED` or `NOT_FOUND`.
///
/// # Errors
///
/// Returns an error on I/O failure or unexpected status.
async fn binary_delete(stream: &mut TcpStream, key: &str) -> Result<String, String> {
    stream
        .write_all(&encode_request(OPCODE_DELETE, b"", key.as_bytes(), b""))
        .await
        .map_err(|err| err.to_string())?;
    let packet = read_binary_response(stream).await?;
    match packet.status {
        STATUS_OK => Ok("DELETED".to_string()),
        STATUS_NOT_FOUND => Ok("NOT_FOUND".to_string()),
        other => Err(format_status(other, &packet.value)),
    }
}

/// Issues binary FLUSH with no delay.
///
/// # Parameters
///
/// - `stream`: SASL-authenticated socket.
///
/// # Returns
///
/// `OK` on success.
///
/// # Errors
///
/// Returns an error on I/O failure or non-OK status.
async fn binary_flush(stream: &mut TcpStream) -> Result<String, String> {
    stream
        .write_all(&encode_request(OPCODE_FLUSH, b"", b"", b""))
        .await
        .map_err(|err| err.to_string())?;
    let packet = read_binary_response(stream).await?;
    if packet.status != STATUS_OK {
        return Err(format_status(packet.status, &packet.value));
    }
    Ok("OK".to_string())
}

/// Formats a binary status code plus optional payload for error messages.
///
/// # Parameters
///
/// - `status`: Binary response status.
/// - `value`: Optional error payload.
///
/// # Returns
///
/// Human-readable status line.
///
/// # Errors
///
/// This function does not return errors.
fn format_status(status: u16, value: &[u8]) -> String {
    let detail = String::from_utf8_lossy(value);
    if detail.is_empty() {
        format!("memcached status 0x{status:04x}")
    } else {
        format!("memcached status 0x{status:04x}: {detail}")
    }
}

/// Renders value bytes as UTF-8 text, falling back to escaped bytes.
///
/// # Parameters
///
/// - `bytes`: Cache value.
///
/// # Returns
///
/// Lossy UTF-8 string.
///
/// # Errors
///
/// This function does not return errors.
fn bytes_as_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Splits simple command strings while preserving quoted whitespace.
///
/// # Parameters
///
/// - `command`: CLI `-x` text.
///
/// # Returns
///
/// Token list; quotes are stripped from quoted tokens.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::memcached::split_command;
///
/// assert_eq!(split_command("set mykey 'hello world'"), ["set", "mykey", "hello world"]);
/// ```
pub fn split_command(command: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in command.chars() {
        match ch {
            '"' | '\'' if !in_quotes => in_quotes = true,
            '"' | '\'' if in_quotes => in_quotes = false,
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    parts.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_command_preserves_quoted_value() {
        assert_eq!(
            split_command("set mykey 'hello world'"),
            ["set", "mykey", "hello world"]
        );
        assert_eq!(split_command("stats"), ["stats"]);
    }
}
