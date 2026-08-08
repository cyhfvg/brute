//! Percent-encoding and Base64 helpers used by proxy URL and HTTP CONNECT auth.

/// Decodes a percent-encoded (and `+` → space) URL userinfo component.
///
/// # Parameters
///
/// - `input`: Percent-encoded text from a URL username or password field.
///
/// # Returns
///
/// Decoded UTF-8 string.
///
/// # Errors
///
/// Returns an error string for truncated escapes, invalid hex, or non-UTF-8 output.
pub(crate) fn urlencoding_decode(input: &str) -> Result<String, String> {
    let bytes = percent_encoding_decode(input.as_bytes())?;
    String::from_utf8(bytes).map_err(|err| err.to_string())
}

/// Decodes raw percent-encoded bytes.
fn percent_encoding_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'%' => {
                if i + 2 >= input.len() {
                    return Err("truncated percent-escape".to_string());
                }
                let h = from_hex(input[i + 1])?;
                let l = from_hex(input[i + 2])?;
                out.push((h << 4) | l);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// Parses one ASCII hex digit.
fn from_hex(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("invalid hex digit in percent-encoding".to_string()),
    }
}

/// Percent-encodes a URL userinfo component (username or password).
///
/// # Parameters
///
/// - `input`: Raw credential fragment.
///
/// # Returns
///
/// Percent-encoded string safe for embedding in a proxy URL.
pub(crate) fn percent_encode_userinfo(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Minimal Base64 encoder for Proxy-Authorization (avoids an extra direct dep).
///
/// # Parameters
///
/// - `input`: Raw bytes as UTF-8 text (typically `user:pass`).
///
/// # Returns
///
/// Standard Base64 string with `=` padding.
pub(crate) fn base64_encode(input: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        let b1 = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
        let b2 = if i + 2 < bytes.len() { bytes[i + 2] } else { 0 };
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if i + 1 < bytes.len() {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < bytes.len() {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_encode_matches_known_vector() {
        assert_eq!(base64_encode("user:pass"), "dXNlcjpwYXNz");
    }

    #[test]
    fn percent_roundtrip_for_special_chars() {
        let encoded = percent_encode_userinfo("u@s:p");
        assert_eq!(encoded, "u%40s%3Ap");
        assert_eq!(urlencoding_decode(&encoded).unwrap(), "u@s:p");
    }
}
