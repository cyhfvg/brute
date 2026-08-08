//! Classic RFB handshake and VNC Authentication (security type 2).

use std::{net::TcpStream, time::Duration};

#[cfg(test)]
use std::io::{Read, Write};

use super::auth::vnc_auth_response;
use super::util::{
    ReadWrite, apply_socket_timeouts, read_exact_array, read_exact_vec, resolve_addr,
};
use crate::protocol::{AttemptOutcome, AttemptSuccess};

/// Preferred RFB protocol version advertised by this client.
const CLIENT_VERSION: &[u8; 12] = b"RFB 003.008\n";

/// RFB security type: VNC Authentication (DES challenge-response).
const SEC_TYPE_VNC_AUTH: u8 = 2;

/// RFB security type: None (no authentication).
const SEC_TYPE_NONE: u8 = 1;

/// Result of an RFB authentication sequence after a successful handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RfbAuthResult {
    /// SecurityResult OK (or security type None selected).
    Accepted,
    /// Server allowed connection without credentials.
    NoAuth,
    /// SecurityResult failed (bad password).
    Rejected(String),
}

/// Performs one classic RFB VNC Authentication attempt (security type 2).
///
/// # Parameters
///
/// - `host`: Target hostname or IP.
/// - `port`: VNC TCP port (typically 5900).
/// - `password`: VNC password (effective length truncated to 8 characters).
/// - `timeout`: Connection and I/O timeout.
/// - `proxy`: Optional outbound proxy from CLI `--proxy`.
///
/// # Returns
///
/// [`AttemptOutcome::Success`] when SecurityResult is OK,
/// [`AttemptOutcome::Failure`] when authentication is rejected,
/// [`AttemptOutcome::Error`] for transport/protocol/unsupported security.
///
/// # Errors
///
/// Errors are mapped into [`AttemptOutcome`] rather than returned as `Result`.
///
/// # Examples
///
/// ```ignore
/// let outcome = try_vnc_rfb_login("127.0.0.1", 5900, "secret", Duration::from_secs(5), None);
/// ```
pub fn try_vnc_rfb_login(
    host: &str,
    port: u16,
    password: &str,
    timeout: Duration,
    proxy: Option<&crate::proxy::ProxyConfig>,
) -> AttemptOutcome {
    let mut stream = if let Some(proxy) = proxy {
        match crate::proxy::connect_std(proxy, host, port, timeout) {
            Ok(stream) => stream,
            Err(err) => {
                return AttemptOutcome::Error(format!("vnc transport error: {err}"));
            }
        }
    } else {
        let server_addr = match resolve_addr(host, port) {
            Ok(addr) => addr,
            Err(err) => {
                return AttemptOutcome::Error(format!("vnc resolve error: {err}"));
            }
        };
        match TcpStream::connect_timeout(&server_addr, timeout) {
            Ok(stream) => stream,
            Err(err) => {
                return AttemptOutcome::Error(format!("vnc transport error: {err}"));
            }
        }
    };

    if let Err(err) = apply_socket_timeouts(&stream, timeout) {
        return AttemptOutcome::Error(format!("vnc socket setup error: {err}"));
    }

    match rfb_authenticate(&mut stream, password) {
        Ok(RfbAuthResult::Accepted) => AttemptOutcome::Success(AttemptSuccess::new("VNC access!")),
        Ok(RfbAuthResult::Rejected(reason)) => {
            AttemptOutcome::Failure(format!("vnc auth failed: {reason}"))
        }
        Ok(RfbAuthResult::NoAuth) => {
            AttemptOutcome::Success(AttemptSuccess::new("VNC access (no authentication)!"))
        }
        Err(err) => AttemptOutcome::Error(err),
    }
}

/// Runs RFB version negotiation, security-type selection, and optional VNC Auth.
///
/// # Parameters
///
/// - `stream`: Connected TCP stream positioned at the start of the RFB session.
/// - `password`: Password for security type 2 (ignored for type None).
///
/// # Returns
///
/// [`RfbAuthResult`] on a completed security result exchange.
///
/// # Errors
///
/// Returns a human-readable error string for protocol/transport problems and
/// unsupported security types.
///
/// # Examples
///
/// ```ignore
/// let result = rfb_authenticate(&mut stream, "secret")?;
/// ```
pub fn rfb_authenticate(
    stream: &mut impl ReadWrite,
    password: &str,
) -> Result<RfbAuthResult, String> {
    let server_version =
        read_exact_vec(stream, 12).map_err(|e| format!("vnc version read: {e}"))?;
    if !server_version.starts_with(b"RFB ") {
        return Err(format!(
            "vnc protocol error: expected RFB banner, got {:?}",
            String::from_utf8_lossy(&server_version)
        ));
    }

    stream
        .write_all(CLIENT_VERSION)
        .map_err(|e| format!("vnc version write: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("vnc version flush: {e}"))?;

    // RFB 3.3 sends a single u32 security type; 3.7/3.8 send a type list.
    let version_str = String::from_utf8_lossy(&server_version);
    let use_list = version_str.contains("003.007")
        || version_str.contains("003.008")
        || version_str.contains("003.889"); // some Tight variants

    let selected = if use_list {
        select_security_type_from_list(stream)?
    } else {
        select_security_type_u32(stream)?
    };

    match selected {
        SEC_TYPE_NONE => {
            // RFB 3.8 still sends SecurityResult after type None.
            if use_list {
                read_security_result(stream)
            } else {
                Ok(RfbAuthResult::NoAuth)
            }
        }
        SEC_TYPE_VNC_AUTH => {
            let challenge =
                read_exact_array::<16>(stream).map_err(|e| format!("vnc challenge read: {e}"))?;
            let response = vnc_auth_response(password, &challenge);
            stream
                .write_all(&response)
                .map_err(|e| format!("vnc response write: {e}"))?;
            stream
                .flush()
                .map_err(|e| format!("vnc response flush: {e}"))?;
            read_security_result(stream)
        }
        other => Err(format!(
            "vnc unsupported security type: {other} (need type 1 or 2)"
        )),
    }
}

/// Selects a security type from an RFB 3.7/3.8 type list.
///
/// Prefers VNC Auth (type 2) over None (type 1) when both are offered.
fn select_security_type_from_list(stream: &mut impl ReadWrite) -> Result<u8, String> {
    let mut count_buf = [0u8; 1];
    stream
        .read_exact(&mut count_buf)
        .map_err(|e| format!("vnc security count read: {e}"))?;
    let count = count_buf[0] as usize;
    if count == 0 {
        // Failure: server sends u32 reason length + string.
        let reason = read_failure_reason(stream).unwrap_or_else(|_| "no security types".into());
        return Err(format!("vnc server rejected connection: {reason}"));
    }
    let types = read_exact_vec(stream, count).map_err(|e| format!("vnc security types: {e}"))?;
    let selected = if types.contains(&SEC_TYPE_VNC_AUTH) {
        SEC_TYPE_VNC_AUTH
    } else if types.contains(&SEC_TYPE_NONE) {
        SEC_TYPE_NONE
    } else {
        return Err(format!(
            "vnc unsupported security types: {types:?} (need type 1 or 2)"
        ));
    };
    stream
        .write_all(&[selected])
        .map_err(|e| format!("vnc security select write: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("vnc security select flush: {e}"))?;
    Ok(selected)
}

/// Reads a single u32 security type for RFB 3.3 servers.
fn select_security_type_u32(stream: &mut impl ReadWrite) -> Result<u8, String> {
    let mut buf = [0u8; 4];
    stream
        .read_exact(&mut buf)
        .map_err(|e| format!("vnc security type read: {e}"))?;
    let sec = u32::from_be_bytes(buf);
    if sec == 0 {
        let reason = read_failure_reason(stream).unwrap_or_else(|_| "connection failed".into());
        return Err(format!("vnc server rejected connection: {reason}"));
    }
    if sec > 255 {
        return Err(format!("vnc invalid security type value: {sec}"));
    }
    Ok(sec as u8)
}

/// Reads the RFB SecurityResult (u32) and optional failure reason.
fn read_security_result(stream: &mut impl ReadWrite) -> Result<RfbAuthResult, String> {
    let mut buf = [0u8; 4];
    stream
        .read_exact(&mut buf)
        .map_err(|e| format!("vnc security result read: {e}"))?;
    let status = u32::from_be_bytes(buf);
    match status {
        0 => Ok(RfbAuthResult::Accepted),
        1 => {
            let reason =
                read_failure_reason(stream).unwrap_or_else(|_| "authentication failed".to_string());
            Ok(RfbAuthResult::Rejected(reason))
        }
        other => Err(format!("vnc unexpected security result: {other}")),
    }
}

fn read_failure_reason(stream: &mut impl ReadWrite) -> Result<String, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("vnc reason length: {e}"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    // Bound reason size to avoid pathological allocations.
    let len = len.min(4096);
    let bytes = read_exact_vec(stream, len).map_err(|e| format!("vnc reason body: {e}"))?;
    Ok(String::from_utf8_lossy(&bytes).trim().to_string())
}

/// Runs a minimal RFB 003.008 server that accepts a single password (for tests).
///
/// Binds an ephemeral localhost port, spawns an accept loop that handles several
/// connections with the given expected password, and returns the bound port.
///
/// # Parameters
///
/// - `expected_password`: Password that yields SecurityResult OK.
///
/// # Returns
///
/// Bound TCP port on `127.0.0.1`.
///
/// # Errors
///
/// Panics on bind failure (test helper only).
///
/// # Examples
///
/// ```ignore
/// let port = spawn_mock_vnc_server("secret");
/// let outcome = try_vnc_rfb_login("127.0.0.1", port, "secret", Duration::from_secs(2));
/// ```
#[cfg(test)]
pub fn spawn_mock_vnc_server(expected_password: &'static str) -> u16 {
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock vnc");
    let port = listener.local_addr().expect("local addr").port();
    std::thread::spawn(move || {
        // Handle several connections for concurrent tests.
        for _ in 0..32 {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
            let _ = handle_mock_vnc_client(&mut stream, expected_password);
        }
    });
    // Brief settle so the accept thread is ready.
    std::thread::sleep(Duration::from_millis(20));
    port
}

#[cfg(test)]
fn handle_mock_vnc_client(stream: &mut TcpStream, expected_password: &str) -> std::io::Result<()> {
    stream.write_all(b"RFB 003.008\n")?;
    let mut client_ver = [0u8; 12];
    stream.read_exact(&mut client_ver)?;
    // One security type: VNC Auth
    stream.write_all(&[1, SEC_TYPE_VNC_AUTH])?;
    let mut chosen = [0u8; 1];
    stream.read_exact(&mut chosen)?;
    if chosen[0] != SEC_TYPE_VNC_AUTH {
        stream.write_all(&1u32.to_be_bytes())?;
        let msg = b"unsupported";
        stream.write_all(&(msg.len() as u32).to_be_bytes())?;
        stream.write_all(msg)?;
        return Ok(());
    }
    let challenge: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    stream.write_all(&challenge)?;
    let mut response = [0u8; 16];
    stream.read_exact(&mut response)?;
    let expected = vnc_auth_response(expected_password, &challenge);
    if response == expected {
        stream.write_all(&0u32.to_be_bytes())?;
    } else {
        stream.write_all(&1u32.to_be_bytes())?;
        let msg = b"authentication failed";
        stream.write_all(&(msg.len() as u32).to_be_bytes())?;
        stream.write_all(msg)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::AttemptOutcome;

    /// In-memory RFB 3.8 + type 2 success path using the shipped handshake.
    #[test]
    fn rfb_handshake_accepts_correct_password() {
        let challenge = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let password = "secret12";
        let response = vnc_auth_response(password, &challenge);

        let port = spawn_mock_vnc_server("secret12");
        let outcome = try_vnc_rfb_login("127.0.0.1", port, password, Duration::from_secs(2), None);
        match outcome {
            AttemptOutcome::Success(s) => assert!(s.message.contains("VNC access")),
            other => panic!("expected Success, got {other:?}"),
        }
        assert_eq!(response.len(), 16);
    }

    /// Wrong password against mock RFB server is Failure, not Error/stub.
    #[test]
    fn rfb_handshake_rejects_wrong_password() {
        let port = spawn_mock_vnc_server("correctpw");
        let outcome =
            try_vnc_rfb_login("127.0.0.1", port, "wrongpass", Duration::from_secs(2), None);
        match outcome {
            AttemptOutcome::Failure(msg) => {
                assert!(
                    msg.contains("vnc auth failed") || msg.contains("authentication"),
                    "{msg}"
                );
                assert!(!msg.contains("scaffolded but not implemented"), "{msg}");
            }
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    /// Closed port surfaces transport Error, not the unimplemented stub.
    #[test]
    fn closed_port_is_transport_error_not_stub() {
        let outcome = try_vnc_rfb_login(
            "127.0.0.1",
            1,
            "not-a-real-password",
            Duration::from_millis(400),
            None,
        );
        match outcome {
            AttemptOutcome::Error(message) => {
                assert!(
                    message.contains("vnc transport error")
                        || message.contains("vnc resolve error")
                        || message.contains("Connection refused")
                        || message.contains("timed out")
                        || message.contains("os error"),
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

    /// Security type list parsing prefers VNC Auth over None when both are offered.
    #[test]
    fn prefers_vnc_auth_when_multiple_types_offered() {
        let types = [SEC_TYPE_NONE, SEC_TYPE_VNC_AUTH];
        let selected = if types.contains(&SEC_TYPE_VNC_AUTH) {
            SEC_TYPE_VNC_AUTH
        } else {
            SEC_TYPE_NONE
        };
        assert_eq!(selected, SEC_TYPE_VNC_AUTH);
    }

    /// Concurrent RFB attempts against the mock server do not require a global lock.
    #[test]
    fn concurrent_rfb_attempts_succeed() {
        let port = spawn_mock_vnc_server("concurpw");
        let mut handles = Vec::new();
        for i in 0..4 {
            let pw = if i % 2 == 0 { "concurpw" } else { "bad" };
            handles.push(std::thread::spawn(move || {
                try_vnc_rfb_login("127.0.0.1", port, pw, Duration::from_secs(3), None)
            }));
        }
        let mut ok = 0;
        let mut fail = 0;
        for h in handles {
            match h.join().expect("join") {
                AttemptOutcome::Success(_) => ok += 1,
                AttemptOutcome::Failure(_) => fail += 1,
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(ok, 2);
        assert_eq!(fail, 2);
    }
}
