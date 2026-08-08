//! Web-VNC gateway path: RFB-banner probe and HTTPS HTTP Basic Auth.

use std::{io::Read, net::TcpStream, time::Duration};

use reqwest::{Client, StatusCode};

use super::util::{apply_socket_timeouts, resolve_addr};
use crate::protocol::{AttemptOutcome, AttemptSuccess};

/// Returns true when the peer does not present an RFB server banner (likely TLS/HTTP).
///
/// Classic VNC servers always send `RFB 00x.00y\n` first. Web gateways either wait for
/// a TLS ClientHello / HTTP request or speak non-RFB data.
///
/// # Parameters
///
/// - `host`: Target host.
/// - `port`: Target port.
/// - `timeout`: Connect and short peek timeout.
///
/// # Returns
///
/// `true` when RFB banner is absent and web Basic Auth should be tried first.
///
/// # Errors
///
/// Connect failures return `false` so the RFB path can still report the transport error.
///
/// # Examples
///
/// ```ignore
/// assert!(looks_like_tls_or_http_gateway("example", 443, Duration::from_secs(2)));
/// ```
pub fn looks_like_tls_or_http_gateway(
    host: &str,
    port: u16,
    timeout: Duration,
    proxy: Option<&crate::proxy::ProxyConfig>,
) -> bool {
    let mut stream = if let Some(proxy) = proxy {
        match crate::proxy::connect_std(proxy, host, port, timeout) {
            Ok(stream) => stream,
            Err(_) => return false,
        }
    } else {
        let Ok(addr) = resolve_addr(host, port) else {
            return false;
        };
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => stream,
            Err(_) => return false,
        }
    };
    if apply_socket_timeouts(&stream, timeout).is_err() {
        return false;
    }
    // VNC speaks first. Peek with a short budget so we do not stall every attempt.
    let peek_timeout = timeout.min(Duration::from_millis(800));
    let _ = stream.set_read_timeout(Some(peek_timeout));
    let mut buf = [0u8; 12];
    match stream.read(&mut buf) {
        Ok(n) if n >= 4 && buf.starts_with(b"RFB ") => false,
        Ok(n) if n > 0 && (buf[0] == 0x16 || buf.starts_with(b"HTTP")) => true,
        // No data / timeout: typical HTTPS listener waiting for ClientHello.
        Ok(0) | Err(_) => true,
        Ok(_) => true,
    }
}

/// HTTPS Basic Auth login used by web-fronted VNC services.
///
/// # Parameters
///
/// - `host`: Target hostname or IP.
/// - `port`: HTTPS port.
/// - `username`: HTTP Basic username.
/// - `password`: HTTP Basic password.
/// - `timeout`: Request timeout.
/// - `proxy`: Optional outbound proxy from CLI `--proxy`.
///
/// # Returns
///
/// Success on HTTP 2xx, Failure on 401/403, Error otherwise.
///
/// # Errors
///
/// Mapped into [`AttemptOutcome`].
///
/// # Examples
///
/// ```ignore
/// let outcome = try_vnc_web_basic_login(
///     "192.168.10.5", 30011, "u", "p", Duration::from_secs(5), None
/// ).await;
/// ```
pub async fn try_vnc_web_basic_login(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    timeout: Duration,
    proxy: Option<&crate::proxy::ProxyConfig>,
) -> AttemptOutcome {
    let url = format!("https://{host}:{port}/");
    let mut builder = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(timeout);
    if let Some(proxy) = proxy {
        match proxy.to_reqwest_proxy() {
            Ok(proxy) => builder = builder.proxy(proxy),
            Err(err) => {
                return AttemptOutcome::Error(format!("vnc web proxy config failed: {err}"));
            }
        }
    }
    let client = match builder.build() {
        Ok(client) => client,
        Err(err) => {
            return AttemptOutcome::Error(format!("vnc web client build failed: {err}"));
        }
    };

    match client
        .get(&url)
        .basic_auth(username, Some(password))
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            AttemptOutcome::Success(AttemptSuccess::new("VNC web access!"))
        }
        Ok(response)
            if response.status() == StatusCode::UNAUTHORIZED
                || response.status() == StatusCode::FORBIDDEN =>
        {
            AttemptOutcome::Failure(format!(
                "vnc web auth failed: HTTP {}",
                response.status().as_u16()
            ))
        }
        Ok(response) => {
            AttemptOutcome::Error(format!("vnc web unexpected status: {}", response.status()))
        }
        Err(err) => AttemptOutcome::Error(format!("vnc web request failed: {err}")),
    }
}
