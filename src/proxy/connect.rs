//! Async and blocking TCP tunnels through HTTP CONNECT / SOCKS5 proxies.

use std::{
    io::{Read, Write},
    net::{TcpStream as StdTcpStream, ToSocketAddrs},
    time::Duration,
};

use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

use super::config::{ProxyConfig, ProxyScheme};
use super::encode::base64_encode;

/// Opens an async TCP tunnel to `target_host:target_port` through `proxy`.
///
/// # Parameters
///
/// - `proxy`: Parsed proxy configuration.
/// - `target_host`: Final destination host (name or IP; not resolved locally for SOCKS5/HTTP CONNECT).
/// - `target_port`: Final destination port.
///
/// # Returns
///
/// Connected [`TcpStream`] whose peer is the target via the proxy tunnel.
///
/// # Errors
///
/// Returns a string error when the proxy is unreachable, authentication fails,
/// or the tunnel cannot be established.
///
/// # Examples
///
/// ```ignore
/// let stream = connect_async(&proxy, "10.0.0.5", 22).await?;
/// ```
pub async fn connect_async(
    proxy: &ProxyConfig,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, String> {
    match proxy.scheme {
        ProxyScheme::Http => http_connect_async(proxy, target_host, target_port).await,
        ProxyScheme::Socks5 => socks5_connect_async(proxy, target_host, target_port).await,
    }
}

/// Opens a blocking TCP tunnel to `target_host:target_port` through `proxy`.
///
/// # Parameters
///
/// - `proxy`: Parsed proxy configuration.
/// - `target_host`: Final destination host.
/// - `target_port`: Final destination port.
/// - `timeout`: Connect and handshake timeout applied to the proxy socket.
///
/// # Returns
///
/// Connected [`StdTcpStream`] tunneled to the target.
///
/// # Errors
///
/// Returns a string error on proxy connect/handshake failure.
///
/// # Examples
///
/// ```ignore
/// let stream = connect_std(&proxy, "10.0.0.5", 3389, Duration::from_secs(5))?;
/// ```
pub fn connect_std(
    proxy: &ProxyConfig,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> Result<StdTcpStream, String> {
    match proxy.scheme {
        ProxyScheme::Http => http_connect_std(proxy, target_host, target_port, timeout),
        ProxyScheme::Socks5 => socks5_connect_std(proxy, target_host, target_port, timeout),
    }
}

async fn http_connect_async(
    proxy: &ProxyConfig,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, String> {
    let mut stream = TcpStream::connect(proxy.addr())
        .await
        .map_err(|err| format!("http proxy connect failed: {err}"))?;

    match (&proxy.username, &proxy.password) {
        (Some(user), Some(pass)) => {
            async_http_proxy::http_connect_tokio_with_basic_auth(
                &mut stream,
                target_host,
                target_port,
                user,
                pass,
            )
            .await
            .map_err(|err| format!("http CONNECT failed: {err}"))?;
        }
        _ => {
            async_http_proxy::http_connect_tokio(&mut stream, target_host, target_port)
                .await
                .map_err(|err| format!("http CONNECT failed: {err}"))?;
        }
    }

    Ok(stream)
}

async fn socks5_connect_async(
    proxy: &ProxyConfig,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, String> {
    let proxy_addr = proxy.addr();
    let target = (target_host, target_port);

    let socks = if let (Some(user), Some(pass)) = (&proxy.username, &proxy.password) {
        Socks5Stream::connect_with_password(proxy_addr.as_str(), target, user, pass)
            .await
            .map_err(|err| format!("socks5 connect failed: {err}"))?
    } else {
        Socks5Stream::connect(proxy_addr.as_str(), target)
            .await
            .map_err(|err| format!("socks5 connect failed: {err}"))?
    };

    Ok(socks.into_inner())
}

fn http_connect_std(
    proxy: &ProxyConfig,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> Result<StdTcpStream, String> {
    let mut stream = std_connect_timeout(&proxy.addr(), timeout)?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let mut request = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
    );
    if let (Some(user), Some(pass)) = (&proxy.username, &proxy.password) {
        let token = base64_encode(&format!("{user}:{pass}"));
        request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    request.push_str("Proxy-Connection: Keep-Alive\r\n\r\n");

    stream
        .write_all(request.as_bytes())
        .map_err(|err| format!("http CONNECT write failed: {err}"))?;

    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        let n = stream
            .read(&mut byte)
            .map_err(|err| format!("http CONNECT read failed: {err}"))?;
        if n == 0 {
            return Err("http CONNECT closed before response".to_string());
        }
        buf.push(byte[0]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            return Err("http CONNECT response too large".to_string());
        }
    }

    let header = String::from_utf8_lossy(&buf);
    let status_line = header.lines().next().unwrap_or_default();
    if !status_line.contains(" 200 ") && !status_line.ends_with(" 200") {
        return Err(format!("http CONNECT rejected: {status_line}"));
    }

    Ok(stream)
}

fn socks5_connect_std(
    proxy: &ProxyConfig,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> Result<StdTcpStream, String> {
    let mut stream = std_connect_timeout(&proxy.addr(), timeout)?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    if proxy.has_credentials() {
        // greeting: ver=5, nmethods=1, method=username/password (0x02)
        stream
            .write_all(&[0x05, 0x01, 0x02])
            .map_err(|err| format!("socks5 greeting failed: {err}"))?;
    } else {
        // greeting: no-auth
        stream
            .write_all(&[0x05, 0x01, 0x00])
            .map_err(|err| format!("socks5 greeting failed: {err}"))?;
    }

    let mut resp = [0u8; 2];
    stream
        .read_exact(&mut resp)
        .map_err(|err| format!("socks5 greeting response failed: {err}"))?;
    if resp[0] != 0x05 {
        return Err(format!("socks5 invalid version in greeting: {}", resp[0]));
    }

    if proxy.has_credentials() {
        if resp[1] != 0x02 {
            return Err(format!(
                "socks5 server rejected username/password auth (method={})",
                resp[1]
            ));
        }
        let user = proxy.username.as_deref().unwrap_or("");
        let pass = proxy.password.as_deref().unwrap_or("");
        if user.len() > 255 || pass.len() > 255 {
            return Err("socks5 username/password too long".to_string());
        }
        let mut auth = Vec::with_capacity(3 + user.len() + pass.len());
        auth.push(0x01);
        auth.push(user.len() as u8);
        auth.extend_from_slice(user.as_bytes());
        auth.push(pass.len() as u8);
        auth.extend_from_slice(pass.as_bytes());
        stream
            .write_all(&auth)
            .map_err(|err| format!("socks5 auth write failed: {err}"))?;
        let mut auth_resp = [0u8; 2];
        stream
            .read_exact(&mut auth_resp)
            .map_err(|err| format!("socks5 auth response failed: {err}"))?;
        if auth_resp[1] != 0x00 {
            return Err("socks5 authentication failed".to_string());
        }
    } else if resp[1] != 0x00 {
        return Err(format!(
            "socks5 server rejected no-auth method (method={})",
            resp[1]
        ));
    }

    // CONNECT request with domain name address type.
    if target_host.len() > 255 {
        return Err("socks5 target host too long".to_string());
    }
    let mut req = Vec::with_capacity(7 + target_host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]);
    req.push(target_host.len() as u8);
    req.extend_from_slice(target_host.as_bytes());
    req.push((target_port >> 8) as u8);
    req.push((target_port & 0xff) as u8);
    stream
        .write_all(&req)
        .map_err(|err| format!("socks5 connect request failed: {err}"))?;

    let mut hdr = [0u8; 4];
    stream
        .read_exact(&mut hdr)
        .map_err(|err| format!("socks5 connect response failed: {err}"))?;
    if hdr[0] != 0x05 {
        return Err(format!("socks5 invalid version in reply: {}", hdr[0]));
    }
    if hdr[1] != 0x00 {
        return Err(format!("socks5 connect failed with code {}", hdr[1]));
    }
    match hdr[3] {
        0x01 => {
            let mut skip = [0u8; 4 + 2];
            stream
                .read_exact(&mut skip)
                .map_err(|err| format!("socks5 reply addr read failed: {err}"))?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .map_err(|err| format!("socks5 reply addr read failed: {err}"))?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            stream
                .read_exact(&mut skip)
                .map_err(|err| format!("socks5 reply addr read failed: {err}"))?;
        }
        0x04 => {
            let mut skip = [0u8; 16 + 2];
            stream
                .read_exact(&mut skip)
                .map_err(|err| format!("socks5 reply addr read failed: {err}"))?;
        }
        other => return Err(format!("socks5 unsupported atyp in reply: {other}")),
    }

    Ok(stream)
}

fn std_connect_timeout(addr: &str, timeout: Duration) -> Result<StdTcpStream, String> {
    let mut last_err = None;
    for socket_addr in addr
        .to_socket_addrs()
        .map_err(|err| format!("proxy resolve failed: {err}"))?
    {
        match StdTcpStream::connect_timeout(&socket_addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }
    Err(format!(
        "proxy connect failed: {}",
        last_err
            .map(|err| err.to_string())
            .unwrap_or_else(|| "no addresses".to_string())
    ))
}
