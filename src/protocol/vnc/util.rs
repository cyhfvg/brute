//! Shared VNC transport helpers: address resolution, socket timeouts, target probe.

use std::{
    io::{self, Read},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    time::Duration,
};

/// Combined read/write trait for RFB helpers (enables in-memory test streams).
pub trait ReadWrite: Read + io::Write {}
impl<T: Read + io::Write> ReadWrite for T {}

/// Reads exactly `len` bytes from `stream`.
///
/// # Parameters
///
/// - `stream`: Readable stream.
/// - `len`: Number of bytes to read.
///
/// # Returns
///
/// Buffer of length `len` on success.
///
/// # Errors
///
/// Propagates underlying I/O errors (including unexpected EOF).
///
/// # Examples
///
/// ```ignore
/// let bytes = read_exact_vec(&mut stream, 12)?;
/// ```
pub fn read_exact_vec(stream: &mut impl Read, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// Reads exactly `N` bytes into a fixed array.
///
/// # Parameters
///
/// - `stream`: Readable stream.
///
/// # Returns
///
/// `[u8; N]` on success.
///
/// # Errors
///
/// Propagates underlying I/O errors.
///
/// # Examples
///
/// ```ignore
/// let challenge: [u8; 16] = read_exact_array(&mut stream)?;
/// ```
pub fn read_exact_array<const N: usize>(stream: &mut impl Read) -> io::Result<[u8; N]> {
    let mut buf = [0u8; N];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// Resolves `host:port` to the first available [`SocketAddr`].
///
/// # Parameters
///
/// - `host`: Hostname or IP literal.
/// - `port`: TCP port.
///
/// # Returns
///
/// First resolved socket address.
///
/// # Errors
///
/// Returns I/O error when resolution fails or yields no addresses.
///
/// # Examples
///
/// ```ignore
/// let addr = resolve_addr("127.0.0.1", 5900)?;
/// ```
pub fn resolve_addr(host: &str, port: u16) -> io::Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no socket address resolved"))
}

/// Applies read/write timeouts and TCP_NODELAY on a connected stream.
///
/// # Parameters
///
/// - `stream`: Connected TCP stream.
/// - `timeout`: I/O timeout for both directions.
///
/// # Returns
///
/// `Ok(())` when socket options are applied.
///
/// # Errors
///
/// Propagates socket option failures.
///
/// # Examples
///
/// ```ignore
/// apply_socket_timeouts(&stream, Duration::from_secs(5))?;
/// ```
pub fn apply_socket_timeouts(stream: &TcpStream, timeout: Duration) -> io::Result<()> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.set_nodelay(true)?;
    Ok(())
}

/// Best-effort TCP readiness probe before credential spraying.
///
/// # Parameters
///
/// - `host`: Target host.
/// - `port`: Target port.
/// - `timeout`: Connect/read timeout.
///
/// # Returns
///
/// `Some(message)` when the port accepts a connection; `None` when unreachable.
///
/// # Errors
///
/// Failures are mapped to `None` (probe is best-effort).
///
/// # Examples
///
/// ```ignore
/// let msg = probe_vnc_port("10.0.0.1", 5900, Duration::from_secs(2));
/// ```
pub fn probe_vnc_port(host: &str, port: u16, timeout: Duration) -> Option<String> {
    let addr = resolve_addr(host, port).ok()?;
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(mut stream) => {
            let _ = apply_socket_timeouts(&stream, timeout.min(Duration::from_millis(500)));
            let mut buf = [0u8; 12];
            match stream.read(&mut buf) {
                Ok(n) if n >= 4 && buf.starts_with(b"RFB ") => {
                    let ver = String::from_utf8_lossy(&buf[..n.min(12)])
                        .trim()
                        .to_string();
                    Some(format!("vnc service on {host}:{port} ({ver})"))
                }
                _ => Some(format!("vnc port open on {host}:{port}")),
            }
        }
        Err(_) => None,
    }
}
