//! Local TCP bridge that forwards accepted sockets through an outbound proxy.

use std::net::SocketAddr;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};

use super::config::ProxyConfig;
use super::connect::connect_async;

/// Local TCP forwarder that accepts connections and tunnels them via `proxy`.
///
/// Used by protocol libraries that only accept `host:port` (MySQL, Redis, Oracle, SMB).
/// Dropping the bridge shuts down the listener.
#[derive(Debug)]
pub struct ProxyTcpBridge {
    local_addr: SocketAddr,
    _shutdown: oneshot::Sender<()>,
}

impl ProxyTcpBridge {
    /// Starts a localhost listener that forwards accepted sockets through `proxy`.
    ///
    /// # Parameters
    ///
    /// - `proxy`: Outbound proxy configuration.
    /// - `target_host`: Ultimate destination host.
    /// - `target_port`: Ultimate destination port.
    ///
    /// # Returns
    ///
    /// Running bridge bound to `127.0.0.1:<ephemeral>`.
    ///
    /// # Errors
    ///
    /// Returns a string error when the local listener cannot be bound.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let bridge = ProxyTcpBridge::start(&proxy, "10.0.0.5", 3306).await?;
    /// let host = bridge.host();
    /// let port = bridge.port();
    /// ```
    pub async fn start(
        proxy: &ProxyConfig,
        target_host: &str,
        target_port: u16,
    ) -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|err| format!("proxy bridge bind failed: {err}"))?;
        let local_addr = listener
            .local_addr()
            .map_err(|err| format!("proxy bridge local_addr failed: {err}"))?;
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let proxy = proxy.clone();
        let target_host = target_host.to_string();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        let Ok((inbound, _)) = accepted else {
                            break;
                        };
                        let proxy = proxy.clone();
                        let target_host = target_host.clone();
                        tokio::spawn(async move {
                            match connect_async(&proxy, &target_host, target_port).await {
                                Ok(outbound) => {
                                    let _ = tunnel_copy(inbound, outbound).await;
                                }
                                Err(_) => {
                                    // Drop inbound on tunnel setup failure.
                                }
                            }
                        });
                    }
                }
            }
        });

        Ok(Self {
            local_addr,
            _shutdown: shutdown_tx,
        })
    }

    /// Returns the bridge listen host (`127.0.0.1`).
    pub fn host(&self) -> &str {
        "127.0.0.1"
    }

    /// Returns the bridge listen port.
    pub fn port(&self) -> u16 {
        self.local_addr.port()
    }

    /// Returns `host:port` for clients that need a single address string.
    pub fn addr(&self) -> String {
        format!("{}:{}", self.host(), self.port())
    }
}

/// Resolves dial target for libraries that only accept host/port.
///
/// When `proxy` is `None`, returns the original target. When set, starts a
/// [`ProxyTcpBridge`] and returns `(bridge_host, bridge_port, Some(bridge))`.
///
/// # Parameters
///
/// - `proxy`: Optional proxy config from CLI.
/// - `target_host`: Real destination host.
/// - `target_port`: Real destination port.
///
/// # Returns
///
/// `(connect_host, connect_port, bridge_guard)`. Keep the guard alive for the
/// duration of the client connection.
///
/// # Errors
///
/// Returns bridge startup errors.
///
/// # Examples
///
/// ```ignore
/// let (host, port, bridge) = resolve_tcp_endpoint(Some(&proxy), "10.0.0.5", 3306).await?;
/// ```
pub async fn resolve_tcp_endpoint(
    proxy: Option<&ProxyConfig>,
    target_host: &str,
    target_port: u16,
) -> Result<(String, u16, Option<ProxyTcpBridge>), String> {
    match proxy {
        Some(proxy) => {
            let bridge = ProxyTcpBridge::start(proxy, target_host, target_port).await?;
            let host = bridge.host().to_string();
            let port = bridge.port();
            Ok((host, port, Some(bridge)))
        }
        None => Ok((target_host.to_string(), target_port, None)),
    }
}

/// Bidirectional byte copy between two connected TCP streams until EOF.
async fn tunnel_copy(left: TcpStream, right: TcpStream) -> std::io::Result<()> {
    let (mut lr, mut lw) = left.into_split();
    let (mut rr, mut rw) = right.into_split();
    let client_to_proxy = async {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = lr.read(&mut buf).await?;
            if n == 0 {
                let _ = rw.shutdown().await;
                break;
            }
            rw.write_all(&buf[..n]).await?;
        }
        Ok::<(), std::io::Error>(())
    };
    let proxy_to_client = async {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = rr.read(&mut buf).await?;
            if n == 0 {
                let _ = lw.shutdown().await;
                break;
            }
            lw.write_all(&buf[..n]).await?;
        }
        Ok::<(), std::io::Error>(())
    };
    tokio::select! {
        r = client_to_proxy => r,
        r = proxy_to_client => r,
    }
}
