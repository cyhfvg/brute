//! Shared outbound proxy support for all protocol modules.
//!
//! Parses CLI `--proxy` URLs (`http://` / `socks5://`), opens tunneled TCP streams
//! (async + blocking), builds `reqwest::Proxy`, and provides a local TCP bridge for
//! libraries that only accept `host:port` endpoints.

mod bridge;
mod config;
mod connect;
mod encode;

pub use bridge::{ProxyTcpBridge, resolve_tcp_endpoint};
pub use config::{ProxyConfig, ProxyScheme, parse_proxy_url};
pub use connect::{connect_async, connect_std};
