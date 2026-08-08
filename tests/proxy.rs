//! Public proxy API tests: URL parsing, tunnels, and local TCP bridge.

use tokio::net::TcpStream;

use brute::proxy::{ProxyConfig, ProxyScheme, ProxyTcpBridge, connect_async};

#[test]
fn parses_socks5_with_credentials() {
    let p = ProxyConfig::parse("socks5://sockproxyuser:sockproxypassword@127.0.0.1:1080")
        .expect("parse");
    assert_eq!(p.scheme, ProxyScheme::Socks5);
    assert_eq!(p.host, "127.0.0.1");
    assert_eq!(p.port, 1080);
    assert_eq!(p.username.as_deref(), Some("sockproxyuser"));
    assert_eq!(p.password.as_deref(), Some("sockproxypassword"));
}

#[test]
fn parses_http_without_credentials() {
    let p = ProxyConfig::parse("http://127.0.0.1:8080").expect("parse");
    assert_eq!(p.scheme, ProxyScheme::Http);
    assert!(p.username.is_none());
    assert!(p.password.is_none());
    assert_eq!(p.to_url_string(), "http://127.0.0.1:8080");
}

#[test]
fn parses_username_only_as_empty_password() {
    let p = ProxyConfig::parse("http://user@127.0.0.1:8080").expect("parse");
    assert_eq!(p.username.as_deref(), Some("user"));
    assert_eq!(p.password.as_deref(), Some(""));
}

#[test]
fn rejects_unsupported_scheme() {
    let err = ProxyConfig::parse("ftp://127.0.0.1:21").unwrap_err();
    assert!(err.contains("unsupported proxy scheme"));
}

#[test]
fn rejects_missing_port() {
    let err = ProxyConfig::parse("socks5://127.0.0.1").unwrap_err();
    assert!(err.contains("port"));
}

#[test]
fn percent_encoded_credentials_roundtrip() {
    let p = ProxyConfig::parse("socks5://u%40s:p%3As@127.0.0.1:1080").expect("parse");
    assert_eq!(p.username.as_deref(), Some("u@s"));
    assert_eq!(p.password.as_deref(), Some("p:s"));
    let rebuilt = p.to_url_string();
    let again = ProxyConfig::parse(&rebuilt).expect("reparse");
    assert_eq!(again.username.as_deref(), Some("u@s"));
    assert_eq!(again.password.as_deref(), Some("p:s"));
}

/// Spins a tiny HTTP CONNECT proxy + echo target and verifies tunneled IO.
#[tokio::test]
async fn http_connect_tunnel_roundtrip() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = target.accept().await.unwrap();
        let mut buf = [0u8; 4];
        sock.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        sock.write_all(b"pong").await.unwrap();
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut client, _) = proxy_listener.accept().await.unwrap();
        let mut header = Vec::new();
        let mut buf = [0u8; 1];
        loop {
            client.read_exact(&mut buf).await.unwrap();
            header.push(buf[0]);
            if header.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let header = String::from_utf8_lossy(&header);
        assert!(header.starts_with("CONNECT "));
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let mut client = client;
        let mut upstream = TcpStream::connect(target_addr).await.unwrap();
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    });

    let proxy = ProxyConfig {
        scheme: ProxyScheme::Http,
        host: proxy_addr.ip().to_string(),
        port: proxy_addr.port(),
        username: None,
        password: None,
    };
    let mut stream = connect_async(&proxy, "127.0.0.1", target_addr.port())
        .await
        .expect("tunnel");
    stream.write_all(b"ping").await.unwrap();
    let mut resp = [0u8; 4];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp, b"pong");
}

/// Verifies the local TCP bridge forwards bytes through an HTTP CONNECT proxy.
#[tokio::test]
async fn proxy_tcp_bridge_roundtrip() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = target.accept().await.unwrap();
        let mut buf = [0u8; 3];
        sock.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"abc");
        sock.write_all(b"xyz").await.unwrap();
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut client, _) = proxy_listener.accept().await.unwrap();
        let mut header = Vec::new();
        let mut buf = [0u8; 1];
        loop {
            client.read_exact(&mut buf).await.unwrap();
            header.push(buf[0]);
            if header.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let mut client = client;
        let mut upstream = TcpStream::connect(target_addr).await.unwrap();
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    });

    let proxy = ProxyConfig {
        scheme: ProxyScheme::Http,
        host: proxy_addr.ip().to_string(),
        port: proxy_addr.port(),
        username: None,
        password: None,
    };
    let bridge = ProxyTcpBridge::start(&proxy, "127.0.0.1", target_addr.port())
        .await
        .expect("bridge");
    let mut client = TcpStream::connect(bridge.addr()).await.unwrap();
    client.write_all(b"abc").await.unwrap();
    let mut resp = [0u8; 3];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp, b"xyz");
}
