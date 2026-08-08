//! Proxy URL parsing and configuration types.

use super::encode::{percent_encode_userinfo, urlencoding_decode};

/// Supported outbound proxy schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyScheme {
    /// HTTP CONNECT proxy.
    Http,
    /// SOCKS5 proxy.
    Socks5,
}

impl ProxyScheme {
    /// Returns the canonical scheme string used in proxy URLs.
    ///
    /// # Returns
    ///
    /// `"http"` or `"socks5"`.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::proxy::ProxyScheme;
    /// assert_eq!(ProxyScheme::Http.as_str(), "http");
    /// ```
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Socks5 => "socks5",
        }
    }
}

/// Parsed proxy endpoint used by protocol modules.
///
/// # Fields
///
/// - `scheme`: `http` or `socks5`
/// - `host`: Proxy host (hostname or IP)
/// - `port`: Proxy port
/// - `username` / `password`: Optional proxy credentials (both empty means no auth)
///
/// # Examples
///
/// ```
/// use brute::proxy::ProxyConfig;
/// let proxy = ProxyConfig::parse("socks5://user:pass@127.0.0.1:1080").unwrap();
/// assert_eq!(proxy.port, 1080);
/// assert_eq!(proxy.username.as_deref(), Some("user"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    pub scheme: ProxyScheme,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl ProxyConfig {
    /// Parses a proxy URL of the form `protocol://[user[:pass]@]host:port`.
    ///
    /// Empty credentials are allowed (`socks5://127.0.0.1:1080`). Username-only
    /// forms (`http://user@host:8080`) yield an empty password.
    ///
    /// # Parameters
    ///
    /// - `raw`: CLI `--proxy` value.
    ///
    /// # Returns
    ///
    /// Parsed [`ProxyConfig`].
    ///
    /// # Errors
    ///
    /// Returns a human-readable error when the URL is invalid, the scheme is
    /// unsupported, the host is missing, or the port is missing/invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::proxy::{ProxyConfig, ProxyScheme};
    /// let p = ProxyConfig::parse("http://127.0.0.1:8080").unwrap();
    /// assert_eq!(p.scheme, ProxyScheme::Http);
    /// ```
    pub fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("proxy URL must not be empty".to_string());
        }

        let url = url::Url::parse(trimmed).map_err(|err| format!("invalid proxy URL: {err}"))?;
        let scheme = match url.scheme() {
            "http" => ProxyScheme::Http,
            "socks5" => ProxyScheme::Socks5,
            other => {
                return Err(format!(
                    "unsupported proxy scheme '{other}' (expected http or socks5)"
                ));
            }
        };

        let host = url
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| "proxy URL must include a host".to_string())?
            .to_string();
        let port = url
            .port()
            .ok_or_else(|| "proxy URL must include an explicit port".to_string())?;

        let username = if url.username().is_empty() {
            None
        } else {
            Some(
                urlencoding_decode(url.username())
                    .map_err(|err| format!("invalid proxy username encoding: {err}"))?,
            )
        };
        let password = match url.password() {
            Some(password) => Some(
                urlencoding_decode(password)
                    .map_err(|err| format!("invalid proxy password encoding: {err}"))?,
            ),
            None if username.is_some() => Some(String::new()),
            None => None,
        };

        Ok(Self {
            scheme,
            host,
            port,
            username,
            password,
        })
    }

    /// Returns `host:port` for the proxy server itself.
    ///
    /// # Returns
    ///
    /// Socket address string for the proxy endpoint.
    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Rebuilds a proxy URL suitable for `reqwest::Proxy` and `winrm-rs`.
    ///
    /// Credentials are percent-encoded. Passwords are included when present
    /// (including empty password with a username).
    ///
    /// # Returns
    ///
    /// Canonical proxy URL string.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::proxy::ProxyConfig;
    /// let p = ProxyConfig::parse("socks5://u:p@127.0.0.1:1080").unwrap();
    /// assert_eq!(p.to_url_string(), "socks5://u:p@127.0.0.1:1080");
    /// ```
    pub fn to_url_string(&self) -> String {
        match (&self.username, &self.password) {
            (Some(user), Some(pass)) => {
                format!(
                    "{}://{}:{}@{}:{}",
                    self.scheme.as_str(),
                    percent_encode_userinfo(user),
                    percent_encode_userinfo(pass),
                    self.host,
                    self.port
                )
            }
            (Some(user), None) => {
                format!(
                    "{}://{}@{}:{}",
                    self.scheme.as_str(),
                    percent_encode_userinfo(user),
                    self.host,
                    self.port
                )
            }
            _ => format!("{}://{}:{}", self.scheme.as_str(), self.host, self.port),
        }
    }

    /// Builds a `reqwest::Proxy` that routes all requests through this endpoint.
    ///
    /// # Returns
    ///
    /// Configured [`reqwest::Proxy`].
    ///
    /// # Errors
    ///
    /// Returns `reqwest::Error` when the proxy URL is rejected by reqwest.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::proxy::ProxyConfig;
    /// let p = ProxyConfig::parse("http://127.0.0.1:8080").unwrap();
    /// let _proxy = p.to_reqwest_proxy().unwrap();
    /// ```
    pub fn to_reqwest_proxy(&self) -> Result<reqwest::Proxy, reqwest::Error> {
        reqwest::Proxy::all(self.to_url_string())
    }

    /// Returns true when username/password authentication should be used.
    pub(crate) fn has_credentials(&self) -> bool {
        self.username.is_some()
    }
}

/// Clap value parser for `--proxy`.
///
/// # Parameters
///
/// - `raw`: CLI argument text.
///
/// # Returns
///
/// Parsed [`ProxyConfig`].
///
/// # Errors
///
/// Propagates [`ProxyConfig::parse`] errors to clap.
///
/// # Examples
///
/// ```
/// use brute::proxy::parse_proxy_url;
/// let p = parse_proxy_url("socks5://127.0.0.1:1080").unwrap();
/// assert_eq!(p.port, 1080);
/// ```
pub fn parse_proxy_url(raw: &str) -> Result<ProxyConfig, String> {
    ProxyConfig::parse(raw)
}
