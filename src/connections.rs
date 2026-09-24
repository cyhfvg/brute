//! Connection URL parsing for paired login attempts.
//!
//! A connection URL keeps username, password, host, and port together. It is
//! not expanded into a cartesian product. Empty username and empty password
//! are preserved so the attempt uses the same empty credentials as `-u '' -p ''`.

use std::{
    fs,
    io::{self, Read},
    path::Path,
};

use anyhow::{Context, Result, bail};

use crate::{
    cli::{HttpUrlScheme, Protocol},
    engine::parse_protocol,
};

/// One paired login parsed from a connection URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    /// Login module selected by the URL scheme.
    pub protocol: Protocol,
    /// HTTP URL scheme. Non-HTTP protocols keep [`HttpUrlScheme::Http`].
    pub scheme: HttpUrlScheme,
    /// Target host. IPv6 is rejected before this is stored.
    pub host: String,
    /// Explicit port. `None` means the protocol default, except `https`, which is stored as `443`.
    pub port: Option<u16>,
    /// Raw username. Empty means an empty username, not a missing field to skip.
    pub username: String,
    /// Raw password. Empty means an empty password, not a missing field to skip.
    pub password: String,
    /// Oracle service name from `?service=`, when present.
    pub service_name: Option<String>,
    /// Oracle SID from `?sid=`, when present.
    pub sid: Option<String>,
    /// HTTP/Tomcat request path, or rsync module name. `None` uses the module default.
    pub path: Option<String>,
}

impl Connection {
    /// Returns the username stored on a [`crate::credentials::CredentialSet`].
    ///
    /// # Returns
    ///
    /// `None` when the URL username is empty, matching `-u ''`.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::connections::parse_connection_line;
    ///
    /// let conn = parse_connection_line("ssh://:@192.168.5.1")?;
    /// assert_eq!(conn.credential_username(), None);
    /// assert_eq!(conn.credential_password(), None);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn credential_username(&self) -> Option<String> {
        none_if_empty(&self.username)
    }

    /// Returns the password stored on a [`crate::credentials::CredentialSet`].
    ///
    /// # Returns
    ///
    /// `None` when the URL password is empty, matching `-p ''`.
    pub fn credential_password(&self) -> Option<String> {
        none_if_empty(&self.password)
    }
}

/// Parses one connection URL.
///
/// # Parameters
///
/// - `line`: `scheme://[username[:password]@]host[:port][/path][?query]`.
///
/// # Returns
///
/// The paired login. A missing port is `None` except for `https`, which becomes `443`.
///
/// # Errors
///
/// Returns an error for a missing scheme, unknown scheme, empty host, IPv6,
/// invalid port, bad percent-encoding, unsupported path, or an Oracle URL that
/// does not contain exactly one of `?service=` or `?sid=`.
///
/// # Examples
///
/// ```
/// use brute::connections::parse_connection_line;
///
/// let conn = parse_connection_line("ssh://root:password@192.168.5.1:22")?;
/// assert_eq!(conn.host, "192.168.5.1");
/// assert_eq!(conn.port, Some(22));
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn parse_connection_line(line: &str) -> Result<Connection> {
    let line = line.trim();
    if line.is_empty() {
        bail!("empty connection URL");
    }
    let Some((scheme_raw, rest)) = line.split_once("://") else {
        bail!("missing scheme; expected scheme://[user[:password]@]host[:port]");
    };
    if scheme_raw.is_empty() || scheme_raw.chars().any(|ch| !is_scheme_char(ch)) {
        bail!("invalid scheme {scheme_raw:?}");
    }
    if rest.is_empty() {
        bail!("empty host");
    }

    let scheme_name = scheme_raw.to_ascii_lowercase();
    let (protocol, scheme) = if scheme_name == "https" {
        (Protocol::Http, HttpUrlScheme::Https)
    } else {
        (parse_protocol(&scheme_name)?, HttpUrlScheme::Http)
    };

    let (userinfo, authority) = match rest.rsplit_once('@') {
        Some((user, auth)) => (Some(user), auth),
        None => (None, rest),
    };
    if authority.is_empty() {
        bail!("empty host");
    }
    if authority.contains('#') {
        bail!("fragments are not supported");
    }

    let (authority, query) = split_once_optional(authority, '?');
    let (hostport, url_path) = split_once_optional(authority, '/');
    if hostport.is_empty() {
        bail!("empty host");
    }

    let (username, password) = split_userinfo(userinfo)?;
    let (host, port) = split_hostport(hostport)?;
    let query_parts = query.map(parse_query).transpose()?.unwrap_or_default();
    let path = resolve_path(
        protocol,
        url_path,
        query_parts.path.as_deref(),
        query_parts.module.as_deref(),
    )?;
    validate_identifiers(
        protocol,
        query_parts.service_name.as_deref(),
        query_parts.sid.as_deref(),
    )?;

    let port = match (scheme, port) {
        (HttpUrlScheme::Https, None) => Some(443),
        _ => port,
    };

    Ok(Connection {
        protocol,
        scheme,
        host,
        port,
        username,
        password,
        service_name: query_parts.service_name,
        sid: query_parts.sid,
        path,
    })
}

/// Loads paired logins from files, stdin, and inline URLs.
///
/// An existing file is read as UTF-8, one URL per line. `-` reads stdin.
/// Any other value containing `://` is one inline URL. Blank lines and lines
/// whose first non-whitespace character is `#` are ignored. A leading UTF-8
/// BOM is stripped from the first line.
///
/// # Parameters
///
/// - `sources`: file paths, `-`, or inline connection URLs, in attempt order.
///
/// # Returns
///
/// Paired logins in source order. Lines are not deduplicated.
///
/// # Errors
///
/// Returns an error when a source is neither a file nor a URL, a file cannot
/// be read, the file contains no URLs, or any line fails [`parse_connection_line`].
/// The first bad line aborts the load. File errors include `path:line`.
///
/// # Examples
///
/// ```
/// use brute::connections::load_connection_sources;
///
/// let rows = load_connection_sources(&["ssh://root:password@192.168.5.1:22"])?;
/// assert_eq!(rows.len(), 1);
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn load_connection_sources(sources: &[impl AsRef<str>]) -> Result<Vec<Connection>> {
    if sources.is_empty() {
        bail!("no connection URLs were provided");
    }
    let mut connections = Vec::new();
    for source in sources {
        append_source(source.as_ref(), &mut connections)?;
    }
    if connections.is_empty() {
        bail!("no connection URLs were found");
    }
    Ok(connections)
}

/// Splits optional userinfo into a decoded username and password.
///
/// # Parameters
///
/// - `userinfo`: text before the last raw `@`, or `None` when the URL has no userinfo.
///
/// # Returns
///
/// Username and password. Missing userinfo and an omitted password are empty strings.
///
/// # Errors
///
/// Returns an error when percent-decoding fails.
fn split_userinfo(userinfo: Option<&str>) -> Result<(String, String)> {
    let Some(userinfo) = userinfo else {
        return Ok((String::new(), String::new()));
    };
    let (user, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    Ok((percent_decode(user)?, percent_decode(password)?))
}

/// Splits `host[:port]` and rejects IPv6.
///
/// # Parameters
///
/// - `hostport`: authority text after the last `@` and before `?` or `/`.
///
/// # Returns
///
/// Decoded host and an explicit port. An omitted or empty port is `None`.
///
/// # Errors
///
/// Returns an error for an empty host, an IPv6 host, or a port outside `1..=65535`.
fn split_hostport(hostport: &str) -> Result<(String, Option<u16>)> {
    if hostport.starts_with('[') {
        bail!("ipv6 hosts are not supported");
    }
    let (host_raw, port_raw) = if let Some((host, port)) = hostport.rsplit_once(':') {
        if host.is_empty() || host.contains(':') {
            bail!("ipv6 hosts are not supported");
        }
        (host, Some(port))
    } else {
        (hostport, None)
    };
    let host = percent_decode(host_raw)?;
    if host.is_empty() || host.contains([':', '/', '@', '?', '#', ' ', '\0']) {
        if host.contains(':') {
            bail!("ipv6 hosts are not supported");
        }
        bail!("invalid host");
    }
    let port = match port_raw {
        Some(raw) => parse_port(raw)?,
        None => None,
    };
    Ok((host, port))
}

/// Parses a decimal port.
///
/// # Parameters
///
/// - `raw`: text after the host colon. Empty means omitted.
///
/// # Returns
///
/// `None` for an empty port, otherwise a port in `1..=65535`.
///
/// # Errors
///
/// Returns an error when the port is not a number, is `0`, or exceeds 65535.
fn parse_port(raw: &str) -> Result<Option<u16>> {
    if raw.is_empty() {
        return Ok(None);
    }
    let port = raw
        .parse::<u16>()
        .map_err(|_| anyhow::anyhow!("invalid port {raw:?}"))?;
    if port == 0 {
        bail!("port must be between 1 and 65535");
    }
    Ok(Some(port))
}

#[derive(Debug, Default)]
struct QueryParts {
    service_name: Option<String>,
    sid: Option<String>,
    path: Option<String>,
    module: Option<String>,
}

/// Parses the known connection query keys.
///
/// # Parameters
///
/// - `query`: text after `?`, without the leading question mark.
///
/// # Returns
///
/// Service, SID, path, and rsync module values.
///
/// # Errors
///
/// Returns an error for an unknown key, a missing `=`, a duplicate key, or an empty value.
fn parse_query(query: &str) -> Result<QueryParts> {
    let mut parts = QueryParts::default();
    if query.is_empty() {
        return Ok(parts);
    }
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let Some((key, value)) = pair.split_once('=') else {
            bail!("invalid query parameter {pair:?}");
        };
        let value = percent_decode(value)?;
        if value.is_empty() {
            bail!("empty query value for {key:?}");
        }
        match key.to_ascii_lowercase().as_str() {
            "service" | "service-name" | "service_name" => {
                set_once(&mut parts.service_name, value, "service")?;
            }
            "sid" => set_once(&mut parts.sid, value, "sid")?,
            "path" => set_once(&mut parts.path, value, "path")?,
            "module" => set_once(&mut parts.module, value, "module")?,
            other => bail!("unknown query key {other:?}"),
        }
    }
    Ok(parts)
}

/// Stores a query value once.
///
/// # Errors
///
/// Returns an error when `slot` is already set.
fn set_once(slot: &mut Option<String>, value: String, name: &str) -> Result<()> {
    if slot.is_some() {
        bail!("duplicate {name} query");
    }
    *slot = Some(value);
    Ok(())
}

/// Merges an optional URL path with query values.
///
/// `url_path` is `None` when the URL has no `/`. An empty string is a trailing slash.
///
/// # Errors
///
/// Returns an error for an unsupported path or conflicting values.
fn resolve_path(
    protocol: Protocol,
    url_path: Option<&str>,
    query_path: Option<&str>,
    query_module: Option<&str>,
) -> Result<Option<String>> {
    match protocol {
        Protocol::Http | Protocol::Tomcat => {
            if query_module.is_some() {
                bail!("module query is only valid for rsync");
            }
            merge_path(url_path.map(slash_path), query_path.map(slash_path))
        }
        Protocol::Rsync => {
            if query_path.is_some() {
                bail!("path query is not valid for rsync; use the URL path or ?module=");
            }
            let from_url = match url_path {
                Some(path) => rsync_module(path)?,
                None => None,
            };
            merge_path(from_url, query_module.map(str::to_string))
        }
        _ => {
            if url_path.is_some() || query_path.is_some() || query_module.is_some() {
                bail!("path is not valid for {}", protocol.as_str());
            }
            Ok(None)
        }
    }
}

/// Requires Oracle URLs to carry exactly one identifier and rejects it elsewhere.
///
/// # Errors
///
/// Returns an error when the identifier combination is invalid for `protocol`.
fn validate_identifiers(
    protocol: Protocol,
    service_name: Option<&str>,
    sid: Option<&str>,
) -> Result<()> {
    let has_service = service_name.is_some();
    let has_sid = sid.is_some();
    if protocol == Protocol::Oracle {
        if has_service && has_sid {
            bail!("oracle service and sid are mutually exclusive");
        }
        if !has_service && !has_sid {
            bail!("oracle URL requires exactly one of ?service= or ?sid=");
        }
        return Ok(());
    }
    if has_service || has_sid {
        bail!("service and sid query keys are only valid for oracle");
    }
    Ok(())
}

/// Decodes `%HH` sequences without treating `+` as a space.
///
/// # Errors
///
/// Returns an error for a truncated escape, a non-hex escape, or non-UTF-8 output.
fn percent_decode(input: &str) -> Result<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            out.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            bail!("invalid percent-encoding");
        }
        let hi = hex_nibble(bytes[index + 1])?;
        let lo = hex_nibble(bytes[index + 2])?;
        out.push(hi * 16 + lo);
        index += 3;
    }
    String::from_utf8(out).map_err(|_| anyhow::anyhow!("percent-decoded value is not utf-8"))
}

/// Converts one hex ASCII byte to its nibble value.
///
/// # Errors
///
/// Returns an error when `byte` is not a hex digit.
fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => bail!("invalid percent-encoding"),
    }
}

/// Reads one source into `out`.
///
/// # Errors
///
/// Returns an error for a missing file, an unreadable file, or a bad URL line.
fn append_source(source: &str, out: &mut Vec<Connection>) -> Result<()> {
    if source == "-" {
        let mut stdin = String::new();
        io::stdin()
            .read_to_string(&mut stdin)
            .context("failed to read stdin")?;
        return append_text("stdin", &stdin, out);
    }
    let path = Path::new(source);
    if path.is_file() {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read connection file {source}"))?;
        return append_text(source, &text, out);
    }
    if source.contains("://") {
        let connection = parse_connection_line(source).with_context(|| format!("{source}:1"))?;
        out.push(connection);
        return Ok(());
    }
    if path.exists() {
        bail!("{source} is not a connection file");
    }
    bail!("not a connection file or URL: {source}");
}

/// Parses non-comment lines from one text source.
///
/// # Errors
///
/// Returns an error on the first invalid URL, including `origin:line`.
fn append_text(origin: &str, text: &str, out: &mut Vec<Connection>) -> Result<()> {
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw.trim();
        let line = if idx == 0 {
            trimmed.strip_prefix('\u{feff}').unwrap_or(trimmed)
        } else {
            trimmed
        };
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let connection =
            parse_connection_line(line).with_context(|| format!("{origin}:{line_no}"))?;
        out.push(connection);
    }
    Ok(())
}

/// Returns `None` for an empty credential component.
fn none_if_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Returns whether `ch` can appear in a URL scheme.
fn is_scheme_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '+' || ch == '-' || ch == '.'
}

/// Splits `text` on the first `sep`, preserving an empty right side.
fn split_once_optional(text: &str, sep: char) -> (&str, Option<&str>) {
    match text.split_once(sep) {
        Some((left, right)) => (left, Some(right)),
        None => (text, None),
    }
}

/// Ensures an HTTP path starts with `/`.
fn slash_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_string()
    } else if let Some(stripped) = path.strip_prefix('/') {
        if stripped.is_empty() {
            "/".to_string()
        } else {
            format!("/{stripped}")
        }
    } else {
        format!("/{path}")
    }
}

/// Converts a URL path into an rsync module name.
///
/// # Errors
///
/// Returns an error when the module contains another `/`.
fn rsync_module(path: &str) -> Result<Option<String>> {
    let module = path.trim_start_matches('/');
    if module.is_empty() {
        return Ok(None);
    }
    if module.contains('/') {
        bail!("rsync module must be a single path segment");
    }
    Ok(Some(module.to_string()))
}

/// Keeps one path when both sources agree.
///
/// # Errors
///
/// Returns an error when both values are set and differ.
fn merge_path(left: Option<String>, right: Option<String>) -> Result<Option<String>> {
    match (left, right) {
        (Some(left), Some(right)) if left != right => {
            bail!("conflicting path values {left:?} and {right:?}")
        }
        (Some(left), Some(_)) => Ok(Some(left)),
        (Some(value), None) | (None, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}
