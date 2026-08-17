//! Target source parsing.
//!
//! Inline `TARGET` values and target-file lines may be hostnames, IPv4
//! addresses, or IPv4 CIDR prefixes. CIDR values are expanded to every
//! address in the prefix, including the network and broadcast addresses.
//! IPv6 addresses and IPv6 CIDR prefixes are rejected.

use std::{fs, net::Ipv4Addr, path::Path};

use anyhow::{Context, Result, bail};
use ipnet::Ipv4Net;

/// Maximum number of addresses expanded from a single IPv4 CIDR prefix.
///
/// This equals a `/16` IPv4 network.
pub const MAX_CIDR_ADDRESSES: u64 = 65_536;

/// Loads targets from inline values and line-based target files.
///
/// Each source is either an existing UTF-8 file or a single target spec.
/// File lines are trimmed; empty lines and `#` comments are ignored. Each
/// remaining spec is passed through [`expand_target_spec`].
///
/// # Parameters
///
/// - `sources`: CLI/MCP `TARGET` values (literals, IPv4 CIDR prefixes, and/or file paths).
///
/// # Returns
///
/// Flattened host strings in input order. An IPv4 CIDR contributes one address
/// per host in the prefix, including network and broadcast addresses.
///
/// # Errors
///
/// Returns an error when a listed file cannot be read, a CIDR-shaped spec is
/// invalid, a single CIDR expands beyond [`MAX_CIDR_ADDRESSES`], or a spec is
/// an IPv6 address or IPv6 CIDR.
///
/// # Examples
///
/// ```
/// use brute::targets::load_targets;
///
/// let hosts = load_targets(&["10.10.50.24/29".to_string()])?;
/// assert_eq!(hosts.len(), 8);
/// assert_eq!(hosts[0], "10.10.50.24");
/// assert_eq!(hosts[7], "10.10.50.31");
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn load_targets(sources: &[String]) -> Result<Vec<String>> {
    let mut targets = Vec::new();

    for source in sources {
        let path = Path::new(source);
        if path.exists() && path.is_file() {
            let content = fs::read_to_string(path)
                .with_context(|| format!("failed to read target file: {}", path.display()))?;
            for line in content
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
            {
                targets.extend(expand_target_spec(line)?);
            }
        } else {
            targets.extend(expand_target_spec(source)?);
        }
    }

    Ok(targets)
}

/// Expands one TARGET token into one or more IPv4 host strings.
///
/// A spec whose address part parses as IPv4 and which contains `/` is treated
/// as CIDR. Hostnames, FQDNs, and bare IPv4 addresses are returned unchanged.
/// IPv6 addresses and IPv6 CIDR prefixes are rejected.
///
/// # Parameters
///
/// - `spec`: A single target token (already trimmed when read from a file).
///
/// # Returns
///
/// One host string for a non-CIDR spec, or every address in an IPv4 CIDR prefix.
///
/// # Errors
///
/// Returns an error when the spec is IPv6, looks like an IPv4 CIDR but the
/// prefix is invalid, or expansion would exceed [`MAX_CIDR_ADDRESSES`].
///
/// # Examples
///
/// ```
/// use brute::targets::expand_target_spec;
///
/// let hosts = expand_target_spec("10.10.50.24/29")?;
/// assert_eq!(
///     hosts,
///     [
///         "10.10.50.24",
///         "10.10.50.25",
///         "10.10.50.26",
///         "10.10.50.27",
///         "10.10.50.28",
///         "10.10.50.29",
///         "10.10.50.30",
///         "10.10.50.31",
///     ]
/// );
/// assert_eq!(expand_target_spec("web.internal")?, ["web.internal"]);
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn expand_target_spec(spec: &str) -> Result<Vec<String>> {
    if is_ipv6_spec(spec) {
        bail!("IPv6 targets are not supported: {spec}");
    }
    match expand_ipv4_cidr(spec)? {
        Some(hosts) => Ok(hosts),
        None => Ok(vec![spec.to_owned()]),
    }
}

/// Returns whether `spec` is an IPv6 address or IPv6 CIDR.
///
/// Bracketed forms such as `[2001:db8::1]` and `[2001:db8::]/126` are included.
///
/// # Parameters
///
/// - `spec`: Target token to inspect.
///
/// # Returns
///
/// `true` when the token is IPv6 (with or without a prefix).
///
/// # Errors
///
/// This function does not return an error.
///
/// # Examples
///
/// ```ignore
/// assert!(is_ipv6_spec("2001:db8::1"));
/// assert!(is_ipv6_spec("[2001:db8::]/126"));
/// assert!(!is_ipv6_spec("10.10.50.24/29"));
/// ```
fn is_ipv6_spec(spec: &str) -> bool {
    if ipv6_addr_text(spec).is_some() {
        return true;
    }
    spec.rsplit_once('/')
        .and_then(|(addr, _)| ipv6_addr_text(addr))
        .is_some()
}

/// Parses a bare or bracketed IPv6 address text.
///
/// # Parameters
///
/// - `text`: Address token, optionally wrapped in `[]`.
///
/// # Returns
///
/// `Some(())` when `text` is an IPv6 address.
///
/// # Errors
///
/// This function does not return an error.
///
/// # Examples
///
/// ```ignore
/// assert!(ipv6_addr_text("::1").is_some());
/// assert!(ipv6_addr_text("[::1]").is_some());
/// assert!(ipv6_addr_text("10.10.50.24").is_none());
/// ```
fn ipv6_addr_text(text: &str) -> Option<()> {
    let text = text
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(text);
    text.parse::<std::net::Ipv6Addr>().ok().map(|_| ())
}

/// Parses `spec` as an IPv4 CIDR and expands it, or returns `None` when it is not CIDR.
///
/// # Parameters
///
/// - `spec`: Target token that may be `ipv4/prefix`.
///
/// # Returns
///
/// - `Ok(Some(hosts))` when `spec` is a valid IPv4 CIDR.
/// - `Ok(None)` when `spec` is not IPv4-CIDR-shaped (no `/`, or the address
///   part is not IPv4, e.g. `example.com/path`).
///
/// # Errors
///
/// Returns an error when the address part is IPv4 but the prefix or range is
/// invalid, or when the expanded range exceeds [`MAX_CIDR_ADDRESSES`].
///
/// # Examples
///
/// ```ignore
/// assert!(expand_ipv4_cidr("web.internal")?.is_none());
/// assert_eq!(expand_ipv4_cidr("10.0.0.1/32")?.unwrap(), ["10.0.0.1"]);
/// ```
fn expand_ipv4_cidr(spec: &str) -> Result<Option<Vec<String>>> {
    let Some((addr_text, prefix_text)) = spec.rsplit_once('/') else {
        return Ok(None);
    };
    if addr_text.parse::<Ipv4Addr>().is_err() {
        return Ok(None);
    }

    let normalized = format!("{addr_text}/{prefix_text}");
    let net: Ipv4Net = normalized
        .parse()
        .with_context(|| format!("invalid CIDR target: {spec}"))?;
    let count = cidr_address_count(net);
    if count > MAX_CIDR_ADDRESSES {
        bail!("CIDR {spec} expands to {count} addresses; maximum is {MAX_CIDR_ADDRESSES}");
    }

    Ok(Some(expand_ipv4_net(net)))
}

/// Returns how many addresses a parsed IPv4 CIDR contains.
///
/// # Parameters
///
/// - `net`: Parsed IPv4 prefix.
///
/// # Returns
///
/// Address count including network and broadcast.
///
/// # Errors
///
/// This function does not return an error.
///
/// # Examples
///
/// ```ignore
/// let net: ipnet::Ipv4Net = "10.10.50.24/29".parse()?;
/// assert_eq!(cidr_address_count(net), 8);
/// ```
fn cidr_address_count(net: Ipv4Net) -> u64 {
    1u64 << (32 - net.prefix_len())
}

/// Enumerates every IPv4 address in `net` from network through broadcast.
///
/// # Parameters
///
/// - `net`: Parsed prefix whose size has already been bounded.
///
/// # Returns
///
/// Host strings in ascending numeric order.
///
/// # Errors
///
/// This function does not return an error.
///
/// # Examples
///
/// ```ignore
/// let net: ipnet::Ipv4Net = "10.10.50.24/30".parse()?;
/// assert_eq!(
///     expand_ipv4_net(net),
///     ["10.10.50.24", "10.10.50.25", "10.10.50.26", "10.10.50.27"]
/// );
/// ```
fn expand_ipv4_net(net: Ipv4Net) -> Vec<String> {
    let start = u32::from(net.network());
    let end = u32::from(net.broadcast());
    let mut hosts = Vec::with_capacity(end.saturating_sub(start) as usize + 1);
    for bits in start..=end {
        hosts.push(Ipv4Addr::from(bits).to_string());
    }
    hosts
}

#[cfg(test)]
mod tests {
    use super::{MAX_CIDR_ADDRESSES, expand_target_spec, load_targets};
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    /// Verifies 10.10.50.24/29 expands to all eight addresses, including
    /// network and broadcast.
    #[test]
    fn expands_ipv4_cidr_including_network_and_broadcast() {
        let hosts = expand_target_spec("10.10.50.24/29").expect("expand /29");
        assert_eq!(
            hosts,
            [
                "10.10.50.24",
                "10.10.50.25",
                "10.10.50.26",
                "10.10.50.27",
                "10.10.50.28",
                "10.10.50.29",
                "10.10.50.30",
                "10.10.50.31",
            ]
        );
    }

    /// Verifies /32 and bare IPv4 stay a single host, and hostnames are kept.
    #[test]
    fn keeps_non_cidr_specs_and_slash32() {
        assert_eq!(
            expand_target_spec("10.10.50.24").expect("bare ip"),
            ["10.10.50.24"]
        );
        assert_eq!(
            expand_target_spec("10.10.50.24/32").expect("/32"),
            ["10.10.50.24"]
        );
        assert_eq!(
            expand_target_spec("web.internal").expect("hostname"),
            ["web.internal"]
        );
        assert_eq!(
            expand_target_spec("example.com/manager").expect("hostname slash"),
            ["example.com/manager"]
        );
    }

    /// Verifies IPv6 addresses and CIDR prefixes are rejected.
    #[test]
    fn rejects_ipv6_address_and_cidr() {
        for spec in [
            "2001:db8::1",
            "[2001:db8::1]",
            "2001:db8::/126",
            "[2001:db8::]/126",
            "::1",
        ] {
            let err = expand_target_spec(spec).expect_err(spec);
            assert!(
                err.to_string().contains("IPv6 targets are not supported"),
                "unexpected error for {spec}: {err}"
            );
        }
    }

    /// Verifies invalid IPv4 prefixes fail instead of being treated as hostnames.
    #[test]
    fn rejects_invalid_cidr_prefix() {
        let err = expand_target_spec("10.10.50.24/99").expect_err("bad prefix");
        assert!(
            err.to_string().contains("invalid CIDR target"),
            "unexpected error: {err}"
        );
    }

    /// Verifies oversized prefixes are rejected before allocation.
    #[test]
    fn rejects_cidr_above_address_limit() {
        let err = expand_target_spec("10.0.0.0/15").expect_err("oversize");
        let message = err.to_string();
        assert!(
            message.contains("maximum is") && message.contains(&MAX_CIDR_ADDRESSES.to_string()),
            "unexpected error: {message}"
        );
    }

    /// Verifies target files expand IPv4 CIDR lines and keep comments/blank lines out.
    #[test]
    fn load_targets_expands_cidr_lines_in_files() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("brute-targets-{}-{nanos}.txt", std::process::id()));
        fs::write(
            &path,
            "# lab\n10.10.50.24/30\n\nweb.internal\n192.168.1.8\n",
        )
        .expect("write targets");

        let hosts = load_targets(&[path.to_string_lossy().into_owned()]);
        let _ = fs::remove_file(&path);
        let hosts = hosts.expect("load");

        assert_eq!(
            hosts,
            [
                "10.10.50.24",
                "10.10.50.25",
                "10.10.50.26",
                "10.10.50.27",
                "web.internal",
                "192.168.1.8",
            ]
        );
    }

    /// Verifies mixed inline hosts and IPv4 CIDR stay in input order.
    #[test]
    fn load_targets_expands_inline_cidr_among_hosts() {
        let hosts = load_targets(&[
            "gateway.lab".to_string(),
            "10.10.50.24/30".to_string(),
            "192.168.1.8".to_string(),
        ])
        .expect("load");
        assert_eq!(
            hosts,
            [
                "gateway.lab",
                "10.10.50.24",
                "10.10.50.25",
                "10.10.50.26",
                "10.10.50.27",
                "192.168.1.8",
            ]
        );
    }
}
