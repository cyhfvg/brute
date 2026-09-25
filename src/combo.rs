//! Groups connection URLs by protocol and runs each group as paired logins.

use anyhow::{Result, bail};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::{
    cli::{HttpUrlScheme, Protocol, WinrmShellType},
    connections::Connection,
    database::CredentialDatabase,
    engine::{AttemptRecord, SprayReport, SprayReporter, SprayRequest, run_paired_spray},
    proxy::ProxyConfig,
};

/// Shared options for a connection-URL run.
///
/// Scheme, host, port, username, and password come from each URL. These fields
/// only control concurrency, persistence, and protocol-specific extras.
#[derive(Debug, Clone)]
pub struct ComboOptions {
    /// In-flight attempt cap inside each protocol group.
    pub threads: usize,
    /// Transient transport retry count.
    pub retries: usize,
    /// Per-attempt timeout in milliseconds.
    pub timeout_ms: u64,
    /// Fixed wait before each credential attempt, in milliseconds.
    pub delay_ms: u64,
    /// Inclusive extra random wait added to `delay_ms`, in milliseconds.
    pub jitter_ms: u64,
    /// When false, a successful `host:port` skips the remaining logins for that endpoint.
    pub continue_on_success: bool,
    /// Outbound proxy applied to every group.
    pub proxy: Option<ProxyConfig>,
    /// Post-auth command for protocols that already support `-x`.
    pub execute: Option<String>,
    /// Enumerate SMB shares after a successful login.
    pub shares: bool,
    /// WinRM shell type applied when a group uses WinRM.
    pub shell_type: Option<WinrmShellType>,
    /// Workspace that receives successful credentials. `None` uses the current workspace.
    pub workspace: Option<String>,
}

impl Default for ComboOptions {
    fn default() -> Self {
        Self {
            threads: 16,
            retries: 3,
            timeout_ms: 5_000,
            delay_ms: 0,
            jitter_ms: 0,
            continue_on_success: false,
            proxy: None,
            execute: None,
            shares: false,
            shell_type: None,
            workspace: None,
        }
    }
}

/// Aggregate result of one connection-URL run.
#[derive(Debug, Clone, Serialize)]
pub struct ComboReport {
    /// Workspace that received successful credentials.
    pub workspace: String,
    /// Successful attempts across every protocol group, in completion order.
    pub successes: Vec<AttemptRecord>,
    /// One spray report per protocol group, in first-seen order.
    pub reports: Vec<SprayReport>,
}

/// Verifies paired connection URLs and persists successes.
///
/// Connections are grouped by `(protocol, HTTP scheme)` in first-seen order.
/// Groups run sequentially. Within a group, attempts run concurrently up to
/// `options.threads` and are not crossed into a cartesian product.
///
/// # Parameters
///
/// - `database`: SQLite store used for workspace resolution and success persistence.
/// - `connections`: paired logins already parsed by [`crate::connections::load_connection_sources`].
/// - `options`: concurrency, timeout, proxy, and protocol extras.
/// - `reporter`: optional live CLI reporter. MCP passes `None`.
/// - `cancel`: stops probes and in-flight attempts for every protocol group.
///
/// # Returns
///
/// A [`ComboReport`] whose `reports` preserve protocol identity for mixed files.
///
/// # Errors
///
/// Returns an error when `connections` is empty, `threads` or `timeout_ms` is
/// zero, or a group fails before its attempts are recorded.
///
/// # Examples
///
/// ```ignore
/// use brute::combo::{ComboOptions, run_connections};
/// use brute::connections::parse_connection_line;
/// use brute::database::CredentialDatabase;
///
/// let database = CredentialDatabase::open_default()?;
/// let conn = parse_connection_line("ssh://root:password@192.168.5.1:22")?;
/// let cancel = tokio_util::sync::CancellationToken::new();
/// let report = run_connections(&database, vec![conn], ComboOptions::default(), None, &cancel).await?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub async fn run_connections(
    database: &CredentialDatabase,
    connections: Vec<Connection>,
    options: ComboOptions,
    reporter: Option<&dyn SprayReporter>,
    cancel: &CancellationToken,
) -> Result<ComboReport> {
    if connections.is_empty() {
        bail!("no connection URLs were found");
    }
    if options.threads == 0 {
        bail!("threads must be >= 1");
    }
    if options.timeout_ms == 0 {
        bail!("timeout_ms must be >= 1");
    }

    let groups = group_connections(connections);
    let mut workspace = options.workspace.clone();
    let mut reports = Vec::with_capacity(groups.len());
    for group in groups {
        let Some(first) = group.first() else {
            continue;
        };
        let request = SprayRequest {
            protocol: first.protocol,
            url_scheme: first.scheme,
            threads: options.threads,
            retries: options.retries,
            timeout_ms: options.timeout_ms,
            delay_ms: options.delay_ms,
            jitter_ms: options.jitter_ms,
            continue_on_success: options.continue_on_success,
            proxy: options.proxy.clone(),
            execute: options.execute.clone(),
            shares: options.shares,
            shell_type: options.shell_type,
            workspace: workspace.clone(),
            ..SprayRequest::default()
        };
        let report = run_paired_spray(database, request, &group, reporter, cancel).await?;
        workspace = Some(report.workspace.clone());
        reports.push(report);
    }

    let Some(first) = reports.first() else {
        bail!("no connection URLs were found");
    };
    let workspace = first.workspace.clone();
    let successes = reports
        .iter()
        .flat_map(|report| report.successes.iter().cloned())
        .collect();
    Ok(ComboReport {
        workspace,
        successes,
        reports,
    })
}

/// Groups connections by protocol and HTTP scheme without reordering first-seen groups.
///
/// # Parameters
///
/// - `connections`: parsed URLs in source order.
///
/// # Returns
///
/// Groups in the order their first URL appeared. `http` and `https` stay separate.
fn group_connections(connections: Vec<Connection>) -> Vec<Vec<Connection>> {
    let mut groups: Vec<(Protocol, HttpUrlScheme, Vec<Connection>)> = Vec::new();
    for connection in connections {
        if let Some(group) = groups
            .iter_mut()
            .find(|group| group.0 == connection.protocol && group.1 == connection.scheme)
        {
            group.2.push(connection);
        } else {
            groups.push((connection.protocol, connection.scheme, vec![connection]));
        }
    }
    groups.into_iter().map(|(_, _, rows)| rows).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connections::parse_connection_line;

    #[test]
    fn groups_preserve_first_seen_protocol_and_scheme() {
        let urls = [
            "ssh://root:a@192.168.5.1",
            "https://admin:secret@10.0.0.9",
            "ftp://:@192.168.5.2",
            "ssh://root:b@192.168.5.3:2222",
            "http://admin:secret@10.0.0.8",
        ];
        let connections = urls
            .into_iter()
            .map(|url| parse_connection_line(url).expect(url))
            .collect();
        let groups = group_connections(connections);
        assert_eq!(groups.len(), 4);
        assert_eq!(groups[0][0].protocol, Protocol::Ssh);
        assert_eq!(groups[0].len(), 2);
        assert_eq!(groups[1][0].scheme, HttpUrlScheme::Https);
        assert_eq!(groups[2][0].protocol, Protocol::Ftp);
        assert_eq!(groups[3][0].scheme, HttpUrlScheme::Http);
    }
}
