//! SMB login attempts and optional share/Access enumeration.
//!
//! Uses the pure-Rust `smb2` crate (SMB2/3 + NTLM, no C FFI) so release builds
//! remain single-file static friendly and do not pull in libsmbclient.

use std::time::Duration;

use async_trait::async_trait;
use smb2::{ClientConfig, ErrorKind, ShareInfo, SmbClient};

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

/// SMB module configuration.
#[derive(Debug, Clone)]
pub struct SmbModule {
    /// When true, list shares and Access after a successful login.
    shares: bool,
}

impl SmbModule {
    /// Creates a new SMB module.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Reserved for API parity with other modules; per-attempt
    ///   timeouts are taken from each [`AttemptContext`] / [`TargetContext`].
    /// - `shares`: When true, enumerate share names and Access after auth succeeds.
    ///
    /// # Returns
    ///
    /// A configured [`SmbModule`] ready for the scheduler.
    ///
    /// # Errors
    ///
    /// This constructor does not fail.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let module = SmbModule::new(5000, true);
    /// ```
    pub fn new(_timeout_ms: u64, shares: bool) -> Self {
        Self { shares }
    }
}

#[async_trait]
impl BruteModule for SmbModule {
    fn name(&self) -> &'static str {
        "smb"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_smb_service(ctx)).await {
            Ok(Some(message)) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        let host = ctx.target_host.clone();
        let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
        let username = ctx.credential.username.clone().unwrap_or_default();
        let password = ctx.credential.password.clone().unwrap_or_default();
        let enumerate_shares = self.shares;
        let timeout = ctx.timeout();
        let proxy = ctx.target.proxy.clone();

        let future = async move {
            try_smb_login(
                &host,
                port,
                &username,
                &password,
                enumerate_shares,
                timeout,
                proxy.as_ref(),
            )
            .await
        };

        match tokio::time::timeout(timeout, future).await {
            Ok(outcome) => outcome,
            Err(_) => AttemptOutcome::Error("attempt timed out".to_string()),
        }
    }
}

/// Performs one SMB authentication attempt, optionally enumerating shares.
///
/// # Parameters
///
/// - `host`: Target hostname or IP.
/// - `port`: SMB TCP port (typically 445).
/// - `username`: Account name; may be `DOMAIN\\user` or `user@domain`.
/// - `password`: Account password.
/// - `enumerate_shares`: When true, list shares and Access after auth succeeds.
/// - `timeout`: Connection and I/O timeout for the SMB client.
/// - `proxy`: Optional outbound proxy from CLI `--proxy`.
///
/// # Returns
///
/// [`AttemptOutcome::Success`] on verified login (share enum failures stay success),
/// [`AttemptOutcome::Failure`] for auth rejections, or [`AttemptOutcome::Error`] for
/// transport and other non-auth problems.
///
/// # Errors
///
/// Errors are mapped into [`AttemptOutcome`] variants rather than returned as `Result`.
///
/// # Examples
///
/// ```ignore
/// let outcome = try_smb_login(
///     "10.10.50.30",
///     445,
///     "admin",
///     "secret",
///     true,
///     Duration::from_secs(5),
///     None,
/// ).await;
/// ```
async fn try_smb_login(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    enumerate_shares: bool,
    timeout: Duration,
    proxy: Option<&crate::proxy::ProxyConfig>,
) -> AttemptOutcome {
    let endpoint = match crate::proxy::resolve_tcp_endpoint(proxy, host, port).await {
        Ok(endpoint) => endpoint,
        Err(err) => {
            return AttemptOutcome::Error(format!("smb proxy bridge failed: {err}"));
        }
    };
    let (connect_host, connect_port, _bridge) = endpoint;

    let (domain, user) = split_domain_user(username);
    let config = ClientConfig {
        addr: format!("{connect_host}:{connect_port}"),
        timeout,
        username: user,
        password: password.to_string(),
        domain,
        auto_reconnect: false,
        compression: true,
        dfs_enabled: false,
        dfs_target_overrides: std::collections::HashMap::new(),
    };

    match SmbClient::connect(config).await {
        Ok(mut client) => {
            if !enumerate_shares {
                return AttemptOutcome::Success(AttemptSuccess::new("SMB access!"));
            }

            match enumerate_shares_with_access(&mut client).await {
                Ok(listing) => {
                    AttemptOutcome::Success(AttemptSuccess::with_command("SMB access!", listing))
                }
                Err(err) => AttemptOutcome::Success(AttemptSuccess::with_command_error(
                    "SMB access!",
                    format!("smb share enumeration failed: {err}"),
                )),
            }
        }
        Err(err) => classify_smb_error(&err),
    }
}

/// Best-effort service probe before credential spraying.
///
/// A successful TCP connect to the SMB port is treated as readiness. When a guest
/// session can be established, a short readiness note is returned; name/domain
/// AV-pair extraction is optional evidence and not required for login attempts.
async fn probe_smb_service(ctx: &TargetContext) -> Option<String> {
    let port = ctx.port();
    let host = &ctx.target_host;
    let timeout = ctx.timeout();

    let endpoint = crate::proxy::resolve_tcp_endpoint(ctx.target.proxy.as_ref(), host, port)
        .await
        .ok()?;
    let (connect_host, connect_port, _bridge) = endpoint;

    // Guest/anonymous connect: success yields a readiness line; failure still
    // leaves the target open for credential attempts (Ready(None) at caller).
    let config = ClientConfig {
        addr: format!("{connect_host}:{connect_port}"),
        timeout,
        username: String::new(),
        password: String::new(),
        domain: String::new(),
        auto_reconnect: false,
        compression: false,
        dfs_enabled: false,
        dfs_target_overrides: std::collections::HashMap::new(),
    };

    match SmbClient::connect(config).await {
        Ok(_client) => Some(format!("smb reachable (guest session ok) on {host}:{port}")),
        Err(err) => {
            // Auth-required still means the SMB service answered — surface a probe line.
            if matches!(
                err.kind(),
                ErrorKind::AuthRequired | ErrorKind::SigningRequired | ErrorKind::AccessDenied
            ) {
                Some(format!("smb service responded on {host}:{port}"))
            } else if is_transport_error_kind(err.kind()) {
                None
            } else {
                Some(format!("smb service responded on {host}:{port}"))
            }
        }
    }
}

/// Lists shares via IPC$/srvsvc and probes Access for each share.
async fn enumerate_shares_with_access(client: &mut SmbClient) -> Result<String, String> {
    let shares = client.list_shares().await.map_err(|err| err.to_string())?;
    let mut rows = Vec::with_capacity(shares.len());
    for share in shares {
        let access = probe_share_access(client, &share).await;
        rows.push(ShareAccessRow {
            name: share.name,
            access,
            remark: share.comment,
        });
    }
    Ok(format_share_access_listing(&rows))
}

/// Probes tree-connect rights for one share and returns Access text.
///
/// Tree connect success yields `READ`. Disk shares additionally try a unique
/// temporary directory create+delete to detect `WRITE` without leaving files.
async fn probe_share_access(client: &mut SmbClient, share: &ShareInfo) -> String {
    let mut tree = match client.connect_share(&share.name).await {
        Ok(tree) => tree,
        Err(_) => return String::new(),
    };

    let mut access = vec!["READ".to_string()];

    // IPC$ and non-disk shares rarely allow directory create; skip WRITE probe.
    let is_disk = share.share_type & 0x0F == 0;
    if is_disk && share_allows_write(client, &mut tree).await {
        access.push("WRITE".to_string());
    }

    let _ = client.disconnect_share(&tree).await;
    access.join(",")
}

/// Best-effort WRITE probe: create and immediately remove a unique temp directory.
async fn share_allows_write(client: &mut SmbClient, tree: &mut smb2::Tree) -> bool {
    let probe = format!(
        ".brute-write-probe-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    if client.create_directory(tree, &probe).await.is_err() {
        return false;
    }
    let _ = client.delete_directory(tree, &probe).await;
    true
}

/// Splits `DOMAIN\\user` or `user@domain` into `(domain, user)`.
///
/// # Parameters
///
/// - `username`: Raw username field from credentials.
///
/// # Returns
///
/// `(domain, user)` where `domain` is empty for unqualified names.
///
/// # Errors
///
/// This function does not fail.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(split_domain_user(r"LAB\alice"), ("LAB".into(), "alice".into()));
/// assert_eq!(split_domain_user("alice@lab.local"), ("lab.local".into(), "alice".into()));
/// assert_eq!(split_domain_user("alice"), ("".into(), "alice".into()));
/// ```
pub fn split_domain_user(username: &str) -> (String, String) {
    if let Some((domain, user)) = username.split_once('\\') {
        return (domain.to_string(), user.to_string());
    }
    if let Some((user, domain)) = username.split_once('@') {
        return (domain.to_string(), user.to_string());
    }
    (String::new(), username.to_string())
}

/// One share row used for console formatting and unit tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareAccessRow {
    /// Share name (for example `C$` or `IPC$`).
    pub name: String,
    /// Access summary such as `READ` or empty when denied.
    pub access: String,
    /// Optional share remark from the server.
    pub remark: String,
}

/// Formats share enumeration output with Share / Access / Remark columns.
///
/// # Parameters
///
/// - `rows`: Share names with Access and remark strings already resolved.
///
/// # Returns
///
/// Multi-line text suitable for [`PostAuthResult::Output`] under a successful login.
///
/// # Errors
///
/// This function does not fail.
///
/// # Examples
///
/// ```ignore
/// let text = format_share_access_listing(&[ShareAccessRow {
///     name: "IPC$".into(),
///     access: "READ".into(),
///     remark: "Remote IPC".into(),
/// }]);
/// assert!(text.contains("IPC$"));
/// assert!(text.contains("READ"));
/// ```
pub fn format_share_access_listing(rows: &[ShareAccessRow]) -> String {
    let mut lines = Vec::with_capacity(rows.len() + 3);
    lines.push("Enumerated shares".to_string());
    lines.push(format!("{:<16} {:<14} {}", "Share", "Access", "Remark"));
    lines.push(format!("{:<16} {:<14} {}", "-----", "------", "------"));
    for row in rows {
        lines.push(format!(
            "{:<16} {:<14} {}",
            row.name, row.access, row.remark
        ));
    }
    if rows.is_empty() {
        lines.push("(no shares returned)".to_string());
    }
    lines.join("\n")
}

/// Returns true when an [`ErrorKind`] represents an authentication failure.
///
/// # Parameters
///
/// - `kind`: High-level SMB error classification from `smb2`.
///
/// # Returns
///
/// `true` for credential / logon style failures that should print as `[-]`.
///
/// # Errors
///
/// This function does not fail.
///
/// # Examples
///
/// ```ignore
/// assert!(is_smb_auth_failure_kind(ErrorKind::AuthRequired));
/// assert!(!is_smb_auth_failure_kind(ErrorKind::TimedOut));
/// ```
pub fn is_smb_auth_failure_kind(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::AuthRequired | ErrorKind::SigningRequired | ErrorKind::AccessDenied
    )
}

/// Returns true when the error is a transport / connectivity failure.
fn is_transport_error_kind(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::ConnectionLost | ErrorKind::TimedOut | ErrorKind::Io
    )
}

/// Maps an `smb2::Error` into a high-level attempt outcome.
///
/// # Parameters
///
/// - `err`: Error returned by the pure-Rust SMB2 client.
///
/// # Returns
///
/// [`AttemptOutcome::Failure`] for auth rejections, otherwise [`AttemptOutcome::Error`].
///
/// # Errors
///
/// This function does not fail.
///
/// # Examples
///
/// ```ignore
/// let outcome = classify_smb_error(&err);
/// ```
pub fn classify_smb_error(err: &smb2::Error) -> AttemptOutcome {
    let kind = err.kind();
    if is_smb_auth_failure_kind(kind) {
        AttemptOutcome::Failure(format!("smb auth failed: {err}"))
    } else if is_transport_error_kind(kind) {
        AttemptOutcome::Error(format!("smb transport error: {err}"))
    } else {
        // Auth-style messages can still surface as Other with a logon NTSTATUS.
        let message = err.to_string();
        if looks_like_auth_failure_message(&message) {
            AttemptOutcome::Failure(format!("smb auth failed: {message}"))
        } else {
            AttemptOutcome::Error(format!("smb error: {message}"))
        }
    }
}

/// Heuristic for protocol errors that represent bad credentials.
fn looks_like_auth_failure_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("logon")
        || lower.contains("password")
        || lower.contains("credential")
        || lower.contains("authentication")
        || lower.contains("access denied")
        || lower.contains("logon_failure")
        || lower.contains("status_logon")
}
