//! Request, report, and parser types for the spray engine.

use anyhow::{Result, bail};
use serde::Serialize;

use crate::cli::{CommonArgs, HttpUrlScheme, Protocol, ProtocolArgs, WinrmShellType};
use crate::database::SavedCredential;
use crate::protocol::{AttemptContext, AttemptOutcome, TargetContext};
use crate::proxy::ProxyConfig;

/// Live reporter used by the CLI console path.
pub trait SprayReporter: Send + Sync {
    /// Emits one successful target-level probe line.
    fn probe(&self, ctx: &TargetContext, message: &str);

    /// Emits one credential attempt outcome.
    fn attempt(&self, ctx: &AttemptContext, outcome: &AttemptOutcome);

    /// Emits a non-fatal credential persistence error.
    fn save_error(&self, err: &anyhow::Error);
}

/// One programmatic spray or single-account verification request.
#[derive(Debug, Clone)]
pub struct SprayRequest {
    /// Protocol module to run.
    pub protocol: Protocol,
    /// Target IPv4 hosts, IPv4 CIDR prefixes, or target-file paths. IPv6 is not supported.
    pub targets: Vec<String>,
    /// Username literals or wordlist paths; ignored when `credential_id` is set.
    pub usernames: Vec<String>,
    /// Password literals or wordlist paths; ignored when `credential_id` is set.
    pub passwords: Vec<String>,
    /// Saved credential id from the selected workspace.
    pub credential_id: Option<i64>,
    /// Optional service port override.
    pub port: Option<u16>,
    /// Global in-flight attempt cap.
    pub threads: usize,
    /// Transient transport retry count.
    pub retries: usize,
    /// Per-attempt timeout in milliseconds.
    pub timeout_ms: u64,
    /// Continue a target after the first success.
    pub continue_on_success: bool,
    /// Optional outbound proxy.
    pub proxy: Option<ProxyConfig>,
    /// Optional post-auth command for protocols that support `-x`.
    pub execute: Option<String>,
    /// HTTP/Tomcat request path.
    pub path: Option<String>,
    /// HTTP URL scheme; ignored by other protocols.
    pub url_scheme: HttpUrlScheme,
    /// Oracle Service Name literals or wordlist paths.
    pub service_names: Vec<String>,
    /// Oracle SID literals or wordlist paths.
    pub sids: Vec<String>,
    /// Enumerate SMB shares after a successful login.
    pub shares: bool,
    /// WinRM shell type for probes and `-x`.
    pub shell_type: Option<WinrmShellType>,
    /// Workspace used for `--id` lookup and success persistence.
    pub workspace: Option<String>,
}

impl Default for SprayRequest {
    fn default() -> Self {
        Self {
            protocol: Protocol::Ssh,
            targets: Vec::new(),
            usernames: Vec::new(),
            passwords: Vec::new(),
            credential_id: None,
            port: None,
            threads: 16,
            retries: 3,
            timeout_ms: 5_000,
            continue_on_success: false,
            proxy: None,
            execute: None,
            path: None,
            url_scheme: HttpUrlScheme::Http,
            service_names: Vec::new(),
            sids: Vec::new(),
            shares: false,
            shell_type: None,
            workspace: None,
        }
    }
}

/// High-level attempt classification returned to MCP clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptStatus {
    /// Authentication succeeded.
    Success,
    /// Authentication was rejected.
    Failure,
    /// Transport, protocol, or local error.
    Error,
}

/// Structured record for one login attempt.
#[derive(Debug, Clone, Serialize)]
pub struct AttemptRecord {
    /// Protocol name stored in the database.
    pub protocol: String,
    /// Target host.
    pub host: String,
    /// Effective service port.
    pub port: u16,
    /// Username used for the attempt.
    pub username: Option<String>,
    /// Password used for the attempt.
    pub password: Option<String>,
    /// Oracle Service Name when present.
    pub service_name: Option<String>,
    /// Oracle SID when present.
    pub sid: Option<String>,
    /// Attempt classification.
    pub status: AttemptStatus,
    /// Human-readable outcome message.
    pub message: String,
    /// Optional post-auth command or share-enum output.
    pub post_auth: Option<String>,
}

/// One target-level probe observation.
#[derive(Debug, Clone, Serialize)]
pub struct ProbeRecord {
    /// Target host that was probed.
    pub host: String,
    /// Effective service port.
    pub port: u16,
    /// Probe summary shown to operators.
    pub message: String,
}

/// Completed spray or verification report.
#[derive(Debug, Clone, Serialize)]
pub struct SprayReport {
    /// Workspace that received successful credentials.
    pub workspace: String,
    /// Protocol that was executed.
    pub protocol: String,
    /// Target-level probe lines.
    pub probes: Vec<ProbeRecord>,
    /// Attempts that were actually executed.
    pub attempts: Vec<AttemptRecord>,
    /// Successful attempts only.
    pub successes: Vec<AttemptRecord>,
    /// Attempts skipped after an earlier success.
    pub skipped: usize,
}

/// One saved credential returned to MCP or library callers.
#[derive(Debug, Clone, Serialize)]
pub struct CredentialRecord {
    /// Database row id.
    pub id: i64,
    /// Workspace name.
    pub workspace: String,
    /// Protocol name.
    pub protocol: String,
    /// Host.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Username.
    pub username: Option<String>,
    /// Password.
    pub password: Option<String>,
    /// Scanner-friendly connection URL.
    pub conn_url: String,
}

/// One workspace row for MCP listing.
#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceInfo {
    /// Workspace name.
    pub name: String,
    /// Whether this workspace is current.
    pub is_current: bool,
}

/// One supported protocol advertised to MCP clients.
#[derive(Debug, Clone, Serialize)]
pub struct ProtocolInfo {
    /// Stable protocol name.
    pub name: String,
    /// Default TCP port.
    pub default_port: u16,
}

impl From<&SavedCredential> for CredentialRecord {
    fn from(credential: &SavedCredential) -> Self {
        Self {
            id: credential.id,
            workspace: credential.workspace.clone(),
            protocol: credential.protocol.clone(),
            host: credential.host.clone(),
            port: credential.port,
            username: credential.username.clone(),
            password: credential.password.clone(),
            conn_url: credential.conn_url.clone(),
        }
    }
}

/// Implemented protocol list in CLI order.
pub(crate) const ALL_PROTOCOLS: [Protocol; 12] = [
    Protocol::Ssh,
    Protocol::Ftp,
    Protocol::Mysql,
    Protocol::Postgresql,
    Protocol::Redis,
    Protocol::Tomcat,
    Protocol::Smb,
    Protocol::Rdp,
    Protocol::Winrm,
    Protocol::Oracle,
    Protocol::Http,
    Protocol::Vnc,
];

/// Parses a protocol name used by MCP tools and library callers.
///
/// # Parameters
///
/// - `name`: Case-insensitive protocol name. `tomcat-manager` is accepted as an alias of `tomcat`.
///
/// # Returns
///
/// The matching [`Protocol`].
///
/// # Errors
///
/// Returns an error when `name` is not a supported protocol.
///
/// # Examples
///
/// ```
/// use brute::cli::Protocol;
/// use brute::engine::parse_protocol;
///
/// assert_eq!(parse_protocol("SSH").unwrap(), Protocol::Ssh);
/// assert_eq!(parse_protocol("tomcat-manager").unwrap(), Protocol::Tomcat);
/// ```
pub fn parse_protocol(name: &str) -> Result<Protocol> {
    match name.trim().to_ascii_lowercase().as_str() {
        "ssh" => Ok(Protocol::Ssh),
        "ftp" => Ok(Protocol::Ftp),
        "mysql" => Ok(Protocol::Mysql),
        "postgresql" | "postgres" => Ok(Protocol::Postgresql),
        "redis" => Ok(Protocol::Redis),
        "tomcat" | "tomcat-manager" => Ok(Protocol::Tomcat),
        "smb" => Ok(Protocol::Smb),
        "rdp" => Ok(Protocol::Rdp),
        "winrm" => Ok(Protocol::Winrm),
        "oracle" => Ok(Protocol::Oracle),
        "http" => Ok(Protocol::Http),
        "vnc" => Ok(Protocol::Vnc),
        other => bail!(
            "unsupported protocol {other:?}; expected one of {}",
            ALL_PROTOCOLS
                .iter()
                .copied()
                .map(Protocol::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Parses an HTTP URL scheme string.
///
/// # Parameters
///
/// - `name`: `http` or `https` (case-insensitive).
///
/// # Returns
///
/// The matching [`HttpUrlScheme`].
///
/// # Errors
///
/// Returns an error when `name` is neither `http` nor `https`.
///
/// # Examples
///
/// ```
/// use brute::cli::HttpUrlScheme;
/// use brute::engine::parse_http_scheme;
///
/// assert_eq!(parse_http_scheme("HTTPS").unwrap(), HttpUrlScheme::Https);
/// ```
pub fn parse_http_scheme(name: &str) -> Result<HttpUrlScheme> {
    match name.trim().to_ascii_lowercase().as_str() {
        "http" => Ok(HttpUrlScheme::Http),
        "https" => Ok(HttpUrlScheme::Https),
        other => bail!("unsupported HTTP scheme {other:?}; expected http or https"),
    }
}

/// Parses a WinRM shell-type string.
///
/// # Parameters
///
/// - `name`: `cmd` or `powershell` (case-insensitive).
///
/// # Returns
///
/// The matching [`WinrmShellType`].
///
/// # Errors
///
/// Returns an error when `name` is not a supported shell type.
///
/// # Examples
///
/// ```
/// use brute::cli::WinrmShellType;
/// use brute::engine::parse_shell_type;
///
/// assert_eq!(parse_shell_type("PowerShell").unwrap(), WinrmShellType::Powershell);
/// ```
pub fn parse_shell_type(name: &str) -> Result<WinrmShellType> {
    match name.trim().to_ascii_lowercase().as_str() {
        "cmd" => Ok(WinrmShellType::Cmd),
        "powershell" => Ok(WinrmShellType::Powershell),
        other => bail!("unsupported WinRM shell type {other:?}; expected cmd or powershell"),
    }
}

impl SprayRequest {
    /// Builds a request from parsed CLI protocol arguments.
    ///
    /// # Parameters
    ///
    /// - `args`: Selected protocol subcommand.
    /// - `proxy`: Top-level `--proxy` configuration.
    ///
    /// # Returns
    ///
    /// A [`SprayRequest`] ready for [`crate::engine::run_spray`].
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let request = SprayRequest::from_protocol_args(&protocol_args, cli.proxy);
    /// ```
    pub fn from_protocol_args(args: &ProtocolArgs, proxy: Option<ProxyConfig>) -> Self {
        let common = args.common();
        let (service_names, sids) = match args {
            ProtocolArgs::Oracle(oracle) => (oracle.service_name.clone(), oracle.sid.clone()),
            _ => (Vec::new(), Vec::new()),
        };
        let url_scheme = match args {
            ProtocolArgs::Http(http) => http.url_scheme,
            _ => HttpUrlScheme::Http,
        };
        Self {
            protocol: args.protocol(),
            targets: common.targets.clone(),
            usernames: common.usernames.clone(),
            passwords: common.passwords.clone(),
            credential_id: common.credential_id,
            port: common.port,
            threads: common.threads,
            retries: common.retries,
            timeout_ms: common.timeout_ms,
            continue_on_success: common.continue_on_success,
            proxy,
            execute: args.execute().map(ToOwned::to_owned),
            path: args.path().map(ToOwned::to_owned),
            url_scheme,
            service_names,
            sids,
            shares: args.shares(),
            shell_type: args.shell_type(),
            workspace: None,
        }
    }

    pub(super) fn to_common_args(&self) -> CommonArgs {
        CommonArgs {
            targets: self.targets.clone(),
            usernames: self.usernames.clone(),
            passwords: self.passwords.clone(),
            credential_id: self.credential_id,
            port: self.port,
            threads: self.threads,
            retries: self.retries,
            timeout_ms: self.timeout_ms,
            continue_on_success: self.continue_on_success,
            proxy: self.proxy.clone(),
        }
    }

    pub(super) fn effective_path(&self) -> Option<String> {
        match self.protocol {
            Protocol::Tomcat => Some(
                self.path
                    .clone()
                    .unwrap_or_else(|| "/manager/html".to_string()),
            ),
            Protocol::Http => Some(self.path.clone().unwrap_or_else(|| "/".to_string())),
            _ => self.path.clone(),
        }
    }

    pub(super) fn validate(&self) -> Result<()> {
        if self.threads == 0 {
            bail!("threads must be at least 1");
        }
        if self.timeout_ms == 0 {
            bail!("timeout-ms must be at least 1");
        }
        if self.credential_id.is_some()
            && (!self.usernames.is_empty() || !self.passwords.is_empty())
        {
            bail!("credential_id cannot be combined with usernames or passwords");
        }
        if self.protocol == Protocol::Oracle {
            if self.service_names.is_empty() && self.sids.is_empty() {
                bail!("oracle requires service_name or sid");
            }
            if !self.service_names.is_empty() && !self.sids.is_empty() {
                bail!("oracle service_name and sid are mutually exclusive");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies protocol aliases used by MCP tools.
    #[test]
    fn parse_protocol_accepts_aliases_and_rejects_unknown() {
        assert_eq!(parse_protocol("tomcat-manager").unwrap(), Protocol::Tomcat);
        assert_eq!(parse_protocol("postgres").unwrap(), Protocol::Postgresql);
        assert!(parse_protocol("ldap").is_err());
    }

    /// Verifies Oracle identifier validation before any network I/O.
    #[test]
    fn validate_request_requires_exclusive_oracle_identifier() {
        let mut request = SprayRequest {
            protocol: Protocol::Oracle,
            targets: vec!["db.internal".into()],
            usernames: vec!["system".into()],
            passwords: vec!["oracle".into()],
            ..SprayRequest::default()
        };
        assert!(request.validate().is_err());
        request.service_names = vec!["XE".into()];
        request.sids = vec!["ORCL".into()];
        assert!(request.validate().is_err());
        request.sids.clear();
        assert!(request.validate().is_ok());
    }
}
