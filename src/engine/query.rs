//! Read-only query helpers for workspaces, saved credentials, and protocols.

use anyhow::Result;

use crate::cli::Protocol;
use crate::database::CredentialDatabase;

use super::types::{ALL_PROTOCOLS, CredentialRecord, ProtocolInfo, WorkspaceInfo};

/// Returns the stable protocol names advertised to MCP clients.
///
/// # Returns
///
/// Lowercase protocol names in CLI order.
///
/// # Examples
///
/// ```
/// use brute::engine::protocol_names;
///
/// assert!(protocol_names().contains(&"ssh"));
/// assert!(protocol_names().contains(&"http"));
/// ```
pub fn protocol_names() -> Vec<&'static str> {
    ALL_PROTOCOLS
        .iter()
        .map(|protocol| protocol.as_str())
        .collect()
}

/// Returns protocol metadata for MCP discovery.
///
/// # Returns
///
/// Name and default port for every implemented protocol.
///
/// # Examples
///
/// ```
/// use brute::engine::list_protocols;
///
/// let protocols = list_protocols();
/// assert!(protocols.iter().any(|item| item.name == "ssh" && item.default_port == 22));
/// ```
pub fn list_protocols() -> Vec<ProtocolInfo> {
    ALL_PROTOCOLS
        .iter()
        .map(|protocol| ProtocolInfo {
            name: protocol.as_str().to_string(),
            default_port: protocol.default_port(),
        })
        .collect()
}

/// Lists workspaces from the credential database.
///
/// # Parameters
///
/// - `database`: Open credential database.
///
/// # Returns
///
/// Workspace names with the current-workspace flag.
///
/// # Errors
///
/// Returns an error when the database cannot be read.
///
/// # Examples
///
/// ```ignore
/// let workspaces = list_workspaces(&database)?;
/// ```
pub fn list_workspaces(database: &CredentialDatabase) -> Result<Vec<WorkspaceInfo>> {
    database.list_workspaces().map(|rows| {
        rows.into_iter()
            .map(|row| WorkspaceInfo {
                name: row.name,
                is_current: row.is_current,
            })
            .collect()
    })
}

/// Lists saved credentials with optional filters.
///
/// # Parameters
///
/// - `database`: Open credential database.
/// - `workspace`: Workspace to search; defaults to the current workspace.
/// - `protocol`: Optional protocol filter.
/// - `host`: Optional exact host filter.
///
/// # Returns
///
/// Matching saved credentials, including plaintext passwords.
///
/// # Errors
///
/// Returns an error when the workspace cannot be resolved or the query fails.
///
/// # Examples
///
/// ```ignore
/// let creds = query_credentials(&database, None, Some(Protocol::Ssh), None)?;
/// ```
pub fn query_credentials(
    database: &CredentialDatabase,
    workspace: Option<&str>,
    protocol: Option<Protocol>,
    host: Option<&str>,
) -> Result<Vec<CredentialRecord>> {
    let workspace = resolve_workspace(database, workspace)?;
    database
        .list_credentials(&workspace, protocol, host)
        .map(|rows| rows.iter().map(CredentialRecord::from).collect())
}

/// Resolves the workspace used for lookup and persistence.
///
/// # Parameters
///
/// - `database`: Open credential database.
/// - `workspace`: Explicit workspace name, or `None` for the current workspace.
///
/// # Returns
///
/// The workspace name to use.
///
/// # Errors
///
/// Returns an error when the current workspace cannot be read.
pub(super) fn resolve_workspace(
    database: &CredentialDatabase,
    workspace: Option<&str>,
) -> Result<String> {
    match workspace {
        Some(name) if !name.trim().is_empty() => Ok(name.to_string()),
        _ => database.current_workspace(),
    }
}
