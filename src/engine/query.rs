//! Workspace, protocol, and saved-credential store helpers.

use std::collections::HashSet;

use anyhow::{Result, bail};

use crate::cli::Protocol;
use crate::database::CredentialDatabase;

use super::types::{
    ALL_PROTOCOLS, CredentialDeleteReport, CredentialRecord, ProtocolInfo, WorkspaceInfo,
};

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

/// Deletes saved credentials in one workspace.
///
/// An unscoped delete is refused unless `delete_all` is set. `delete_all`
/// cannot be combined with ids or filters. Requested ids that are not in the
/// matched set are reported and are not treated as a database failure.
///
/// # Parameters
///
/// - `database`: Open credential database.
/// - `workspace`: Workspace to delete from; defaults to the current workspace.
/// - `protocol`: Optional protocol filter.
/// - `host`: Optional exact host filter. Blank values are ignored.
/// - `ids`: Credential ids to delete. Empty means do not filter by id.
/// - `delete_all`: Delete every credential in the workspace when no other selector is set.
///
/// # Returns
///
/// The workspace, deleted credential records, and requested ids that were not deleted.
///
/// # Errors
///
/// Returns an error when the selector is missing, `delete_all` is combined with
/// another selector, the workspace cannot be resolved, or the delete fails.
///
/// # Examples
///
/// ```ignore
/// let report = delete_credentials(&database, None, None, None, &[3], false)?;
/// ```
pub fn delete_credentials(
    database: &CredentialDatabase,
    workspace: Option<&str>,
    protocol: Option<Protocol>,
    host: Option<&str>,
    ids: &[i64],
    delete_all: bool,
) -> Result<CredentialDeleteReport> {
    let host = nonempty_host(host);
    ensure_delete_scope(ids, protocol, host, delete_all)?;
    let workspace_name = resolve_workspace(database, workspace)?;
    let requested_ids = unique_ids(ids);
    let id_filter = if delete_all {
        &[][..]
    } else {
        requested_ids.as_slice()
    };
    let deleted = database.delete_credentials(&workspace_name, protocol, host, id_filter)?;
    let deleted_ids: HashSet<i64> = deleted.iter().map(|row| row.id).collect();
    let missing_ids = requested_ids
        .into_iter()
        .filter(|id| !deleted_ids.contains(id))
        .collect();
    Ok(CredentialDeleteReport {
        workspace: workspace_name,
        deleted: deleted.iter().map(CredentialRecord::from).collect(),
        missing_ids,
    })
}

/// Returns a trimmed host selector, or `None` when the value is blank.
fn nonempty_host(host: Option<&str>) -> Option<&str> {
    host.map(str::trim).filter(|value| !value.is_empty())
}

/// Rejects an unscoped delete and a delete that mixes `--all` with other selectors.
fn ensure_delete_scope(
    ids: &[i64],
    protocol: Option<Protocol>,
    host: Option<&str>,
    delete_all: bool,
) -> Result<()> {
    let scoped = !ids.is_empty() || protocol.is_some() || host.is_some();
    if delete_all && scoped {
        bail!("all cannot be combined with ids, protocol, or host");
    }
    if !delete_all && !scoped {
        bail!(
            "refusing to delete every credential in the workspace; pass ids, protocol, host, or all"
        );
    }
    Ok(())
}

/// Deduplicates ids while preserving first-seen order.
fn unique_ids(ids: &[i64]) -> Vec<i64> {
    let mut seen = HashSet::with_capacity(ids.len());
    let mut unique = Vec::with_capacity(ids.len());
    for id in ids {
        if seen.insert(*id) {
            unique.push(*id);
        }
    }
    unique
}
