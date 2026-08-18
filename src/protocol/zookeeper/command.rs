//! Post-auth ZooKeeper command parsing and execution.

use zookeeper_client::{Acls, Client, CreateMode, Stat};

use crate::protocol::AttemptSuccess;

/// Executes a zkCli-style command against an established session.
///
/// # Parameters
///
/// - `client`: Authenticated or anonymous ZooKeeper client.
/// - `command`: Whitespace-separated command; quotes preserve arguments.
/// - `success_message`: Login banner preserved on command success.
///
/// # Returns
///
/// [`AttemptSuccess`] with formatted command output.
///
/// # Errors
///
/// Returns a string when the command is empty, unknown, missing arguments,
/// or the ZooKeeper operation fails.
///
/// # Examples
///
/// ```ignore
/// let success = execute_zookeeper_command(&client, "ls /", "ZooKeeper access!").await?;
/// ```
pub async fn execute_zookeeper_command(
    client: &Client,
    command: &str,
    success_message: &str,
) -> Result<AttemptSuccess, String> {
    let parts = split_command(command);
    let Some((name, args)) = parts.split_first() else {
        return Err("empty zookeeper command".to_string());
    };
    let output = dispatch_command(client, name, args).await?;
    Ok(AttemptSuccess::with_command(success_message, output))
}

/// Dispatches one parsed ZooKeeper command.
///
/// # Parameters
///
/// - `client`: Established session.
/// - `name`: Command verb (`ls`, `get`, `create`, `set`, `delete`, `stat`, `mkdir`, `deleteall`).
/// - `args`: Remaining tokens after the verb.
///
/// # Returns
///
/// Human-readable command result.
///
/// # Errors
///
/// Returns a string for unknown verbs, missing arguments, or ZooKeeper errors.
///
/// # Examples
///
/// ```ignore
/// let text = dispatch_command(&client, "ls", &["/".into()]).await?;
/// ```
async fn dispatch_command(client: &Client, name: &str, args: &[String]) -> Result<String, String> {
    match name.to_ascii_lowercase().as_str() {
        "ls" | "dir" => {
            let path = args.first().map(String::as_str).unwrap_or("/");
            let children = client.list_children(path).await.map_err(zk_err)?;
            Ok(format_children(path, &children))
        }
        "get" => {
            let path = require_path(args, "get")?;
            let (data, stat) = client.get_data(path).await.map_err(zk_err)?;
            Ok(format!("{}\n{}", format_bytes(&data), format_stat(&stat)))
        }
        "stat" => {
            let path = require_path(args, "stat")?;
            match client.check_stat(path).await.map_err(zk_err)? {
                Some(stat) => Ok(format_stat(&stat)),
                None => Err(format!("no node {path}")),
            }
        }
        "create" => {
            let path = require_path(args, "create")?;
            let data = args.get(1).map(String::as_bytes).unwrap_or(b"");
            client
                .create(
                    path,
                    data,
                    &CreateMode::Persistent.with_acls(Acls::anyone_all()),
                )
                .await
                .map_err(zk_err)?;
            Ok(format!("created {path}"))
        }
        "set" => {
            let path = require_path(args, "set")?;
            let data = args.get(1).map(String::as_bytes).unwrap_or(b"");
            let stat = client.set_data(path, data, None).await.map_err(zk_err)?;
            Ok(format!("set {path}\n{}", format_stat(&stat)))
        }
        "delete" | "rm" => {
            let path = require_path(args, "delete")?;
            client.delete(path, None).await.map_err(zk_err)?;
            Ok(format!("deleted {path}"))
        }
        "deleteall" | "rmr" => {
            let path = require_path(args, "deleteall")?;
            delete_recursive(client, path).await?;
            Ok(format!("deleted {path}"))
        }
        "mkdir" => {
            let path = require_path(args, "mkdir")?;
            client
                .mkdir(path, &CreateMode::Persistent.with_acls(Acls::anyone_all()))
                .await
                .map_err(zk_err)?;
            Ok(format!("created {path}"))
        }
        other => Err(format!(
            "unsupported zookeeper command {other:?}; expected ls, get, stat, create, set, delete, deleteall, mkdir"
        )),
    }
}

/// Recursively deletes a znode and its descendants.
///
/// # Parameters
///
/// - `client`: Established session.
/// - `path`: Absolute znode path to remove.
///
/// # Returns
///
/// `Ok(())` when the subtree is removed.
///
/// # Errors
///
/// Returns a string when listing or deleting any node fails.
///
/// # Examples
///
/// ```ignore
/// delete_recursive(&client, "/tmp").await?;
/// ```
async fn delete_recursive(client: &Client, path: &str) -> Result<(), String> {
    let children = client.list_children(path).await.map_err(zk_err)?;
    for child in children {
        let child_path = join_zk_path(path, &child);
        Box::pin(delete_recursive(client, &child_path)).await?;
    }
    client.delete(path, None).await.map_err(zk_err)
}

/// Joins a parent ZooKeeper path with a child name.
///
/// # Parameters
///
/// - `parent`: Absolute parent path (`/` or `/foo`).
/// - `child`: Single path segment.
///
/// # Returns
///
/// Combined absolute path.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::zookeeper::join_zk_path;
///
/// assert_eq!(join_zk_path("/", "zookeeper"), "/zookeeper");
/// assert_eq!(join_zk_path("/app", "conf"), "/app/conf");
/// ```
pub fn join_zk_path(parent: &str, child: &str) -> String {
    if parent == "/" {
        format!("/{child}")
    } else {
        format!("{parent}/{child}")
    }
}

/// Requires a path argument for path-taking commands.
///
/// # Parameters
///
/// - `args`: Tokens after the command verb.
/// - `command`: Verb used in the error message.
///
/// # Returns
///
/// The first argument as a path.
///
/// # Errors
///
/// Returns a string when `args` is empty.
///
/// # Examples
///
/// ```ignore
/// let path = require_path(&["/".into()], "get")?;
/// ```
fn require_path<'a>(args: &'a [String], command: &str) -> Result<&'a str, String> {
    args.first()
        .map(String::as_str)
        .ok_or_else(|| format!("{command} requires a path"))
}

/// Formats a `list_children` result as one child per line.
///
/// # Parameters
///
/// - `path`: Queried path, shown when the node is empty.
/// - `children`: Child names returned by the server.
///
/// # Returns
///
/// Terminal-friendly listing.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(format_children("/", &["zookeeper".into()]), "[zookeeper]");
/// ```
fn format_children(path: &str, children: &[String]) -> String {
    if children.is_empty() {
        format!("{path} has no children")
    } else {
        format!("[{}]", children.join(", "))
    }
}

/// Formats znode bytes as UTF-8 text or a debug byte dump.
///
/// # Parameters
///
/// - `bytes`: Raw znode payload.
///
/// # Returns
///
/// UTF-8 text when valid; otherwise a debug dump.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(format_bytes(b"ok"), "ok");
/// ```
fn format_bytes(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_string(),
        Err(_) => format!("{bytes:?}"),
    }
}

/// Formats a ZooKeeper [`Stat`] as zkCli-style key/value lines.
///
/// # Parameters
///
/// - `stat`: Node metadata from get/stat/set.
///
/// # Returns
///
/// Multi-line stat dump.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// let text = format_stat(&stat);
/// assert!(text.contains("dataLength"));
/// ```
fn format_stat(stat: &Stat) -> String {
    format!(
        "cZxid = {:#x}\nmZxid = {:#x}\npZxid = {:#x}\nctime = {}\nmtime = {}\nversion = {}\ncversion = {}\naversion = {}\nephemeralOwner = {:#x}\ndataLength = {}\nnumChildren = {}",
        stat.czxid,
        stat.mzxid,
        stat.pzxid,
        stat.ctime,
        stat.mtime,
        stat.version,
        stat.cversion,
        stat.aversion,
        stat.ephemeral_owner,
        stat.data_length,
        stat.num_children
    )
}

/// Converts a ZooKeeper client error into a command error string.
///
/// # Parameters
///
/// - `err`: Operation error.
///
/// # Returns
///
/// Display text of `err`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// let text = zk_err(err);
/// ```
fn zk_err(err: zookeeper_client::Error) -> String {
    err.to_string()
}

/// Splits a command string while preserving quoted whitespace.
///
/// # Parameters
///
/// - `command`: Raw `-x` value.
///
/// # Returns
///
/// Tokens with surrounding quotes removed.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::zookeeper::split_command;
///
/// assert_eq!(split_command("create /app 'hello world'"), ["create", "/app", "hello world"]);
/// ```
pub fn split_command(command: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quote = None;

    for ch in command.chars() {
        match (ch, quote) {
            ('\'' | '"', None) => quote = Some(ch),
            (c, Some(q)) if c == q => quote = None,
            (c, None) if c.is_whitespace() => {
                if !current.is_empty() {
                    parts.push(std::mem::take(&mut current));
                }
            }
            (c, _) => current.push(c),
        }
    }

    if !current.is_empty() {
        parts.push(current);
    }

    parts
}

#[cfg(test)]
mod tests {
    use super::{format_children, join_zk_path, split_command};

    /// Verifies quoted arguments keep interior whitespace.
    #[test]
    fn split_command_preserves_quoted_data() {
        assert_eq!(
            split_command("create /app 'hello world'"),
            ["create", "/app", "hello world"]
        );
    }

    /// Verifies child path joining at root and nested parents.
    #[test]
    fn join_zk_path_handles_root_and_nested() {
        assert_eq!(join_zk_path("/", "zookeeper"), "/zookeeper");
        assert_eq!(join_zk_path("/app", "conf"), "/app/conf");
    }

    /// Verifies empty listings mention the queried path.
    #[test]
    fn format_children_empty_mentions_path() {
        assert_eq!(format_children("/empty", &[]), "/empty has no children");
        assert_eq!(format_children("/", &["zookeeper".into()]), "[zookeeper]");
    }
}
