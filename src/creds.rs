//! Saved-credential CLI commands.

use anyhow::{Result, bail};

use crate::cli::{CredsAction, CredsArgs, CredsDeleteArgs, CredsListArgs};
use crate::database::CredentialDatabase;
use crate::engine::{CredentialRecord, delete_credentials, query_credentials};

/// Executes `creds list` or `creds delete`.
///
/// # Parameters
///
/// - `database`: Open credential database.
/// - `args`: Parsed `creds` subcommand.
///
/// # Returns
///
/// `Ok(())` when the command finishes. A requested id that was not deleted is an error.
///
/// # Errors
///
/// Returns an error when the query or delete fails, the delete is unscoped, or a
/// requested credential id was not found.
///
/// # Examples
///
/// ```ignore
/// creds::run(&database, args)?;
/// ```
pub fn run(database: &CredentialDatabase, args: CredsArgs) -> Result<()> {
    match args.action {
        CredsAction::List(args) => list(database, args),
        CredsAction::Delete(args) => delete(database, args),
    }
}

/// Prints saved credentials in the current workspace.
///
/// # Parameters
///
/// - `database`: Open credential database.
/// - `args`: Parsed `creds list` arguments. The workspace is always the current one.
///
/// # Returns
///
/// `Ok(())` after the table is printed.
///
/// # Errors
///
/// Returns an error when the current workspace cannot be read or the query fails.
///
/// # Examples
///
/// ```ignore
/// list(&database, args)?;
/// ```
fn list(database: &CredentialDatabase, args: CredsListArgs) -> Result<()> {
    let workspace = database.current_workspace()?;
    let credentials = query_credentials(
        database,
        Some(workspace.as_str()),
        args.protocol,
        args.host.as_deref(),
    )?;
    println!("current workspace: {workspace}");
    print_saved_credentials(&credentials, args.conn_url);
    Ok(())
}

/// Deletes saved credentials in the current workspace and prints that workspace.
///
/// # Parameters
///
/// - `database`: Open credential database.
/// - `args`: Parsed `creds delete` arguments. The workspace is always the current one.
///
/// # Returns
///
/// `Ok(())` when every requested id was deleted, or when a filter delete finishes.
///
/// # Errors
///
/// Returns an error when the delete is unscoped, the database call fails, or a
/// requested credential id was not found in the current workspace.
///
/// # Examples
///
/// ```ignore
/// delete(&database, args)?;
/// ```
fn delete(database: &CredentialDatabase, args: CredsDeleteArgs) -> Result<()> {
    let report = delete_credentials(
        database,
        None,
        args.protocol,
        args.host.as_deref(),
        &args.ids,
        args.all,
    )?;
    println!("current workspace: {}", report.workspace);
    for credential in &report.deleted {
        println!(
            "deleted credential: {} {} {}@{}:{}",
            credential.id,
            credential.protocol,
            display_username(credential.username.as_deref()),
            credential.host,
            credential.port
        );
    }
    let count = report.deleted.len();
    if count == 1 {
        println!("deleted 1 credential");
    } else {
        println!("deleted {count} credentials");
    }
    if report.missing_ids.is_empty() {
        return Ok(());
    }
    let missing = report
        .missing_ids
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    bail!("credential not found: {missing}")
}

/// Renders an empty username as `-`.
fn display_username(username: Option<&str>) -> &str {
    match username {
        Some(value) if !value.is_empty() => value,
        _ => "-",
    }
}

/// Prints saved credentials as a simple list table.
fn print_saved_credentials(credentials: &[CredentialRecord], show_conn_url: bool) {
    if show_conn_url {
        println!("{:<6} {:<12} CONN_URL", "ID", "PROTOCOL");
    } else {
        println!(
            "{:<6} {:<16} {:<12} {:<20} {:<6} {:<20} PASSWORD",
            "ID", "WORKSPACE", "PROTOCOL", "HOST", "PORT", "USERNAME"
        );
    }

    for credential in credentials {
        let username = credential.username.as_deref().unwrap_or("");
        let password = credential.password.as_deref().unwrap_or("");

        if show_conn_url {
            println!(
                "{:<6} {:<12} {}",
                credential.id, credential.protocol, credential.conn_url
            );
        } else {
            println!(
                "{:<6} {:<16} {:<12} {:<20} {:<6} {:<20} {}",
                credential.id,
                credential.workspace,
                credential.protocol,
                credential.host,
                credential.port,
                username,
                password
            );
        }
    }
}
