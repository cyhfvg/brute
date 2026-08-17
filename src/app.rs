//! Top-level orchestration for the brute-force CLI.

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;

use crate::cli::{
    Cli, Command, CredsAction, CredsArgs, ProtocolArgs, WorkspaceAction, WorkspaceArgs,
};
use crate::database::{CredentialDatabase, SavedCredential};
use crate::engine::{SprayReporter, SprayRequest, run_spray};
use crate::output::Console;
use crate::protocol::{AttemptContext, AttemptOutcome, TargetContext};

/// Parses CLI arguments and executes the selected command.
pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    let (database, initialized) = CredentialDatabase::open_default()?;
    let is_mcp = matches!(cli.command, Command::Mcp);
    if initialized && !is_mcp {
        println!(
            "[*] initialized credential database: {}",
            database.path().display()
        );
        println!("[*] initialized default workspace: default");
    }

    match cli.command {
        Command::Protocol(protocol_args) => {
            run_protocol(cli.no_color, cli.proxy, database, protocol_args).await
        }
        Command::Workspace(args) => run_workspace(database, args),
        Command::Creds(args) => run_creds(database, args),
        Command::Mcp => crate::mcp::serve_stdio(database).await,
    }
}

/// Executes one protocol module with loaded or database-backed credentials.
///
/// # Parameters
///
/// - `no_color`: Disable ANSI colors when true.
/// - `proxy`: Optional top-level `--proxy` configuration applied to all attempts.
/// - `database`: Open credential database handle.
/// - `protocol_args`: Parsed protocol subcommand arguments.
///
/// # Returns
///
/// `Ok(())` when the spray completes; errors on invalid targets/credentials or DB failures.
///
/// # Errors
///
/// Returns [`anyhow::Error`] when target/credential expansion fails or persistence fails fatally.
async fn run_protocol(
    no_color: bool,
    proxy: Option<crate::proxy::ProxyConfig>,
    database: CredentialDatabase,
    protocol_args: ProtocolArgs,
) -> Result<()> {
    let request = SprayRequest::from_protocol_args(&protocol_args, proxy);
    let reporter = ConsoleReporter(Arc::new(Console::new(no_color)));
    run_spray(&database, request, Some(&reporter)).await?;
    Ok(())
}

/// Handles workspace commands.
fn run_workspace(database: CredentialDatabase, args: WorkspaceArgs) -> Result<()> {
    match args.action {
        WorkspaceAction::Current => {
            println!("{}", database.current_workspace()?);
        }
        WorkspaceAction::Use { name } => {
            database.set_current_workspace(&name)?;
            println!("current workspace: {name}");
        }
        WorkspaceAction::New { name } => {
            if database.create_workspace(&name)? {
                println!("created workspace: {name}");
            } else {
                println!("workspace already exists: {name}");
            }
        }
        WorkspaceAction::Delete { name } => {
            if database.delete_workspace(&name)? {
                println!("deleted workspace: {name}");
            } else {
                println!("workspace not found: {name}");
            }
        }
        WorkspaceAction::List => {
            for workspace in database.list_workspaces()? {
                let marker = if workspace.is_current { "*" } else { " " };
                println!("{marker} {}", workspace.name);
            }
        }
    }

    Ok(())
}

/// Handles saved credential commands.
fn run_creds(database: CredentialDatabase, args: CredsArgs) -> Result<()> {
    match args.action {
        CredsAction::List(args) => {
            let workspace = match args.workspace {
                Some(workspace) => workspace,
                None => database.current_workspace()?,
            };
            let credentials =
                database.list_credentials(&workspace, args.protocol, args.host.as_deref())?;
            print_saved_credentials(&credentials, args.conn_url);
        }
    }

    Ok(())
}

/// Prints saved credentials as a simple list table.
fn print_saved_credentials(credentials: &[SavedCredential], show_conn_url: bool) {
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

/// Console adapter that prints engine events in NetExec style.
struct ConsoleReporter(Arc<Console>);

impl SprayReporter for ConsoleReporter {
    fn probe(&self, ctx: &TargetContext, message: &str) {
        self.0.print_probe(ctx, message);
    }

    fn attempt(&self, ctx: &AttemptContext, outcome: &AttemptOutcome) {
        self.0.print_attempt(ctx, outcome);
    }

    fn save_error(&self, err: &anyhow::Error) {
        eprintln!("failed to save credential: {err:#}");
    }
}

#[cfg(test)]
mod tests {
    /// Verifies RDP attempt scheduling has no module-level serial mutex in source.
    #[test]
    fn rdp_module_source_has_no_global_serial_mutex() {
        let source = include_str!("protocol/rdp.rs");
        assert!(
            source.contains("run_blocking_with_timeout"),
            "RDP attempts must use spawn_blocking via run_blocking_with_timeout"
        );
        assert!(
            !source.contains("std::sync::Mutex"),
            "RDP module must not use std::sync::Mutex across attempts"
        );
        assert!(
            !source.contains("tokio::sync::Mutex"),
            "RDP module must not use tokio::sync::Mutex across attempts"
        );
        assert!(
            !source.contains("lazy_static") && !source.contains("OnceLock"),
            "RDP module must not introduce process-wide locks for attempts"
        );
    }
}
