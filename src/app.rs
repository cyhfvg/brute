//! Top-level orchestration for the brute-force CLI.

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tokio_util::sync::CancellationToken;

use crate::cli::{Cli, ComboArgs, Command, ProtocolArgs, WorkspaceAction, WorkspaceArgs};
use crate::database::CredentialDatabase;
use crate::engine::{SprayReporter, SprayRequest, run_spray};
use crate::output::Console;
use crate::protocol::{AttemptContext, AttemptOutcome, TargetContext};

/// Parses CLI arguments and executes the selected command.
pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    let (database, initialized) = CredentialDatabase::open_default()?;
    let cancel = CancellationToken::new();
    let shutdown = cancel.clone();
    let _shutdown_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            shutdown.cancel();
        }
    });
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
            run_protocol(cli.no_color, cli.proxy, database, protocol_args, &cancel).await
        }
        Command::Combo(args) => run_combo(cli.no_color, cli.proxy, database, args, &cancel).await,
        Command::Workspace(args) => run_workspace(database, args),
        Command::Creds(args) => crate::creds::run(&database, args),
        Command::Mcp => crate::mcp::serve_stdio(database, cancel).await,
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
/// - `cancel`: Process cancellation token. Ctrl-C cancels in-flight attempts.
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
    cancel: &CancellationToken,
) -> Result<()> {
    let request = SprayRequest::from_protocol_args(&protocol_args, proxy);
    let reporter = ConsoleReporter(Arc::new(Console::new(no_color)));
    run_spray(&database, request, Some(&reporter), cancel).await?;
    Ok(())
}

/// Verifies paired connection URLs and prints live progress.
///
/// # Parameters
///
/// - `no_color`: Disable ANSI colors when true.
/// - `proxy`: Top-level `--proxy` configuration applied to every protocol group.
/// - `database`: Open credential database handle.
/// - `args`: Parsed `combo` sources and shared options.
/// - `cancel`: Process cancellation token shared by every protocol group.
///
/// # Returns
///
/// `Ok(())` when every protocol group finishes.
///
/// # Errors
///
/// Returns an error when a source cannot be parsed or a group fails before attempts are recorded.
///
/// # Examples
///
/// ```ignore
/// brute combo connections.txt --threads 32
/// ```
async fn run_combo(
    no_color: bool,
    proxy: Option<crate::proxy::ProxyConfig>,
    database: CredentialDatabase,
    args: ComboArgs,
    cancel: &CancellationToken,
) -> Result<()> {
    let connections = crate::connections::load_connection_sources(&args.sources)?;
    let reporter = ConsoleReporter(Arc::new(Console::new(no_color)));
    let options = crate::combo::ComboOptions {
        threads: args.threads,
        retries: args.retries,
        timeout_ms: args.timeout_ms,
        delay_ms: args.delay_ms,
        jitter_ms: args.jitter_ms,
        continue_on_success: args.continue_on_success,
        proxy,
        execute: args.execute,
        shares: args.shares,
        shell_type: args.shell_type,
        workspace: None,
    };
    crate::combo::run_connections(&database, connections, options, Some(&reporter), cancel).await?;
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
