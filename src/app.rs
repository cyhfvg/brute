//! Top-level orchestration for the brute-force CLI.

use std::sync::Arc;

use anyhow::Result;
use clap::{CommandFactory, Parser};
use tokio_util::sync::CancellationToken;

use crate::cli::{Cli, ComboArgs, Command, OutputFormat, ProtocolArgs, WorkspaceAction, WorkspaceArgs};
use crate::database::CredentialDatabase;
use crate::engine::{SprayReporter, SprayRequest, run_spray};
use crate::output::{Console, NdjsonReporter};
use crate::protocol::{AttemptContext, AttemptOutcome, TargetContext};

/// Parses CLI arguments and executes the selected command.
pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    if cli.list_protocol {
        print_protocol_list();
        return Ok(());
    }
    let (database, initialized) = CredentialDatabase::open_default()?;
    let cancel = CancellationToken::new();
    let shutdown = cancel.clone();
    let _shutdown_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            shutdown.cancel();
        }
    });
    let is_mcp = matches!(cli.command, Some(Command::Mcp));
    if initialized && !is_mcp && cli.format == OutputFormat::Text {
        println!(
            "[*] initialized credential database: {}",
            database.path().display()
        );
        println!("[*] initialized default workspace: default");
    }

    match cli.command {
        Some(Command::Protocol(protocol_args)) => {
            run_protocol(
                cli.no_color,
                cli.format,
                cli.proxy,
                database,
                protocol_args,
                &cancel,
            )
            .await
        }
        Some(Command::Combo(args)) => {
            run_combo(cli.no_color, cli.format, cli.proxy, database, args, &cancel).await
        }
        Some(Command::Workspace(args)) => run_workspace(database, args),
        Some(Command::Creds(args)) => crate::creds::run(&database, args),
        Some(Command::Mcp) => crate::mcp::serve_stdio(database, cancel).await,
        None => {
            Cli::command().print_long_help()?;
            println!();
            Ok(())
        }
    }
}

/// Executes one protocol module with loaded or database-backed credentials.
///
/// # Parameters
///
/// - `no_color`: Disable ANSI colors when true.
/// - `format`: Console output format. `json` prints the report once at the end.
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
    format: OutputFormat,
    proxy: Option<crate::proxy::ProxyConfig>,
    database: CredentialDatabase,
    protocol_args: ProtocolArgs,
    cancel: &CancellationToken,
) -> Result<()> {
    let request = SprayRequest::from_protocol_args(&protocol_args, proxy);
    let reporter = build_reporter(no_color, format);
    let report = run_spray(
        &database,
        request,
        reporter.as_ref().map(|r| r as &dyn SprayReporter),
        cancel,
    )
    .await?;
    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }
    Ok(())
}

/// Verifies paired connection URLs and prints live progress.
///
/// # Parameters
///
/// - `no_color`: Disable ANSI colors when true.
/// - `format`: Console output format. `json` prints the report once at the end.
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
    format: OutputFormat,
    proxy: Option<crate::proxy::ProxyConfig>,
    database: CredentialDatabase,
    args: ComboArgs,
    cancel: &CancellationToken,
) -> Result<()> {
    let connections = crate::connections::load_connection_sources(&args.sources)?;
    let reporter = build_reporter(no_color, format);
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
    let report = crate::combo::run_connections(
        &database,
        connections,
        options,
        reporter.as_ref().map(|r| r as &dyn SprayReporter),
        cancel,
    )
    .await?;
    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }
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

/// Prints the supported protocol list for the top-level `--list-protocol` flag.
///
/// Each row shows a stable protocol name and its default TCP port in ascending
/// port order.
fn print_protocol_list() {
    let mut protocols = crate::engine::list_protocols();
    protocols.sort_by_key(|protocol| protocol.default_port);
    println!("Supported protocols:");
    println!("  {:<16} {:>5}", "protocol", "port");
    for protocol in protocols {
        println!("  {:<16} {:>5}", protocol.name, protocol.default_port);
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

/// Live reporter selected by `--format`.
enum Reporter {
    /// NetExec-style colored console (`--format text`).
    Console(ConsoleReporter),
    /// One JSON object per line (`--format ndjson`).
    Ndjson(NdjsonReporter),
}

impl SprayReporter for Reporter {
    fn probe(&self, ctx: &TargetContext, message: &str) {
        match self {
            Self::Console(reporter) => reporter.probe(ctx, message),
            Self::Ndjson(reporter) => reporter.probe(ctx, message),
        }
    }

    fn attempt(&self, ctx: &AttemptContext, outcome: &AttemptOutcome) {
        match self {
            Self::Console(reporter) => reporter.attempt(ctx, outcome),
            Self::Ndjson(reporter) => reporter.attempt(ctx, outcome),
        }
    }

    fn save_error(&self, err: &anyhow::Error) {
        match self {
            Self::Console(reporter) => reporter.save_error(err),
            Self::Ndjson(reporter) => reporter.save_error(err),
        }
    }
}

/// Builds the live reporter for a protocol/combo run.
///
/// `json` returns [`None`] because the whole report is serialized once the run
/// finishes; no per-event streaming is needed.
fn build_reporter(no_color: bool, format: OutputFormat) -> Option<Reporter> {
    match format {
        OutputFormat::Text => Some(Reporter::Console(ConsoleReporter(Arc::new(Console::new(
            no_color,
        ))))),
        OutputFormat::Ndjson => Some(Reporter::Ndjson(NdjsonReporter)),
        OutputFormat::Json => None,
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
