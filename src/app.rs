//! Top-level orchestration for the brute-force CLI.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Result, bail};
use clap::Parser;
use futures::{StreamExt, stream};
use tokio::sync::Mutex;

use crate::cli::{
    Cli, Command, CredsAction, CredsArgs, Protocol, ProtocolArgs, WorkspaceAction, WorkspaceArgs,
};
use crate::credentials::{LoadedCredentials, load_credentials, load_service_names, load_sids};
use crate::database::{CredentialDatabase, SavedCredential};
use crate::output::Console;
use crate::protocol::{
    AttemptContext, AttemptOutcome, BruteModule, TargetContext, TargetProbe, ftp::FtpModule,
    mysql::MySqlModule, oracle::OracleModule, postgresql::PostgreSqlModule, rdp::RdpModule,
    redis::RedisModule, smb::SmbModule, ssh::SshModule, tomcat::TomcatManagerModule,
};
use crate::targets::load_targets;

/// Parses CLI arguments and executes the selected command.
pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    let (database, initialized) = CredentialDatabase::open_default()?;
    if initialized {
        println!(
            "[*] initialized credential database: {}",
            database.path().display()
        );
        println!("[*] initialized default workspace: default");
    }

    match cli.command {
        Command::Protocol(protocol_args) => {
            run_protocol(cli.no_color, database, protocol_args).await
        }
        Command::Workspace(args) => run_workspace(database, args),
        Command::Creds(args) => run_creds(database, args),
    }
}

/// Executes one protocol module with loaded or database-backed credentials.
async fn run_protocol(
    no_color: bool,
    database: CredentialDatabase,
    protocol_args: ProtocolArgs,
) -> Result<()> {
    let module = build_module(&protocol_args);
    let credentials = load_protocol_credentials(&database, &protocol_args)?;
    let targets = load_targets(protocol_args.common())?;
    let protocol = protocol_args.protocol();
    let current_workspace = database.current_workspace()?;
    let request_path = protocol_args.path().map(ToOwned::to_owned);
    let request_execute = protocol_args.execute().map(ToOwned::to_owned);
    let credentials = credentials.expand();

    let console = Arc::new(Console::new(no_color));
    if targets.is_empty() {
        bail!("no targets were generated from the supplied TARGET arguments");
    }

    if credentials.is_empty() {
        bail!("no credential combinations were generated from the supplied arguments");
    }

    let mut ready_targets = Vec::new();
    for target_host in targets {
        let target_ctx = TargetContext {
            protocol,
            target_host,
            target: protocol_args.common().clone(),
        };

        match module.probe_target(&target_ctx).await {
            TargetProbe::Ready(Some(message)) => {
                console.print_probe(&target_ctx, &message);
                ready_targets.push(target_ctx.target_host);
            }
            TargetProbe::Ready(None) => ready_targets.push(target_ctx.target_host),
        }
    }

    if ready_targets.is_empty() {
        return Ok(());
    }

    let target_success_flags = Arc::new(
        ready_targets
            .iter()
            .cloned()
            .map(|target_host| (target_host, Arc::new(AtomicBool::new(false))))
            .collect::<HashMap<_, _>>(),
    );
    let account_successes = Arc::new(Mutex::new(HashSet::new()));

    // Global concurrency only: --threads caps in-flight attempts across all targets
    // and credentials. No per-host semaphore; dictionary sprays overlap freely under
    // that global cap (including single-host RDP).
    stream::iter(credentials.into_iter().flat_map(|credential| {
        ready_targets
            .iter()
            .cloned()
            .map(move |target_host| (target_host, credential.clone()))
    }))
    .for_each_concurrent(
        protocol_args.common().threads,
        |(target_host, credential)| {
            let console = console.clone();
            let module = module.clone();
            let target = protocol_args.common().clone();
            let path = request_path.clone();
            let execute = request_execute.clone();
            let target_success_flags = target_success_flags.clone();
            let account_successes = account_successes.clone();
            let database = database.clone();
            let workspace = current_workspace.clone();

            async move {
                let success_flag = target_success_flags
                    .get(&target_host)
                    .expect("target success flag missing")
                    .clone();
                let account_key = account_success_key(
                    &target_host,
                    &credential.service_name,
                    &credential.sid,
                    &credential.username,
                );

                if should_skip_attempt(
                    target.continue_on_success,
                    &success_flag,
                    account_successes.lock().await.contains(&account_key),
                ) {
                    return;
                }

                let ctx = AttemptContext {
                    protocol,
                    target_host,
                    target,
                    path,
                    execute,
                    credential,
                };

                let outcome = module.attempt(&ctx).await;
                if matches!(outcome, AttemptOutcome::Success(_)) {
                    account_successes.lock().await.insert(account_key);
                    if !ctx.target.continue_on_success {
                        success_flag.store(true, Ordering::Relaxed);
                    }

                    if let Err(err) = save_successful_credential(&database, &workspace, &ctx) {
                        eprintln!("failed to save credential: {err:#}");
                    }
                }
                console.print_attempt(&ctx, &outcome);
            }
        },
    )
    .await;

    Ok(())
}

/// Builds a stable key used to skip further passwords for an already-successful account.
///
/// # Parameters
///
/// - `target_host`: Target host for the attempt.
/// - `service_name`: Optional Oracle Service Name (other protocols pass `None`).
/// - `sid`: Optional Oracle SID (other protocols pass `None`).
/// - `username`: Optional username for the attempt.
///
/// # Returns
///
/// A delimiter-separated key unique to `(host, service_name, sid, username)`.
///
/// # Examples
///
/// ```ignore
/// let key = account_success_key(
///     "db",
///     &None,
///     &Some("ORCL".into()),
///     &Some("APPUSER".into()),
/// );
/// ```
fn account_success_key(
    target_host: &str,
    service_name: &Option<String>,
    sid: &Option<String>,
    username: &Option<String>,
) -> String {
    format!(
        "{}\0{}\0{}\0{}",
        target_host,
        service_name.as_deref().unwrap_or(""),
        sid.as_deref().unwrap_or(""),
        username.as_deref().unwrap_or("")
    )
}

fn should_skip_attempt(
    continue_on_success: bool,
    target_success_flag: &AtomicBool,
    account_succeeded: bool,
) -> bool {
    account_succeeded || (!continue_on_success && target_success_flag.load(Ordering::Relaxed))
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

/// Loads credentials from `-u/-p` or from the current workspace via `--id`.
///
/// For Oracle, also expands `--service-name` or `--sid` sources into the matching
/// identifier list so the scheduler can build the full
/// `identifier × user × password` cartesian product.
///
/// # Parameters
///
/// - `database`: Open credential database used when `--id` is set.
/// - `args`: Selected protocol arguments.
///
/// # Returns
///
/// Loaded credential sources ready for [`LoadedCredentials::expand`].
///
/// # Errors
///
/// Returns an error when wordlist files cannot be read, when a saved credential id is missing,
/// or when Oracle identifier mode yields an empty list after expansion.
///
/// # Examples
///
/// ```ignore
/// let credentials = load_protocol_credentials(&database, &protocol_args)?;
/// let attempts = credentials.expand();
/// ```
fn load_protocol_credentials(
    database: &CredentialDatabase,
    args: &ProtocolArgs,
) -> Result<LoadedCredentials> {
    let common = args.common();
    let mut loaded = if let Some(id) = common.credential_id {
        let workspace = database.current_workspace()?;
        let saved = database.get_credential(id, &workspace)?;
        LoadedCredentials {
            usernames: vec![saved.username.unwrap_or_default()],
            passwords: vec![saved.password.unwrap_or_default()],
            service_names: Vec::new(),
            sids: Vec::new(),
        }
    } else {
        load_credentials(common)?
    };

    if let ProtocolArgs::Oracle(oracle_args) = args {
        if !oracle_args.service_name.is_empty() {
            loaded.service_names = load_service_names(&oracle_args.service_name)?;
            if loaded.service_names.is_empty() {
                bail!("no Oracle Service Name values were generated from --service-name");
            }
        } else if !oracle_args.sid.is_empty() {
            loaded.sids = load_sids(&oracle_args.sid)?;
            if loaded.sids.is_empty() {
                bail!("no Oracle SID values were generated from --sid");
            }
        }
    }

    Ok(loaded)
}

/// Saves a successful credential to SQLite.
fn save_successful_credential(
    database: &CredentialDatabase,
    workspace: &str,
    ctx: &AttemptContext,
) -> Result<()> {
    database.save_success(
        workspace,
        ctx.protocol,
        &ctx.target_host,
        ctx.target.port.unwrap_or(ctx.protocol.default_port()),
        &ctx.credential,
    )
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

/// Builds the protocol implementation selected by the CLI.
fn build_module(args: &ProtocolArgs) -> Arc<dyn BruteModule> {
    match args {
        ProtocolArgs::Ssh(args) => Arc::new(SshModule::new(args.common.timeout_ms)),
        ProtocolArgs::Ftp(args) => Arc::new(FtpModule::new(args.common.timeout_ms)),
        ProtocolArgs::Mysql(args) => Arc::new(MySqlModule::new(args.common.timeout_ms)),
        ProtocolArgs::Postgresql(args) => Arc::new(PostgreSqlModule::new(args.common.timeout_ms)),
        ProtocolArgs::Redis(args) => Arc::new(RedisModule::new(args.common.timeout_ms)),
        ProtocolArgs::Tomcat(args) => Arc::new(TomcatManagerModule::new(args.common.timeout_ms)),
        ProtocolArgs::Oracle(args) => Arc::new(OracleModule::new(args.execute.common.timeout_ms)),
        ProtocolArgs::Smb(args) => Arc::new(SmbModule::new(args.common.timeout_ms, args.shares)),
        ProtocolArgs::Rdp(common) => Arc::new(RdpModule::new(common.timeout_ms)),
        ProtocolArgs::Winrm(common) | ProtocolArgs::Vnc(common) => Arc::new(
            crate::protocol::stub::StubModule::new(args.protocol(), common.timeout_ms),
        ),
        ProtocolArgs::Http(args) => Arc::new(crate::protocol::stub::StubModule::new(
            Protocol::Http,
            args.common.timeout_ms,
        )),
    }
}

#[cfg(test)]
mod tests {
    /// Verifies the scheduler source applies global `--threads` via for_each_concurrent
    /// and does not reintroduce a per-host semaphore.
    #[test]
    fn scheduler_uses_global_threads_without_per_target_semaphore() {
        let source = include_str!("app.rs");
        // Strip this test module so string literals here do not false-positive.
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production app source");
        assert!(
            production.contains("for_each_concurrent"),
            "scheduler must use for_each_concurrent for --threads"
        );
        assert!(
            !production.contains("Semaphore::new"),
            "per-target Semaphore must be removed; --threads alone caps concurrency"
        );
        assert!(
            !production.contains("target_semaphore") && !production.contains("target_semaphores"),
            "per-target semaphore variables must be removed from the scheduler"
        );
    }

    /// Verifies RDP attempt scheduling has no module-level serial mutex in source.
    #[test]
    fn rdp_module_source_has_no_global_serial_mutex() {
        // Structural guard: concurrent RDP attempts must not be forced serial by a
        // process-wide lock inside the shipped RDP module.
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
