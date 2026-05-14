//! Top-level orchestration for the brute-force CLI.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Result, bail};
use clap::Parser;
use futures::{StreamExt, stream};
use tokio::sync::Semaphore;

use crate::cli::{
    Cli, Command, CredsAction, CredsArgs, Protocol, ProtocolArgs, WorkspaceAction, WorkspaceArgs,
};
use crate::credentials::{LoadedCredentials, load_credentials};
use crate::database::{CredentialDatabase, SavedCredential};
use crate::output::Console;
use crate::protocol::{
    AttemptContext, AttemptOutcome, BruteModule, TargetContext, TargetProbe, ftp::FtpModule,
    mysql::MySqlModule, postgresql::PostgreSqlModule, redis::RedisModule, ssh::SshModule,
    tomcat::TomcatManagerModule,
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
    let semaphore = Arc::new(Semaphore::new(protocol_args.common().threads));

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
            path: request_path.clone(),
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

    let target_semaphores = Arc::new(
        ready_targets
            .iter()
            .cloned()
            .map(|target_host| {
                (
                    target_host,
                    Arc::new(Semaphore::new(protocol_args.common().target_threads.max(1))),
                )
            })
            .collect::<HashMap<_, _>>(),
    );
    let target_success_flags = Arc::new(
        ready_targets
            .iter()
            .cloned()
            .map(|target_host| (target_host, Arc::new(AtomicBool::new(false))))
            .collect::<HashMap<_, _>>(),
    );

    let attempts: Vec<_> = credentials
        .iter()
        .cloned()
        .flat_map(|credential| {
            ready_targets
                .iter()
                .cloned()
                .map(move |target_host| (target_host, credential.clone()))
        })
        .collect();
    let total_attempts = attempts.len();

    stream::iter(attempts.into_iter().enumerate())
        .for_each_concurrent(
            protocol_args.common().threads,
            |(index, (target_host, credential))| {
                let semaphore = semaphore.clone();
                let console = console.clone();
                let module = module.clone();
                let target = protocol_args.common().clone();
                let path = request_path.clone();
                let execute = request_execute.clone();
                let target_semaphores = target_semaphores.clone();
                let target_success_flags = target_success_flags.clone();
                let database = database.clone();
                let workspace = current_workspace.clone();
                let protocol = protocol;

                async move {
                    let success_flag = target_success_flags
                        .get(&target_host)
                        .expect("target success flag missing")
                        .clone();

                    if !target.continue_on_success && success_flag.load(Ordering::Relaxed) {
                        return;
                    }

                    let _permit = semaphore.acquire().await.expect("semaphore poisoned");
                    let target_semaphore = target_semaphores
                        .get(&target_host)
                        .expect("target semaphore missing")
                        .clone();
                    let _target_permit = target_semaphore
                        .acquire()
                        .await
                        .expect("semaphore poisoned");

                    if !target.continue_on_success && success_flag.load(Ordering::Relaxed) {
                        return;
                    }

                    let ctx = AttemptContext {
                        index: index + 1,
                        total: total_attempts,
                        protocol,
                        target_host,
                        target,
                        path,
                        execute,
                        credential,
                    };

                    let outcome = module.attempt(&ctx).await;
                    if matches!(outcome, AttemptOutcome::Success(_)) {
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
fn load_protocol_credentials(
    database: &CredentialDatabase,
    args: &ProtocolArgs,
) -> Result<LoadedCredentials> {
    let common = args.common();
    let Some(id) = common.credential_id else {
        return load_credentials(common);
    };

    let workspace = database.current_workspace()?;
    let saved = database.get_credential(id, &workspace)?;

    Ok(LoadedCredentials {
        usernames: vec![saved.username.unwrap_or_default()],
        passwords: vec![saved.password.unwrap_or_default()],
    })
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
        ProtocolArgs::Smb(common)
        | ProtocolArgs::Rdp(common)
        | ProtocolArgs::Winrm(common)
        | ProtocolArgs::Oracle(common)
        | ProtocolArgs::Vnc(common) => Arc::new(crate::protocol::stub::StubModule::new(
            args.protocol(),
            common.timeout_ms,
        )),
        ProtocolArgs::Http(args) => Arc::new(crate::protocol::stub::StubModule::new(
            Protocol::Http,
            args.common.timeout_ms,
        )),
    }
}
