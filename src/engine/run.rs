//! Concurrent verify/spray scheduler shared by CLI and MCP.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use anyhow::{Result, bail};
use futures::{StreamExt, stream};
use tokio::sync::Mutex;

use crate::cli::Protocol;
use crate::credentials::{LoadedCredentials, load_credentials, load_service_names, load_sids};
use crate::database::CredentialDatabase;
use crate::protocol::{
    AttemptContext, AttemptOutcome, BruteModule, PostAuthResult, TargetContext, TargetProbe,
    ftp::FtpModule, http::HttpBasicModule, mysql::MySqlModule, oracle::OracleModule,
    postgresql::PostgreSqlModule, rdp::RdpModule, redis::RedisModule, smb::SmbModule,
    ssh::SshModule, tomcat::TomcatManagerModule, vnc::VncModule, winrm::WinrmModule,
};
use crate::targets::load_targets;

use super::query::resolve_workspace;
use super::types::{
    AttemptRecord, AttemptStatus, ProbeRecord, SprayReport, SprayReporter, SprayRequest,
};

/// Executes a verify or spray request and optionally reports live CLI output.
///
/// # Parameters
///
/// - `database`: Open credential database used for `--id` and success persistence.
/// - `request`: Targets, credentials, and protocol options.
/// - `reporter`: Optional live sink; MCP callers pass [`None`].
///
/// # Returns
///
/// A [`SprayReport`] containing probes, executed attempts, and successes.
///
/// # Errors
///
/// Returns an error when targets/credentials cannot be expanded, Oracle
/// identifiers are missing, or a workspace cannot be resolved.
///
/// # Examples
///
/// ```ignore
/// let report = run_spray(&database, request, None).await?;
/// assert!(report.successes.iter().all(|item| item.status == AttemptStatus::Success));
/// ```
pub async fn run_spray(
    database: &CredentialDatabase,
    request: SprayRequest,
    reporter: Option<&dyn SprayReporter>,
) -> Result<SprayReport> {
    request.validate()?;
    let workspace = resolve_workspace(database, request.workspace.as_deref())?;
    let common = request.to_common_args();
    let module = build_module(&request);
    let credentials = load_request_credentials(database, &request, &workspace)?;
    let targets = load_targets(&common)?;
    if targets.is_empty() {
        bail!("no targets were generated from the supplied TARGET arguments");
    }
    let credentials = credentials.expand();
    if credentials.is_empty() {
        bail!("no credential combinations were generated from the supplied arguments");
    }

    let protocol = request.protocol;
    let request_path = request.effective_path();
    let request_execute = request.execute.clone();
    let mut probes = Vec::new();
    let mut ready_targets = Vec::new();

    for target_host in targets {
        let target_ctx = TargetContext {
            protocol,
            target_host,
            target: common.clone(),
        };
        match module.probe_target(&target_ctx).await {
            TargetProbe::Ready(Some(message)) => {
                if let Some(reporter) = reporter {
                    reporter.probe(&target_ctx, &message);
                }
                probes.push(ProbeRecord {
                    host: target_ctx.target_host.clone(),
                    port: target_ctx.port(),
                    message,
                });
                ready_targets.push(target_ctx.target_host);
            }
            TargetProbe::Ready(None) => ready_targets.push(target_ctx.target_host),
        }
    }

    if ready_targets.is_empty() {
        return Ok(SprayReport {
            workspace,
            protocol: protocol.as_str().to_string(),
            probes,
            attempts: Vec::new(),
            successes: Vec::new(),
            skipped: 0,
        });
    }

    let target_success_flags = Arc::new(
        ready_targets
            .iter()
            .cloned()
            .map(|target_host| (target_host, Arc::new(AtomicBool::new(false))))
            .collect::<HashMap<_, _>>(),
    );
    let account_successes = Arc::new(Mutex::new(HashSet::new()));
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let skipped = Arc::new(AtomicUsize::new(0));

    stream::iter(credentials.into_iter().flat_map(|credential| {
        ready_targets
            .iter()
            .cloned()
            .map(move |target_host| (target_host, credential.clone()))
    }))
    .for_each_concurrent(common.threads, |(target_host, credential)| {
        let module = module.clone();
        let target = common.clone();
        let path = request_path.clone();
        let execute = request_execute.clone();
        let target_success_flags = target_success_flags.clone();
        let account_successes = account_successes.clone();
        let attempts = attempts.clone();
        let skipped = skipped.clone();
        let database = database.clone();
        let workspace = workspace.clone();

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
                skipped.fetch_add(1, Ordering::Relaxed);
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
                if let Err(err) = save_successful_credential(&database, &workspace, &ctx)
                    && let Some(reporter) = reporter
                {
                    reporter.save_error(&err);
                }
            }
            if let Some(reporter) = reporter {
                reporter.attempt(&ctx, &outcome);
            }
            attempts
                .lock()
                .await
                .push(attempt_record_from_outcome(&ctx, &outcome));
        }
    })
    .await;

    let attempts = Arc::try_unwrap(attempts)
        .map_err(|_| anyhow::anyhow!("attempt collector still shared"))?
        .into_inner();
    let successes = attempts
        .iter()
        .filter(|record| record.status == AttemptStatus::Success)
        .cloned()
        .collect();

    Ok(SprayReport {
        workspace,
        protocol: protocol.as_str().to_string(),
        probes,
        attempts,
        successes,
        skipped: skipped.load(Ordering::Relaxed),
    })
}

fn load_request_credentials(
    database: &CredentialDatabase,
    request: &SprayRequest,
    workspace: &str,
) -> Result<LoadedCredentials> {
    let common = request.to_common_args();
    let mut loaded = if let Some(id) = request.credential_id {
        let saved = database.get_credential(id, workspace)?;
        LoadedCredentials {
            usernames: vec![saved.username.unwrap_or_default()],
            passwords: vec![saved.password.unwrap_or_default()],
            service_names: Vec::new(),
            sids: Vec::new(),
        }
    } else {
        load_credentials(&common)?
    };

    if request.protocol == Protocol::Oracle {
        if !request.service_names.is_empty() {
            loaded.service_names = load_service_names(&request.service_names)?;
            if loaded.service_names.is_empty() {
                bail!("no Oracle Service Name values were generated from service_name");
            }
        } else if !request.sids.is_empty() {
            loaded.sids = load_sids(&request.sids)?;
            if loaded.sids.is_empty() {
                bail!("no Oracle SID values were generated from sid");
            }
        }
    }

    Ok(loaded)
}

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

fn build_module(request: &SprayRequest) -> Arc<dyn BruteModule> {
    match request.protocol {
        Protocol::Ssh => Arc::new(SshModule::new(request.timeout_ms)),
        Protocol::Ftp => Arc::new(FtpModule::new(request.timeout_ms)),
        Protocol::Mysql => Arc::new(MySqlModule::new(request.timeout_ms)),
        Protocol::Postgresql => Arc::new(PostgreSqlModule::new(request.timeout_ms)),
        Protocol::Redis => Arc::new(RedisModule::new(request.timeout_ms)),
        Protocol::Tomcat => Arc::new(TomcatManagerModule::new(request.timeout_ms)),
        Protocol::Oracle => Arc::new(OracleModule::new(request.timeout_ms)),
        Protocol::Smb => Arc::new(SmbModule::new(request.timeout_ms, request.shares)),
        Protocol::Rdp => Arc::new(RdpModule::new(request.timeout_ms)),
        Protocol::Winrm => Arc::new(WinrmModule::new(request.timeout_ms, request.shell_type)),
        Protocol::Vnc => Arc::new(VncModule::new(request.timeout_ms)),
        Protocol::Http => Arc::new(HttpBasicModule::new(request.timeout_ms, request.url_scheme)),
    }
}

fn attempt_record_from_outcome(ctx: &AttemptContext, outcome: &AttemptOutcome) -> AttemptRecord {
    let (status, message, post_auth) = match outcome {
        AttemptOutcome::Success(success) => {
            let post_auth = success
                .post_auth_result
                .as_ref()
                .map(|result| match result {
                    PostAuthResult::Output(output) => output.clone(),
                    PostAuthResult::Failed(error) => format!("post-auth failed: {error}"),
                });
            (AttemptStatus::Success, success.message.clone(), post_auth)
        }
        AttemptOutcome::Failure(reason) => (AttemptStatus::Failure, reason.clone(), None),
        AttemptOutcome::Error(message) => (AttemptStatus::Error, message.clone(), None),
    };
    AttemptRecord {
        protocol: ctx.protocol.as_str().to_string(),
        host: ctx.target_host.clone(),
        port: ctx.target.port.unwrap_or(ctx.protocol.default_port()),
        username: ctx.credential.username.clone(),
        password: ctx.credential.password.clone(),
        service_name: ctx.credential.service_name.clone(),
        sid: ctx.credential.sid.clone(),
        status,
        message,
        post_auth,
    }
}

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

#[cfg(test)]
mod tests {
    /// Verifies the scheduler source applies global `--threads` via for_each_concurrent.
    #[test]
    fn scheduler_uses_global_threads_without_per_target_semaphore() {
        let source = include_str!("run.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production engine source");
        assert!(
            production.contains("for_each_concurrent"),
            "scheduler must use for_each_concurrent for --threads"
        );
        assert!(
            !production.contains("Semaphore::new"),
            "per-target Semaphore must be removed; --threads alone caps concurrency"
        );
    }
}
