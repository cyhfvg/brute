//! Paired connection scheduler.
//!
//! Unlike [`super::run::run_spray`], this path does not cartesian-cross
//! usernames, passwords, and targets. Each connection is one attempt.

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
use tokio_util::sync::CancellationToken;

use crate::{
    cli::Protocol,
    connections::Connection,
    credentials::CredentialSet,
    database::CredentialDatabase,
    protocol::{AttemptContext, AttemptOutcome, BruteModule, TargetContext, TargetProbe},
};

use super::{
    attempt::{AttemptControl, attempt_with_retries},
    query::resolve_workspace,
    run::{
        attempt_record_from_outcome, build_module, save_successful_credential, should_skip_attempt,
    },
    types::{AttemptStatus, ProbeRecord, SprayReport, SprayReporter, SprayRequest},
};

/// Runs paired logins for one protocol group.
///
/// # Parameters
///
/// - `database`: store used to persist successes.
/// - `request`: protocol, scheme, concurrency, and persistence options. Target and credential fields are ignored.
/// - `logins`: paired logins. Every login should already match `request.protocol`.
/// - `reporter`: optional live progress sink.
/// - `cancel`: stops probes and in-flight attempts. A cancelled try is counted as skipped.
///
/// # Returns
///
/// A [`SprayReport`] for this group. Successful passwords are stored in the resolved workspace.
///
/// # Errors
///
/// Returns an error when `logins` is empty, concurrency settings are invalid, an
/// Oracle login lacks exactly one identifier, or workspace resolution fails.
/// Individual login failures are recorded on the report.
///
/// # Examples
///
/// ```ignore
/// use brute::engine::run_paired_spray;
/// let cancel = tokio_util::sync::CancellationToken::new();
/// let report = run_paired_spray(&database, request, &logins, None, &cancel).await?;
/// ```
pub async fn run_paired_spray(
    database: &CredentialDatabase,
    request: SprayRequest,
    logins: &[Connection],
    reporter: Option<&dyn SprayReporter>,
    cancel: &CancellationToken,
) -> Result<SprayReport> {
    if logins.is_empty() {
        bail!("no connection URLs were found");
    }
    if request.threads == 0 {
        bail!("threads must be >= 1");
    }
    if request.timeout_ms == 0 {
        bail!("timeout_ms must be >= 1");
    }
    for login in logins {
        let has_service = login.service_name.is_some();
        let has_sid = login.sid.is_some();
        if request.protocol == Protocol::Oracle && has_service == has_sid {
            bail!(
                "oracle connection {} requires exactly one of service or sid",
                login.host
            );
        }
    }

    let workspace = resolve_workspace(database, request.workspace.as_deref())?;
    let module = build_module(&request);
    let common = request.to_common_args();
    let mut probes = Vec::new();
    let mut target_success_flags = HashMap::new();
    let mut target_cancels = HashMap::new();
    let mut unique_targets = Vec::new();
    let mut seen_endpoints = HashSet::new();

    for login in logins {
        let effective_port = login.port.unwrap_or(request.protocol.default_port());
        let key = endpoint_key(&login.host, effective_port);
        if !seen_endpoints.insert(key.clone()) {
            continue;
        }
        target_success_flags.insert(key.clone(), Arc::new(AtomicBool::new(false)));
        target_cancels.insert(key, cancel.child_token());
        unique_targets.push((login.host.clone(), login.port, effective_port));
    }

    for (host, port, effective_port) in unique_targets {
        if cancel.is_cancelled() {
            break;
        }
        let mut target_args = common.clone();
        target_args.targets = vec![host.clone()];
        target_args.port = port;
        target_args.usernames.clear();
        target_args.passwords.clear();
        target_args.credential_id = None;
        let target_ctx = TargetContext {
            protocol: request.protocol,
            target_host: host.clone(),
            target: target_args,
            url_scheme: request.url_scheme,
        };
        let probe = tokio::select! {
            biased;
            _ = cancel.cancelled() => None,
            probe = module.probe_target(&target_ctx) => Some(probe),
        };
        let Some(probe) = probe else {
            break;
        };
        if let TargetProbe::Ready(Some(message)) = probe {
            if let Some(reporter) = reporter {
                reporter.probe(&target_ctx, &message);
            }
            probes.push(ProbeRecord {
                host,
                port: effective_port,
                message,
            });
        }
    }

    let target_cancels = Arc::new(target_cancels);

    let target_success_flags = Arc::new(target_success_flags);
    let account_successes = Arc::new(Mutex::new(HashSet::<String>::new()));
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let skipped = Arc::new(AtomicUsize::new(0));
    let module: Arc<dyn BruteModule> = module;
    let planned = planned_attempts(&request, logins);
    let protocol = request.protocol;
    let url_scheme = request.url_scheme;

    stream::iter(planned)
        .for_each_concurrent(request.threads, |planned| {
            let module = Arc::clone(&module);
            let common = common.clone();
            let execute = request.execute.clone();
            let continue_on_success = request.continue_on_success;
            let target_success_flags = Arc::clone(&target_success_flags);
            let account_successes = Arc::clone(&account_successes);
            let attempts = Arc::clone(&attempts);
            let skipped = Arc::clone(&skipped);
            let database = database.clone();
            let workspace = workspace.clone();
            let path = planned.path.clone().or_else(|| request.effective_path());
            let target_cancels = Arc::clone(&target_cancels);

            async move {
                let success_flag = target_success_flags
                    .get(&endpoint_key(&planned.host, planned.effective_port))
                    .expect("target success flag missing")
                    .clone();
                let account = account_key(&planned);
                if should_skip_attempt(
                    continue_on_success,
                    &success_flag,
                    account_successes.lock().await.contains(&account),
                ) {
                    skipped.fetch_add(1, Ordering::Relaxed);
                    return;
                }

                let mut target = common;
                target.targets = vec![planned.host.clone()];
                target.port = planned.port;
                target.usernames.clear();
                target.passwords.clear();
                target.credential_id = None;
                let ctx = AttemptContext {
                    protocol,
                    target_host: planned.host,
                    target,
                    url_scheme,
                    path,
                    execute,
                    credential: planned.credential,
                };
                let target_cancel = target_cancels
                    .get(&endpoint_key(&ctx.target_host, planned.effective_port))
                    .cloned()
                    .expect("target cancel token missing");
                let outcome =
                    match attempt_with_retries(module.as_ref(), &ctx, &target_cancel).await {
                        AttemptControl::Cancelled => {
                            skipped.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                        AttemptControl::Finished(outcome) => outcome,
                    };
                if matches!(outcome, AttemptOutcome::Success(_)) {
                    account_successes.lock().await.insert(account);
                    if !ctx.target.continue_on_success {
                        success_flag.store(true, Ordering::Relaxed);
                        target_cancel.cancel();
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

struct PlannedAttempt {
    host: String,
    port: Option<u16>,
    effective_port: u16,
    path: Option<String>,
    credential: CredentialSet,
}

/// Converts parsed logins into owned attempt plans.
///
/// # Parameters
///
/// - `request`: protocol used to fill an omitted port.
/// - `logins`: paired connection URLs.
///
/// # Returns
///
/// One plan per login, preserving source order.
fn planned_attempts(request: &SprayRequest, logins: &[Connection]) -> Vec<PlannedAttempt> {
    logins
        .iter()
        .map(|login| PlannedAttempt {
            host: login.host.clone(),
            port: login.port,
            effective_port: login.port.unwrap_or(request.protocol.default_port()),
            path: login.path.clone(),
            credential: CredentialSet {
                username: login.credential_username(),
                password: login.credential_password(),
                service_name: login.service_name.clone(),
                sid: login.sid.clone(),
            },
        })
        .collect()
}

/// Returns the skip key for one host and effective port.
///
/// # Parameters
///
/// - `host`: target host.
/// - `port`: effective service port.
///
/// # Returns
///
/// A key that does not collide across ports on the same host.
fn endpoint_key(host: &str, port: u16) -> String {
    format!("{host}\0{port}")
}

/// Returns the account skip key, including port so `:22` and `:2222` stay independent.
///
/// # Parameters
///
/// - `planned`: one paired login.
///
/// # Returns
///
/// A key of host, port, Oracle identifier, and username.
fn account_key(planned: &PlannedAttempt) -> String {
    format!(
        "{}\0{}\0{}\0{}\0{}",
        planned.host,
        planned.effective_port,
        planned.credential.service_name.as_deref().unwrap_or(""),
        planned.credential.sid.as_deref().unwrap_or(""),
        planned.credential.username.as_deref().unwrap_or("")
    )
}
