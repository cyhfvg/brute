//! Concurrent verify/spray scheduler shared by CLI and MCP.

use std::{
    collections::{HashMap, HashSet},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use anyhow::{Result, bail};
use futures::{StreamExt, stream};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::cli::Protocol;
use crate::credentials::{LoadedCredentials, load_credentials, load_service_names, load_sids};
use crate::database::CredentialDatabase;
use crate::protocol::{
    AttemptContext, AttemptFaultClass, AttemptOutcome, BruteModule, PostAuthResult, TargetContext,
    TargetProbe, activemq::ActiveMqModule, clickhouse::ClickHouseModule, couchdb::CouchDbModule,
    docker::DockerModule, druid::DruidModule, elasticsearch::ElasticsearchModule, etcd::EtcdModule,
    ftp::FtpModule, gitlab::GitlabModule, grafana::GrafanaModule, hadoop::HadoopModule,
    harbor::HarborModule, http::HttpBasicModule, influxdb::InfluxDbModule, jboss::JbossModule,
    jenkins::JenkinsModule, kafka::KafkaModule, kibana::KibanaModule, kubelet::KubeletModule,
    ldap::LdapModule, memcached::MemcachedModule, minio::MinioModule, mongodb::MongoDbModule,
    mssql::MssqlModule, mysql::MySqlModule, nacos::NacosModule, neo4j::Neo4jModule,
    nexus::NexusModule, nfs::NfsModule, oracle::OracleModule, postgresql::PostgreSqlModule,
    prometheus::PrometheusModule, rabbitmq::RabbitMqModule, rdp::RdpModule, redis::RedisModule,
    rsync::RsyncModule, smb::SmbModule, snmp::SnmpModule, solr::SolrModule, spark::SparkModule,
    ssh::SshModule, telnet::TelnetModule, tomcat::TomcatManagerModule, vnc::VncModule,
    weblogic::WeblogicModule, websphere::WebsphereModule, winrm::WinrmModule,
    zookeeper::ZookeeperModule,
};
use crate::targets::load_targets;

use super::attempt::{AttemptControl, attempt_with_retries};
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
/// - `cancel`: Stops probes and in-flight attempts. A cancelled try is counted as skipped.
///
/// # Returns
///
/// A [`SprayReport`] containing probe banners, executed attempts, and successes.
/// Probe banners are collected concurrently and do not gate credential attempts.
///
/// # Errors
///
/// Returns an error when targets/credentials cannot be expanded, Oracle
/// identifiers are missing, or a workspace cannot be resolved.
///
/// # Examples
///
/// ```ignore
/// let cancel = tokio_util::sync::CancellationToken::new();
/// let report = run_spray(&database, request, None, &cancel).await?;
/// assert!(report.successes.iter().all(|item| item.status == AttemptStatus::Success));
/// ```
pub async fn run_spray(
    database: &CredentialDatabase,
    request: SprayRequest,
    reporter: Option<&dyn SprayReporter>,
    cancel: &CancellationToken,
) -> Result<SprayReport> {
    request.validate()?;
    let workspace = resolve_workspace(database, request.workspace.as_deref())?;
    let common = request.to_common_args();
    let module = build_module(&request);
    let credentials = load_request_credentials(database, &request, &workspace)?;
    let targets = load_targets(&common.targets)?;
    if targets.is_empty() {
        bail!("no targets were generated from the supplied TARGET arguments");
    }
    let credentials = credentials.expand();
    if credentials.is_empty() {
        bail!("no credential combinations were generated from the supplied arguments");
    }

    let protocol = request.protocol;
    let url_scheme = request.url_scheme;
    let request_path = request.effective_path();
    let request_execute = request.execute.clone();
    let target_contexts = targets
        .iter()
        .cloned()
        .map(|target_host| TargetContext {
            protocol,
            target_host,
            target: common.clone(),
            url_scheme,
        })
        .collect();
    let probe_task =
        probe_targets_concurrent(&module, target_contexts, common.threads, reporter, cancel);
    let target_success_flags = Arc::new(
        targets
            .iter()
            .cloned()
            .map(|target_host| (target_host, Arc::new(AtomicBool::new(false))))
            .collect::<HashMap<_, _>>(),
    );
    let target_cancels = Arc::new(
        targets
            .iter()
            .cloned()
            .map(|target_host| (target_host, cancel.child_token()))
            .collect::<HashMap<_, _>>(),
    );
    let account_successes = Arc::new(Mutex::new(HashSet::new()));
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let skipped = Arc::new(AtomicUsize::new(0));

    let spray_task: Pin<Box<dyn Future<Output = ()> + Send + '_>> = Box::pin(
        stream::iter(credentials.into_iter().flat_map(|credential| {
            targets
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

            let target_cancels = Arc::clone(&target_cancels);
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
                let target_cancel = target_cancels
                    .get(&target_host)
                    .expect("target cancel token missing")
                    .clone();

                let ctx = AttemptContext {
                    protocol,
                    target_host,
                    target,
                    url_scheme,
                    path,
                    execute,
                    credential,
                };
                let outcome =
                    match attempt_with_retries(module.as_ref(), &ctx, &target_cancel).await {
                        AttemptControl::Cancelled => {
                            skipped.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                        AttemptControl::Finished(outcome) => outcome,
                    };
                if matches!(outcome, AttemptOutcome::Success(_)) {
                    account_successes.lock().await.insert(account_key);
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
        }),
    );
    let probe_task: Pin<Box<dyn Future<Output = Vec<ProbeRecord>> + Send + '_>> =
        Box::pin(probe_task);
    let ((), probes) = tokio::join!(spray_task, probe_task);

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

/// Probes targets concurrently. Credential attempts must not wait for this future.
///
/// # Parameters
///
/// - `module`: protocol implementation that performs the probe.
/// - `targets`: one context per spray target.
/// - `threads`: maximum concurrent probes. Probes do not consume attempt slots.
/// - `reporter`: optional live banner sink.
/// - `cancel`: stops probes that have not finished.
///
/// # Returns
///
/// Banner records. A probe without a banner is omitted. Probe failure does not
/// remove the target from the spray.
///
/// # Errors
///
/// This function does not fail. Transport and timeout results are silent.
///
/// # Example
///
/// ```ignore
/// let probes = probe_targets_concurrent(&module, contexts, 16, None, &cancel).await;
/// ```
pub(super) async fn probe_targets_concurrent(
    module: &Arc<dyn BruteModule>,
    targets: Vec<TargetContext>,
    threads: usize,
    reporter: Option<&dyn SprayReporter>,
    cancel: &CancellationToken,
) -> Vec<ProbeRecord> {
    let probes = Arc::new(Mutex::new(Vec::new()));
    stream::iter(targets)
        .for_each_concurrent(threads, |target_ctx| {
            let module = Arc::clone(module);
            let probes = Arc::clone(&probes);
            async move {
                if cancel.is_cancelled() {
                    return;
                }
                let probe = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    probe = module.probe_target(&target_ctx) => probe,
                };
                if let TargetProbe::Ready(Some(message)) = probe {
                    if let Some(reporter) = reporter {
                        reporter.probe(&target_ctx, &message);
                    }
                    let port = target_ctx.port();
                    probes.lock().await.push(ProbeRecord {
                        host: target_ctx.target_host,
                        port,
                        message,
                    });
                }
            }
        })
        .await;
    match Arc::try_unwrap(probes) {
        Ok(mutex) => mutex.into_inner(),
        Err(probes) => probes.lock().await.clone(),
    }
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

pub(super) fn save_successful_credential(
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

pub(super) fn build_module(request: &SprayRequest) -> Arc<dyn BruteModule> {
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
        Protocol::Zookeeper => Arc::new(ZookeeperModule::new(request.timeout_ms)),
        Protocol::Memcached => Arc::new(MemcachedModule::new(request.timeout_ms)),
        Protocol::Mongodb => Arc::new(MongoDbModule::new(request.timeout_ms)),
        Protocol::Elasticsearch => Arc::new(ElasticsearchModule::new(request.timeout_ms)),
        Protocol::Docker => Arc::new(DockerModule::new(request.timeout_ms)),
        Protocol::Snmp => Arc::new(SnmpModule::new(request.timeout_ms)),
        Protocol::Activemq => Arc::new(ActiveMqModule::new(request.timeout_ms)),
        Protocol::Rabbitmq => Arc::new(RabbitMqModule::new(request.timeout_ms)),
        Protocol::Rsync => Arc::new(RsyncModule::new(request.timeout_ms)),
        Protocol::Mssql => Arc::new(MssqlModule::new(request.timeout_ms)),
        Protocol::Kafka => Arc::new(KafkaModule::new(request.timeout_ms)),
        Protocol::Kibana => Arc::new(KibanaModule::new(request.timeout_ms)),
        Protocol::Nfs => Arc::new(NfsModule::new(request.timeout_ms)),
        Protocol::Telnet => Arc::new(TelnetModule::new(request.timeout_ms)),
        Protocol::Ldap => Arc::new(LdapModule::new(request.timeout_ms)),
        Protocol::Grafana => Arc::new(GrafanaModule::new(request.timeout_ms)),
        Protocol::Prometheus => Arc::new(PrometheusModule::new(request.timeout_ms)),
        Protocol::Jenkins => Arc::new(JenkinsModule::new(request.timeout_ms)),
        Protocol::Couchdb => Arc::new(CouchDbModule::new(request.timeout_ms)),
        Protocol::Clickhouse => Arc::new(ClickHouseModule::new(request.timeout_ms)),
        Protocol::Neo4j => Arc::new(Neo4jModule::new(request.timeout_ms)),
        Protocol::Etcd => Arc::new(EtcdModule::new(request.timeout_ms)),
        Protocol::Influxdb => Arc::new(InfluxDbModule::new(request.timeout_ms)),
        Protocol::Minio => Arc::new(MinioModule::new(request.timeout_ms)),
        Protocol::Solr => Arc::new(SolrModule::new(request.timeout_ms)),
        Protocol::Nacos => Arc::new(NacosModule::new(request.timeout_ms)),
        Protocol::Nexus => Arc::new(NexusModule::new(request.timeout_ms)),
        Protocol::Jboss => Arc::new(JbossModule::new(request.timeout_ms)),
        Protocol::Druid => Arc::new(DruidModule::new(request.timeout_ms)),
        Protocol::Spark => Arc::new(SparkModule::new(request.timeout_ms)),
        Protocol::Hadoop => Arc::new(HadoopModule::new(request.timeout_ms)),
        Protocol::Gitlab => Arc::new(GitlabModule::new(request.timeout_ms)),
        Protocol::Harbor => Arc::new(HarborModule::new(request.timeout_ms)),
        Protocol::Weblogic => Arc::new(WeblogicModule::new(request.timeout_ms)),
        Protocol::Websphere => Arc::new(WebsphereModule::new(request.timeout_ms)),
        Protocol::Kubelet => Arc::new(KubeletModule::new(request.timeout_ms)),
    }
}

pub(super) fn attempt_record_from_outcome(
    ctx: &AttemptContext,
    outcome: &AttemptOutcome,
) -> AttemptRecord {
    let (status, message, post_auth, fault_class) = match outcome {
        AttemptOutcome::Success(success) => {
            let post_auth = success
                .post_auth_result
                .as_ref()
                .map(|result| match result {
                    PostAuthResult::Output(output) => output.clone(),
                    PostAuthResult::Failed(error) => format!("post-auth failed: {error}"),
                });
            (
                AttemptStatus::Success,
                success.message.clone(),
                post_auth,
                None,
            )
        }
        AttemptOutcome::Failure(fault) | AttemptOutcome::Error(fault) => {
            let status = match fault.class {
                AttemptFaultClass::Auth => AttemptStatus::Failure,
                AttemptFaultClass::Lockout => AttemptStatus::Lockout,
                AttemptFaultClass::Transport => AttemptStatus::Error,
            };
            (status, fault.message.clone(), None, Some(fault.class))
        }
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
        fault_class,
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

pub(super) fn should_skip_attempt(
    continue_on_success: bool,
    target_success_flag: &AtomicBool,
    account_succeeded: bool,
) -> bool {
    account_succeeded || (!continue_on_success && target_success_flag.load(Ordering::Relaxed))
}

#[cfg(test)]
mod tests {
    use super::{AttemptFaultClass, AttemptOutcome, AttemptStatus};

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
    /// Lockout records keep the structured fault class.
    #[test]
    fn lockout_record_keeps_fault_class() {
        let outcome = AttemptOutcome::lockout("account locked");
        let record =
            super::attempt_record_from_outcome(&super::super::attempt::scripted_ctx(3), &outcome);
        assert_eq!(record.status, AttemptStatus::Lockout);
        assert_eq!(record.fault_class, Some(AttemptFaultClass::Lockout));
        assert_eq!(record.message, "account locked");
    }
}
