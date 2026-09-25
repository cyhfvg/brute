//! Protocol implementations and shared abstractions.

pub mod activemq;
pub mod clickhouse;
pub mod couchdb;
pub mod docker;
pub mod druid;
pub mod elasticsearch;
pub mod etcd;
pub mod ftp;
pub mod gitlab;
pub mod grafana;
pub mod hadoop;
pub mod harbor;
pub mod http;
pub mod http_attempt;
pub mod http_auth;
pub mod influxdb;
pub mod jboss;
pub mod jenkins;
pub mod kafka;
pub mod kibana;
pub mod kubelet;
pub mod ldap;
pub mod memcached;
pub mod minio;
pub mod mongodb;
pub mod mssql;
pub mod mysql;
pub mod nacos;
pub mod neo4j;
pub mod nexus;
pub mod nfs;
pub mod oracle;
pub mod postgresql;
pub mod prometheus;
pub mod rabbitmq;
pub mod rdp;
pub mod redis;
pub mod rsync;
pub mod smb;
pub mod snmp;
pub mod solr;
pub mod spark;
pub mod ssh;
pub mod stub;
pub mod telnet;
pub mod tomcat;
pub mod vnc;
pub mod weblogic;
pub mod websphere;
pub mod winrm;
pub mod zookeeper;

use std::time::Duration;

use async_trait::async_trait;

use crate::{
    cli::{CommonArgs, Protocol},
    credentials::CredentialSet,
};

/// Per-target immutable context used before credential attempts begin.
#[derive(Debug, Clone)]
pub struct TargetContext {
    pub protocol: Protocol,
    pub target_host: String,
    pub target: CommonArgs,
    /// URL scheme from `--protocol`, or the protocol default.
    pub url_scheme: crate::cli::HttpUrlScheme,
}

impl TargetContext {
    /// Returns the socket address string used by most modules.
    pub fn addr(&self) -> String {
        format!(
            "{}:{}",
            self.target_host,
            self.target.port.unwrap_or(self.protocol.default_port())
        )
    }

    /// Returns the timeout configured for this target probe.
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.target.timeout_ms)
    }

    /// Returns the effective service port.
    pub fn port(&self) -> u16 {
        self.target.port.unwrap_or(self.protocol.default_port())
    }
}

/// Per-attempt immutable context.
#[derive(Debug, Clone)]
pub struct AttemptContext {
    pub protocol: Protocol,
    pub target_host: String,
    pub target: CommonArgs,
    /// URL scheme from `--protocol`, or the protocol default.
    pub url_scheme: crate::cli::HttpUrlScheme,
    pub path: Option<String>,
    pub execute: Option<String>,
    pub credential: CredentialSet,
}

impl From<&AttemptContext> for TargetContext {
    fn from(ctx: &AttemptContext) -> Self {
        Self {
            protocol: ctx.protocol,
            target_host: ctx.target_host.clone(),
            target: ctx.target.clone(),
            url_scheme: ctx.url_scheme,
        }
    }
}

impl AttemptContext {
    /// Returns the socket address string used by most modules.
    pub fn addr(&self) -> String {
        format!(
            "{}:{}",
            self.target_host,
            self.target.port.unwrap_or(self.protocol.default_port())
        )
    }

    /// Returns the timeout configured for this attempt.
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.target.timeout_ms)
    }
}

/// Result of a per-target service probe.
#[derive(Debug, Clone)]
pub enum TargetProbe {
    Ready(Option<String>),
}

pub use crate::error::{AttemptFault, AttemptFaultClass};

/// High-level result of a login attempt.
#[derive(Debug, Clone)]
pub enum AttemptOutcome {
    /// Authentication succeeded.
    Success(AttemptSuccess),
    /// Credentials were rejected or the account is locked. Not retried.
    Failure(AttemptFault),
    /// Transport or local failure. Retried only when the class is transport.
    Error(AttemptFault),
}

impl AttemptOutcome {
    /// Builds an authentication failure.
    ///
    /// # Parameters
    ///
    /// * `message`: Operator-facing rejection detail.
    ///
    /// # Returns
    ///
    /// [`AttemptOutcome::Failure`] with [`AttemptFaultClass::Auth`].
    ///
    /// # Errors
    ///
    /// Does not return [`Result`].
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::AttemptOutcome;
    ///
    /// assert!(!AttemptOutcome::failure("rejected").is_retriable_transport());
    /// ```
    pub fn failure(message: impl Into<String>) -> Self {
        Self::Failure(AttemptFault::auth(message))
    }

    /// Builds a retriable transport error.
    ///
    /// # Parameters
    ///
    /// * `message`: Operator-facing transport detail.
    ///
    /// # Returns
    ///
    /// [`AttemptOutcome::Error`] with [`AttemptFaultClass::Transport`].
    ///
    /// # Errors
    ///
    /// Does not return [`Result`].
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::AttemptOutcome;
    ///
    /// assert!(AttemptOutcome::error("timed out").is_retriable_transport());
    /// ```
    pub fn error(message: impl Into<String>) -> Self {
        Self::Error(AttemptFault::transport(message))
    }

    /// Builds an account or service lockout.
    ///
    /// # Parameters
    ///
    /// * `message`: Operator-facing lockout detail.
    ///
    /// # Returns
    ///
    /// [`AttemptOutcome::Failure`] with [`AttemptFaultClass::Lockout`].
    ///
    /// # Errors
    ///
    /// Does not return [`Result`].
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::AttemptOutcome;
    ///
    /// assert!(!AttemptOutcome::lockout("account locked").is_retriable_transport());
    /// ```
    pub fn lockout(message: impl Into<String>) -> Self {
        Self::Failure(AttemptFault::lockout(message))
    }

    /// Returns the structured fault when the attempt did not succeed.
    ///
    /// # Returns
    ///
    /// `None` for success. Otherwise the auth, lockout, or transport fault.
    ///
    /// # Errors
    ///
    /// Does not return [`Result`].
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::error::AttemptFaultClass;
    /// use brute::protocol::AttemptOutcome;
    ///
    /// let class = AttemptOutcome::error("down").fault().unwrap().class;
    /// assert_eq!(class, AttemptFaultClass::Transport);
    /// ```
    pub fn fault(&self) -> Option<&AttemptFault> {
        match self {
            Self::Success(_) => None,
            Self::Failure(fault) | Self::Error(fault) => Some(fault),
        }
    }

    /// Reports whether the scheduler should retry this outcome.
    ///
    /// # Returns
    ///
    /// `true` only when the fault class is [`AttemptFaultClass::Transport`].
    ///
    /// # Errors
    ///
    /// Does not return [`Result`].
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::AttemptOutcome;
    ///
    /// assert!(AttemptOutcome::error("down").is_retriable_transport());
    /// assert!(!AttemptOutcome::failure("rejected").is_retriable_transport());
    /// assert!(!AttemptOutcome::lockout("locked").is_retriable_transport());
    /// ```
    pub fn is_retriable_transport(&self) -> bool {
        self.fault().is_some_and(AttemptFault::is_retriable)
    }
}

/// Successful authentication result plus optional command output.
#[derive(Debug, Clone)]
pub struct AttemptSuccess {
    pub message: String,
    pub post_auth_result: Option<PostAuthResult>,
}

/// Result of an optional command issued after authentication succeeds.
#[derive(Debug, Clone)]
pub enum PostAuthResult {
    /// Command completed and produced terminal output.
    Output(String),
    /// Authentication succeeded, but the requested command could not be completed.
    Failed(String),
}

impl AttemptSuccess {
    /// Creates a success result without command output.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            post_auth_result: None,
        }
    }

    /// Creates a success result with post-auth command output.
    pub fn with_command(message: impl Into<String>, command_output: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            post_auth_result: Some(PostAuthResult::Output(command_output.into())),
        }
    }

    /// Creates a successful authentication result with a post-auth command error.
    ///
    /// A command failure must not turn a confirmed login into an authentication failure: callers
    /// use successful outcomes to persist verified credentials.
    pub fn with_command_error(message: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            post_auth_result: Some(PostAuthResult::Failed(error.into())),
        }
    }
}

/// Shared protocol interface.
#[async_trait]
pub trait BruteModule: Send + Sync {
    /// User-facing module name.
    fn name(&self) -> &'static str;
    /// Performs one optional target-level probe before credential attempts.
    async fn probe_target(&self, _ctx: &TargetContext) -> TargetProbe {
        TargetProbe::Ready(None)
    }
    /// Executes one credential attempt against the remote service.
    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome;
}

/// Runs a blocking login on the blocking pool and bounds the wait.
///
/// Dropping this future, including a timeout, does not abort the blocking thread.
/// The join is detached onto a supervisor task so the thread can finish and drop
/// values it owns, such as a proxy bridge.
///
/// # Parameters
///
/// - `timeout`: Maximum time to wait for the blocking function.
/// - `task`: Blocking login. It must own every resource it needs until it returns.
///
/// # Returns
///
/// The blocking function's outcome, a join error, or an `attempt timed out` transport fault.
///
/// # Errors
///
/// Does not return [`Result`]. Join and timeout failures are [`AttemptOutcome::Error`].
///
/// # Examples
///
/// ```ignore
/// run_blocking_with_timeout(timeout, move || connect(bridge)).await
/// ```
pub async fn run_blocking_with_timeout<F>(timeout: Duration, task: F) -> AttemptOutcome
where
    F: FnOnce() -> AttemptOutcome + Send + 'static,
{
    let mut supervised = SupervisedBlocking {
        handle: Some(tokio::task::spawn_blocking(task)),
    };
    let joined = tokio::time::timeout(
        timeout,
        supervised
            .handle
            .as_mut()
            .expect("blocking attempt handle is present"),
    )
    .await;
    match joined {
        Ok(Ok(outcome)) => {
            supervised.handle.take();
            outcome
        }
        Ok(Err(join_err)) => {
            supervised.handle.take();
            AttemptOutcome::error(format!("task join error: {join_err}"))
        }
        Err(_) => AttemptOutcome::error("attempt timed out"),
    }
}

/// Detaches a still-running blocking join when the caller stops waiting.
struct SupervisedBlocking {
    handle: Option<tokio::task::JoinHandle<AttemptOutcome>>,
}

impl Drop for SupervisedBlocking {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            drop(tokio::spawn(async move {
                let _ = handle.await;
            }));
        }
    }
}

#[cfg(test)]
mod blocking_timeout_tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;

    use super::run_blocking_with_timeout;

    struct HoldUntilDrop {
        dropped: Arc<AtomicBool>,
    }

    impl Drop for HoldUntilDrop {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    async fn wait_until(flag: &AtomicBool) {
        for _ in 0..50 {
            if flag.load(Ordering::SeqCst) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// A timeout must not drop resources owned by the still-running blocking function.
    #[tokio::test]
    async fn timeout_keeps_blocking_guard_until_the_task_returns() {
        let dropped = Arc::new(AtomicBool::new(false));
        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let dropped_task = Arc::clone(&dropped);
        let started_task = Arc::clone(&started);
        let release_task = Arc::clone(&release);

        let outcome = tokio::spawn(async move {
            run_blocking_with_timeout(Duration::from_millis(40), move || {
                let _guard = HoldUntilDrop {
                    dropped: dropped_task,
                };
                started_task.store(true, Ordering::SeqCst);
                while !release_task.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                crate::protocol::AttemptOutcome::failure("released")
            })
            .await
        });

        wait_until(&started).await;
        let outcome = outcome.await.expect("timeout task");
        match outcome {
            super::AttemptOutcome::Error(fault) => assert_eq!(&*fault, "attempt timed out"),
            other => panic!("expected timeout, got {other:?}"),
        }
        assert!(!dropped.load(Ordering::SeqCst));
        release.store(true, Ordering::SeqCst);
        wait_until(&dropped).await;
        assert!(dropped.load(Ordering::SeqCst));
    }

    /// Dropping the helper future must not drop the blocking function's guard.
    #[tokio::test]
    async fn dropped_wait_keeps_blocking_guard_until_the_task_returns() {
        let dropped = Arc::new(AtomicBool::new(false));
        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let dropped_task = Arc::clone(&dropped);
        let started_task = Arc::clone(&started);
        let release_task = Arc::clone(&release);
        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel_task = cancel.clone();

        let run = tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = cancel_task.cancelled() => {}
                _ = run_blocking_with_timeout(Duration::from_secs(5), move || {
                    let _guard = HoldUntilDrop {
                        dropped: dropped_task,
                    };
                    started_task.store(true, Ordering::SeqCst);
                    while !release_task.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    crate::protocol::AttemptOutcome::failure("released")
                }) => {}
            }
        });

        wait_until(&started).await;
        cancel.cancel();
        run.await.expect("dropped wait");
        assert!(!dropped.load(Ordering::SeqCst));
        release.store(true, Ordering::SeqCst);
        wait_until(&dropped).await;
        assert!(dropped.load(Ordering::SeqCst));
    }
}
