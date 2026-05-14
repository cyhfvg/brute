//! Protocol implementations and shared abstractions.

pub mod ftp;
pub mod mysql;
pub mod postgresql;
pub mod redis;
pub mod ssh;
pub mod stub;
pub mod tomcat;

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
    pub path: Option<String>,
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
    pub index: usize,
    pub total: usize,
    pub protocol: Protocol,
    pub target_host: String,
    pub target: CommonArgs,
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
            path: ctx.path.clone(),
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

/// High-level result of a login attempt.
#[derive(Debug, Clone)]
pub enum AttemptOutcome {
    Success(AttemptSuccess),
    Failure(String),
    Error(String),
}

/// Successful authentication result plus optional command output.
#[derive(Debug, Clone)]
pub struct AttemptSuccess {
    pub message: String,
    pub command_output: Option<String>,
}

impl AttemptSuccess {
    /// Creates a success result without command output.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            command_output: None,
        }
    }

    /// Creates a success result with post-auth command output.
    pub fn with_command(message: impl Into<String>, command_output: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            command_output: Some(command_output.into()),
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

impl Clone for Box<dyn BruteModule> {
    fn clone(&self) -> Self {
        panic!("Box<dyn BruteModule> cloning is not supported; use Arc<dyn BruteModule> instead")
    }
}

/// Helper for wrapping blocking client libraries in a Tokio timeout.
pub async fn run_blocking_with_timeout<F>(timeout: Duration, task: F) -> AttemptOutcome
where
    F: FnOnce() -> AttemptOutcome + Send + 'static,
{
    match tokio::time::timeout(timeout, tokio::task::spawn_blocking(task)).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(join_err)) => AttemptOutcome::Error(format!("task join error: {join_err}")),
        Err(_) => AttemptOutcome::Error("attempt timed out".to_string()),
    }
}
