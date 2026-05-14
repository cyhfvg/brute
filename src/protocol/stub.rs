//! Placeholder modules for protocols not implemented yet.

use async_trait::async_trait;

use crate::cli::Protocol;

use super::{AttemptContext, AttemptOutcome, BruteModule};

/// Generic stub for planned protocols.
#[derive(Debug, Clone)]
pub struct StubModule {
    protocol: Protocol,
}

impl StubModule {
    /// Creates a new stub module.
    pub fn new(protocol: Protocol, _timeout_ms: u64) -> Self {
        Self { protocol }
    }
}

#[async_trait]
impl BruteModule for StubModule {
    fn name(&self) -> &'static str {
        match self.protocol {
            Protocol::Smb => "smb",
            Protocol::Rdp => "rdp",
            Protocol::Winrm => "winrm",
            Protocol::Oracle => "oracle",
            Protocol::Http => "http",
            Protocol::Vnc => "vnc",
            _ => "unknown",
        }
    }

    async fn attempt(&self, _ctx: &AttemptContext) -> AttemptOutcome {
        AttemptOutcome::Error(format!(
            "{} is scaffolded but not implemented in this build",
            self.name()
        ))
    }
}
