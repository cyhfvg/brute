//! WinRM login attempts and optional remote command/script execution.
//!
//! Uses the forked pure-Rust [`winrm_rs`] client
//! (`https://github.com/cyhfvg/winrm-rs`: WS-Man + sealed NTLMv2 + real PSRP)
//! so release builds stay single-file friendly without in-tree path crates or
//! Cargo `[patch]`.
//!
//! Module layout (keep each file roughly ≤600 lines):
//! - [`attempt`]: login/execute orchestration
//! - [`probe`]: shell capability probes and status banners
//! - [`classify`]: error → outcome mapping
//! - [`util`]: config, `@file` payload, formatting

mod attempt;
mod classify;
mod probe;
mod util;

pub use classify::{
    classify_winrm_error, format_cmd_invoke_denied, is_access_denied_message,
    is_authenticated_but_shell_denied, is_credential_rejection_message, is_invoke_denied_error,
};
pub use probe::{
    ShellProbe, ShellProbePlan, cmd_status_after_auth_proven, format_shell_status_banner,
    shell_access_banner, shell_probe_plan,
};
pub use util::{
    build_remote_invocation, format_command_output, powershell_args_bypass_execution_policy,
    resolve_execute_payload, split_domain_user, winrm_config_for_attempt,
};

use std::time::Duration;

use async_trait::async_trait;

use crate::cli::WinrmShellType;

use super::{AttemptContext, AttemptOutcome, BruteModule, TargetContext, TargetProbe};

use attempt::try_winrm_login;
use util::probe_winrm_port;

/// WinRM module configuration.
#[derive(Debug, Clone)]
pub struct WinrmModule {
    /// Explicit `--shell-type` when set; `None` means auto (default powershell for `-x`,
    /// ordered serial probes for no-`-x`).
    shell_type: Option<WinrmShellType>,
}

impl WinrmModule {
    /// Creates a new WinRM module.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Reserved for API parity with other modules; per-attempt
    ///   timeouts are taken from each [`AttemptContext`] / [`TargetContext`].
    /// - `shell_type`: Explicit CLI `--shell-type`, or `None` when omitted.
    ///
    /// # Returns
    ///
    /// A configured [`WinrmModule`] ready for the scheduler.
    ///
    /// # Errors
    ///
    /// This constructor does not fail.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use crate::cli::WinrmShellType;
    /// let module = WinrmModule::new(5000, None);
    /// let only_cmd = WinrmModule::new(5000, Some(WinrmShellType::Cmd));
    /// ```
    pub fn new(_timeout_ms: u64, shell_type: Option<WinrmShellType>) -> Self {
        Self { shell_type }
    }
}

#[async_trait]
impl BruteModule for WinrmModule {
    fn name(&self) -> &'static str {
        "winrm"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        let host = ctx.target_host.clone();
        let port = ctx.port();
        let timeout = ctx.timeout();

        let probe = tokio::task::spawn_blocking(move || probe_winrm_port(&host, port, timeout));
        match tokio::time::timeout(timeout, probe).await {
            Ok(Ok(Some(message))) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        let host = ctx.target_host.clone();
        let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
        let username = ctx.credential.username.clone().unwrap_or_default();
        let password = ctx.credential.password.clone().unwrap_or_default();
        let execute = ctx.execute.clone();
        let shell_type = self.shell_type;
        let timeout = ctx.timeout();

        // Dual shell probe (no -x) and PSRP execute need more headroom than a TCP probe.
        let attempt_timeout = if execute.is_some() {
            timeout.max(Duration::from_secs(30))
        } else {
            // Ordered shell capability probes after auth.
            timeout.max(Duration::from_secs(15))
        };

        let future = async move {
            try_winrm_login(
                &host,
                port,
                &username,
                &password,
                execute.as_deref(),
                shell_type,
                attempt_timeout,
            )
            .await
        };

        match tokio::time::timeout(attempt_timeout, future).await {
            Ok(outcome) => outcome,
            Err(_) => AttemptOutcome::Error("attempt timed out".to_string()),
        }
    }
}
