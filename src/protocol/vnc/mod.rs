//! VNC login attempts: classic RFB Authentication (security type 2) and web-VNC Basic Auth.
//!
//! ## Classic RFB (RFC 6143)
//!
//! Handshake versions 003.003 / 003.007 / 003.008 are accepted. Security type 2
//! (VNC Authentication) uses DES challenge-response with the VNC bit-reversed
//! 8-byte password key. Username is accepted by the CLI and ignored for type 2
//! (password-only), matching NetExec-style VNC spraying.
//!
//! ## Web VNC gateways
//!
//! Many lab deployments (linuxserver webtop / Selkies / noVNC behind nginx) expose
//! HTTPS with HTTP Basic Auth rather than raw RFB on the published port. When the
//! TCP peer does not send an RFB banner, this module falls back to HTTPS Basic
//! Auth so those credentials can still be validated.
//!
//! Module layout (keep each file roughly ≤600 lines):
//! - [`auth`]: DES password key + challenge-response
//! - [`rfb`]: RFB handshake, security-type selection, classic login
//! - [`web`]: gateway detection + HTTPS Basic Auth
//! - [`util`]: sockets, probe, I/O helpers

mod auth;
mod rfb;
mod util;
mod web;

pub use auth::{vnc_auth_response, vnc_password_key};
pub use rfb::{RfbAuthResult, rfb_authenticate, try_vnc_rfb_login};
pub use util::ReadWrite;

use async_trait::async_trait;

use super::{
    AttemptContext, AttemptOutcome, BruteModule, TargetContext, TargetProbe,
    run_blocking_with_timeout,
};

use rfb::try_vnc_rfb_login as try_rfb;
use util::probe_vnc_port;
use web::{looks_like_tls_or_http_gateway, try_vnc_web_basic_login};

/// VNC module configuration.
#[derive(Debug, Clone)]
pub struct VncModule;

impl VncModule {
    /// Creates a new VNC module.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Reserved for API parity with other modules; per-attempt
    ///   timeouts are taken from each [`AttemptContext`] / [`TargetContext`].
    ///
    /// # Returns
    ///
    /// A configured [`VncModule`] ready for the scheduler.
    ///
    /// # Errors
    ///
    /// This constructor does not fail.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let module = VncModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for VncModule {
    fn name(&self) -> &'static str {
        "vnc"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        let host = ctx.target_host.clone();
        let port = ctx.port();
        let timeout = ctx.timeout();

        let probe = tokio::task::spawn_blocking(move || probe_vnc_port(&host, port, timeout));
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
        let timeout = ctx.timeout();

        // Peek off the async runtime: classic VNC speaks first; TLS/HTTP gateways do not.
        let host_peek = host.clone();
        let is_web_gateway = match tokio::task::spawn_blocking(move || {
            looks_like_tls_or_http_gateway(&host_peek, port, timeout)
        })
        .await
        {
            Ok(value) => value,
            Err(err) => {
                return AttemptOutcome::Error(format!("vnc probe task join error: {err}"));
            }
        };

        if is_web_gateway {
            // linuxserver webtop / noVNC-style HTTPS Basic Auth in front of the desktop.
            try_vnc_web_basic_login(&host, port, &username, &password, timeout).await
        } else {
            run_blocking_with_timeout(timeout, move || try_rfb(&host, port, &password, timeout))
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Module name and wiring are not the stub.
    #[test]
    fn module_name_is_vnc() {
        let m = VncModule::new(1000);
        assert_eq!(m.name(), "vnc");
    }
}
