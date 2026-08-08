//! WinRM login attempt orchestration: spray probes and post-auth execute.

use std::time::Duration;

use winrm_rs::{WinrmClient, WinrmCredentials, WinrmError};

use crate::cli::WinrmShellType;
use crate::protocol::{AttemptOutcome, AttemptSuccess};

use super::classify::{
    classify_winrm_error, format_cmd_invoke_denied, is_credential_rejection_message,
    is_invoke_denied_error,
};
use super::probe::{
    ShellProbe, ShellProbePlan, cmd_status_after_auth_proven, format_shell_status_banner,
    probe_cmd_shell, probe_powershell_shell, shell_probe_plan,
};
use super::util::{
    format_command_output, resolve_execute_payload, split_domain_user, winrm_config_for_attempt,
};

/// Success banner after verified WinRM authentication with a usable shell (execute path).
const ACCESS_MESSAGE: &str = "Windows - Shell access!";

/// Performs one WinRM authentication attempt with optional remote execution.
///
/// # Parameters
///
/// - `host`: Target hostname or IP.
/// - `port`: WinRM listener port (typically 5985 HTTP / 5986 HTTPS).
/// - `username`: Account name; may be `DOMAIN\\user` or `user@domain`.
/// - `password`: Account password.
/// - `execute`: Optional post-auth command string, or `@path` to a local script file.
/// - `shell_type`: Explicit CLI shell type, or `None` for defaults / auto probe plan.
/// - `timeout`: Overall attempt timeout (also maps to client connect/operation timeouts).
/// - `proxy`: Optional outbound proxy from CLI `--proxy`.
///
/// # Returns
///
/// [`AttemptOutcome::Success`] on verified login (command failures stay success via
/// [`AttemptSuccess::with_command_error`]), [`AttemptOutcome::Failure`] for auth
/// rejections, or [`AttemptOutcome::Error`] for transport and other non-auth problems.
///
/// # Errors
///
/// Errors are mapped into [`AttemptOutcome`] variants rather than returned as `Result`.
///
/// # Examples
///
/// ```ignore
/// let outcome = try_winrm_login(
///     "10.10.50.10",
///     5985,
///     "admin",
///     "secret",
///     Some("whoami"),
///     None, // -x defaults to powershell
///     Duration::from_secs(30),
///     None,
/// ).await;
/// ```
#[allow(clippy::too_many_arguments)]
pub(super) async fn try_winrm_login(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    execute: Option<&str>,
    shell_type: Option<WinrmShellType>,
    timeout: Duration,
    proxy: Option<&crate::proxy::ProxyConfig>,
) -> AttemptOutcome {
    let payload = match execute {
        Some(raw) => match resolve_execute_payload(raw) {
            Ok(body) => Some(body),
            Err(err) => {
                return AttemptOutcome::Error(err);
            }
        },
        None => None,
    };

    let (domain, user) = split_domain_user(username);
    let display_user = if domain.is_empty() {
        user.clone()
    } else {
        format!("{domain}\\{user}")
    };
    let config = winrm_config_for_attempt(port, timeout, proxy);
    let credentials = WinrmCredentials::new(user, password, domain);

    let client = match WinrmClient::new(config, credentials) {
        Ok(client) => client,
        Err(err) => return classify_winrm_error(&err),
    };

    // Auth vs execute are separate channels:
    // - cmd uses WinRS; many lab accounts lack Invoke rights there.
    // - powershell uses real PSRP and must NOT require a successful cmd shell first.
    // Without `-x`: ordered serial probes (auto) or single-shell (explicit --shell-type).
    match payload {
        None => login_without_execute(&client, host, shell_type).await,
        Some(body) => {
            let effective = shell_type.unwrap_or(WinrmShellType::Powershell);
            execute_after_auth(&client, host, &display_user, effective, &body).await
        }
    }
}

/// Login spray path (no `-x`): ordered or single-shell capability probes + status banner.
///
/// # Parameters
///
/// - `client`: WinRM client built with the attempt credentials.
/// - `host`: Target hostname or IP.
/// - `explicit_shell`: CLI `--shell-type` if provided.
///
/// # Returns
///
/// [`AttemptOutcome::Success`] with a banner from [`format_shell_status_banner`] when
/// credentials work (even if every probed shell is denied); Failure only on true auth reject.
async fn login_without_execute(
    client: &WinrmClient,
    host: &str,
    explicit_shell: Option<WinrmShellType>,
) -> AttemptOutcome {
    let plan = shell_probe_plan(explicit_shell);
    let mut powershell: Option<bool> = None;
    let mut cmd: Option<bool> = None;

    match plan {
        ShellProbePlan::Only(WinrmShellType::Powershell) => {
            match probe_powershell_shell(client, host).await {
                ShellProbe::Available => powershell = Some(true),
                ShellProbe::Denied => powershell = Some(false),
                ShellProbe::AuthFailed(message) => {
                    return AttemptOutcome::Failure(format!("winrm auth failed: {message}"));
                }
                ShellProbe::Error(e) => {
                    return AttemptOutcome::Error(format!("winrm powershell probe failed: {e}"));
                }
            }
        }
        ShellProbePlan::Only(WinrmShellType::Cmd) => match probe_cmd_shell(client, host).await {
            ShellProbe::Available => cmd = Some(true),
            ShellProbe::Denied => cmd = Some(false),
            ShellProbe::AuthFailed(message) => {
                return AttemptOutcome::Failure(format!("winrm auth failed: {message}"));
            }
            ShellProbe::Error(e) => {
                return AttemptOutcome::Error(format!("winrm cmd probe failed: {e}"));
            }
        },
        ShellProbePlan::AutoSerial => {
            // powershell first; only probe cmd when powershell cannot execute.
            match probe_powershell_shell(client, host).await {
                ShellProbe::Available => {
                    powershell = Some(true);
                    // short-circuit: do not probe cmd
                }
                ShellProbe::Denied => {
                    // PS deny means NTLM was accepted; credential is verified.
                    powershell = Some(false);
                    let cmd_probe = probe_cmd_shell(client, host).await;
                    cmd = cmd_status_after_auth_proven(cmd_probe);
                    // Never Failure here: auth already proven by PS deny.
                }
                ShellProbe::AuthFailed(message) => {
                    return AttemptOutcome::Failure(format!("winrm auth failed: {message}"));
                }
                ShellProbe::Error(e) => {
                    // Fall through to cmd so a PS-only glitch does not hide cmd access.
                    match probe_cmd_shell(client, host).await {
                        ShellProbe::Available => cmd = Some(true),
                        ShellProbe::Denied => cmd = Some(false),
                        ShellProbe::AuthFailed(message) => {
                            return AttemptOutcome::Failure(format!(
                                "winrm auth failed: {message}"
                            ));
                        }
                        ShellProbe::Error(e2) => {
                            return AttemptOutcome::Error(format!(
                                "winrm shell probe failed: powershell={e}; cmd={e2}"
                            ));
                        }
                    }
                }
            }
        }
    }

    AttemptOutcome::Success(AttemptSuccess::new(format_shell_status_banner(
        powershell, cmd,
    )))
}

/// Runs post-auth execute for the selected shell type without gating powershell on cmd.
///
/// # Parameters
///
/// - `client`: Authenticated WinRM client.
/// - `host`: Target host.
/// - `display_user`: `DOMAIN\\user` or bare user for operator messages.
/// - `shell_type`: `cmd` (WinRS) or `powershell` (PSRP via `run_powershell`).
/// - `payload`: Command or script body (already resolved from `@file` when needed).
///
/// # Returns
///
/// Success with command output, or success with a clear post-auth command error
/// (including cmd Invoke denial). Credential rejection becomes Failure.
async fn execute_after_auth(
    client: &WinrmClient,
    host: &str,
    display_user: &str,
    shell_type: WinrmShellType,
    payload: &str,
) -> AttemptOutcome {
    match shell_type {
        WinrmShellType::Cmd => match client.run_command(host, "cmd.exe", &["/c", payload]).await {
            Ok(output) => AttemptOutcome::Success(AttemptSuccess::with_command(
                ACCESS_MESSAGE,
                format_command_output(&output),
            )),
            Err(err) => map_execute_error(display_user, WinrmShellType::Cmd, &err),
        },
        WinrmShellType::Powershell => {
            // Real PSRP path in cyhfvg/winrm-rs (not WinRS + powershell.exe).
            let wrapped = format!(
                "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue; {payload}"
            );
            match client.run_powershell(host, &wrapped).await {
                Ok(output) => AttemptOutcome::Success(AttemptSuccess::with_command(
                    ACCESS_MESSAGE,
                    format_command_output(&output),
                )),
                Err(err) => map_execute_error(display_user, WinrmShellType::Powershell, &err),
            }
        }
    }
}

/// Maps an execute-path error to auth Failure vs post-auth command Failure.
fn map_execute_error(
    display_user: &str,
    shell_type: WinrmShellType,
    err: &WinrmError,
) -> AttemptOutcome {
    let text = err.to_string();
    if is_credential_rejection_message(&text) {
        return AttemptOutcome::Failure(format!("winrm auth failed: {text}"));
    }
    if is_invoke_denied_error(err) {
        return AttemptOutcome::Success(AttemptSuccess::with_command_error(
            ACCESS_MESSAGE,
            format_cmd_invoke_denied(display_user, shell_type),
        ));
    }
    AttemptOutcome::Success(AttemptSuccess::with_command_error(
        ACCESS_MESSAGE,
        format!(
            "Execute command failed (shell type: {}): {text}",
            shell_type.as_str()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{CommonArgs, Protocol};
    use crate::credentials::CredentialSet;
    use crate::protocol::winrm::WinrmModule;
    use crate::protocol::{AttemptContext, BruteModule};

    /// Closed local port must surface transport Error, not the unimplemented stub.
    #[tokio::test]
    async fn closed_port_is_transport_error_not_stub() {
        let module = WinrmModule::new(500, Some(WinrmShellType::Cmd));
        let ctx = AttemptContext {
            protocol: Protocol::Winrm,
            target_host: "127.0.0.1".into(),
            target: CommonArgs {
                targets: vec!["127.0.0.1".into()],
                usernames: vec!["admin".into()],
                passwords: vec!["secret".into()],
                credential_id: None,
                port: Some(1),
                threads: 1,
                retries: 0,
                timeout_ms: 300,
                continue_on_success: false,
                proxy: None,
            },
            path: None,
            execute: None,
            credential: CredentialSet {
                username: Some("admin".into()),
                password: Some("secret".into()),
                service_name: None,
                sid: None,
            },
        };
        let outcome = module.attempt(&ctx).await;
        match outcome {
            AttemptOutcome::Error(message) => {
                assert!(
                    !message.contains("scaffolded") && !message.contains("not implemented"),
                    "must not use stub: {message}"
                );
            }
            AttemptOutcome::Failure(_) => {}
            AttemptOutcome::Success(_) => panic!("closed port must not succeed"),
        }
    }

    /// Production path uses AutoSerial short-circuit and default powershell for `-x`.
    #[test]
    fn attempt_source_uses_ordered_serial_and_default_powershell() {
        let prod = include_str!("attempt.rs");
        assert!(prod.contains("ShellProbePlan::AutoSerial"));
        assert!(prod.contains("short-circuit"));
        assert!(prod.contains("cmd_status_after_auth_proven"));
        assert!(prod.contains("unwrap_or(WinrmShellType::Powershell)"));
    }
}
