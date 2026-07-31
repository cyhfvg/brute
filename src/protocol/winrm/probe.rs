//! Shell capability probes and no-`-x` status banners.

use winrm_rs::{WinrmClient, WinrmError};

use crate::cli::WinrmShellType;

use super::classify::{
    AUTH_SHELL_DENIED_MESSAGE, is_access_denied_message, is_authenticated_but_shell_denied,
    is_credential_rejection_message, is_invoke_denied_error,
};

/// Result of probing one remote shell after NTLM has been attempted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellProbe {
    /// Shell open/execute succeeded.
    Available,
    /// Auth was accepted but this shell type was denied (AccessDenied / Invoke).
    Denied,
    /// Real credential rejection (should stop probing and report Failure).
    AuthFailed(String),
    /// Transport/protocol problem (not a clean auth or shell-deny signal).
    Error(String),
}

/// How no-`-x` shell capability probes are planned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellProbePlan {
    /// Probe powershell first; probe cmd only if powershell is not available.
    AutoSerial,
    /// Probe only the operator-selected shell.
    Only(WinrmShellType),
}

/// Builds the no-`-x` probe plan from optional explicit `--shell-type`.
///
/// # Parameters
///
/// - `explicit`: `Some` when the CLI flag was supplied; `None` when omitted.
///
/// # Returns
///
/// [`ShellProbePlan::AutoSerial`] when omitted; [`ShellProbePlan::Only`] when set.
///
/// # Errors
///
/// This function does not fail.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(shell_probe_plan(None), ShellProbePlan::AutoSerial);
/// assert_eq!(
///     shell_probe_plan(Some(WinrmShellType::Cmd)),
///     ShellProbePlan::Only(WinrmShellType::Cmd)
/// );
/// ```
pub fn shell_probe_plan(explicit: Option<WinrmShellType>) -> ShellProbePlan {
    match explicit {
        None => ShellProbePlan::AutoSerial,
        Some(t) => ShellProbePlan::Only(t),
    }
}

/// Maps a cmd probe after authentication is already proven (e.g. powershell denied).
///
/// # Parameters
///
/// - `cmd`: Result of a follow-up cmd shell probe.
///
/// # Returns
///
/// - `Some(true)` / `Some(false)` when the probe cleanly reports available/denied.
/// - `None` when the probe is AuthFailed or Error — **must not** turn a verified login
///   into auth Failure.
///
/// # Errors
///
/// This function does not fail.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(cmd_status_after_auth_proven(ShellProbe::Denied), Some(false));
/// assert_eq!(
///     cmd_status_after_auth_proven(ShellProbe::AuthFailed("x".into())),
///     None
/// );
/// ```
pub fn cmd_status_after_auth_proven(cmd: ShellProbe) -> Option<bool> {
    match cmd {
        ShellProbe::Available => Some(true),
        ShellProbe::Denied => Some(false),
        ShellProbe::AuthFailed(_) | ShellProbe::Error(_) => None,
    }
}

/// Probes WinRS/cmd shell availability (open + close).
pub(super) async fn probe_cmd_shell(client: &WinrmClient, host: &str) -> ShellProbe {
    match client.open_shell(host).await {
        Ok(shell) => {
            let _ = shell.close().await;
            ShellProbe::Available
        }
        Err(err) => classify_shell_probe_error(&err),
    }
}

/// Probes PowerShell/PSRP availability with a minimal script.
pub(super) async fn probe_powershell_shell(client: &WinrmClient, host: &str) -> ShellProbe {
    // Lightweight PSRP check (not user -x payload).
    match client.run_powershell(host, "1").await {
        Ok(_) => ShellProbe::Available,
        Err(err) => classify_shell_probe_error(&err),
    }
}

/// Maps a WinRM client error to a shell-probe classification.
///
/// # Parameters
///
/// - `err`: Error from open_shell or run_powershell.
///
/// # Returns
///
/// [`ShellProbe::AuthFailed`], [`ShellProbe::Denied`], or [`ShellProbe::Error`].
pub(super) fn classify_shell_probe_error(err: &WinrmError) -> ShellProbe {
    let text = err.to_string();
    if matches!(err, WinrmError::AuthFailed(_)) && !is_authenticated_but_shell_denied(&text) {
        return ShellProbe::AuthFailed(text);
    }
    if is_credential_rejection_message(&text) && !is_authenticated_but_shell_denied(&text) {
        return ShellProbe::AuthFailed(text);
    }
    if is_invoke_denied_error(err) || is_access_denied_message(&text) {
        return ShellProbe::Denied;
    }
    if matches!(err, WinrmError::HttpStatus { status: 500, .. }) {
        return ShellProbe::Denied;
    }
    if matches!(err, WinrmError::Soap(_)) && text.to_ascii_lowercase().contains("access") {
        return ShellProbe::Denied;
    }
    if matches!(err, WinrmError::Psrp(_)) && is_access_denied_message(&text) {
        return ShellProbe::Denied;
    }
    ShellProbe::Error(text)
}

/// Builds the no-`-x` success banner from **probed** shell results only.
///
/// # Parameters
///
/// - `powershell`: `None` = not probed; `Some(true)` = available; `Some(false)` = denied.
/// - `cmd`: Same encoding for the WinRS/cmd shell.
///
/// # Returns
///
/// - `Windows - Shell access! (powershell)` / `(cmd)` / listed available shells when any work.
/// - Probed-but-denied shells are listed after a semicolon when something still works.
/// - `Windows - Shell access denied!` when every probed shell is unavailable (optionally
///   naming probed-denied shells).
/// - Unprobed shells never appear.
///
/// # Errors
///
/// This function does not fail.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(
///     format_shell_status_banner(Some(true), None),
///     "Windows - Shell access! (powershell)"
/// );
/// assert_eq!(
///     format_shell_status_banner(Some(false), Some(true)),
///     "Windows - Shell access! (cmd; powershell denied)"
/// );
/// assert!(format_shell_status_banner(Some(false), None).contains("Shell access denied!"));
/// ```
pub fn format_shell_status_banner(powershell: Option<bool>, cmd: Option<bool>) -> String {
    let mut available: Vec<&'static str> = Vec::new();
    let mut denied: Vec<&'static str> = Vec::new();

    // Prefer listing powershell before cmd for stable operator-facing order.
    if let Some(ok) = powershell {
        if ok {
            available.push("powershell");
        } else {
            denied.push("powershell");
        }
    }
    if let Some(ok) = cmd {
        if ok {
            available.push("cmd");
        } else {
            denied.push("cmd");
        }
    }

    if !available.is_empty() {
        let mut msg = format!("Windows - Shell access! ({})", available.join(", "));
        if !denied.is_empty() {
            msg.push_str(&format!("; {} denied", denied.join(", ")));
        }
        msg
    } else if !denied.is_empty() {
        // Required form: Shell access denied! — name probed-denied shells only.
        if denied.len() == 1 {
            format!("Windows - Shell access denied! ({})", denied[0])
        } else {
            format!("Windows - Shell access denied! ({})", denied.join(", "))
        }
    } else {
        AUTH_SHELL_DENIED_MESSAGE.to_string()
    }
}

/// Legacy dual-bool helper; prefer [`format_shell_status_banner`].
///
/// Treats both shells as probed.
///
/// # Parameters
///
/// - `cmd_ok`: Whether cmd was available.
/// - `powershell_ok`: Whether powershell was available.
///
/// # Returns
///
/// Banner string for both shells probed.
///
/// # Errors
///
/// This function does not fail.
pub fn shell_access_banner(cmd_ok: bool, powershell_ok: bool) -> String {
    format_shell_status_banner(Some(powershell_ok), Some(cmd_ok))
}

#[cfg(test)]
mod tests {
    use super::*;
    use winrm_rs::SoapError;

    /// Private helper: AccessDenied is Denied, NTLM reject is AuthFailed.
    #[test]
    fn classify_shell_probe_error_access_denied_is_denied() {
        let err = WinrmError::Soap(SoapError::Fault {
            code: "w:AccessDenied".into(),
            reason: "拒绝访问。".into(),
        });
        assert_eq!(classify_shell_probe_error(&err), ShellProbe::Denied);

        let auth = WinrmError::AuthFailed(
            "NTLM authentication rejected (bad credentials or CBT mismatch)".into(),
        );
        assert!(matches!(
            classify_shell_probe_error(&auth),
            ShellProbe::AuthFailed(_)
        ));
    }
}
