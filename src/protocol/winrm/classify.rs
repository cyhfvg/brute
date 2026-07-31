//! WinRM error classification and operator-facing deny messages.

use winrm_rs::WinrmError;

use crate::cli::WinrmShellType;
use crate::protocol::{AttemptOutcome, AttemptSuccess};

/// Success banner when NTLM/password is accepted but every **probed** shell is denied.
pub(crate) const AUTH_SHELL_DENIED_MESSAGE: &str = "Windows - Shell access denied!";

/// Operator-facing message for WinRM Invoke / AccessDenied on a shell type.
///
/// # Parameters
///
/// - `display_user`: Account shown to the operator.
/// - `shell_type`: Shell that was denied.
///
/// # Returns
///
/// NetExec-comparable text naming Invoke rights and shell type.
///
/// # Examples
///
/// ```ignore
/// let msg = format_cmd_invoke_denied(r"normal\rdp_user01", WinrmShellType::Cmd);
/// assert!(msg.contains("Invoke"));
/// assert!(msg.contains("cmd"));
/// ```
pub fn format_cmd_invoke_denied(display_user: &str, shell_type: WinrmShellType) -> String {
    format!(
        "Execute command failed, current user: '{display_user}' has no 'Invoke' rights to execute command (shell type: {})",
        shell_type.as_str()
    )
}

/// Returns true when `err` is AccessDenied / Invoke denial after successful NTLM.
///
/// # Parameters
///
/// - `err`: Error from the WinRM client.
///
/// # Returns
///
/// `true` for SOAP AccessDenied, HTTP 500 post-auth, or matching message text.
///
/// # Examples
///
/// ```ignore
/// assert!(is_invoke_denied_error(&err));
/// ```
pub fn is_invoke_denied_error(err: &WinrmError) -> bool {
    match err {
        WinrmError::Soap(soap) => is_access_denied_message(&soap.to_string()),
        WinrmError::HttpStatus { status, body } => {
            *status == 500
                || is_access_denied_message(body)
                || is_authenticated_but_shell_denied(&format!("HTTP {status}: {body}"))
        }
        WinrmError::AuthFailed(msg) => is_authenticated_but_shell_denied(msg),
        other => is_access_denied_message(&other.to_string()),
    }
}

/// Maps a `winrm_rs` error into a scheduler outcome.
///
/// # Parameters
///
/// - `err`: Error returned by client construction or shell open.
///
/// # Returns
///
/// - [`AttemptOutcome::Failure`] for rejected passwords / NTLM 401.
/// - [`AttemptOutcome::Success`] when authentication is accepted but remote shell
///   creation is denied (HTTP 500 / SOAP AccessDenied after NTLM Type3).
/// - [`AttemptOutcome::Error`] for transport and other non-auth problems.
///
/// # Errors
///
/// This function does not fail.
///
/// # Examples
///
/// ```ignore
/// let bad = classify_winrm_error(&WinrmError::AuthFailed(
///     "NTLM authentication rejected (bad credentials or CBT mismatch)".into(),
/// ));
/// assert!(matches!(bad, AttemptOutcome::Failure(_)));
/// ```
pub fn classify_winrm_error(err: &WinrmError) -> AttemptOutcome {
    match err {
        WinrmError::AuthFailed(message) => {
            if is_authenticated_but_shell_denied(message) {
                AttemptOutcome::Success(AttemptSuccess::new(AUTH_SHELL_DENIED_MESSAGE))
            } else {
                AttemptOutcome::Failure(format!("winrm auth failed: {message}"))
            }
        }
        WinrmError::HttpStatus { status, body } => {
            let text = if body.is_empty() {
                format!("HTTP {status}")
            } else {
                format!("HTTP {status}: {body}")
            };
            if *status == 500
                || is_access_denied_message(&text)
                || is_authenticated_but_shell_denied(&text)
            {
                AttemptOutcome::Success(AttemptSuccess::new(AUTH_SHELL_DENIED_MESSAGE))
            } else if is_credential_rejection_message(&text) {
                AttemptOutcome::Failure(format!("winrm auth failed: {text}"))
            } else {
                AttemptOutcome::Error(format!("winrm http status: {text}"))
            }
        }
        WinrmError::Ntlm(ntlm_err) => {
            let text = ntlm_err.to_string();
            if is_credential_rejection_message(&text) {
                AttemptOutcome::Failure(format!("winrm auth failed: {text}"))
            } else {
                AttemptOutcome::Error(format!("winrm ntlm error: {text}"))
            }
        }
        WinrmError::Http(http_err) => {
            let text = http_err.to_string();
            if is_credential_rejection_message(&text) {
                AttemptOutcome::Failure(format!("winrm auth failed: {text}"))
            } else {
                AttemptOutcome::Error(format!("winrm transport error: {text}"))
            }
        }
        WinrmError::Timeout(secs) => {
            AttemptOutcome::Error(format!("winrm operation timed out after {secs}s"))
        }
        WinrmError::Soap(soap_err) => {
            let text = soap_err.to_string();
            if is_access_denied_message(&text) {
                AttemptOutcome::Success(AttemptSuccess::new(AUTH_SHELL_DENIED_MESSAGE))
            } else if is_credential_rejection_message(&text) {
                AttemptOutcome::Failure(format!("winrm auth failed: {text}"))
            } else {
                AttemptOutcome::Error(format!("winrm soap error: {text}"))
            }
        }
        other => AttemptOutcome::Error(format!("winrm error: {other}")),
    }
}

/// Returns true when the client reported credential rejection (bad password).
///
/// # Parameters
///
/// - `message`: Error text from `winrm_rs` or HTTP layers.
///
/// # Returns
///
/// `true` for NTLM 401 / unauthorized / logon-failure style messages.
///
/// # Errors
///
/// This function does not fail.
///
/// # Examples
///
/// ```ignore
/// assert!(is_credential_rejection_message(
///     "NTLM authentication rejected (bad credentials or CBT mismatch)"
/// ));
/// ```
pub fn is_credential_rejection_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("ntlm authentication rejected")
        || lower.contains("bad credentials")
        || lower.contains("401")
        || lower.contains("unauthorized")
        || lower.contains("logon failure")
        || lower.contains("logon_failure")
}

/// Returns true when the remote side denied shell/resource access after auth.
///
/// # Parameters
///
/// - `message`: SOAP fault or HTTP error text.
///
/// # Returns
///
/// `true` for AccessDenied-style faults (English / common codes / Chinese).
///
/// # Errors
///
/// This function does not fail.
///
/// # Examples
///
/// ```ignore
/// assert!(is_access_denied_message("SOAP fault: AccessDenied"));
/// assert!(is_access_denied_message("拒绝访问"));
/// ```
pub fn is_access_denied_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("access denied")
        || lower.contains("access is denied")
        || lower.contains("accessdenied")
        || lower.contains("0x80070005")
        || message.contains("拒绝访问")
}

/// Returns true when auth was accepted but WinRM shell creation still failed.
///
/// Older clients surface post-NTLM AccessDenied as
/// `AuthFailed("HTTP 500 Internal Server Error: ")`. Newer cyhfvg/winrm-rs
/// uses `HttpStatus` / `Soap` instead; this helper remains for defensive mapping.
///
/// # Parameters
///
/// - `message`: Error payload text.
///
/// # Returns
///
/// `true` when the message indicates HTTP 500 / access-denied after handshake.
///
/// # Errors
///
/// This function does not fail.
///
/// # Examples
///
/// ```ignore
/// assert!(is_authenticated_but_shell_denied("HTTP 500 Internal Server Error: "));
/// assert!(!is_authenticated_but_shell_denied(
///     "NTLM authentication rejected (bad credentials or CBT mismatch)"
/// ));
/// ```
pub fn is_authenticated_but_shell_denied(message: &str) -> bool {
    if is_credential_rejection_message(message) {
        return false;
    }
    let lower = message.to_ascii_lowercase();
    lower.contains("http 500") || is_access_denied_message(message)
}
