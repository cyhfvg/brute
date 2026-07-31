//! Integration tests for public WinRM error classification helpers.

use brute::cli::WinrmShellType;
use brute::protocol::AttemptOutcome;
use brute::protocol::winrm::{
    classify_winrm_error, format_cmd_invoke_denied, is_access_denied_message,
    is_authenticated_but_shell_denied, is_credential_rejection_message, is_invoke_denied_error,
};
use winrm_rs::{SoapError, WinrmError};

/// Verifies cmd Invoke denial messaging names shell type and rights.
#[test]
fn format_cmd_invoke_denied_names_shell_and_user() {
    let msg = format_cmd_invoke_denied(r"normal\rdp_user01", WinrmShellType::Cmd);
    assert!(msg.contains("Invoke"), "{msg}");
    assert!(msg.contains("cmd"), "{msg}");
    assert!(msg.contains(r"normal\rdp_user01"), "{msg}");
    assert!(!msg.contains("HTTP 500"), "{msg}");
}

/// Verifies SOAP AccessDenied is treated as Invoke denial.
#[test]
fn soap_access_denied_is_invoke_denied() {
    let err = WinrmError::Soap(SoapError::Fault {
        code: "w:AccessDenied".into(),
        reason: "拒绝访问。".into(),
    });
    assert!(is_invoke_denied_error(&err));
}

/// Verifies NTLM rejection maps to Failure, not transport Error.
#[test]
fn classify_auth_failed_is_failure() {
    let outcome = classify_winrm_error(&WinrmError::AuthFailed(
        "NTLM authentication rejected (bad credentials or CBT mismatch)".into(),
    ));
    match outcome {
        AttemptOutcome::Failure(message) => {
            assert!(message.contains("auth failed"), "{message}");
        }
        other => panic!("expected Failure, got {other:?}"),
    }
}

/// Verifies HTTP 500 after NTLM (password accepted, shell denied) is Success.
#[test]
fn classify_http_500_after_ntlm_is_authenticated_success() {
    let outcome = classify_winrm_error(&WinrmError::HttpStatus {
        status: 500,
        body: String::new(),
    });
    match outcome {
        AttemptOutcome::Success(success) => {
            assert!(
                success.message.contains("Shell access denied!")
                    || success.message.contains("shell denied")
                    || success.message.contains("Authenticated"),
                "{}",
                success.message
            );
        }
        other => panic!("expected Success for shell-denied auth, got {other:?}"),
    }
}

/// Verifies AccessDenied SOAP fault is Success (valid password, no shell).
#[test]
fn classify_soap_access_denied_is_authenticated_success() {
    let outcome = classify_winrm_error(&WinrmError::Soap(SoapError::Fault {
        code: "s:Sender".into(),
        reason: "Access Denied".into(),
    }));
    assert!(
        matches!(outcome, AttemptOutcome::Success(_)),
        "expected Success, got {outcome:?}"
    );
}

/// Verifies helper predicates used by classification.
#[test]
fn auth_message_predicates() {
    assert!(is_credential_rejection_message(
        "NTLM authentication rejected (bad credentials or CBT mismatch)"
    ));
    assert!(is_authenticated_but_shell_denied(
        "HTTP 500 Internal Server Error: "
    ));
    assert!(!is_authenticated_but_shell_denied(
        "NTLM authentication rejected (bad credentials or CBT mismatch)"
    ));
    assert!(is_access_denied_message("拒绝访问"));
}
