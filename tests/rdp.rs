//! Public RDP helper and attempt classification tests.

use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::time::Duration;

use rdp::model::error::{Error as RdpClientError, RdpError, RdpErrorKind};

use brute::protocol::AttemptOutcome;
use brute::protocol::rdp::{
    classify_rdp_error, is_rdp_auth_failure, split_domain_user, try_rdp_login,
};

/// Verifies domain/user splitting used before CredSSP.
#[test]
fn splits_domain_user_forms() {
    assert_eq!(
        split_domain_user(r"LAB\alice"),
        ("LAB".to_string(), "alice".to_string())
    );
    assert_eq!(
        split_domain_user("alice@lab.local"),
        ("lab.local".to_string(), "alice".to_string())
    );
    assert_eq!(
        split_domain_user("alice"),
        (String::new(), "alice".to_string())
    );
}

/// Verifies TLS access-denied style messages map to auth failure.
#[test]
fn classifies_tls_access_denied_as_auth_failure() {
    let io_err = IoError::other("ssl3_read_bytes: tlsv1 alert access denied (SSL alert number 49)");
    let err = RdpClientError::Io(io_err);
    assert!(is_rdp_auth_failure(&err));
    match classify_rdp_error(&err) {
        AttemptOutcome::Failure(message) => {
            assert!(message.contains("rdp auth failed"));
        }
        other => panic!("expected Failure, got {other:?}"),
    }
}

/// Verifies protocol RejectedByServer maps to auth failure.
#[test]
fn classifies_rejected_by_server_as_auth_failure() {
    let err = RdpClientError::RdpError(RdpError::new(RdpErrorKind::RejectedByServer, "rejected"));
    assert!(is_rdp_auth_failure(&err));
    match classify_rdp_error(&err) {
        AttemptOutcome::Failure(message) => {
            assert!(message.contains("rdp auth failed"));
        }
        other => panic!("expected Failure, got {other:?}"),
    }
}

/// Verifies transport-style messages stay Error.
#[test]
fn classifies_connection_refused_as_error() {
    let io_err = IoError::new(IoErrorKind::ConnectionRefused, "connection refused");
    let err = RdpClientError::Io(io_err);
    match classify_rdp_error(&err) {
        AttemptOutcome::Error(message) => {
            assert!(
                message.contains("rdp transport error") || message.contains("rdp error"),
                "{message}"
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

/// Closed local port must surface transport Error, not the unimplemented stub.
#[test]
fn closed_port_is_transport_error_not_stub() {
    let outcome = try_rdp_login(
        "127.0.0.1",
        1,
        "admin",
        "not-a-real-password",
        Duration::from_millis(400),
        None,
    );
    match outcome {
        AttemptOutcome::Error(message) => {
            assert!(
                message.contains("rdp transport error")
                    || message.contains("rdp resolve error")
                    || message.contains("Connection refused")
                    || message.contains("timed out")
                    || message.contains("os error")
                    || message.contains("rdp error"),
                "unexpected error text: {message}"
            );
            assert!(
                !message.contains("scaffolded but not implemented"),
                "must not use stub: {message}"
            );
        }
        other => panic!("expected Error for closed port, got {other:?}"),
    }
}
