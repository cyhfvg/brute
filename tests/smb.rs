//! Public SMB helper tests.

use smb2::ErrorKind;

use brute::protocol::AttemptOutcome;
use brute::protocol::smb::{
    ShareAccessRow, classify_smb_error, format_share_access_listing, is_smb_auth_failure_kind,
    split_domain_user,
};

/// Verifies domain/user splitting used before SmbClient::connect.
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

/// Verifies auth-failure kind mapping used by the live attempt path.
#[test]
fn maps_auth_error_kinds() {
    assert!(is_smb_auth_failure_kind(ErrorKind::AuthRequired));
    assert!(is_smb_auth_failure_kind(ErrorKind::SigningRequired));
    assert!(is_smb_auth_failure_kind(ErrorKind::AccessDenied));
    assert!(!is_smb_auth_failure_kind(ErrorKind::TimedOut));
    assert!(!is_smb_auth_failure_kind(ErrorKind::ConnectionLost));
    assert!(!is_smb_auth_failure_kind(ErrorKind::Io));
}

/// Verifies share/Access listing text includes names and Access columns.
#[test]
fn formats_share_access_rows() {
    let text = format_share_access_listing(&[
        ShareAccessRow {
            name: "ADMIN$".into(),
            access: "READ".into(),
            remark: "Remote Admin".into(),
        },
        ShareAccessRow {
            name: "IPC$".into(),
            access: "READ".into(),
            remark: "Remote IPC".into(),
        },
        ShareAccessRow {
            name: "secret".into(),
            access: String::new(),
            remark: String::new(),
        },
    ]);

    assert!(text.contains("Enumerated shares"));
    assert!(text.contains("Share"));
    assert!(text.contains("Access"));
    assert!(text.contains("ADMIN$"));
    assert!(text.contains("READ"));
    assert!(text.contains("IPC$"));
    assert!(text.contains("Remote IPC"));
    assert!(text.contains("secret"));
}

/// Verifies empty share lists still produce a clear success-detail body.
#[test]
fn formats_empty_share_list() {
    let text = format_share_access_listing(&[]);
    assert!(text.contains("Enumerated shares"));
    assert!(text.contains("(no shares returned)"));
}

/// Verifies classify_smb_error maps real smb2 auth errors to Failure.
#[test]
fn classify_auth_error_as_failure() {
    let err = smb2::Error::Auth {
        message: "STATUS_LOGON_FAILURE".into(),
    };
    match classify_smb_error(&err) {
        AttemptOutcome::Failure(message) => {
            assert!(message.contains("smb auth failed"));
            assert!(message.to_ascii_lowercase().contains("authentication"));
        }
        other => panic!("expected Failure, got {other:?}"),
    }
}

/// Verifies classify_smb_error maps transport timeouts to Error.
#[test]
fn classify_timeout_as_error() {
    let err = smb2::Error::Timeout;
    match classify_smb_error(&err) {
        AttemptOutcome::Error(message) => {
            assert!(message.contains("smb transport error") || message.contains("timed out"));
        }
        other => panic!("expected Error, got {other:?}"),
    }
}
