//! Integration tests for public WinRM utility helpers (`brute::protocol::winrm`).

use std::{
    io::Write,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use brute::cli::WinrmShellType;
use brute::protocol::winrm::{
    build_remote_invocation, format_command_output, powershell_args_bypass_execution_policy,
    resolve_execute_payload, split_domain_user, winrm_config_for_attempt,
};
use winrm_rs::{AuthMethod, CommandOutput, encode_powershell_command};

/// Verifies literal `-x` values pass through unchanged.
#[test]
fn resolve_execute_payload_literal() {
    assert_eq!(
        resolve_execute_payload("whoami /all").expect("literal"),
        "whoami /all"
    );
}

/// Verifies `@path` loads file contents via the shipped helper.
#[test]
fn resolve_execute_payload_at_file() {
    let dir = std::env::temp_dir().join(format!(
        "brute-winrm-atfile-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("script.ps1");
    {
        let mut f = std::fs::File::create(&path).expect("create");
        writeln!(f, "whoami").expect("write");
    }
    let raw = format!("@{}", path.display());
    let body = resolve_execute_payload(&raw).expect("read @file");
    assert_eq!(body, "whoami\n");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Verifies empty `@` path is rejected.
#[test]
fn resolve_execute_payload_empty_at_path_errors() {
    assert!(resolve_execute_payload("@").is_err());
    assert!(resolve_execute_payload("@   ").is_err());
}

/// Verifies missing `@file` surfaces a readable error.
#[test]
fn resolve_execute_payload_missing_file_errors() {
    let err = resolve_execute_payload("@/no/such/brute-winrm-script.ps1").unwrap_err();
    assert!(
        err.contains("failed to read") || err.contains("winrm"),
        "{err}"
    );
}

/// Verifies cmd invocation shape used by the execute path.
#[test]
fn build_remote_invocation_cmd() {
    let (exe, args) = build_remote_invocation(WinrmShellType::Cmd, "echo hi");
    assert_eq!(exe, "cmd.exe");
    assert_eq!(args, vec!["/c".to_string(), "echo hi".to_string()]);
}

/// Verifies powershell EncodedCommand helper still encodes scripts.
#[test]
fn build_remote_invocation_powershell_bypasses_execution_policy() {
    let script = "Get-Date";
    let (exe, args) = build_remote_invocation(WinrmShellType::Powershell, script);
    assert_eq!(exe, "powershell.exe");
    assert!(powershell_args_bypass_execution_policy(&args));
    let encoded = args
        .iter()
        .skip_while(|a| !a.eq_ignore_ascii_case("-EncodedCommand"))
        .nth(1)
        .expect("encoded command");
    assert_ne!(encoded, script);
    assert!(!encoded.is_empty());
    assert_eq!(encoded, &encode_powershell_command(script));
}

/// Verifies domain/user splitting matches SMB/RDP conventions.
#[test]
fn split_domain_user_forms() {
    assert_eq!(
        split_domain_user(r"LAB\alice"),
        ("LAB".into(), "alice".into())
    );
    assert_eq!(
        split_domain_user("alice@lab.local"),
        ("lab.local".into(), "alice".into())
    );
    assert_eq!(split_domain_user("alice"), ("".into(), "alice".into()));
}

/// Verifies HTTP 5985 config stays cleartext NTLM; 5986 enables TLS + session_id.
#[test]
fn winrm_config_port_tls_mapping() {
    let http = winrm_config_for_attempt(5985, Duration::from_millis(2500));
    assert_eq!(http.port, 5985);
    assert!(!http.use_tls);
    assert!(matches!(http.auth_method, AuthMethod::Ntlm));
    assert_eq!(http.connect_timeout_secs, 5);
    assert_eq!(http.operation_timeout_secs, 5);
    assert_eq!(http.max_envelope_size, 512_000);
    assert!(!http.session_id.is_nil());

    let https = winrm_config_for_attempt(5986, Duration::from_secs(10));
    assert_eq!(https.port, 5986);
    assert!(https.use_tls);
    assert!(https.accept_invalid_certs);
    assert!(!https.session_id.is_nil());
}

/// Verifies each attempt config gets a distinct SessionId (clone keeps the same).
#[test]
fn winrm_config_assigns_unique_session_id_per_attempt() {
    let a = winrm_config_for_attempt(5985, Duration::from_secs(30));
    let b = winrm_config_for_attempt(5985, Duration::from_secs(30));
    assert_ne!(a.session_id, b.session_id);
    assert!(!a.session_id.is_nil());
    assert!(!b.session_id.is_nil());
    let cloned = a.clone();
    assert_eq!(cloned.session_id, a.session_id);
}

/// Verifies command output formatting for stdout/stderr/empty cases.
#[test]
fn format_command_output_variants() {
    let both = format_command_output(&CommandOutput {
        stdout: b"out\n".to_vec(),
        stderr: b"err\n".to_vec(),
        exit_code: 1,
    });
    assert!(both.contains("out"));
    assert!(both.contains("stderr: err"));

    let empty = format_command_output(&CommandOutput {
        stdout: Vec::new(),
        stderr: Vec::new(),
        exit_code: 0,
    });
    assert_eq!(empty, "exit status: 0");
}
