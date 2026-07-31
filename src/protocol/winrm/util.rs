//! Pure helpers for WinRM config, payload resolution, and formatting.

use std::{net::TcpStream, path::Path, time::Duration};

use winrm_rs::{AuthMethod, CommandOutput, WinrmConfig, encode_powershell_command};

use crate::cli::WinrmShellType;

/// Builds WinRM client configuration for one attempt.
///
/// Uses [`WinrmConfig::default`] so fork-provided fields stay correct, including
/// a stable Microsoft `session_id` (required for fast sealed PSRP on many hosts).
///
/// # Parameters
///
/// - `port`: Target WinRM port; `5986` enables HTTPS with invalid-cert acceptance for labs.
/// - `timeout`: Attempt timeout used for connect and operation seconds (minimum 1s).
///
/// # Returns
///
/// A [`WinrmConfig`] with NTLM auth, roomy envelope size, and timeouts from `timeout`.
/// Each call gets a fresh `session_id` via `Default`.
///
/// # Errors
///
/// This function does not fail.
///
/// # Examples
///
/// ```ignore
/// let config = winrm_config_for_attempt(5985, Duration::from_millis(5000));
/// assert_eq!(config.port, 5985);
/// assert!(!config.use_tls);
/// assert!(!config.session_id.is_nil());
/// ```
pub fn winrm_config_for_attempt(port: u16, timeout: Duration) -> WinrmConfig {
    // PSRP envelopes are larger than simple cmd shells; keep a roomy max size.
    // `..Default` preserves session_id and other fork defaults (SessionId SOAP header).
    let secs = timeout.as_secs().max(1).max(5);
    let use_tls = port == 5986;
    WinrmConfig {
        port,
        use_tls,
        // Lab / self-signed HTTPS WinRM listeners are common on 5986.
        accept_invalid_certs: use_tls,
        connect_timeout_secs: secs,
        operation_timeout_secs: secs,
        auth_method: AuthMethod::Ntlm,
        max_retries: 0,
        max_envelope_size: 512_000,
        ..WinrmConfig::default()
    }
}

/// Resolves a `-x` value into the remote payload body.
///
/// When `raw` starts with `@`, the remainder is treated as a local filesystem path
/// and the file contents are returned. Otherwise the string is used as-is.
///
/// # Parameters
///
/// - `raw`: CLI `-x` / `--execute` value.
///
/// # Returns
///
/// The command/script body to send to the remote shell.
///
/// # Errors
///
/// Returns an error string when `@path` is empty, the path is missing, or the file
/// cannot be read.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(resolve_execute_payload("whoami").unwrap(), "whoami");
/// let body = resolve_execute_payload("@./script.ps1").unwrap();
/// ```
pub fn resolve_execute_payload(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if let Some(path) = trimmed.strip_prefix('@') {
        let path = path.trim();
        if path.is_empty() {
            return Err("winrm -x @path is missing a file path".to_string());
        }
        std::fs::read_to_string(Path::new(path))
            .map_err(|err| format!("winrm failed to read execute script {path:?}: {err}"))
    } else {
        Ok(raw.to_string())
    }
}

/// Builds the remote process name and arguments for a shell type + payload.
///
/// For `cmd`, invokes `cmd.exe /c <payload>`.
/// For `powershell`, documents the EncodedCommand shape used by legacy WinRS
/// paths; the shipped runtime uses [`winrm_rs::WinrmClient::run_powershell`] (PSRP).
///
/// # Parameters
///
/// - `shell_type`: Selected remote shell.
/// - `payload`: Command string or script body (already resolved from `@file` when applicable).
///
/// # Returns
///
/// `(executable, args)` suitable for WinRM `Execute` / tests.
///
/// # Errors
///
/// This function does not fail.
///
/// # Examples
///
/// ```ignore
/// let (exe, args) = build_remote_invocation(WinrmShellType::Cmd, "whoami");
/// assert_eq!(exe, "cmd.exe");
/// assert_eq!(args[0], "/c");
/// ```
pub fn build_remote_invocation(shell_type: WinrmShellType, payload: &str) -> (String, Vec<String>) {
    match shell_type {
        WinrmShellType::Cmd => (
            "cmd.exe".to_string(),
            vec!["/c".to_string(), payload.to_string()],
        ),
        WinrmShellType::Powershell => {
            let encoded = encode_powershell_command(payload);
            (
                "powershell.exe".to_string(),
                vec![
                    "-NoProfile".to_string(),
                    "-NonInteractive".to_string(),
                    "-ExecutionPolicy".to_string(),
                    "Bypass".to_string(),
                    "-EncodedCommand".to_string(),
                    encoded,
                ],
            )
        }
    }
}

/// Returns true when the PowerShell argv list includes execution-policy bypass flags.
///
/// # Parameters
///
/// - `args`: Argument list produced by [`build_remote_invocation`] for powershell.
///
/// # Returns
///
/// `true` when `-ExecutionPolicy Bypass` (case-insensitive token match) is present.
///
/// # Errors
///
/// This function does not fail.
///
/// # Examples
///
/// ```ignore
/// let (_, args) = build_remote_invocation(WinrmShellType::Powershell, "Get-Date");
/// assert!(powershell_args_bypass_execution_policy(&args));
/// ```
pub fn powershell_args_bypass_execution_policy(args: &[String]) -> bool {
    let mut saw_flag = false;
    for arg in args {
        if saw_flag {
            return arg.eq_ignore_ascii_case("Bypass");
        }
        if arg.eq_ignore_ascii_case("-ExecutionPolicy") {
            saw_flag = true;
        }
    }
    false
}

/// Formats remote command output for NetExec-style follow-up lines.
///
/// # Parameters
///
/// - `output`: Stdout/stderr/exit from the WinRM client.
///
/// # Returns
///
/// Human-readable multi-line text suitable for post-auth command body lines.
///
/// # Errors
///
/// This function does not fail.
///
/// # Examples
///
/// ```ignore
/// let text = format_command_output(&CommandOutput {
///     stdout: b"ok".to_vec(),
///     stderr: Vec::new(),
///     exit_code: 0,
/// });
/// assert!(text.contains("ok"));
/// ```
pub fn format_command_output(output: &CommandOutput) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => format!("exit status: {}", output.exit_code),
        (false, true) => stdout,
        (true, false) => format!("stderr: {stderr}"),
        (false, false) => format!("{stdout}\nstderr: {stderr}"),
    }
}

/// Splits `DOMAIN\\user` or `user@domain` into `(domain, user)`.
///
/// # Parameters
///
/// - `username`: Raw username field from credentials.
///
/// # Returns
///
/// `(domain, user)` where `domain` is empty for unqualified names.
///
/// # Errors
///
/// This function does not fail.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(split_domain_user(r"LAB\alice"), ("LAB".into(), "alice".into()));
/// assert_eq!(split_domain_user("alice@lab.local"), ("lab.local".into(), "alice".into()));
/// assert_eq!(split_domain_user("alice"), ("".into(), "alice".into()));
/// ```
pub fn split_domain_user(username: &str) -> (String, String) {
    if let Some((domain, user)) = username.split_once('\\') {
        return (domain.to_string(), user.to_string());
    }
    if let Some((user, domain)) = username.split_once('@') {
        return (domain.to_string(), user.to_string());
    }
    (String::new(), username.to_string())
}

/// Best-effort TCP probe of the WinRM port before credential sprays.
///
/// # Parameters
///
/// - `host`: Target hostname or IP.
/// - `port`: WinRM port.
/// - `timeout`: Connect timeout.
///
/// # Returns
///
/// [`Some`] readiness message when TCP connect succeeds; [`None`] otherwise.
pub(crate) fn probe_winrm_port(host: &str, port: u16, timeout: Duration) -> Option<String> {
    let addr = format!("{host}:{port}");
    match TcpStream::connect_timeout(
        &addr.parse().ok().or_else(|| {
            use std::net::ToSocketAddrs;
            addr.to_socket_addrs().ok()?.next()
        })?,
        timeout,
    ) {
        Ok(_) => Some(format!("winrm port open on {host}:{port}")),
        Err(_) => None,
    }
}
