//! Integration tests for public WinRM probe plan and status banners.

use brute::cli::WinrmShellType;
use brute::protocol::winrm::{
    ShellProbe, ShellProbePlan, cmd_status_after_auth_proven, format_shell_status_banner,
    shell_access_banner, shell_probe_plan,
};

/// Banner mapping: probed-only; required access/denied forms.
#[test]
fn format_shell_status_banner_probed_only() {
    assert_eq!(
        format_shell_status_banner(Some(true), None),
        "Windows - Shell access! (powershell)"
    );
    assert_eq!(
        format_shell_status_banner(None, Some(true)),
        "Windows - Shell access! (cmd)"
    );
    let ps_deny_cmd_ok = format_shell_status_banner(Some(false), Some(true));
    assert!(
        ps_deny_cmd_ok.starts_with("Windows - Shell access! (cmd)"),
        "{ps_deny_cmd_ok}"
    );
    assert!(
        ps_deny_cmd_ok.contains("powershell denied"),
        "{ps_deny_cmd_ok}"
    );
    assert!(
        !ps_deny_cmd_ok.contains("Shell access denied!"),
        "{ps_deny_cmd_ok}"
    );

    let only_ps = format_shell_status_banner(Some(true), None);
    assert!(!only_ps.contains("cmd"), "{only_ps}");

    let both_deny = format_shell_status_banner(Some(false), Some(false));
    assert!(both_deny.contains("Shell access denied!"), "{both_deny}");
    assert!(
        both_deny.contains("powershell") && both_deny.contains("cmd"),
        "{both_deny}"
    );

    let only_ps_deny = format_shell_status_banner(Some(false), None);
    assert_eq!(only_ps_deny, "Windows - Shell access denied! (powershell)");

    let both_ok = format_shell_status_banner(Some(true), Some(true));
    assert!(both_ok.contains("Shell access!"), "{both_ok}");
    assert!(
        both_ok.contains("powershell") && both_ok.contains("cmd"),
        "{both_ok}"
    );
}

/// Probe plan: omitted → auto serial; explicit → only that shell.
#[test]
fn shell_probe_plan_auto_vs_explicit() {
    assert_eq!(shell_probe_plan(None), ShellProbePlan::AutoSerial);
    assert_eq!(
        shell_probe_plan(Some(WinrmShellType::Powershell)),
        ShellProbePlan::Only(WinrmShellType::Powershell)
    );
    assert_eq!(
        shell_probe_plan(Some(WinrmShellType::Cmd)),
        ShellProbePlan::Only(WinrmShellType::Cmd)
    );
}

/// After auth proven, follow-up cmd AuthFailed/Error must leave cmd unprobed.
#[test]
fn after_auth_proven_cmd_authfailed_keeps_success_banner() {
    assert_eq!(
        cmd_status_after_auth_proven(ShellProbe::Available),
        Some(true)
    );
    assert_eq!(
        cmd_status_after_auth_proven(ShellProbe::Denied),
        Some(false)
    );
    assert_eq!(
        cmd_status_after_auth_proven(ShellProbe::AuthFailed("odd".into())),
        None
    );
    assert_eq!(
        cmd_status_after_auth_proven(ShellProbe::Error("timeout".into())),
        None
    );

    let banner = format_shell_status_banner(Some(false), None);
    assert!(
        banner.contains("Shell access denied!"),
        "expected denial banner, got {banner}"
    );
    assert!(banner.contains("powershell"), "{banner}");
    assert!(
        !banner.contains("cmd"),
        "unprobed cmd must not appear: {banner}"
    );
}

/// Legacy dual-bool wrapper still delegates to format_shell_status_banner.
#[test]
fn shell_access_banner_delegates() {
    let msg = shell_access_banner(true, false);
    assert!(msg.contains("cmd"), "{msg}");
    assert!(msg.contains("powershell denied"), "{msg}");
}

/// Production sources use ordered serial short-circuit (structural).
#[test]
fn production_uses_ordered_serial_not_always_dual() {
    let attempt = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/protocol/winrm/attempt.rs"
    ));
    assert!(attempt.contains("ShellProbePlan::AutoSerial"));
    assert!(attempt.contains("short-circuit"));
    assert!(attempt.contains("cmd_status_after_auth_proven"));
    assert!(attempt.contains("unwrap_or(WinrmShellType::Powershell)"));
}
