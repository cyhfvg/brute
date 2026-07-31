//! Structural policy checks for WinRM dependency and module wiring.

/// Policy: WinRM uses git cyhfvg/winrm-rs; no path brute-winrm/psrp; no [patch].
#[test]
fn cargo_toml_uses_git_winrm_rs_without_patch_or_path_crates() {
    let cargo = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
    let has_patch_table = cargo.lines().any(|l| l.trim() == "[patch.crates-io]");
    assert!(
        !has_patch_table,
        "root Cargo.toml must not declare a [patch.crates-io] table"
    );
    let has_path_brute_winrm = cargo.lines().any(|l| {
        let t = l.trim();
        t.starts_with("brute-winrm ") || t.starts_with("brute-winrm=")
    });
    let has_path_brute_psrp = cargo.lines().any(|l| {
        let t = l.trim();
        t.starts_with("brute-psrp ") || t.starts_with("brute-psrp=")
    });
    assert!(
        !has_path_brute_winrm && !has_path_brute_psrp,
        "root Cargo.toml must not depend on brute-winrm / brute-psrp path crates"
    );
    assert!(
        cargo.contains("winrm-rs") && cargo.contains("cyhfvg/winrm-rs"),
        "root Cargo.toml must depend on git cyhfvg/winrm-rs"
    );
}

/// Lockfile must pin the git winrm-rs used for SessionId/PSRP fixes.
#[test]
fn cargo_lock_pins_cyhfvg_winrm_rs_git() {
    let lock = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock"));
    assert!(
        lock.contains("git+https://github.com/cyhfvg/winrm-rs"),
        "Cargo.lock must record cyhfvg/winrm-rs git source"
    );
    assert!(
        !lock.contains("name = \"brute-winrm\"") && !lock.contains("name = \"brute-psrp\""),
        "Cargo.lock must not retain brute-winrm / brute-psrp packages"
    );
}

/// Module layout: winrm is a directory under protocol, not a single huge file.
#[test]
fn winrm_is_split_into_submodules() {
    let root = env!("CARGO_MANIFEST_DIR");
    for name in ["mod.rs", "attempt.rs", "probe.rs", "classify.rs", "util.rs"] {
        let path = format!("{root}/src/protocol/winrm/{name}");
        assert!(
            std::path::Path::new(&path).is_file(),
            "expected winrm submodule {path}"
        );
        let lines = std::fs::read_to_string(&path)
            .expect("read")
            .lines()
            .count();
        assert!(lines <= 600, "{path} has {lines} lines (limit 600)");
    }
    assert!(
        !std::path::Path::new(&format!("{root}/src/protocol/winrm.rs")).exists(),
        "monolithic src/protocol/winrm.rs must be removed"
    );
}

/// Shipped powershell path uses run_powershell (PSRP).
#[test]
fn powershell_execute_path_uses_run_powershell() {
    let attempt = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/protocol/winrm/attempt.rs"
    ));
    assert!(attempt.contains("run_powershell"));
    assert!(attempt.contains("unwrap_or(WinrmShellType::Powershell)"));
}
