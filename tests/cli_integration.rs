use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

fn brute_bin() -> &'static str {
    env!("CARGO_BIN_EXE_brute")
}

#[derive(Debug)]
struct TempHome {
    path: PathBuf,
}

impl TempHome {
    fn new(prefix: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("brute-{prefix}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).expect("failed to create temporary home");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run_with_home<I, S>(home: &TempHome, args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(brute_bin())
        .args(args)
        .env("HOME", home.path())
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run brute")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "expected command to succeed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn help_lists_primary_command_groups() {
    let home = TempHome::new("help");

    let output = run_with_home(&home, ["--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("commands"));
    assert!(stdout.contains("workspace"));
    assert!(stdout.contains("creds"));
    assert!(stdout.contains("ssh"));
}

#[test]
fn workspace_commands_use_isolated_database() {
    let home = TempHome::new("workspace");

    let output = run_with_home(&home, ["workspace", "current"]);
    assert_success(&output);
    assert!(stdout(&output).contains("default"));

    let output = run_with_home(&home, ["workspace", "new", "audit"]);
    assert_success(&output);
    assert!(stdout(&output).contains("created workspace: audit"));

    let output = run_with_home(&home, ["workspace", "use", "audit"]);
    assert_success(&output);
    assert!(stdout(&output).contains("current workspace: audit"));

    let output = run_with_home(&home, ["workspace", "list"]);
    assert_success(&output);
    let listing = stdout(&output);
    assert!(listing.contains("* audit"));
    assert!(listing.contains("  default"));

    let output = run_with_home(&home, ["workspace", "delete", "audit"]);
    assert_success(&output);
    assert!(stdout(&output).contains("deleted workspace: audit"));

    let output = run_with_home(&home, ["workspace", "current"]);
    assert_success(&output);
    assert!(stdout(&output).ends_with("default\n"));
}

#[test]
fn creds_list_renders_empty_table() {
    let home = TempHome::new("creds");

    let output = run_with_home(&home, ["creds", "list", "--conn-url"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("ID"));
    assert!(stdout.contains("PROTOCOL"));
    assert!(stdout.contains("CONN_URL"));
}

#[test]
fn zero_concurrency_options_are_rejected() {
    let home = TempHome::new("invalid-concurrency");

    let output = run_with_home(
        &home,
        [
            "http",
            "127.0.0.1",
            "-u",
            "admin",
            "-p",
            "secret",
            "--threads",
            "0",
        ],
    );

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("value must be at least 1"));
}

#[test]
fn scaffolded_protocol_reports_unimplemented_attempt() {
    let home = TempHome::new("stub-protocol");

    let output = run_with_home(
        &home,
        [
            "--no-color",
            "http",
            "127.0.0.1",
            "-u",
            "admin",
            "-p",
            "secret",
            "--threads",
            "1",
            "--target-threads",
            "1",
            "--timeout-ms",
            "1",
        ],
    );

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("admin:secret"));
    assert!(stdout.contains("http is scaffolded but not implemented in this build"));
}

#[test]
fn smb_help_exposes_shares_and_rejects_execute() {
    let home = TempHome::new("smb-help");

    let output = run_with_home(&home, ["smb", "--help"]);
    assert_success(&output);
    let help = stdout(&output);
    assert!(
        help.contains("--shares"),
        "smb help should document --shares:\n{help}"
    );
    // clap option lines look like "      --execute" / "  -x, --execute"; prose may
    // mention that -x is omitted, so only reject actual option definitions.
    let defines_execute_option = help.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with("-x,")
            || trimmed.starts_with("--execute")
            || trimmed.contains("-x, --execute")
    });
    assert!(
        !defines_execute_option,
        "smb help must not define -x/--execute as an option:\n{help}"
    );

    let rejected = run_with_home(
        &home,
        [
            "smb",
            "10.10.50.30",
            "-u",
            "admin",
            "-p",
            "secret",
            "-x",
            "whoami",
        ],
    );
    assert!(!rejected.status.success(), "smb must reject -x/--execute");
}

#[test]
fn smb_attempt_against_closed_port_is_not_unimplemented_stub() {
    let home = TempHome::new("smb-closed-port");

    // 127.0.0.1:1 is almost certainly closed; the shipped SMB module must
    // report a transport/error outcome rather than the old scaffold stub.
    let output = run_with_home(
        &home,
        [
            "--no-color",
            "smb",
            "127.0.0.1",
            "--port",
            "1",
            "-u",
            "admin",
            "-p",
            "not-a-real-password",
            "--threads",
            "1",
            "--target-threads",
            "1",
            "--timeout-ms",
            "500",
            "--retries",
            "0",
        ],
    );

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(
        !stdout.contains("scaffolded but not implemented"),
        "smb must not use the unimplemented stub:\n{stdout}"
    );
    assert!(
        stdout.contains("admin:not-a-real-password"),
        "expected credential columns in output:\n{stdout}"
    );
    assert!(
        stdout.contains("[!]") || stdout.contains("[-]"),
        "expected failure or error marker for closed port:\n{stdout}"
    );
}

#[test]
fn oracle_help_exposes_sql_query_execution() {
    let home = TempHome::new("oracle-help");

    let output = run_with_home(&home, ["oracle", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("--service-name <SERVICE_NAME>"));
    assert!(stdout.contains("--sid <SID>"));
    assert!(stdout.contains("select * from dual"));
}
