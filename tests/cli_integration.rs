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
    assert!(
        stdout.contains("Author: cyhfvg <https://github.com/cyhfvg/brute>"),
        "root --help must show author info\nstdout:\n{stdout}"
    );
}

#[test]
fn default_database_lives_under_config_brute() {
    let home = TempHome::new("config-db");

    let output = run_with_home(&home, ["workspace", "current"]);
    assert_success(&output);

    let expected = home.path().join(".config/brute/brute.db");
    assert!(
        expected.is_file(),
        "expected default database at {}\nstdout:\n{}\nstderr:\n{}",
        expected.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !home.path().join(".brute/brute.db").exists(),
        "legacy ~/.brute/brute.db must not be created by default"
    );
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
fn http_help_exposes_path_protocol_and_is_implemented() {
    let home = TempHome::new("http-help");

    let output = run_with_home(&home, ["http", "--help"]);
    assert_success(&output);
    let help = stdout(&output);
    assert!(
        help.contains("--path"),
        "http help should document --path:\n{help}"
    );
    assert!(
        help.contains("--protocol"),
        "http help should document --protocol:\n{help}"
    );
    assert!(
        help.contains("http") && help.contains("https"),
        "http help should list http/https scheme values:\n{help}"
    );
    assert!(
        !help.to_ascii_lowercase().contains("not implemented")
            && !help.to_ascii_lowercase().contains("scaffolded"),
        "http help must not describe the module as unimplemented:\n{help}"
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
        "http help must not define -x/--execute as an option:\n{help}"
    );
}

#[test]
fn http_attempt_against_closed_port_is_not_unimplemented_stub() {
    let home = TempHome::new("http-closed-port");

    // 127.0.0.1:1 is almost certainly closed; the shipped HTTP Basic module must
    // report a transport/error outcome rather than the old scaffold stub.
    let output = run_with_home(
        &home,
        [
            "--no-color",
            "http",
            "127.0.0.1",
            "--port",
            "1",
            "-u",
            "admin",
            "-p",
            "not-a-real-password",
            "--threads",
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
        "http must not use the unimplemented stub:\n{stdout}"
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
fn http_https_scheme_against_closed_port_is_not_unimplemented_stub() {
    let home = TempHome::new("http-https-closed-port");

    let output = run_with_home(
        &home,
        [
            "--no-color",
            "http",
            "127.0.0.1",
            "--port",
            "1",
            "--protocol",
            "https",
            "-u",
            "admin",
            "-p",
            "not-a-real-password",
            "--threads",
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
        "http --protocol https must not use the unimplemented stub:\n{stdout}"
    );
    assert!(
        stdout.contains("admin:not-a-real-password"),
        "expected credential columns in output:\n{stdout}"
    );
    assert!(
        stdout.contains("[!]") || stdout.contains("[-]"),
        "expected failure or error marker for closed HTTPS port:\n{stdout}"
    );
    // Error text from reqwest typically embeds the attempted URL with https://
    assert!(
        stdout.contains("https://") || stdout.contains("http request failed"),
        "expected https request path evidence:\n{stdout}"
    );
}

#[test]
fn http_rejects_invalid_protocol_scheme() {
    let home = TempHome::new("http-bad-protocol");

    let output = run_with_home(
        &home,
        [
            "http",
            "127.0.0.1",
            "-u",
            "admin",
            "-p",
            "secret",
            "--protocol",
            "ftp",
        ],
    );

    assert!(!output.status.success());
    let err = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        err.to_ascii_lowercase().contains("possible values")
            || err.to_ascii_lowercase().contains("invalid")
            || err.contains("http")
            || err.contains("https"),
        "invalid --protocol should be rejected by clap:\n{err}"
    );
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
fn rdp_help_documents_login_and_rejects_execute() {
    let home = TempHome::new("rdp-help");

    let output = run_with_home(&home, ["rdp", "--help"]);
    assert_success(&output);
    let help = stdout(&output);
    assert!(
        help.contains("RDP") || help.to_ascii_lowercase().contains("rdp"),
        "rdp help should mention RDP:\n{help}"
    );
    assert!(
        help.contains("--threads"),
        "rdp help must document --threads:\n{help}"
    );
    assert!(
        !help.contains("--target-threads"),
        "rdp help must not list removed --target-threads:\n{help}"
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
        "rdp help must not define -x/--execute as an option:\n{help}"
    );

    let rejected = run_with_home(
        &home,
        [
            "rdp",
            "10.10.50.10",
            "-u",
            "admin",
            "-p",
            "secret",
            "-x",
            "whoami",
        ],
    );
    assert!(!rejected.status.success(), "rdp must reject -x/--execute");
}

#[test]
fn rdp_accepts_threads_flag_and_rejects_target_threads() {
    let home = TempHome::new("rdp-threads-parse");

    // Closed port: prove the shipped CLI accepts --threads on the RDP path
    // and reaches the real module (not a clap parse error / stub).
    let output = run_with_home(
        &home,
        [
            "--no-color",
            "rdp",
            "127.0.0.1",
            "--port",
            "1",
            "-u",
            "admin",
            "-p",
            "not-a-real-password",
            "--threads",
            "4",
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
        "rdp must not use the unimplemented stub:\n{stdout}"
    );
    assert!(
        stdout.contains("admin:not-a-real-password"),
        "expected credential attempt output:\n{stdout}"
    );

    let rejected = run_with_home(
        &home,
        [
            "rdp",
            "127.0.0.1",
            "-u",
            "admin",
            "-p",
            "secret",
            "--target-threads",
            "2",
        ],
    );
    assert!(
        !rejected.status.success(),
        "rdp must reject removed --target-threads"
    );
}

#[test]
fn rdp_attempt_against_closed_port_is_not_unimplemented_stub() {
    let home = TempHome::new("rdp-closed-port");

    // 127.0.0.1:1 is almost certainly closed; the shipped RDP module must
    // report a transport/error outcome rather than the old scaffold stub.
    let output = run_with_home(
        &home,
        [
            "--no-color",
            "rdp",
            "127.0.0.1",
            "--port",
            "1",
            "-u",
            "admin",
            "-p",
            "not-a-real-password",
            "--threads",
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
        "rdp must not use the unimplemented stub:\n{stdout}"
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
