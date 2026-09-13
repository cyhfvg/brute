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
    assert!(stdout.contains("mcp"));
    assert!(stdout.contains("ssh"));
    assert!(stdout.contains("zookeeper"));
    assert!(stdout.contains("memcached"));
    assert!(stdout.contains("mongodb"));
    assert!(stdout.contains("elasticsearch"));
    assert!(stdout.contains("docker"));
    assert!(stdout.contains("snmp"));
    assert!(stdout.contains("activemq"));
    assert!(stdout.contains("rabbitmq"));
    assert!(stdout.contains("rsync"));
    assert!(stdout.contains("mssql"));
    assert!(stdout.contains("kafka"));
    assert!(stdout.contains("kibana"));
    assert!(stdout.contains("nfs"));
    assert!(stdout.contains("telnet"));
    assert!(stdout.contains("ldap"));
    assert!(stdout.contains("grafana"));
    assert!(stdout.contains("prometheus"));
    assert!(stdout.contains("jenkins"));
    assert!(stdout.contains("couchdb"));
    assert!(stdout.contains("clickhouse"));
    assert!(stdout.contains("neo4j"));
    assert!(stdout.contains("etcd"));
    assert!(stdout.contains("influxdb"));
    assert!(stdout.contains("solr"));
    assert!(stdout.contains("minio"));
    assert!(stdout.contains("nacos"));
    assert!(stdout.contains("nexus"));
    assert!(stdout.contains("jboss"));
    assert!(stdout.contains("druid"));
    assert!(stdout.contains("spark"));
    assert!(stdout.contains("hadoop"));
    assert!(stdout.contains("kubelet"));
    assert!(stdout.contains("gitlab"));
    assert!(stdout.contains("harbor"));
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

#[test]
fn zookeeper_help_exposes_command_execution() {
    let home = TempHome::new("zookeeper-help");

    let output = run_with_home(&home, ["zookeeper", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("ls /"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn memcached_help_exposes_command_execution() {
    let home = TempHome::new("memcached-help");

    let output = run_with_home(&home, ["memcached", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("stats"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn mongodb_help_exposes_command_execution() {
    let home = TempHome::new("mongodb-help");

    let output = run_with_home(&home, ["mongodb", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("listDatabases"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn elasticsearch_help_exposes_command_execution() {
    let home = TempHome::new("elasticsearch-help");

    let output = run_with_home(&home, ["elasticsearch", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("indices"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn docker_help_exposes_command_execution() {
    let home = TempHome::new("docker-help");

    let output = run_with_home(&home, ["docker", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("containers"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn snmp_help_exposes_command_execution() {
    let home = TempHome::new("snmp-help");

    let output = run_with_home(&home, ["snmp", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("sysName"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn activemq_help_exposes_command_execution() {
    let home = TempHome::new("activemq-help");

    let output = run_with_home(&home, ["activemq", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("hello"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn rabbitmq_help_exposes_command_execution() {
    let home = TempHome::new("rabbitmq-help");

    let output = run_with_home(&home, ["rabbitmq", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("brute"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn rsync_help_exposes_module_option() {
    let home = TempHome::new("rsync-help");

    let output = run_with_home(&home, ["rsync", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("--module"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn mssql_help_exposes_command_execution() {
    let home = TempHome::new("mssql-help");

    let output = run_with_home(&home, ["mssql", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("@@VERSION"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn kafka_help_exposes_command_execution() {
    let home = TempHome::new("kafka-help");

    let output = run_with_home(&home, ["kafka", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("metadata"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn kibana_help_exposes_command_execution() {
    let home = TempHome::new("kibana-help");

    let output = run_with_home(&home, ["kibana", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("status"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn nfs_help_exposes_command_execution() {
    let home = TempHome::new("nfs-help");

    let output = run_with_home(&home, ["nfs", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("dump"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn telnet_help_exposes_command_execution() {
    let home = TempHome::new("telnet-help");

    let output = run_with_home(&home, ["telnet", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("id"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn ldap_help_exposes_command_execution() {
    let home = TempHome::new("ldap-help");

    let output = run_with_home(&home, ["ldap", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("whoami"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn grafana_help_exposes_command_execution() {
    let home = TempHome::new("grafana-help");

    let output = run_with_home(&home, ["grafana", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("org"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn prometheus_help_exposes_command_execution() {
    let home = TempHome::new("prometheus-help");

    let output = run_with_home(&home, ["prometheus", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("query"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn jenkins_help_exposes_command_execution() {
    let home = TempHome::new("jenkins-help");

    let output = run_with_home(&home, ["jenkins", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("whoami"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn couchdb_help_exposes_command_execution() {
    let home = TempHome::new("couchdb-help");

    let output = run_with_home(&home, ["couchdb", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("dbs"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn clickhouse_help_exposes_command_execution() {
    let home = TempHome::new("clickhouse-help");

    let output = run_with_home(&home, ["clickhouse", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("version"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn neo4j_help_exposes_command_execution() {
    let home = TempHome::new("neo4j-help");

    let output = run_with_home(&home, ["neo4j", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("ping"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn etcd_help_exposes_command_execution() {
    let home = TempHome::new("etcd-help");

    let output = run_with_home(&home, ["etcd", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("version"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn influxdb_help_exposes_command_execution() {
    let home = TempHome::new("influxdb-help");

    let output = run_with_home(&home, ["influxdb", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("dbs"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn solr_help_exposes_command_execution() {
    let home = TempHome::new("solr-help");

    let output = run_with_home(&home, ["solr", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("cores"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn minio_help_exposes_command_execution() {
    let home = TempHome::new("minio-help");

    let output = run_with_home(&home, ["minio", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("buckets"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn nacos_help_exposes_command_execution() {
    let home = TempHome::new("nacos-help");

    let output = run_with_home(&home, ["nacos", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("namespaces"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn nexus_help_exposes_command_execution() {
    let home = TempHome::new("nexus-help");

    let output = run_with_home(&home, ["nexus", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("repos"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn jboss_help_exposes_command_execution() {
    let home = TempHome::new("jboss-help");

    let output = run_with_home(&home, ["jboss", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("version"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn druid_help_exposes_command_execution() {
    let home = TempHome::new("druid-help");

    let output = run_with_home(&home, ["druid", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("status"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn spark_help_exposes_command_execution() {
    let home = TempHome::new("spark-help");

    let output = run_with_home(&home, ["spark", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("json"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn hadoop_help_exposes_command_execution() {
    let home = TempHome::new("hadoop-help");

    let output = run_with_home(&home, ["hadoop", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("jmx"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn kubelet_help_exposes_command_execution() {
    let home = TempHome::new("kubelet-help");

    let output = run_with_home(&home, ["kubelet", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("pods"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn gitlab_help_exposes_command_execution() {
    let home = TempHome::new("gitlab-help");

    let output = run_with_home(&home, ["gitlab", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("user"));
    assert!(stdout.contains("192.168.5.10"));
}

#[test]
fn harbor_help_exposes_command_execution() {
    let home = TempHome::new("harbor-help");

    let output = run_with_home(&home, ["harbor", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("-x, --execute <COMMAND>"));
    assert!(stdout.contains("projects"));
    assert!(stdout.contains("192.168.5.10"));
}
#[test]
fn protocol_help_documents_cidr_targets() {
    let home = TempHome::new("cidr-help");

    let output = run_with_home(&home, ["tomcat", "--help"]);
    assert_success(&output);
    let help = stdout(&output);
    assert!(
        help.contains("CIDR"),
        "tomcat help should document CIDR TARGET expansion:\n{help}"
    );
}

#[test]
fn cidr_target_is_expanded_across_protocol_spray() {
    let home = TempHome::new("cidr-expand");

    // 127.0.0.1/30 -> 127.0.0.0..127.0.0.3. Port 1 is almost certainly closed,
    // so the spray should still emit one outcome line per expanded host.
    let output = run_with_home(
        &home,
        [
            "--no-color",
            "tomcat",
            "127.0.0.1/30",
            "--port",
            "1",
            "-u",
            "admin",
            "-p",
            "admin123",
            "--threads",
            "4",
            "--timeout-ms",
            "300",
            "--retries",
            "0",
        ],
    );

    assert_success(&output);
    let stdout = stdout(&output);
    for host in ["127.0.0.0", "127.0.0.1", "127.0.0.2", "127.0.0.3"] {
        assert!(
            stdout.contains(host),
            "expected expanded CIDR host {host} in spray output:\n{stdout}"
        );
    }
    assert!(
        !stdout.contains("127.0.0.1/30"),
        "CIDR token must be expanded, not used as a literal host:\n{stdout}"
    );
}

#[test]
fn ipv6_target_is_rejected() {
    let home = TempHome::new("ipv6-reject");

    let output = run_with_home(
        &home,
        [
            "--no-color",
            "tomcat",
            "2001:db8::1",
            "-u",
            "admin",
            "-p",
            "admin123",
        ],
    );

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("IPv6 targets are not supported"),
        "expected IPv6 rejection on stderr:\n{stderr}"
    );
}
