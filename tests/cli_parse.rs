//! CLI parsing unit tests for public clap types (top-level and protocol flags).

use clap::Parser;

use brute::cli::{Cli, Command, HttpUrlScheme, Protocol, ProtocolArgs, WinrmShellType};

/// Verifies that Oracle Service Name and `-x` query arguments are parsed into the execution options.
#[test]
fn parses_oracle_service_name_and_sql_query_execution_arguments() {
    let cli = Cli::try_parse_from([
        "brute",
        "oracle",
        "db.internal",
        "-u",
        "system",
        "-p",
        "oracle",
        "--service-name",
        "ORCLPDB1",
        "-x",
        "select * from dual",
    ])
    .expect("oracle service name arguments should parse");

    let Command::Protocol(ProtocolArgs::Oracle(args)) = cli.command else {
        panic!("expected oracle protocol arguments");
    };
    assert_eq!(args.execute.common.targets, ["db.internal"]);
    assert_eq!(args.service_name, ["ORCLPDB1"]);
    assert!(args.sid.is_empty());
    assert_eq!(args.execute.execute.as_deref(), Some("select * from dual"));
    assert_eq!(ProtocolArgs::Oracle(args).protocol(), Protocol::Oracle);
}

/// Verifies that multiple Oracle Service Names are accepted for enumeration.
#[test]
fn parses_multiple_oracle_service_names() {
    let cli = Cli::try_parse_from([
        "brute",
        "oracle",
        "db.internal",
        "-u",
        "system",
        "-p",
        "oracle",
        "--service-name",
        "XE",
        "ORCL",
        "services.txt",
    ])
    .expect("multiple oracle service names should parse");

    let Command::Protocol(ProtocolArgs::Oracle(args)) = cli.command else {
        panic!("expected oracle protocol arguments");
    };
    assert_eq!(args.service_name, ["XE", "ORCL", "services.txt"]);
    assert!(args.sid.is_empty());
}

/// Verifies that Oracle SID arguments are accepted without a Service Name.
#[test]
fn parses_oracle_sid_argument() {
    let cli = Cli::try_parse_from([
        "brute",
        "oracle",
        "db.internal",
        "-u",
        "system",
        "-p",
        "oracle",
        "--sid",
        "ORCL",
    ])
    .expect("oracle SID arguments should parse");

    let Command::Protocol(ProtocolArgs::Oracle(args)) = cli.command else {
        panic!("expected oracle protocol arguments");
    };
    assert!(args.service_name.is_empty());
    assert_eq!(args.sid, ["ORCL"]);
}

/// Verifies that multiple Oracle SIDs are accepted for enumeration.
#[test]
fn parses_multiple_oracle_sids() {
    let cli = Cli::try_parse_from([
        "brute",
        "oracle",
        "db.internal",
        "-u",
        "system",
        "-p",
        "oracle",
        "--sid",
        "XE",
        "ORCL",
        "sids.txt",
    ])
    .expect("multiple oracle SIDs should parse");

    let Command::Protocol(ProtocolArgs::Oracle(args)) = cli.command else {
        panic!("expected oracle protocol arguments");
    };
    assert!(args.service_name.is_empty());
    assert_eq!(args.sid, ["XE", "ORCL", "sids.txt"]);
}

/// Verifies that Oracle Service Name and SID cannot be supplied together.
#[test]
fn rejects_oracle_service_name_and_sid_together() {
    let result = Cli::try_parse_from([
        "brute",
        "oracle",
        "db.internal",
        "-u",
        "system",
        "-p",
        "oracle",
        "--service-name",
        "XE",
        "--sid",
        "ORCL",
    ]);

    assert!(result.is_err());
}

/// Verifies that SMB parses `--shares` and does not accept `-x` / `--execute`.
#[test]
fn parses_smb_shares_flag_and_rejects_execute() {
    let cli = Cli::try_parse_from([
        "brute",
        "smb",
        "192.168.10.5",
        "-u",
        "admin",
        "-p",
        "secret",
        "--port",
        "445",
        "--shares",
    ])
    .expect("smb --shares should parse");

    let Command::Protocol(ProtocolArgs::Smb(args)) = cli.command else {
        panic!("expected smb protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.10.5"]);
    assert_eq!(args.common.port, Some(445));
    assert!(args.shares);
    assert!(ProtocolArgs::Smb(args.clone()).shares());
    assert_eq!(ProtocolArgs::Smb(args).execute(), None);

    let with_execute = Cli::try_parse_from([
        "brute",
        "smb",
        "192.168.10.5",
        "-u",
        "admin",
        "-p",
        "secret",
        "-x",
        "whoami",
    ]);
    assert!(
        with_execute.is_err(),
        "smb must not accept -x/--execute: {with_execute:?}"
    );
}

/// Verifies RDP accepts `--threads` and rejects removed `--target-threads` / `-x`.
#[test]
fn parses_rdp_threads_and_rejects_target_threads() {
    let with_threads = Cli::try_parse_from([
        "brute",
        "rdp",
        "192.168.10.5",
        "-u",
        "admin",
        "-p",
        "secret",
        "--threads",
        "8",
    ])
    .expect("rdp --threads should parse");
    let Command::Protocol(ProtocolArgs::Rdp(common)) = with_threads.command else {
        panic!("expected rdp protocol arguments");
    };
    assert_eq!(common.threads, 8);
    assert_eq!(ProtocolArgs::Rdp(common).execute(), None);

    let with_target_threads = Cli::try_parse_from([
        "brute",
        "rdp",
        "192.168.10.5",
        "-u",
        "admin",
        "-p",
        "secret",
        "--target-threads",
        "4",
    ]);
    assert!(
        with_target_threads.is_err(),
        "rdp must not accept --target-threads: {with_target_threads:?}"
    );

    let with_execute = Cli::try_parse_from([
        "brute",
        "rdp",
        "192.168.10.5",
        "-u",
        "admin",
        "-p",
        "secret",
        "-x",
        "whoami",
    ]);
    assert!(
        with_execute.is_err(),
        "rdp must not accept -x/--execute: {with_execute:?}"
    );
}

/// Verifies WinRM parses `-x`, omits `--shell-type` as None (default PS at execute), and accepts explicit values.
#[test]
fn parses_winrm_execute_and_shell_type() {
    let default_shell = Cli::try_parse_from([
        "brute",
        "winrm",
        "192.168.10.5",
        "-u",
        "admin",
        "-p",
        "secret",
        "-x",
        "whoami",
    ])
    .expect("winrm -x should parse");
    let Command::Protocol(ProtocolArgs::Winrm(args)) = default_shell.command else {
        panic!("expected winrm protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.10.5"]);
    assert_eq!(args.execute.as_deref(), Some("whoami"));
    // Omitted flag must stay None so no-x can auto-serial probe; -x defaults later.
    assert_eq!(args.shell_type, None);
    assert_eq!(WinrmShellType::default(), WinrmShellType::Powershell);
    assert_eq!(ProtocolArgs::Winrm(args.clone()).execute(), Some("whoami"));
    assert_eq!(ProtocolArgs::Winrm(args).shell_type(), None);

    let powershell = Cli::try_parse_from([
        "brute",
        "winrm",
        "192.168.10.5",
        "-u",
        "admin",
        "-p",
        "secret",
        "--shell-type",
        "powershell",
        "-x",
        "@script.ps1",
    ])
    .expect("winrm powershell shell-type should parse");
    let Command::Protocol(ProtocolArgs::Winrm(args)) = powershell.command else {
        panic!("expected winrm protocol arguments");
    };
    assert_eq!(args.shell_type, Some(WinrmShellType::Powershell));
    assert_eq!(args.execute.as_deref(), Some("@script.ps1"));
    assert_eq!(
        ProtocolArgs::Winrm(args).shell_type(),
        Some(WinrmShellType::Powershell)
    );

    let cmd_shell = Cli::try_parse_from([
        "brute",
        "winrm",
        "192.168.10.5",
        "-u",
        "admin",
        "-p",
        "secret",
        "--shell-type",
        "cmd",
        "-x",
        "@script.bat",
    ])
    .expect("winrm cmd shell-type should parse");
    let Command::Protocol(ProtocolArgs::Winrm(args)) = cmd_shell.command else {
        panic!("expected winrm protocol arguments");
    };
    assert_eq!(args.shell_type, Some(WinrmShellType::Cmd));
    assert_eq!(args.execute.as_deref(), Some("@script.bat"));

    let no_x_auto = Cli::try_parse_from([
        "brute",
        "winrm",
        "192.168.10.5",
        "-u",
        "admin",
        "-p",
        "secret",
    ])
    .expect("winrm without -x should parse");
    let Command::Protocol(ProtocolArgs::Winrm(args)) = no_x_auto.command else {
        panic!("expected winrm");
    };
    assert_eq!(args.shell_type, None);
    assert_eq!(args.execute, None);
}

/// Verifies protocol default service ports used when `--port` is omitted.
#[test]
fn http_default_port_is_80() {
    assert_eq!(Protocol::Http.default_port(), 80);
    assert_eq!(Protocol::Tomcat.default_port(), 8080);
}

/// Verifies HTTP `--protocol` defaults to http and accepts https.
#[test]
fn parses_http_url_scheme_protocol_flag() {
    let default_http = Cli::try_parse_from([
        "brute",
        "http",
        "192.168.10.5",
        "-u",
        "admin",
        "-p",
        "secret",
    ])
    .expect("http without --protocol should parse");
    let Command::Protocol(ProtocolArgs::Http(args)) = default_http.command else {
        panic!("expected http protocol arguments");
    };
    assert_eq!(args.url_scheme, HttpUrlScheme::Http);
    assert_eq!(args.path, "/");

    let https = Cli::try_parse_from([
        "brute",
        "http",
        "192.168.10.5",
        "-u",
        "admin",
        "-p",
        "secret",
        "--protocol",
        "https",
        "--path",
        "/manager/html",
    ])
    .expect("http --protocol https should parse");
    let Command::Protocol(ProtocolArgs::Http(args)) = https.command else {
        panic!("expected http protocol arguments");
    };
    assert_eq!(args.url_scheme, HttpUrlScheme::Https);
    assert_eq!(args.path, "/manager/html");
    assert_eq!(args.url_scheme.as_str(), "https");

    let explicit_http = Cli::try_parse_from([
        "brute",
        "http",
        "192.168.10.5",
        "-u",
        "admin",
        "-p",
        "secret",
        "--protocol",
        "http",
    ])
    .expect("http --protocol http should parse");
    let Command::Protocol(ProtocolArgs::Http(args)) = explicit_http.command else {
        panic!("expected http");
    };
    assert_eq!(args.url_scheme, HttpUrlScheme::Http);
}

/// Verifies invalid HTTP `--protocol` values are rejected by clap.
#[test]
fn rejects_invalid_http_url_scheme() {
    let result = Cli::try_parse_from([
        "brute",
        "http",
        "192.168.10.5",
        "-u",
        "admin",
        "-p",
        "secret",
        "--protocol",
        "ftp",
    ]);
    assert!(result.is_err(), "invalid --protocol value must be rejected");
}

/// Verifies invalid `--shell-type` values are rejected.
#[test]
fn rejects_invalid_winrm_shell_type() {
    let result = Cli::try_parse_from([
        "brute",
        "winrm",
        "192.168.10.5",
        "-u",
        "admin",
        "-p",
        "secret",
        "--shell-type",
        "bash",
    ]);
    assert!(
        result.is_err(),
        "invalid shell-type must be rejected: {result:?}"
    );
}

/// Verifies top-level `--proxy` accepts http/socks5 URLs with and without credentials.
#[test]
fn parses_top_level_proxy_url() {
    use brute::proxy::ProxyScheme;

    let socks = Cli::try_parse_from([
        "brute",
        "--proxy",
        "socks5://sockproxyuser:sockproxypassword@127.0.0.1:1080",
        "ssh",
        "192.168.10.5",
        "-u",
        "admin",
        "-p",
        "secret",
    ])
    .expect("top-level socks5 proxy should parse");
    let proxy = socks.proxy.expect("proxy must be set on Cli");
    assert_eq!(proxy.scheme, ProxyScheme::Socks5);
    assert_eq!(proxy.host, "127.0.0.1");
    assert_eq!(proxy.port, 1080);
    assert_eq!(proxy.username.as_deref(), Some("sockproxyuser"));
    assert_eq!(proxy.password.as_deref(), Some("sockproxypassword"));
    assert!(
        matches!(socks.command, Command::Protocol(ProtocolArgs::Ssh(_))),
        "subcommand must still parse"
    );

    let http = Cli::try_parse_from([
        "brute",
        "--proxy",
        "http://127.0.0.1:8080",
        "http",
        "192.168.10.5",
        "-u",
        "admin",
        "-p",
        "secret",
    ])
    .expect("top-level http proxy without credentials should parse");
    let proxy = http.proxy.expect("proxy must be set on Cli");
    assert_eq!(proxy.scheme, ProxyScheme::Http);
    assert!(proxy.username.is_none());
    assert!(proxy.password.is_none());
}

/// Verifies unsupported or malformed top-level `--proxy` values are rejected by clap.
#[test]
fn rejects_invalid_top_level_proxy_url() {
    let bad_scheme = Cli::try_parse_from([
        "brute",
        "--proxy",
        "ftp://127.0.0.1:21",
        "ssh",
        "192.168.10.5",
        "-u",
        "admin",
        "-p",
        "secret",
    ]);
    assert!(bad_scheme.is_err(), "unsupported scheme must be rejected");

    let missing_port = Cli::try_parse_from([
        "brute",
        "--proxy",
        "socks5://127.0.0.1",
        "ssh",
        "192.168.10.5",
        "-u",
        "admin",
        "-p",
        "secret",
    ]);
    assert!(missing_port.is_err(), "proxy without port must be rejected");
}

/// Verifies `--proxy` is not accepted as a protocol-subcommand flag.
#[test]
fn rejects_proxy_flag_under_protocol_subcommand() {
    let result = Cli::try_parse_from([
        "brute",
        "ssh",
        "192.168.10.5",
        "-u",
        "admin",
        "-p",
        "secret",
        "--proxy",
        "socks5://127.0.0.1:1080",
    ]);
    assert!(
        result.is_err(),
        "--proxy must be top-level only, not under protocol subcommands: {result:?}"
    );
}

/// Verifies `brute mcp` is accepted as a top-level command.
#[test]
fn parses_mcp_stdio_command() {
    let cli = Cli::try_parse_from(["brute", "mcp"]).expect("mcp command should parse");
    assert!(matches!(cli.command, Command::Mcp));
}

/// Verifies protocol TARGET accepts a CIDR token for later expansion.
#[test]
fn parses_cidr_target_token() {
    let cli = Cli::try_parse_from([
        "brute",
        "tomcat",
        "10.10.50.24/29",
        "-u",
        "admin",
        "-p",
        "admin123",
    ])
    .expect("CIDR TARGET should parse as a target token");

    let Command::Protocol(ProtocolArgs::Tomcat(args)) = cli.command else {
        panic!("expected tomcat protocol arguments");
    };
    assert_eq!(args.common.targets, ["10.10.50.24/29"]);
}

/// Verifies ZooKeeper default port and `-x` command parsing.
#[test]
fn parses_zookeeper_execute_and_default_port() {
    assert_eq!(Protocol::Zookeeper.default_port(), 2181);
    assert_eq!(Protocol::Zookeeper.as_str(), "zookeeper");

    let cli = Cli::try_parse_from([
        "brute",
        "zookeeper",
        "192.168.5.10",
        "-u",
        "zkadmin",
        "-p",
        "secret",
        "-x",
        "ls /",
    ])
    .expect("zookeeper execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Zookeeper(args)) = cli.command else {
        panic!("expected zookeeper protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.common.usernames, ["zkadmin"]);
    assert_eq!(args.common.passwords, ["secret"]);
    assert_eq!(args.execute.as_deref(), Some("ls /"));
}

/// Verifies the `zk` alias maps to the ZooKeeper subcommand.
#[test]
fn parses_zookeeper_zk_alias() {
    let cli = Cli::try_parse_from(["brute", "zk", "192.168.5.10", "-u", "", "-p", ""])
        .expect("zk alias should parse as zookeeper");

    let Command::Protocol(ProtocolArgs::Zookeeper(args)) = cli.command else {
        panic!("expected zookeeper protocol arguments from zk alias");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
}
