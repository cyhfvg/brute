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

/// Verifies Memcached default port and `-x` command parsing.
#[test]
fn parses_memcached_execute_and_default_port() {
    assert_eq!(Protocol::Memcached.default_port(), 11211);
    assert_eq!(Protocol::Memcached.as_str(), "memcached");

    let cli = Cli::try_parse_from([
        "brute",
        "memcached",
        "192.168.5.10",
        "-u",
        "admin",
        "-p",
        "secret",
        "-x",
        "stats",
    ])
    .expect("memcached execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Memcached(args)) = cli.command else {
        panic!("expected memcached protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.common.usernames, ["admin"]);
    assert_eq!(args.common.passwords, ["secret"]);
    assert_eq!(args.execute.as_deref(), Some("stats"));
}

/// Verifies the `memcache` alias maps to the Memcached subcommand.
#[test]
fn parses_memcached_memcache_alias() {
    let cli = Cli::try_parse_from(["brute", "memcache", "192.168.5.10", "-u", "", "-p", ""])
        .expect("memcache alias should parse as memcached");

    let Command::Protocol(ProtocolArgs::Memcached(args)) = cli.command else {
        panic!("expected memcached protocol arguments from memcache alias");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
}

/// Verifies MongoDB default port and `-x` command parsing.
#[test]
fn parses_mongodb_execute_and_default_port() {
    assert_eq!(Protocol::Mongodb.default_port(), 27017);
    assert_eq!(Protocol::Mongodb.as_str(), "mongodb");

    let cli = Cli::try_parse_from([
        "brute",
        "mongodb",
        "192.168.5.10",
        "-u",
        "admin",
        "-p",
        "secret",
        "-x",
        "listDatabases",
    ])
    .expect("mongodb execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Mongodb(args)) = cli.command else {
        panic!("expected mongodb protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.common.usernames, ["admin"]);
    assert_eq!(args.common.passwords, ["secret"]);
    assert_eq!(args.execute.as_deref(), Some("listDatabases"));
}

/// Verifies the `mongo` alias maps to the MongoDB subcommand.
#[test]
fn parses_mongodb_mongo_alias() {
    let cli = Cli::try_parse_from(["brute", "mongo", "192.168.5.10", "-u", "", "-p", ""])
        .expect("mongo alias should parse as mongodb");

    let Command::Protocol(ProtocolArgs::Mongodb(args)) = cli.command else {
        panic!("expected mongodb protocol arguments from mongo alias");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
}

/// Verifies Elasticsearch default port and `-x` command parsing.
#[test]
fn parses_elasticsearch_execute_and_default_port() {
    assert_eq!(Protocol::Elasticsearch.default_port(), 9200);
    assert_eq!(Protocol::Elasticsearch.as_str(), "elasticsearch");

    let cli = Cli::try_parse_from([
        "brute",
        "elasticsearch",
        "192.168.5.10",
        "-u",
        "elastic",
        "-p",
        "secret",
        "-x",
        "indices",
    ])
    .expect("elasticsearch execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Elasticsearch(args)) = cli.command else {
        panic!("expected elasticsearch protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.common.usernames, ["elastic"]);
    assert_eq!(args.common.passwords, ["secret"]);
    assert_eq!(args.execute.as_deref(), Some("indices"));
}

/// Verifies the `es` alias maps to the Elasticsearch subcommand.
#[test]
fn parses_elasticsearch_es_alias() {
    let cli = Cli::try_parse_from(["brute", "es", "192.168.5.10", "-u", "", "-p", ""])
        .expect("es alias should parse as elasticsearch");

    let Command::Protocol(ProtocolArgs::Elasticsearch(args)) = cli.command else {
        panic!("expected elasticsearch protocol arguments from es alias");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
}

/// Verifies Docker API default port and `-x` command parsing.
#[test]
fn parses_docker_execute_and_default_port() {
    assert_eq!(Protocol::Docker.default_port(), 2375);
    assert_eq!(Protocol::Docker.as_str(), "docker");

    let cli = Cli::try_parse_from([
        "brute",
        "docker",
        "192.168.5.10",
        "-u",
        "",
        "-p",
        "",
        "-x",
        "containers",
    ])
    .expect("docker execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Docker(args)) = cli.command else {
        panic!("expected docker protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("containers"));
}

/// Verifies the `docker-api` alias maps to the Docker subcommand.
#[test]
fn parses_docker_api_alias() {
    let cli = Cli::try_parse_from(["brute", "docker-api", "192.168.5.10", "-u", "", "-p", ""])
        .expect("docker-api alias should parse as docker");

    let Command::Protocol(ProtocolArgs::Docker(args)) = cli.command else {
        panic!("expected docker protocol arguments from docker-api alias");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
}

/// Verifies SNMP default port and `-x` OID parsing.
#[test]
fn parses_snmp_execute_and_default_port() {
    assert_eq!(Protocol::Snmp.default_port(), 161);
    assert_eq!(Protocol::Snmp.as_str(), "snmp");

    let cli = Cli::try_parse_from([
        "brute",
        "snmp",
        "192.168.5.10",
        "-u",
        "",
        "-p",
        "secret",
        "-x",
        "sysName",
    ])
    .expect("snmp execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Snmp(args)) = cli.command else {
        panic!("expected snmp protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.common.passwords, ["secret"]);
    assert_eq!(args.execute.as_deref(), Some("sysName"));
}

/// Verifies ActiveMQ default port and `-x` command parsing.
#[test]
fn parses_activemq_execute_and_default_port() {
    assert_eq!(Protocol::Activemq.default_port(), 61613);
    assert_eq!(Protocol::Activemq.as_str(), "activemq");

    let cli = Cli::try_parse_from([
        "brute",
        "activemq",
        "192.168.5.10",
        "-u",
        "admin",
        "-p",
        "admin",
        "-x",
        "hello",
    ])
    .expect("activemq execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Activemq(args)) = cli.command else {
        panic!("expected activemq protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.common.usernames, ["admin"]);
    assert_eq!(args.execute.as_deref(), Some("hello"));
}

/// Verifies the `amq` alias maps to the ActiveMQ subcommand.
#[test]
fn parses_activemq_amq_alias() {
    let cli = Cli::try_parse_from(["brute", "amq", "192.168.5.10", "-u", "admin", "-p", "admin"])
        .expect("amq alias should parse as activemq");

    let Command::Protocol(ProtocolArgs::Activemq(args)) = cli.command else {
        panic!("expected activemq protocol arguments from amq alias");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
}

/// Verifies RabbitMQ default port and `-x` command parsing.
#[test]
fn parses_rabbitmq_execute_and_default_port() {
    assert_eq!(Protocol::Rabbitmq.default_port(), 5672);
    assert_eq!(Protocol::Rabbitmq.as_str(), "rabbitmq");

    let cli = Cli::try_parse_from([
        "brute",
        "rabbitmq",
        "192.168.5.10",
        "-u",
        "admin",
        "-p",
        "secret",
        "-x",
        "brute",
    ])
    .expect("rabbitmq execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Rabbitmq(args)) = cli.command else {
        panic!("expected rabbitmq protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("brute"));
}

/// Verifies the `amqp` alias maps to the RabbitMQ subcommand.
#[test]
fn parses_rabbitmq_amqp_alias() {
    let cli = Cli::try_parse_from([
        "brute",
        "amqp",
        "192.168.5.10",
        "-u",
        "admin",
        "-p",
        "secret",
    ])
    .expect("amqp alias should parse as rabbitmq");

    let Command::Protocol(ProtocolArgs::Rabbitmq(args)) = cli.command else {
        panic!("expected rabbitmq protocol arguments from amqp alias");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
}

/// Verifies rsync default port and `--module` parsing.
#[test]
fn parses_rsync_module_and_default_port() {
    assert_eq!(Protocol::Rsync.default_port(), 873);
    assert_eq!(Protocol::Rsync.as_str(), "rsync");

    let cli = Cli::try_parse_from([
        "brute",
        "rsync",
        "192.168.5.10",
        "-u",
        "admin",
        "-p",
        "secret",
        "--module",
        "backup",
    ])
    .expect("rsync module arguments should parse");

    let Command::Protocol(ProtocolArgs::Rsync(args)) = cli.command else {
        panic!("expected rsync protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.module, "backup");
}

/// Verifies MSSQL default port, `-x`, and `sqlserver` alias.
#[test]
fn parses_mssql_execute_and_sqlserver_alias() {
    assert_eq!(Protocol::Mssql.default_port(), 1433);
    assert_eq!(Protocol::Mssql.as_str(), "mssql");

    let cli = Cli::try_parse_from([
        "brute",
        "mssql",
        "192.168.5.10",
        "-u",
        "sa",
        "-p",
        "Your_password1",
        "-x",
        "SELECT @@VERSION",
    ])
    .expect("mssql execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Mssql(args)) = cli.command else {
        panic!("expected mssql protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("SELECT @@VERSION"));

    let cli = Cli::try_parse_from([
        "brute",
        "sqlserver",
        "192.168.5.10",
        "-u",
        "sa",
        "-p",
        "Your_password1",
    ])
    .expect("sqlserver alias should parse as mssql");
    let Command::Protocol(ProtocolArgs::Mssql(args)) = cli.command else {
        panic!("expected mssql protocol arguments from sqlserver alias");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
}

/// Verifies Kafka default port and `-x` command parsing.
#[test]
fn parses_kafka_execute_and_default_port() {
    assert_eq!(Protocol::Kafka.default_port(), 9092);
    assert_eq!(Protocol::Kafka.as_str(), "kafka");

    let cli = Cli::try_parse_from([
        "brute",
        "kafka",
        "192.168.5.10",
        "-u",
        "admin",
        "-p",
        "kafka_pass",
        "-x",
        "metadata",
    ])
    .expect("kafka execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Kafka(args)) = cli.command else {
        panic!("expected kafka protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("metadata"));
}

/// Verifies Kibana default port and `-x` command parsing.
#[test]
fn parses_kibana_execute_and_default_port() {
    assert_eq!(Protocol::Kibana.default_port(), 5601);
    assert_eq!(Protocol::Kibana.as_str(), "kibana");

    let cli = Cli::try_parse_from([
        "brute",
        "kibana",
        "192.168.5.10",
        "-u",
        "elastic",
        "-p",
        "elastic_pass",
        "-x",
        "status",
    ])
    .expect("kibana execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Kibana(args)) = cli.command else {
        panic!("expected kibana protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("status"));
}

/// Verifies NFS default port and `-x` command parsing.
#[test]
fn parses_nfs_execute_and_default_port() {
    assert_eq!(Protocol::Nfs.default_port(), 2049);
    assert_eq!(Protocol::Nfs.as_str(), "nfs");

    let cli = Cli::try_parse_from([
        "brute",
        "nfs",
        "192.168.5.10",
        "-u",
        "",
        "-p",
        "",
        "-x",
        "dump",
    ])
    .expect("nfs execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Nfs(args)) = cli.command else {
        panic!("expected nfs protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("dump"));
}

/// Verifies Telnet default port and `-x` command parsing.
#[test]
fn parses_telnet_execute_and_default_port() {
    assert_eq!(Protocol::Telnet.default_port(), 23);
    assert_eq!(Protocol::Telnet.as_str(), "telnet");

    let cli = Cli::try_parse_from([
        "brute",
        "telnet",
        "192.168.5.10",
        "-u",
        "admin",
        "-p",
        "telnet_pass",
        "-x",
        "id",
    ])
    .expect("telnet execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Telnet(args)) = cli.command else {
        panic!("expected telnet protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("id"));
}

/// Verifies LDAP default port and `-x` command parsing.
#[test]
fn parses_ldap_execute_and_default_port() {
    assert_eq!(Protocol::Ldap.default_port(), 389);
    assert_eq!(Protocol::Ldap.as_str(), "ldap");

    let cli = Cli::try_parse_from([
        "brute",
        "ldap",
        "192.168.5.10",
        "-u",
        "cn=admin,dc=example,dc=org",
        "-p",
        "ldap_pass",
        "-x",
        "whoami",
    ])
    .expect("ldap execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Ldap(args)) = cli.command else {
        panic!("expected ldap protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("whoami"));
}

/// Verifies Grafana default port and `-x` command parsing.
#[test]
fn parses_grafana_execute_and_default_port() {
    assert_eq!(Protocol::Grafana.default_port(), 3000);
    assert_eq!(Protocol::Grafana.as_str(), "grafana");

    let cli = Cli::try_parse_from([
        "brute",
        "grafana",
        "192.168.5.10",
        "-u",
        "admin",
        "-p",
        "grafana_pass",
        "-x",
        "org",
    ])
    .expect("grafana execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Grafana(args)) = cli.command else {
        panic!("expected grafana protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("org"));
}

/// Verifies Prometheus default port, alias, and `-x` command parsing.
#[test]
fn parses_prometheus_execute_and_default_port() {
    assert_eq!(Protocol::Prometheus.default_port(), 9090);
    assert_eq!(Protocol::Prometheus.as_str(), "prometheus");

    let cli = Cli::try_parse_from([
        "brute",
        "prometheus",
        "192.168.5.10",
        "-u",
        "admin",
        "-p",
        "prometheus_pass",
        "-x",
        "query",
    ])
    .expect("prometheus execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Prometheus(args)) = cli.command else {
        panic!("expected prometheus protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("query"));
}

/// Verifies Jenkins default port and `-x` command parsing.
#[test]
fn parses_jenkins_execute_and_default_port() {
    assert_eq!(Protocol::Jenkins.default_port(), 8080);
    assert_eq!(Protocol::Jenkins.as_str(), "jenkins");

    let cli = Cli::try_parse_from([
        "brute",
        "jenkins",
        "192.168.5.10",
        "-u",
        "admin",
        "-p",
        "jenkins_pass",
        "-x",
        "whoami",
    ])
    .expect("jenkins execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Jenkins(args)) = cli.command else {
        panic!("expected jenkins protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("whoami"));
}

/// Verifies CouchDB default port, alias, and `-x` command parsing.
#[test]
fn parses_couchdb_execute_and_default_port() {
    assert_eq!(Protocol::Couchdb.default_port(), 5984);
    assert_eq!(Protocol::Couchdb.as_str(), "couchdb");

    let cli = Cli::try_parse_from([
        "brute",
        "couchdb",
        "192.168.5.10",
        "-u",
        "admin",
        "-p",
        "couch_pass",
        "-x",
        "dbs",
    ])
    .expect("couchdb execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Couchdb(args)) = cli.command else {
        panic!("expected couchdb protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("dbs"));
}

/// Verifies ClickHouse default port, alias, and `-x` command parsing.
#[test]
fn parses_clickhouse_execute_and_default_port() {
    assert_eq!(Protocol::Clickhouse.default_port(), 8123);
    assert_eq!(Protocol::Clickhouse.as_str(), "clickhouse");

    let cli = Cli::try_parse_from([
        "brute",
        "clickhouse",
        "192.168.5.10",
        "-u",
        "admin",
        "-p",
        "click_pass",
        "-x",
        "version",
    ])
    .expect("clickhouse execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Clickhouse(args)) = cli.command else {
        panic!("expected clickhouse protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("version"));
}

/// Verifies Neo4j default port and `-x` command parsing.
#[test]
fn parses_neo4j_execute_and_default_port() {
    assert_eq!(Protocol::Neo4j.default_port(), 7474);
    assert_eq!(Protocol::Neo4j.as_str(), "neo4j");

    let cli = Cli::try_parse_from([
        "brute",
        "neo4j",
        "192.168.5.10",
        "-u",
        "neo4j",
        "-p",
        "neo4j_pass",
        "-x",
        "ping",
    ])
    .expect("neo4j execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Neo4j(args)) = cli.command else {
        panic!("expected neo4j protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("ping"));
}

/// Verifies etcd default port and `-x` command parsing.
#[test]
fn parses_etcd_execute_and_default_port() {
    assert_eq!(Protocol::Etcd.default_port(), 2379);
    assert_eq!(Protocol::Etcd.as_str(), "etcd");

    let cli = Cli::try_parse_from([
        "brute",
        "etcd",
        "192.168.5.10",
        "-u",
        "root",
        "-p",
        "etcd_pass",
        "-x",
        "version",
    ])
    .expect("etcd execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Etcd(args)) = cli.command else {
        panic!("expected etcd protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("version"));
}

/// Verifies InfluxDB default port, alias, and `-x` command parsing.
#[test]
fn parses_influxdb_execute_and_default_port() {
    assert_eq!(Protocol::Influxdb.default_port(), 8086);
    assert_eq!(Protocol::Influxdb.as_str(), "influxdb");

    let cli = Cli::try_parse_from([
        "brute",
        "influxdb",
        "192.168.5.10",
        "-u",
        "admin",
        "-p",
        "influx_pass",
        "-x",
        "dbs",
    ])
    .expect("influxdb execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Influxdb(args)) = cli.command else {
        panic!("expected influxdb protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("dbs"));
}

/// Verifies Solr default port and `-x` command parsing.
#[test]
fn parses_solr_execute_and_default_port() {
    assert_eq!(Protocol::Solr.default_port(), 8983);
    assert_eq!(Protocol::Solr.as_str(), "solr");

    let cli = Cli::try_parse_from([
        "brute",
        "solr",
        "192.168.5.10",
        "-u",
        "solr",
        "-p",
        "solr_pass",
        "-x",
        "cores",
    ])
    .expect("solr execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Solr(args)) = cli.command else {
        panic!("expected solr protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("cores"));
}

/// Verifies MinIO default port and `-x` command parsing.
#[test]
fn parses_minio_execute_and_default_port() {
    assert_eq!(Protocol::Minio.default_port(), 9001);
    assert_eq!(Protocol::Minio.as_str(), "minio");

    let cli = Cli::try_parse_from([
        "brute",
        "minio",
        "192.168.5.10",
        "-u",
        "minioadmin",
        "-p",
        "minio_pass",
        "-x",
        "buckets",
    ])
    .expect("minio execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Minio(args)) = cli.command else {
        panic!("expected minio protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("buckets"));
}

/// Verifies Nacos default port and `-x` command parsing.
#[test]
fn parses_nacos_execute_and_default_port() {
    assert_eq!(Protocol::Nacos.default_port(), 8848);
    assert_eq!(Protocol::Nacos.as_str(), "nacos");

    let cli = Cli::try_parse_from([
        "brute",
        "nacos",
        "192.168.5.10",
        "-u",
        "nacos",
        "-p",
        "nacos",
        "-x",
        "namespaces",
    ])
    .expect("nacos execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Nacos(args)) = cli.command else {
        panic!("expected nacos protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("namespaces"));
}

/// Verifies Nexus default port and `-x` command parsing.
#[test]
fn parses_nexus_execute_and_default_port() {
    assert_eq!(Protocol::Nexus.default_port(), 8081);
    assert_eq!(Protocol::Nexus.as_str(), "nexus");

    let cli = Cli::try_parse_from([
        "brute",
        "nexus",
        "192.168.5.10",
        "-u",
        "admin",
        "-p",
        "nexus_pass",
        "-x",
        "repos",
    ])
    .expect("nexus execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Nexus(args)) = cli.command else {
        panic!("expected nexus protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("repos"));
}

/// Verifies JBoss default port, alias, and `-x` command parsing.
#[test]
fn parses_jboss_execute_and_default_port() {
    assert_eq!(Protocol::Jboss.default_port(), 9990);
    assert_eq!(Protocol::Jboss.as_str(), "jboss");

    let cli = Cli::try_parse_from([
        "brute",
        "wildfly",
        "192.168.5.10",
        "-u",
        "admin",
        "-p",
        "jboss_pass",
        "-x",
        "version",
    ])
    .expect("jboss execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Jboss(args)) = cli.command else {
        panic!("expected jboss protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("version"));
}

/// Verifies Druid default port and `-x` command parsing.
#[test]
fn parses_druid_execute_and_default_port() {
    assert_eq!(Protocol::Druid.default_port(), 8888);
    assert_eq!(Protocol::Druid.as_str(), "druid");

    let cli = Cli::try_parse_from([
        "brute",
        "druid",
        "192.168.5.10",
        "-u",
        "admin",
        "-p",
        "druid_pass",
        "-x",
        "status",
    ])
    .expect("druid execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Druid(args)) = cli.command else {
        panic!("expected druid protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("status"));
}

/// Verifies Spark default port and `-x` command parsing.
#[test]
fn parses_spark_execute_and_default_port() {
    assert_eq!(Protocol::Spark.default_port(), 8080);
    assert_eq!(Protocol::Spark.as_str(), "spark");

    let cli = Cli::try_parse_from([
        "brute",
        "spark",
        "192.168.5.10",
        "-u",
        "spark",
        "-p",
        "spark_pass",
        "-x",
        "json",
    ])
    .expect("spark execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Spark(args)) = cli.command else {
        panic!("expected spark protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("json"));
}

/// Verifies Hadoop default port, alias, and `-x` command parsing.
#[test]
fn parses_hadoop_execute_and_default_port() {
    assert_eq!(Protocol::Hadoop.default_port(), 9870);
    assert_eq!(Protocol::Hadoop.as_str(), "hadoop");

    let cli = Cli::try_parse_from([
        "brute",
        "hdfs",
        "192.168.5.10",
        "-u",
        "hdfs",
        "-p",
        "hadoop_pass",
        "-x",
        "jmx",
    ])
    .expect("hadoop execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Hadoop(args)) = cli.command else {
        panic!("expected hadoop protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("jmx"));
}

/// Verifies kubelet default port and `-x` command parsing.
#[test]
fn parses_kubelet_execute_and_default_port() {
    assert_eq!(Protocol::Kubelet.default_port(), 10250);
    assert_eq!(Protocol::Kubelet.as_str(), "kubelet");

    let cli = Cli::try_parse_from([
        "brute",
        "kubelet",
        "192.168.5.10",
        "-u",
        "",
        "-p",
        "k8s-token",
        "-x",
        "pods",
    ])
    .expect("kubelet execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Kubelet(args)) = cli.command else {
        panic!("expected kubelet protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("pods"));
}

/// Verifies GitLab default port and `-x` command parsing.
#[test]
fn parses_gitlab_execute_and_default_port() {
    assert_eq!(Protocol::Gitlab.default_port(), 80);
    assert_eq!(Protocol::Gitlab.as_str(), "gitlab");

    let cli = Cli::try_parse_from([
        "brute",
        "gitlab",
        "192.168.5.10",
        "-u",
        "root",
        "-p",
        "Gl7ab-Rx9p2q",
        "-x",
        "user",
    ])
    .expect("gitlab execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Gitlab(args)) = cli.command else {
        panic!("expected gitlab protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("user"));
}

/// Verifies Harbor default port and `-x` command parsing.
#[test]
fn parses_harbor_execute_and_default_port() {
    assert_eq!(Protocol::Harbor.default_port(), 80);
    assert_eq!(Protocol::Harbor.as_str(), "harbor");

    let cli = Cli::try_parse_from([
        "brute",
        "harbor",
        "192.168.5.10",
        "-u",
        "admin",
        "-p",
        "Harbor12345",
        "-x",
        "projects",
    ])
    .expect("harbor execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Harbor(args)) = cli.command else {
        panic!("expected harbor protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("projects"));
}

/// Verifies WebLogic default port, alias, and `-x` command parsing.
#[test]
fn parses_weblogic_execute_and_default_port() {
    assert_eq!(Protocol::Weblogic.default_port(), 7001);
    assert_eq!(Protocol::Weblogic.as_str(), "weblogic");

    let cli = Cli::try_parse_from([
        "brute",
        "wls",
        "192.168.5.10",
        "-u",
        "weblogic",
        "-p",
        "Webl0gic-Pass1",
        "-x",
        "console",
    ])
    .expect("weblogic execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Weblogic(args)) = cli.command else {
        panic!("expected weblogic protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("console"));
}

/// Verifies WebSphere default port, alias, and `-x` command parsing.
#[test]
fn parses_websphere_execute_and_default_port() {
    assert_eq!(Protocol::Websphere.default_port(), 9043);
    assert_eq!(Protocol::Websphere.as_str(), "websphere");

    let cli = Cli::try_parse_from([
        "brute",
        "was",
        "192.168.5.10",
        "-u",
        "wsadmin",
        "-p",
        "WsbPassw0rd1",
        "-x",
        "console",
    ])
    .expect("websphere execute arguments should parse");

    let Command::Protocol(ProtocolArgs::Websphere(args)) = cli.command else {
        panic!("expected websphere protocol arguments");
    };
    assert_eq!(args.common.targets, ["192.168.5.10"]);
    assert_eq!(args.execute.as_deref(), Some("console"));
}
