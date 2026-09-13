//! Command-line parsing types.

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Root CLI definition.
#[derive(Debug, Parser)]
#[command(
    name = "brute",
    version,
    author = "cyhfvg <https://github.com/cyhfvg/brute>",
    about = "A multi-protocol credential attack and login verification utility",
    help_template = "\
{before-help}{about-with-newline}\
Author: {author-with-newline}\
{usage-heading} {usage}

{all-args}{after-help}",
    subcommand_value_name = "COMMAND",
    subcommand_help_heading = "commands"
)]
pub struct Cli {
    /// Disable ANSI colors in the terminal output.
    #[arg(long)]
    pub no_color: bool,

    /// Outbound proxy URL: `http://[user[:pass]@]host:port` or `socks5://[user[:pass]@]host:port`.
    ///
    /// Applies to login, spray, probe, and post-auth command paths for every protocol module.
    /// Username and password may be omitted for unauthenticated proxies.
    #[arg(long = "proxy", value_name = "PROXY_URL", value_parser = crate::proxy::parse_proxy_url)]
    pub proxy: Option<crate::proxy::ProxyConfig>,

    #[command(subcommand)]
    pub command: Command,
}

/// Top-level command groups.
#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)] // ProtocolArgs carries full CommonArgs.
pub enum Command {
    #[command(flatten)]
    Protocol(ProtocolArgs),
    #[command(about = "Manage credential workspaces")]
    Workspace(WorkspaceArgs),
    #[command(about = "Search saved credentials")]
    Creds(CredsArgs),
    #[command(about = "Start the MCP stdio server for LLM tool use")]
    Mcp,
}

/// Supported protocol subcommands.
#[derive(Debug, Subcommand)]
pub enum ProtocolArgs {
    #[command(
        about = "own stuff using SSH",
        override_usage = "brute ssh <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute ssh 192.168.5.5 -u admin -p 123456 -x 'id'"
    )]
    Ssh(ExecuteArgs),

    #[command(
        about = "own stuff using FTP",
        override_usage = "brute ftp <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute ftp 192.168.5.5 -u admin -p 123456 -x 'PWD'"
    )]
    Ftp(ExecuteArgs),

    #[command(
        about = "own stuff using MYSQL",
        override_usage = "brute mysql <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute mysql 192.168.5.5 -u root -p 123456 -x 'show databases;'"
    )]
    Mysql(ExecuteArgs),

    #[command(
        about = "own stuff using POSTGRESQL",
        override_usage = "brute postgresql <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute postgresql 192.168.5.5 -u postgres -p 123456 -x 'select version();'"
    )]
    Postgresql(ExecuteArgs),

    #[command(
        about = "own stuff using REDIS",
        override_usage = "brute redis <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute redis 192.168.5.5 -u '' -p 123456 -x 'INFO server'"
    )]
    Redis(ExecuteArgs),

    #[command(
        name = "tomcat-manager",
        visible_alias = "tomcat",
        about = "own stuff using TOMCAT MANAGER",
        override_usage = "brute tomcat-manager <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute tomcat 192.168.5.5 -u tomcat -p s3cret --path /manager/html"
    )]
    Tomcat(TomcatArgs),

    #[command(
        about = "own stuff using SMB",
        override_usage = "brute smb <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute smb 192.168.5.5 -u admin -p 123456\n  brute smb 192.168.5.5 -u admin -p 123456 --shares"
    )]
    Smb(SmbArgs),

    #[command(
        about = "own stuff using RDP",
        override_usage = "brute rdp <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute rdp 192.168.5.5 -u admin -p 123456"
    )]
    Rdp(CommonArgs),

    #[command(
        about = "own stuff using WINRM",
        override_usage = "brute winrm <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute winrm 192.168.5.5 -u admin -p 123456\n  brute winrm 192.168.5.5 -u admin -p 123456 -x 'whoami'\n  brute winrm 192.168.5.5 -u admin -p 123456 --shell-type cmd -x 'whoami'\n  brute winrm 192.168.5.5 -u admin -p 123456 --shell-type powershell\n  brute winrm 192.168.5.5 -u admin -p 123456 --shell-type cmd -x @script.bat\n  brute winrm 192.168.5.5 -u admin -p 123456 -x @script.ps1"
    )]
    Winrm(WinrmArgs),

    #[command(
        about = "own stuff using ORACLE",
        override_usage = "brute oracle <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute oracle cloud.home.lab -u APPUSER -p PASSWORD --service-name XE -x 'select * from dual'\n  brute oracle cloud.home.lab -u users.txt -p pass.txt --service-name services.txt\n  brute oracle cloud.home.lab -u users.txt -p pass.txt --sid sids.txt"
    )]
    Oracle(OracleArgs),

    #[command(
        about = "own stuff using HTTP Basic Auth",
        override_usage = "brute http <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute http 192.168.10.5 -u admin -p 123456 --path /\n  brute http 10.10.50.30 -u users.txt -p pass.txt --port 8080 --path /manager/html --threads 16\n  brute http 10.10.50.30 -u admin -p secret --protocol https --port 8443 --path /"
    )]
    Http(HttpArgs),

    #[command(
        about = "own stuff using VNC",
        override_usage = "brute vnc <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute vnc 192.168.10.5 -u '' -p 123456\n  brute vnc 192.168.10.5 -u users.txt -p pass.txt --port 5900 --threads 16"
    )]
    Vnc(CommonArgs),

    #[command(
        about = "own stuff using ZOOKEEPER",
        visible_alias = "zk",
        override_usage = "brute zookeeper <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute zookeeper 192.168.5.10 -u zkadmin -p 'zkadmin_pass'\n  brute zookeeper 192.168.5.10 -u '' -p ''\n  brute zookeeper 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute zookeeper 192.168.5.10 -u zkadmin -p 'zkadmin_pass' -x 'ls /'"
    )]
    Zookeeper(ExecuteArgs),

    #[command(
        about = "own stuff using MEMCACHED",
        visible_alias = "memcache",
        override_usage = "brute memcached <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute memcached 192.168.5.10 -u admin -p 'memcached_pass'\n  brute memcached 192.168.5.10 -u '' -p ''\n  brute memcached 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute memcached 192.168.5.10 -u admin -p 'memcached_pass' -x 'stats'"
    )]
    Memcached(ExecuteArgs),

    #[command(
        about = "own stuff using MONGODB",
        visible_alias = "mongo",
        override_usage = "brute mongodb <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute mongodb 192.168.5.10 -u admin -p 'mongodb_pass'\n  brute mongodb 192.168.5.10 -u '' -p ''\n  brute mongodb 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute mongodb 192.168.5.10 -u admin -p 'mongodb_pass' -x 'listDatabases'"
    )]
    Mongodb(ExecuteArgs),

    #[command(
        about = "own stuff using ELASTICSEARCH",
        visible_alias = "es",
        override_usage = "brute elasticsearch <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute elasticsearch 192.168.5.10 -u elastic -p 'elastic_pass'\n  brute elasticsearch 192.168.5.10 -u '' -p ''\n  brute elasticsearch 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute elasticsearch 192.168.5.10 -u elastic -p 'elastic_pass' -x 'indices'"
    )]
    Elasticsearch(ExecuteArgs),

    #[command(
        name = "docker",
        visible_alias = "docker-api",
        about = "own stuff using DOCKER API",
        override_usage = "brute docker <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute docker 192.168.5.10 -u '' -p ''\n  brute docker 192.168.5.10 -u admin -p 'docker_pass'\n  brute docker 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute docker 192.168.5.10 -u '' -p '' -x 'containers'"
    )]
    Docker(ExecuteArgs),

    #[command(
        about = "own stuff using SNMP",
        override_usage = "brute snmp <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute snmp 192.168.5.10 -u '' -p public\n  brute snmp 192.168.5.10 -u '' -p ''\n  brute snmp 192.168.5.10 -u '' -p communities.txt --continue-on-success\n  brute snmp 192.168.5.10 -u '' -p secret -x sysName"
    )]
    Snmp(ExecuteArgs),

    #[command(
        about = "own stuff using ACTIVEMQ",
        visible_alias = "amq",
        override_usage = "brute activemq <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute activemq 192.168.5.10 -u admin -p admin\n  brute activemq 192.168.5.10 -u '' -p ''\n  brute activemq 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute activemq 192.168.5.10 -u admin -p admin -x 'hello'"
    )]
    Activemq(ExecuteArgs),

    #[command(
        about = "own stuff using RABBITMQ",
        visible_alias = "amqp",
        override_usage = "brute rabbitmq <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute rabbitmq 192.168.5.10 -u admin -p 'rabbit_pass'\n  brute rabbitmq 192.168.5.10 -u '' -p ''\n  brute rabbitmq 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute rabbitmq 192.168.5.10 -u admin -p 'rabbit_pass' -x brute"
    )]
    Rabbitmq(ExecuteArgs),

    #[command(
        about = "own stuff using RSYNC",
        override_usage = "brute rsync <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute rsync 192.168.5.10 -u admin -p secret\n  brute rsync 192.168.5.10 -u '' -p '' --module files\n  brute rsync 192.168.5.10 -u users.txt -p pass.txt --module files --threads 8"
    )]
    Rsync(RsyncArgs),

    #[command(
        about = "own stuff using MSSQL",
        visible_alias = "sqlserver",
        override_usage = "brute mssql <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute mssql 192.168.5.10 -u sa -p 'Your_password1'\n  brute mssql 192.168.5.10 -u sa -p 'Your_password1' -x 'SELECT @@VERSION'"
    )]
    Mssql(ExecuteArgs),

    #[command(
        about = "own stuff using KAFKA",
        override_usage = "brute kafka <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute kafka 192.168.5.10 -u admin -p kafka_pass\n  brute kafka 192.168.5.10 -u admin -p kafka_pass -x metadata"
    )]
    Kafka(ExecuteArgs),

    #[command(
        about = "own stuff using KIBANA",
        override_usage = "brute kibana <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute kibana 192.168.5.10 -u elastic -p changeme\n  brute kibana 192.168.5.10 -u elastic -p changeme -x status"
    )]
    Kibana(ExecuteArgs),

    #[command(
        about = "own stuff using NFS",
        override_usage = "brute nfs <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute nfs 192.168.5.10 -u '' -p ''\n  brute nfs 192.168.5.10 -u 0 -p '' -x dump"
    )]
    Nfs(ExecuteArgs),

    #[command(
        about = "own stuff using TELNET",
        override_usage = "brute telnet <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute telnet 192.168.5.10 -u admin -p telnet_pass\n  brute telnet 192.168.5.10 -u '' -p ''\n  brute telnet 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute telnet 192.168.5.10 -u admin -p telnet_pass -x id"
    )]
    Telnet(ExecuteArgs),

    #[command(
        about = "own stuff using LDAP",
        override_usage = "brute ldap <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute ldap 192.168.5.10 -u 'cn=admin,dc=example,dc=org' -p ldap_pass\n  brute ldap 192.168.5.10 -u '' -p ''\n  brute ldap 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute ldap 192.168.5.10 -u 'cn=admin,dc=example,dc=org' -p ldap_pass -x whoami"
    )]
    Ldap(ExecuteArgs),

    #[command(
        about = "own stuff using GRAFANA",
        override_usage = "brute grafana <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute grafana 192.168.5.10 -u admin -p grafana_pass\n  brute grafana 192.168.5.10 -u '' -p ''\n  brute grafana 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute grafana 192.168.5.10 -u admin -p grafana_pass -x org"
    )]
    Grafana(ExecuteArgs),

    #[command(
        about = "own stuff using PROMETHEUS",
        visible_alias = "prom",
        override_usage = "brute prometheus <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute prometheus 192.168.5.10 -u admin -p prometheus_pass\n  brute prometheus 192.168.5.10 -u '' -p ''\n  brute prometheus 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute prometheus 192.168.5.10 -u admin -p prometheus_pass -x query"
    )]
    Prometheus(ExecuteArgs),

    #[command(
        about = "own stuff using JENKINS",
        override_usage = "brute jenkins <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute jenkins 192.168.5.10 -u admin -p jenkins_pass\n  brute jenkins 192.168.5.10 -u '' -p ''\n  brute jenkins 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute jenkins 192.168.5.10 -u admin -p jenkins_pass -x whoami"
    )]
    Jenkins(ExecuteArgs),

    #[command(
        about = "own stuff using COUCHDB",
        visible_alias = "couch",
        override_usage = "brute couchdb <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute couchdb 192.168.5.10 -u admin -p couch_pass\n  brute couchdb 192.168.5.10 -u '' -p ''\n  brute couchdb 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute couchdb 192.168.5.10 -u admin -p couch_pass -x dbs"
    )]
    Couchdb(ExecuteArgs),

    #[command(
        about = "own stuff using CLICKHOUSE",
        visible_alias = "ch",
        override_usage = "brute clickhouse <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute clickhouse 192.168.5.10 -u admin -p click_pass\n  brute clickhouse 192.168.5.10 -u '' -p ''\n  brute clickhouse 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute clickhouse 192.168.5.10 -u admin -p click_pass -x version"
    )]
    Clickhouse(ExecuteArgs),

    #[command(
        about = "own stuff using NEO4J",
        override_usage = "brute neo4j <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute neo4j 192.168.5.10 -u neo4j -p neo4j_pass\n  brute neo4j 192.168.5.10 -u '' -p ''\n  brute neo4j 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute neo4j 192.168.5.10 -u neo4j -p neo4j_pass -x ping"
    )]
    Neo4j(ExecuteArgs),

    #[command(
        about = "own stuff using ETCD",
        override_usage = "brute etcd <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute etcd 192.168.5.10 -u root -p etcd_pass\n  brute etcd 192.168.5.10 -u '' -p ''\n  brute etcd 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute etcd 192.168.5.10 -u root -p etcd_pass -x version"
    )]
    Etcd(ExecuteArgs),

    #[command(
        about = "own stuff using INFLUXDB",
        visible_alias = "influx",
        override_usage = "brute influxdb <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute influxdb 192.168.5.10 -u admin -p influx_pass\n  brute influxdb 192.168.5.10 -u '' -p ''\n  brute influxdb 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute influxdb 192.168.5.10 -u admin -p influx_pass -x dbs"
    )]
    Influxdb(ExecuteArgs),

    #[command(
        about = "own stuff using SOLR",
        override_usage = "brute solr <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute solr 192.168.5.10 -u solr -p solr_pass\n  brute solr 192.168.5.10 -u '' -p ''\n  brute solr 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute solr 192.168.5.10 -u solr -p solr_pass -x cores"
    )]
    Solr(ExecuteArgs),

    #[command(
        about = "own stuff using MINIO",
        override_usage = "brute minio <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute minio 192.168.5.10 -u minioadmin -p minio_pass\n  brute minio 192.168.5.10 -u '' -p ''\n  brute minio 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute minio 192.168.5.10 -u minioadmin -p minio_pass -x buckets"
    )]
    Minio(ExecuteArgs),

    #[command(
        about = "own stuff using NACOS",
        override_usage = "brute nacos <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute nacos 192.168.5.10 -u nacos -p nacos\n  brute nacos 192.168.5.10 -u '' -p ''\n  brute nacos 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute nacos 192.168.5.10 -u nacos -p nacos -x namespaces"
    )]
    Nacos(ExecuteArgs),

    #[command(
        about = "own stuff using NEXUS",
        override_usage = "brute nexus <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute nexus 192.168.5.10 -u admin -p nexus_pass\n  brute nexus 192.168.5.10 -u '' -p ''\n  brute nexus 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute nexus 192.168.5.10 -u admin -p nexus_pass -x repos"
    )]
    Nexus(ExecuteArgs),

    #[command(
        about = "own stuff using JBOSS",
        visible_alias = "wildfly",
        override_usage = "brute jboss <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute jboss 192.168.5.10 -u admin -p jboss_pass\n  brute jboss 192.168.5.10 -u '' -p ''\n  brute jboss 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute jboss 192.168.5.10 -u admin -p jboss_pass -x version"
    )]
    Jboss(ExecuteArgs),

    #[command(
        about = "own stuff using DRUID",
        override_usage = "brute druid <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute druid 192.168.5.10 -u admin -p druid_pass\n  brute druid 192.168.5.10 -u '' -p ''\n  brute druid 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute druid 192.168.5.10 -u admin -p druid_pass -x status"
    )]
    Druid(ExecuteArgs),

    #[command(
        about = "own stuff using SPARK",
        override_usage = "brute spark <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute spark 192.168.5.10 -u spark -p spark_pass\n  brute spark 192.168.5.10 -u '' -p ''\n  brute spark 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute spark 192.168.5.10 -u spark -p spark_pass -x json"
    )]
    Spark(ExecuteArgs),

    #[command(
        about = "own stuff using HADOOP",
        visible_alias = "hdfs",
        override_usage = "brute hadoop <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute hadoop 192.168.5.10 -u hdfs -p hadoop_pass\n  brute hadoop 192.168.5.10 -u '' -p ''\n  brute hadoop 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute hadoop 192.168.5.10 -u hdfs -p hadoop_pass -x jmx"
    )]
    Hadoop(ExecuteArgs),

    #[command(
        about = "own stuff using KUBELET",
        override_usage = "brute kubelet <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute kubelet 192.168.5.10 -u '' -p k8s-token\n  brute kubelet 192.168.5.10 -u '' -p ''\n  brute kubelet 192.168.5.10 -u users.txt -p tokens.txt --threads 8\n  brute kubelet 192.168.5.10 -u '' -p k8s-token -x pods"
    )]
    Kubelet(ExecuteArgs),

    #[command(
        about = "own stuff using GITLAB",
        override_usage = "brute gitlab <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute gitlab 192.168.5.10 -u root -p gitlab_pass1\n  brute gitlab 192.168.5.10 -u '' -p ''\n  brute gitlab 192.168.5.10 -u users.txt -p pass.txt --threads 8\n  brute gitlab 192.168.5.10 -u root -p gitlab_pass1 -x user"
    )]
    Gitlab(ExecuteArgs),
}

impl ProtocolArgs {
    /// Returns a shared view over the common options.
    pub fn common(&self) -> &CommonArgs {
        match self {
            Self::Ssh(args)
            | Self::Ftp(args)
            | Self::Mysql(args)
            | Self::Postgresql(args)
            | Self::Redis(args)
            | Self::Zookeeper(args)
            | Self::Memcached(args)
            | Self::Mongodb(args)
            | Self::Elasticsearch(args)
            | Self::Docker(args)
            | Self::Snmp(args)
            | Self::Activemq(args)
            | Self::Rabbitmq(args)
            | Self::Mssql(args)
            | Self::Kafka(args)
            | Self::Kibana(args)
            | Self::Nfs(args)
            | Self::Telnet(args)
            | Self::Ldap(args)
            | Self::Grafana(args)
            | Self::Prometheus(args)
            | Self::Jenkins(args)
            | Self::Couchdb(args)
            | Self::Clickhouse(args)
            | Self::Neo4j(args)
            | Self::Etcd(args)
            | Self::Influxdb(args)
            | Self::Solr(args)
            | Self::Minio(args)
            | Self::Nacos(args)
            | Self::Nexus(args)
            | Self::Jboss(args)
            | Self::Druid(args)
            | Self::Spark(args)
            | Self::Hadoop(args)
            | Self::Kubelet(args)
            | Self::Gitlab(args) => &args.common,
            Self::Oracle(args) => &args.execute.common,
            Self::Smb(args) => &args.common,
            Self::Winrm(args) => &args.common,
            Self::Rdp(args) | Self::Vnc(args) => args,
            Self::Tomcat(args) => &args.common,
            Self::Http(args) => &args.common,
            Self::Rsync(args) => &args.common,
        }
    }

    /// Returns a request path for HTTP-like modules.
    pub fn path(&self) -> Option<&str> {
        match self {
            Self::Tomcat(args) => Some(&args.path),
            Self::Http(args) => Some(&args.path),
            Self::Rsync(args) => Some(&args.module),
            _ => None,
        }
    }

    /// Returns the post-authentication command for protocols that support it.
    ///
    /// SMB and RDP do not support `-x` / `--execute`; SMB uses [`ProtocolArgs::shares`] instead.
    pub fn execute(&self) -> Option<&str> {
        match self {
            Self::Ssh(args)
            | Self::Ftp(args)
            | Self::Mysql(args)
            | Self::Postgresql(args)
            | Self::Redis(args)
            | Self::Zookeeper(args)
            | Self::Memcached(args)
            | Self::Mongodb(args)
            | Self::Elasticsearch(args)
            | Self::Docker(args)
            | Self::Snmp(args)
            | Self::Activemq(args)
            | Self::Rabbitmq(args)
            | Self::Mssql(args)
            | Self::Kafka(args)
            | Self::Kibana(args)
            | Self::Nfs(args)
            | Self::Telnet(args)
            | Self::Ldap(args)
            | Self::Grafana(args)
            | Self::Prometheus(args)
            | Self::Jenkins(args)
            | Self::Couchdb(args)
            | Self::Clickhouse(args)
            | Self::Neo4j(args)
            | Self::Etcd(args)
            | Self::Influxdb(args)
            | Self::Solr(args)
            | Self::Minio(args)
            | Self::Nacos(args)
            | Self::Nexus(args)
            | Self::Jboss(args)
            | Self::Druid(args)
            | Self::Spark(args)
            | Self::Hadoop(args)
            | Self::Kubelet(args)
            | Self::Gitlab(args) => args.execute.as_deref(),
            Self::Oracle(args) => args.execute.execute.as_deref(),
            Self::Winrm(args) => args.execute.as_deref(),
            _ => None,
        }
    }

    /// Returns the WinRM remote shell type when the protocol is WinRM.
    ///
    /// # Returns
    ///
    /// [`Some`] shell type for `brute winrm ...`; [`None`] for every other protocol.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let shell = protocol_args.shell_type();
    /// ```
    #[allow(dead_code)]
    pub fn shell_type(&self) -> Option<WinrmShellType> {
        match self {
            Self::Winrm(args) => args.shell_type,
            _ => None,
        }
    }

    /// Returns whether SMB share enumeration was requested.
    ///
    /// Used by callers that need the flag without matching on [`ProtocolArgs::Smb`].
    ///
    /// # Returns
    ///
    /// `true` only for `brute smb ... --shares`; `false` for every other protocol.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let shares = protocol_args.shares();
    /// ```
    #[allow(dead_code)]
    pub fn shares(&self) -> bool {
        matches!(self, Self::Smb(args) if args.shares)
    }
}

/// Parses a strictly positive concurrency value.
fn parse_positive_usize(value: &str) -> Result<usize, String> {
    value
        .parse()
        .map_err(|_| format!("{value:?} is not a valid positive integer"))
        .and_then(|parsed: usize| {
            (parsed > 0)
                .then_some(parsed)
                .ok_or_else(|| "value must be at least 1".to_string())
        })
}

/// Parses a strictly positive timeout in milliseconds.
fn parse_positive_u64(value: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|_| format!("{value:?} is not a valid positive integer"))
        .and_then(|parsed: u64| {
            (parsed > 0)
                .then_some(parsed)
                .ok_or_else(|| "value must be at least 1".to_string())
        })
}

/// Common options shared by all protocols.
#[derive(Debug, Clone, Args)]
pub struct CommonArgs {
    /// Target IPv4 address(es), IPv4 CIDR(s), hostname(s), FQDN(s), or file path(s) containing those values.
    #[arg(required = true, num_args = 1.., value_name = "TARGET")]
    pub targets: Vec<String>,
    /// Username(s) or file path(s) containing usernames; required unless --id is used.
    #[arg(
        short = 'u',
        long = "username",
        required_unless_present = "credential_id",
        conflicts_with = "credential_id",
        num_args = 1..,
        value_name = "USERNAME"
    )]
    pub usernames: Vec<String>,
    /// Password(s) or file path(s) containing passwords; required unless --id is used.
    #[arg(
        short = 'p',
        long = "password",
        required_unless_present = "credential_id",
        conflicts_with = "credential_id",
        num_args = 1..,
        value_name = "PASSWORD"
    )]
    pub passwords: Vec<String>,
    /// Saved credential id from the current workspace.
    #[arg(long = "id", value_name = "ID", conflicts_with_all = ["usernames", "passwords"])]
    pub credential_id: Option<i64>,
    /// Target service port override.
    #[arg(long)]
    pub port: Option<u16>,
    /// Concurrent attempt cap (in-flight logins across all targets and credentials).
    #[arg(long, default_value_t = 16, value_parser = parse_positive_usize)]
    pub threads: usize,
    /// Retry count for transient transport failures.
    #[arg(long, default_value_t = 3)]
    pub retries: usize,
    /// Timeout per attempt in milliseconds.
    #[arg(long, default_value_t = 5000, value_parser = parse_positive_u64)]
    pub timeout_ms: u64,
    /// Continue authentication attempts even after successes.
    #[arg(long)]
    pub continue_on_success: bool,
    /// Runtime-only outbound proxy injected from top-level `Cli::proxy` (not a subcommand flag).
    #[arg(skip)]
    pub proxy: Option<crate::proxy::ProxyConfig>,
}

/// Common protocol options plus post-authentication command execution.
#[derive(Debug, Clone, Args)]
pub struct ExecuteArgs {
    #[command(flatten)]
    pub common: CommonArgs,
    /// Execute the specified command after a successful login.
    #[arg(short = 'x', long = "execute", value_name = "COMMAND")]
    pub execute: Option<String>,
}

/// Remote shell type used by WinRM command execution and login probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum WinrmShellType {
    /// Run commands through `cmd.exe`.
    Cmd,
    /// Run commands through PowerShell / PSRP (default for `-x` when omitted).
    #[default]
    Powershell,
}

impl WinrmShellType {
    /// Returns the stable lowercase shell-type name used in messages and help text.
    ///
    /// # Returns
    ///
    /// `"cmd"` or `"powershell"`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert_eq!(WinrmShellType::Powershell.as_str(), "powershell");
    /// ```
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cmd => "cmd",
            Self::Powershell => "powershell",
        }
    }
}

/// WinRM-specific options: common credentials, post-auth execute, and shell type.
#[derive(Debug, Clone, Args)]
pub struct WinrmArgs {
    #[command(flatten)]
    pub common: CommonArgs,
    /// Execute the specified command after a successful login.
    ///
    /// Prefix with `@` to load a local script file and run its contents remotely
    /// (for example `-x @script.bat` or `-x @script.ps1`).
    #[arg(short = 'x', long = "execute", value_name = "COMMAND")]
    pub execute: Option<String>,
    /// Remote shell for `-x` and for no-`-x` capability probes.
    ///
    /// When omitted with `-x`, defaults to `powershell`. When omitted without `-x`,
    /// login probes powershell first then cmd (short-circuit). When set, only that
    /// shell is used for execute and for no-`-x` probes.
    #[arg(long = "shell-type", value_enum)]
    pub shell_type: Option<WinrmShellType>,
}

/// Oracle-specific options including the required database service identifier.
#[derive(Debug, Clone, Args)]
pub struct OracleArgs {
    #[command(flatten)]
    pub execute: ExecuteArgs,
    /// Oracle Service Name(s) or file path(s) used in Easy Connect syntax.
    ///
    /// Multiple values and wordlist files are expanded with `-u`/`-p` as a full
    /// cartesian product: `service-name × username × password`.
    #[arg(
        long,
        value_name = "SERVICE_NAME",
        required_unless_present = "sid",
        conflicts_with = "sid",
        num_args = 1..,
    )]
    pub service_name: Vec<String>,
    /// Oracle SID(s) or file path(s) used in a full Oracle Net connect descriptor.
    ///
    /// Multiple values and wordlist files are expanded with `-u`/`-p` as a full
    /// cartesian product: `sid × username × password`. Mutually exclusive with
    /// `--service-name`.
    #[arg(
        long,
        value_name = "SID",
        required_unless_present = "service_name",
        conflicts_with = "service_name",
        num_args = 1..,
    )]
    pub sid: Vec<String>,
}

/// SMB-specific options: common credentials plus optional share enumeration.
///
/// SMB intentionally omits `-x` / `--execute`. After a successful login, use
/// `--shares` to list share names and Access permissions.
#[derive(Debug, Clone, Args)]
pub struct SmbArgs {
    #[command(flatten)]
    pub common: CommonArgs,
    /// Enumerate shares and Access permissions after successful authentication.
    #[arg(long)]
    pub shares: bool,
}

/// Options for Apache Tomcat Manager.
#[derive(Debug, Clone, Args)]
pub struct TomcatArgs {
    #[command(flatten)]
    pub common: CommonArgs,
    /// Request path for the Tomcat Manager endpoint.
    #[arg(long, default_value = "/manager/html")]
    pub path: String,
}

/// URL scheme for the HTTP Basic Auth module (`--protocol`).
///
/// Distinct from the top-level CLI protocol selector (`brute http` / `Protocol::Http`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum HttpUrlScheme {
    /// Plain HTTP (`http://`).
    #[default]
    Http,
    /// HTTPS (`https://`); TLS certificate verification is skipped by default.
    Https,
}

impl HttpUrlScheme {
    /// Returns the URL scheme string used in request URLs.
    ///
    /// # Returns
    ///
    /// `"http"` or `"https"`.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::cli::HttpUrlScheme;
    /// assert_eq!(HttpUrlScheme::Http.as_str(), "http");
    /// assert_eq!(HttpUrlScheme::Https.as_str(), "https");
    /// ```
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// Options for generic HTTP Basic Auth login and spray.
#[derive(Debug, Clone, Args)]
pub struct HttpArgs {
    #[command(flatten)]
    pub common: CommonArgs,
    /// Request path used for the HTTP Basic Auth GET (default `/`).
    #[arg(long, default_value = "/")]
    pub path: String,
    /// URL scheme: `http` (default) or `https`. HTTPS skips TLS certificate verification.
    #[arg(long = "protocol", value_enum, default_value_t = HttpUrlScheme::Http)]
    pub url_scheme: HttpUrlScheme,
}

/// Options for rsync daemon module login and spray.
#[derive(Debug, Clone, Args)]
pub struct RsyncArgs {
    #[command(flatten)]
    pub common: CommonArgs,
    /// rsync daemon module name (default `files`).
    #[arg(long, default_value = "files")]
    pub module: String,
}

/// Workspace management command.
#[derive(Debug, Args)]
pub struct WorkspaceArgs {
    #[command(subcommand)]
    pub action: WorkspaceAction,
}

/// Workspace management actions.
#[derive(Debug, Subcommand)]
pub enum WorkspaceAction {
    /// Show the current workspace.
    Current,
    /// Switch to an existing workspace.
    Use {
        /// Workspace name to mark as current.
        name: String,
    },
    /// Create a workspace without switching to it.
    New {
        /// Workspace name to create.
        name: String,
    },
    /// Delete a workspace and its saved credentials.
    Delete {
        /// Workspace name to delete.
        name: String,
    },
    /// List known workspaces.
    List,
}

/// Saved credential command.
#[derive(Debug, Args)]
pub struct CredsArgs {
    #[command(subcommand)]
    pub action: CredsAction,
}

/// Saved credential actions.
#[derive(Debug, Subcommand)]
pub enum CredsAction {
    /// List saved credentials.
    List(CredsListArgs),
}

/// Options for saved credential listing.
#[derive(Debug, Args)]
pub struct CredsListArgs {
    /// Workspace to search; defaults to the current workspace.
    #[arg(long)]
    pub workspace: Option<String>,
    /// Protocol filter.
    #[arg(long, value_enum)]
    pub protocol: Option<Protocol>,
    /// Host/IP filter.
    #[arg(long)]
    pub host: Option<String>,
    /// Include connection URLs in output.
    #[arg(long)]
    pub conn_url: bool,
}

/// Supported protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Protocol {
    Ssh,
    Ftp,
    Mysql,
    Postgresql,
    Redis,
    Tomcat,
    Smb,
    Rdp,
    Winrm,
    Oracle,
    Http,
    Vnc,
    Zookeeper,
    Memcached,
    Mongodb,
    Elasticsearch,
    Docker,
    Snmp,
    Activemq,
    Rabbitmq,
    Rsync,
    Mssql,
    Kafka,
    Kibana,
    Nfs,
    Telnet,
    Ldap,
    Grafana,
    Prometheus,
    Jenkins,
    Couchdb,
    Clickhouse,
    Neo4j,
    Etcd,
    Influxdb,
    Kubelet,
    Gitlab,
    Solr,
    Minio,
    Nacos,
    Jboss,
    Nexus,
    Druid,
    Spark,
    Hadoop,
}

impl Protocol {
    /// Returns the default port associated with a protocol.
    pub fn default_port(self) -> u16 {
        match self {
            Self::Ssh => 22,
            Self::Ftp => 21,
            Self::Mysql => 3306,
            Self::Postgresql => 5432,
            Self::Redis => 6379,
            Self::Tomcat => 8080,
            Self::Http => 80,
            Self::Smb => 445,
            Self::Rdp => 3389,
            Self::Winrm => 5985,
            Self::Oracle => 1521,
            Self::Vnc => 5900,
            Self::Zookeeper => 2181,
            Self::Memcached => 11211,
            Self::Mongodb => 27017,
            Self::Elasticsearch => 9200,
            Self::Docker => 2375,
            Self::Snmp => 161,
            Self::Activemq => 61613,
            Self::Rabbitmq => 5672,
            Self::Rsync => 873,
            Self::Mssql => 1433,
            Self::Kafka => 9092,
            Self::Kibana => 5601,
            Self::Nfs => 2049,
            Self::Telnet => 23,
            Self::Ldap => 389,
            Self::Grafana => 3000,
            Self::Prometheus => 9090,
            Self::Jenkins => 8080,
            Self::Couchdb => 5984,
            Self::Clickhouse => 8123,
            Self::Neo4j => 7474,
            Self::Etcd => 2379,
            Self::Influxdb => 8086,
            Self::Kubelet => 10250,
            Self::Gitlab => 80,
            Self::Solr => 8983,
            Self::Minio => 9001,
            Self::Nacos => 8848,
            Self::Jboss => 9990,
            Self::Nexus => 8081,
            Self::Druid => 8888,
            Self::Spark => 8080,
            Self::Hadoop => 9870,
        }
    }

    /// Returns the stable lowercase protocol name used in storage.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Ftp => "ftp",
            Self::Mysql => "mysql",
            Self::Postgresql => "postgresql",
            Self::Redis => "redis",
            Self::Tomcat => "tomcat",
            Self::Smb => "smb",
            Self::Rdp => "rdp",
            Self::Winrm => "winrm",
            Self::Oracle => "oracle",
            Self::Http => "http",
            Self::Vnc => "vnc",
            Self::Zookeeper => "zookeeper",
            Self::Memcached => "memcached",
            Self::Mongodb => "mongodb",
            Self::Elasticsearch => "elasticsearch",
            Self::Docker => "docker",
            Self::Snmp => "snmp",
            Self::Activemq => "activemq",
            Self::Rabbitmq => "rabbitmq",
            Self::Rsync => "rsync",
            Self::Mssql => "mssql",
            Self::Kafka => "kafka",
            Self::Kibana => "kibana",
            Self::Nfs => "nfs",
            Self::Telnet => "telnet",
            Self::Ldap => "ldap",
            Self::Grafana => "grafana",
            Self::Prometheus => "prometheus",
            Self::Jenkins => "jenkins",
            Self::Couchdb => "couchdb",
            Self::Clickhouse => "clickhouse",
            Self::Neo4j => "neo4j",
            Self::Etcd => "etcd",
            Self::Influxdb => "influxdb",
            Self::Kubelet => "kubelet",
            Self::Gitlab => "gitlab",
            Self::Solr => "solr",
            Self::Minio => "minio",
            Self::Nacos => "nacos",
            Self::Jboss => "jboss",
            Self::Nexus => "nexus",
            Self::Druid => "druid",
            Self::Spark => "spark",
            Self::Hadoop => "hadoop",
        }
    }
}

impl ProtocolArgs {
    /// Returns the protocol represented by this subcommand.
    pub fn protocol(&self) -> Protocol {
        match self {
            Self::Ssh(_) => Protocol::Ssh,
            Self::Ftp(_) => Protocol::Ftp,
            Self::Mysql(_) => Protocol::Mysql,
            Self::Postgresql(_) => Protocol::Postgresql,
            Self::Redis(_) => Protocol::Redis,
            Self::Tomcat(_) => Protocol::Tomcat,
            Self::Smb(_) => Protocol::Smb,
            Self::Rdp(_) => Protocol::Rdp,
            Self::Winrm(_) => Protocol::Winrm,
            Self::Oracle(_) => Protocol::Oracle,
            Self::Http(_) => Protocol::Http,
            Self::Vnc(_) => Protocol::Vnc,
            Self::Zookeeper(_) => Protocol::Zookeeper,
            Self::Memcached(_) => Protocol::Memcached,
            Self::Mongodb(_) => Protocol::Mongodb,
            Self::Elasticsearch(_) => Protocol::Elasticsearch,
            Self::Docker(_) => Protocol::Docker,
            Self::Snmp(_) => Protocol::Snmp,
            Self::Activemq(_) => Protocol::Activemq,
            Self::Rabbitmq(_) => Protocol::Rabbitmq,
            Self::Rsync(_) => Protocol::Rsync,
            Self::Mssql(_) => Protocol::Mssql,
            Self::Kafka(_) => Protocol::Kafka,
            Self::Kibana(_) => Protocol::Kibana,
            Self::Nfs(_) => Protocol::Nfs,
            Self::Telnet(_) => Protocol::Telnet,
            Self::Ldap(_) => Protocol::Ldap,
            Self::Grafana(_) => Protocol::Grafana,
            Self::Prometheus(_) => Protocol::Prometheus,
            Self::Jenkins(_) => Protocol::Jenkins,
            Self::Couchdb(_) => Protocol::Couchdb,
            Self::Clickhouse(_) => Protocol::Clickhouse,
            Self::Neo4j(_) => Protocol::Neo4j,
            Self::Etcd(_) => Protocol::Etcd,
            Self::Influxdb(_) => Protocol::Influxdb,
            Self::Kubelet(_) => Protocol::Kubelet,
            Self::Gitlab(_) => Protocol::Gitlab,
            Self::Solr(_) => Protocol::Solr,
            Self::Minio(_) => Protocol::Minio,
            Self::Nacos(_) => Protocol::Nacos,
            Self::Jboss(_) => Protocol::Jboss,
            Self::Nexus(_) => Protocol::Nexus,
            Self::Druid(_) => Protocol::Druid,
            Self::Spark(_) => Protocol::Spark,
            Self::Hadoop(_) => Protocol::Hadoop,
        }
    }
}
