//! Command-line parsing types.

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Root CLI definition.
#[derive(Debug, Parser)]
#[command(
    name = "brute",
    version,
    about = "A multi-protocol credential attack and login verification utility",
    subcommand_value_name = "COMMAND",
    subcommand_help_heading = "commands"
)]
pub struct Cli {
    /// Disable ANSI colors in the terminal output.
    #[arg(long)]
    pub no_color: bool,

    #[command(subcommand)]
    pub command: Command,
}

/// Top-level command groups.
#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(flatten)]
    Protocol(ProtocolArgs),
    #[command(about = "Manage credential workspaces")]
    Workspace(WorkspaceArgs),
    #[command(about = "Search saved credentials")]
    Creds(CredsArgs),
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
        after_help = "Example:\n  brute smb 192.168.5.5 -u admin -p 123456"
    )]
    Smb(CommonArgs),

    #[command(
        about = "own stuff using RDP",
        override_usage = "brute rdp <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute rdp 192.168.5.5 -u admin -p 123456"
    )]
    Rdp(CommonArgs),

    #[command(
        about = "own stuff using WINRM",
        override_usage = "brute winrm <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute winrm 192.168.5.5 -u admin -p 123456"
    )]
    Winrm(CommonArgs),

    #[command(
        about = "own stuff using ORACLE",
        override_usage = "brute oracle <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute oracle 192.168.5.5 -u system -p oracle"
    )]
    Oracle(CommonArgs),

    #[command(
        about = "own stuff using HTTP",
        override_usage = "brute http <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute http 192.168.5.5 -u admin -p 123456 --path /login"
    )]
    Http(HttpArgs),

    #[command(
        about = "own stuff using VNC",
        override_usage = "brute vnc <TARGET> (-u <USERNAME>... -p <PASSWORD>... | --id <ID>) [OPTIONS] ...",
        after_help = "Example:\n  brute vnc 192.168.5.5 -u '' -p 123456"
    )]
    Vnc(CommonArgs),
}

impl ProtocolArgs {
    /// Returns a shared view over the common options.
    pub fn common(&self) -> &CommonArgs {
        match self {
            Self::Ssh(args)
            | Self::Ftp(args)
            | Self::Mysql(args)
            | Self::Postgresql(args)
            | Self::Redis(args) => &args.common,
            Self::Smb(args)
            | Self::Rdp(args)
            | Self::Winrm(args)
            | Self::Oracle(args)
            | Self::Vnc(args) => args,
            Self::Tomcat(args) => &args.common,
            Self::Http(args) => &args.common,
        }
    }

    /// Returns a request path for HTTP-like modules.
    pub fn path(&self) -> Option<&str> {
        match self {
            Self::Tomcat(args) => Some(&args.path),
            Self::Http(args) => Some(&args.path),
            _ => None,
        }
    }

    /// Returns the post-authentication command for protocols that support it.
    pub fn execute(&self) -> Option<&str> {
        match self {
            Self::Ssh(args)
            | Self::Ftp(args)
            | Self::Mysql(args)
            | Self::Postgresql(args)
            | Self::Redis(args) => args.execute.as_deref(),
            _ => None,
        }
    }
}

/// Common options shared by all protocols.
#[derive(Debug, Clone, Args)]
pub struct CommonArgs {
    /// Target IP(s), hostname(s), FQDN(s), or file path(s) containing targets.
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
    /// Number of concurrent attempts.
    #[arg(long, default_value_t = 16)]
    pub threads: usize,
    /// Maximum concurrent attempts against the same target.
    #[arg(long, default_value_t = 1)]
    pub target_threads: usize,
    /// Retry count for transient transport failures.
    #[arg(long, default_value_t = 3)]
    pub retries: usize,
    /// Timeout per attempt in milliseconds.
    #[arg(long, default_value_t = 5000)]
    pub timeout_ms: u64,
    /// Continue authentication attempts even after successes.
    #[arg(long)]
    pub continue_on_success: bool,
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

/// Options for Apache Tomcat Manager.
#[derive(Debug, Clone, Args)]
pub struct TomcatArgs {
    #[command(flatten)]
    pub common: CommonArgs,
    /// Request path for the Tomcat Manager endpoint.
    #[arg(long, default_value = "/manager/html")]
    pub path: String,
}

/// Options for generic HTTP modules.
#[derive(Debug, Clone, Args)]
pub struct HttpArgs {
    #[command(flatten)]
    pub common: CommonArgs,
    /// Request path used by the HTTP module.
    #[arg(long, default_value = "/")]
    pub path: String,
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
            Self::Tomcat | Self::Http => 8080,
            Self::Smb => 445,
            Self::Rdp => 3389,
            Self::Winrm => 5985,
            Self::Oracle => 1521,
            Self::Vnc => 5900,
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
        }
    }
}
