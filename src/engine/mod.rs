//! Programmatic spray, verify, and credential-query engine.
//!
//! Shared by the CLI and the MCP server so both paths persist successes to the
//! same SQLite workspace store and return structured attempt records.

mod query;
mod run;
mod types;

pub use query::{list_protocols, list_workspaces, protocol_names, query_credentials};
pub use run::run_spray;
pub use types::{
    AttemptRecord, AttemptStatus, CredentialRecord, ProbeRecord, ProtocolInfo, SprayReport,
    SprayReporter, SprayRequest, WorkspaceInfo, parse_http_scheme, parse_protocol,
    parse_shell_type,
};
