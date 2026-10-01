//! Programmatic spray, verify, and credential-store engine.
//!
//! Shared by the CLI and the MCP server so both paths persist successes to the
//! same SQLite workspace store and return structured attempt records.

mod attempt;
mod pacing;
mod paired;
mod query;
mod run;
mod types;

pub use pacing::paced_delay_ms;
pub use paired::run_paired_spray;
pub use query::{
    delete_credentials, list_protocols, list_workspaces, protocol_names, query_credentials,
};
pub(crate) use run::attempt_record_from_outcome;
pub use run::{probe_target, run_command, run_spray};
pub use types::{
    AttemptRecord, AttemptStatus, CommandResult, CredentialDeleteReport, CredentialRecord,
    ProbeRecord, ProtocolInfo, SprayReport, SprayReporter, SprayRequest, WorkspaceInfo,
    parse_credential_order, parse_http_scheme, parse_pg_ssl_mode, parse_protocol, parse_shell_type,
};
