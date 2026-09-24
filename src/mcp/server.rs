//! rmcp tool router exposing brute verify, spray, and credential store tools.

use rmcp::{
    ErrorData, ServerHandler,
    handler::server::wrapper::Parameters,
    model::{Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};

use crate::database::CredentialDatabase;
use crate::engine::{
    delete_credentials, list_protocols, list_workspaces, query_credentials, run_spray,
};

use super::tools::{
    DeleteCredentialsParams, ListCredentialsParams, SprayPasswordsParams, VerifyAccountParams,
    VerifyConnectionsParams,
};

/// MCP server that reuses the local brute credential database.
#[derive(Clone)]
pub struct BruteMcp {
    database: CredentialDatabase,
}

impl BruteMcp {
    /// Constructs an MCP handler bound to an open credential database.
    ///
    /// # Parameters
    ///
    /// - `database`: Shared SQLite workspace/credential store.
    ///
    /// # Returns
    ///
    /// A cloneable handler for the rmcp stdio service.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let server = BruteMcp::new(database);
    /// ```
    pub fn new(database: CredentialDatabase) -> Self {
        Self { database }
    }
}

#[tool_router]
impl BruteMcp {
    /// Verifies one account against one target.
    ///
    /// Use this for a single username/password (or saved credential id). Successful
    /// logins are saved to the selected workspace. Authorized targets only.
    #[tool(
        name = "verify_account",
        description = "Verify one account against one target. Use for a single username/password or saved credential id. Successful logins are saved to the selected workspace. Authorized targets only."
    )]
    async fn verify_account(
        &self,
        Parameters(params): Parameters<VerifyAccountParams>,
    ) -> Result<String, ErrorData> {
        let request = params
            .into_request()
            .map_err(|err| ErrorData::invalid_params(err.to_string(), None))?;
        let report = run_spray(&self.database, request, None)
            .await
            .map_err(|err| ErrorData::internal_error(err.to_string(), None))?;
        to_json(&report)
    }

    /// Sprays passwords across one or more targets and username lists.
    ///
    /// Expands username x password (and Oracle identifier) combinations under
    /// the global thread cap. Successful logins are saved to the workspace.
    /// Authorized targets only.
    #[tool(
        name = "spray_passwords",
        description = "Password-spray one or more targets. Accepts username/password lists or wordlist paths, optional saved credential id, and protocol options. Successful logins are saved. Authorized targets only."
    )]
    async fn spray_passwords(
        &self,
        Parameters(params): Parameters<SprayPasswordsParams>,
    ) -> Result<String, ErrorData> {
        let request = params
            .into_request()
            .map_err(|err| ErrorData::invalid_params(err.to_string(), None))?;
        let report = run_spray(&self.database, request, None)
            .await
            .map_err(|err| ErrorData::internal_error(err.to_string(), None))?;
        to_json(&report)
    }

    /// Lists credentials already verified and stored by brute.
    #[tool(
        name = "list_credentials",
        description = "Query credentials already verified by brute. Filter by workspace, protocol, and host. Returns plaintext usernames, passwords, and connection URLs from the local SQLite store."
    )]
    fn list_credentials(
        &self,
        Parameters(params): Parameters<ListCredentialsParams>,
    ) -> Result<String, ErrorData> {
        let protocol = match params.protocol.as_deref() {
            Some(name) => Some(
                crate::engine::parse_protocol(name)
                    .map_err(|err| ErrorData::invalid_params(err.to_string(), None))?,
            ),
            None => None,
        };
        let credentials = query_credentials(
            &self.database,
            params.workspace.as_deref(),
            protocol,
            params.host.as_deref(),
        )
        .map_err(|err| ErrorData::internal_error(err.to_string(), None))?;
        to_json(&credentials)
    }

    /// Deletes saved credentials from the local workspace store.
    #[tool(
        name = "delete_credentials",
        description = "Delete saved credentials in one workspace by id, protocol, host, or all. Refuses an unscoped delete. Returns deleted records, including passwords, and missing ids."
    )]
    fn delete_credentials(
        &self,
        Parameters(params): Parameters<DeleteCredentialsParams>,
    ) -> Result<String, ErrorData> {
        let protocol = match params.protocol.as_deref() {
            Some(name) => Some(
                crate::engine::parse_protocol(name)
                    .map_err(|err| ErrorData::invalid_params(err.to_string(), None))?,
            ),
            None => None,
        };
        let report = delete_credentials(
            &self.database,
            params.workspace.as_deref(),
            protocol,
            params.host.as_deref(),
            &params.ids,
            params.all,
        )
        .map_err(credential_delete_error)?;
        to_json(&report)
    }

    /// Lists local credential workspaces.
    #[tool(
        name = "list_workspaces",
        description = "List local brute workspaces and mark the current workspace."
    )]
    fn list_workspaces(&self) -> Result<String, ErrorData> {
        let workspaces = list_workspaces(&self.database)
            .map_err(|err| ErrorData::internal_error(err.to_string(), None))?;
        to_json(&workspaces)
    }

    /// Lists protocols brute can verify or spray.
    #[tool(
        name = "list_protocols",
        description = "List supported brute protocols and their default TCP ports."
    )]
    fn list_protocols(&self) -> Result<String, ErrorData> {
        to_json(&list_protocols())
    }

    /// Verifies paired connection URLs from a file and/or inline list.
    #[tool(
        name = "verify_connections",
        description = "Verify paired connection URLs such as ssh://root:password@192.168.5.1:22. Empty username, empty password, and omitted port are attempted; https with no port uses 443. Oracle needs ?service= or ?sid=. Use only against authorized targets. Successes are saved to the local SQLite workspace."
    )]
    async fn verify_connections(
        &self,
        Parameters(params): Parameters<VerifyConnectionsParams>,
    ) -> Result<String, ErrorData> {
        let (sources, options) = params
            .into_run()
            .map_err(|err| ErrorData::invalid_params(err.to_string(), None))?;
        let connections = crate::connections::load_connection_sources(&sources)
            .map_err(|err| ErrorData::invalid_params(err.to_string(), None))?;
        let report = crate::combo::run_connections(&self.database, connections, options, None)
            .await
            .map_err(|err| ErrorData::internal_error(err.to_string(), None))?;
        to_json(&report)
    }
}

#[tool_handler]
impl ServerHandler for BruteMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("brute", env!("CARGO_PKG_VERSION"))
                    .with_title("brute")
                    .with_description(
                        "Authorized multi-protocol credential verification and password spray",
                    ),
            )
            .with_instructions(concat!(
                "Use brute only against systems you are authorized to test. ",
                "verify_account checks one account. spray_passwords tests username/password ",
                "lists. delete_credentials removes saved rows by id, protocol, host, or all ",
                "and refuses an unscoped delete. list_workspaces and list_protocols help choose ",
                "filters. Successful verifications are persisted automatically."
            ))
    }
}

fn to_json<T: serde::Serialize>(value: &T) -> Result<String, ErrorData> {
    serde_json::to_string_pretty(value).map_err(|err| {
        ErrorData::internal_error(format!("failed to encode MCP result: {err}"), None)
    })
}

/// Maps credential-delete failures to MCP parameter or internal errors.
fn credential_delete_error(err: anyhow::Error) -> ErrorData {
    let message = err.to_string();
    if message.starts_with("refusing to delete") || message.starts_with("all cannot be combined") {
        ErrorData::invalid_params(message, None)
    } else {
        ErrorData::internal_error(message, None)
    }
}
