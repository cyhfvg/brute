//! Model Context Protocol server for authorized credential testing.
//!
//! Starts a stdio JSON-RPC server so an LLM host can verify accounts, spray
//! passwords, and query credentials already stored in the local workspace DB.

mod server;
mod tools;

use anyhow::{Context, Result};
use rmcp::{ServiceExt, transport::stdio};
use tokio_util::sync::CancellationToken;

use crate::database::CredentialDatabase;

use server::BruteMcp;

/// Serves brute capabilities over MCP stdio until the client disconnects.
///
/// # Parameters
///
/// - `database`: Open credential database shared with the CLI.
/// - `cancel`: Process token. Client request cancellation is a child of this token.
///
/// # Returns
///
/// `Ok(())` after a clean client shutdown.
///
/// # Errors
///
/// Returns an error when the stdio transport cannot start or the service loop
/// fails after initialization.
///
/// # Examples
///
/// ```ignore
/// brute::mcp::serve_stdio(database, cancel).await?;
/// ```
pub async fn serve_stdio(database: CredentialDatabase, cancel: CancellationToken) -> Result<()> {
    let service = BruteMcp::new(database)
        .serve_with_ct(stdio(), cancel)
        .await
        .context("failed to start MCP stdio server")?;
    service
        .waiting()
        .await
        .context("MCP stdio server terminated unexpectedly")?;
    Ok(())
}
