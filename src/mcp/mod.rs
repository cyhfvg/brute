//! Model Context Protocol server for authorized credential testing.
//!
//! Starts a stdio JSON-RPC server so an LLM host can verify accounts, spray
//! passwords, and query credentials already stored in the local workspace DB.

mod server;
mod tools;

use anyhow::{Context, Result};
use rmcp::{ServiceExt, transport::stdio};

use crate::database::CredentialDatabase;

use server::BruteMcp;

/// Serves brute capabilities over MCP stdio until the client disconnects.
///
/// # Parameters
///
/// - `database`: Open credential database shared with the CLI.
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
/// brute::mcp::serve_stdio(database).await?;
/// ```
pub async fn serve_stdio(database: CredentialDatabase) -> Result<()> {
    let service = BruteMcp::new(database)
        .serve(stdio())
        .await
        .context("failed to start MCP stdio server")?;
    service
        .waiting()
        .await
        .context("MCP stdio server terminated unexpectedly")?;
    Ok(())
}
