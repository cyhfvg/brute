//! Application entrypoint for the `brute` CLI.

mod app;
mod cli;
mod credentials;
mod database;
mod error;
mod output;
mod protocol;
mod targets;

use anyhow::Result;

/// Bootstraps the asynchronous runtime and launches the CLI application.
#[tokio::main]
async fn main() -> Result<()> {
    app::run().await
}
