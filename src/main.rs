//! Application entrypoint for the `brute` CLI.

mod app;
mod cli;
mod credentials;
mod database;
mod error;
mod output;
mod protocol;
mod targets;
mod tls;

use anyhow::Result;

/// Bootstraps the asynchronous runtime and launches the CLI application.
#[tokio::main]
async fn main() -> Result<()> {
    tls::install_crypto_provider();
    app::run().await
}
