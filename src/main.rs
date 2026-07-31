//! Application entrypoint for the `brute` CLI.

use anyhow::Result;

/// Bootstraps the asynchronous runtime and launches the CLI application.
#[tokio::main]
async fn main() -> Result<()> {
    brute::tls::install_crypto_provider();
    brute::app::run().await
}
