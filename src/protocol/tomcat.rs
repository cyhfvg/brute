//! Apache Tomcat Manager brute-force implementation.

use async_trait::async_trait;
use reqwest::{Client, StatusCode};

use super::{AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule};

/// Tomcat Manager module configuration.
#[derive(Debug, Clone)]
pub struct TomcatManagerModule;

impl TomcatManagerModule {
    /// Creates a new Tomcat Manager module instance.
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for TomcatManagerModule {
    fn name(&self) -> &'static str {
        "tomcat"
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        let username = ctx.credential.username.clone().unwrap_or_default();
        let password = ctx.credential.password.clone().unwrap_or_default();
        let url = format!(
            "http://{}:{}{}",
            ctx.target_host,
            ctx.target.port.unwrap_or(ctx.protocol.default_port()),
            normalize_path(ctx.path.as_deref().unwrap_or("/manager/html"))
        );

        let client = match Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(ctx.timeout())
            .build()
        {
            Ok(client) => client,
            Err(err) => return AttemptOutcome::Error(format!("http client build failed: {err}")),
        };

        match client
            .get(url)
            .basic_auth(username, Some(password))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                AttemptOutcome::Success(AttemptSuccess::new("Tomcat Manager access!"))
            }
            Ok(response) if response.status() == StatusCode::UNAUTHORIZED => {
                AttemptOutcome::Failure("tomcat manager rejected credentials".to_string())
            }
            Ok(response) if response.status() == StatusCode::FORBIDDEN => {
                AttemptOutcome::Success(AttemptSuccess::new(
                    "Credentials accepted but account lacks manager role (HTTP 403)",
                ))
            }
            Ok(response) => {
                AttemptOutcome::Error(format!("unexpected HTTP status: {}", response.status()))
            }
            Err(err) => AttemptOutcome::Error(format!("http request failed: {err}")),
        }
    }
}

/// Ensures the request path is absolute.
fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}
