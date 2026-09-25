//! Apache Tomcat Manager brute-force implementation.

use super::{AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule};
use async_trait::async_trait;

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
        let path = normalize_path(ctx.path.as_deref().unwrap_or("/manager/html"));
        let url = super::http::build_http_basic_url(
            ctx.url_scheme,
            &ctx.target_host,
            ctx.target.port.unwrap_or(ctx.protocol.default_port()),
            &path,
        );
        let client = match super::http::build_http_basic_client(
            ctx.timeout(),
            ctx.url_scheme,
            ctx.target.proxy.as_ref(),
        ) {
            Ok(client) => client,
            Err(err) => {
                return AttemptOutcome::Error(format!("http client build failed: {err}"));
            }
        };

        let response = match client
            .get(url)
            .basic_auth(username, Some(password))
            .send()
            .await
        {
            Ok(response) => response,
            Err(err) => return AttemptOutcome::Error(format!("http request failed: {err}")),
        };
        match super::http_auth::classify_http_auth_status(
            response.status(),
            super::http_auth::HttpForbiddenPolicy::CredentialHit,
        ) {
            super::http_auth::HttpAuthDecision::Success if response.status().is_success() => {
                AttemptOutcome::Success(AttemptSuccess::new("Tomcat Manager access!"))
            }
            super::http_auth::HttpAuthDecision::Success => {
                AttemptOutcome::Success(AttemptSuccess::new(
                    "Credentials accepted but account lacks manager role (HTTP 403)",
                ))
            }
            super::http_auth::HttpAuthDecision::AuthFailure => {
                AttemptOutcome::Failure("tomcat manager rejected credentials".to_string())
            }
            super::http_auth::HttpAuthDecision::Transport => {
                AttemptOutcome::Error(format!("unexpected HTTP status: {}", response.status()))
            }
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
