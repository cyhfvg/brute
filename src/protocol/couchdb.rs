//! CouchDB login, unauthorized access, and post-auth HTTP API (`-x`).
//!
//! Empty username and password probe `GET /` without Authorization.
//! Non-empty credentials use HTTP Basic Auth against the same endpoint.

use async_trait::async_trait;
use reqwest::StatusCode;

use crate::protocol::http::normalize_path;

use super::http_attempt::{
    classify_basic_status, credentials_absent, http_attempt_url, http_target_url,
    open_attempt_client, target_http_client, with_basic_auth,
};
use super::http_auth::HttpForbiddenPolicy;
use super::{AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext};

/// CouchDB attempt errors split auth failures from post-auth command failures.
type CouchAttemptError = crate::protocol::http_attempt::HttpAttemptFailure;

/// CouchDB module configuration.
#[derive(Debug, Clone)]
pub struct CouchDbModule;

impl CouchDbModule {
    /// Creates a new CouchDB module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`CouchDbModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::couchdb::CouchDbModule;
    ///
    /// let _module = CouchDbModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for CouchDbModule {
    fn name(&self) -> &'static str {
        "couchdb"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> Option<String> {
        match tokio::time::timeout(ctx.timeout(), probe_root(ctx)).await {
            Ok(Some(message)) => Some(message),
            _ => None,
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        crate::protocol::http_attempt::run_http_attempt(
            ctx.timeout(),
            "couchdb",
            || success_message(credentials_absent(ctx)),
            attempt_once(ctx),
        )
        .await
    }
}

/// Runs one CouchDB login or unauthorized probe, then optional `-x`.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, CouchAttemptError> {
    let unauthenticated = credentials_absent(ctx);
    let client = open_attempt_client(ctx)?;
    let url = http_attempt_url(ctx, "/");
    let mut request = client.get(&url);
    request = with_basic_auth(request, ctx);
    let response = request
        .send()
        .await
        .map_err(|err| CouchAttemptError::Transport(err.to_string()))?;
    classify_basic_status(response.status(), HttpForbiddenPolicy::CredentialHit)?;
    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => execute_command(&client, ctx, command, message).await,
        None => Ok(AttemptSuccess::new(message)),
    }
}

async fn execute_command(
    client: &reqwest::Client,
    ctx: &AttemptContext,
    command: &str,
    success_message: &str,
) -> Result<AttemptSuccess, CouchAttemptError> {
    let path = execute_path(command);
    let url = http_attempt_url(ctx, &path);
    let mut request = client.get(&url);
    request = with_basic_auth(request, ctx);
    let response = request
        .send()
        .await
        .map_err(|err| CouchAttemptError::Command(err.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| CouchAttemptError::Command(err.to_string()))?;
    if status.is_success() {
        Ok(AttemptSuccess::with_command(
            success_message,
            trim_body(&body),
        ))
    } else {
        Err(CouchAttemptError::Command(format!(
            "HTTP {status}: {}",
            trim_body(&body)
        )))
    }
}

/// Normalizes `-x` text into a CouchDB API path.
///
/// # Parameters
///
/// - `command`: CLI `-x` value (`dbs`, `up`, or a path).
///
/// # Returns
///
/// Absolute path.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::couchdb::execute_path;
///
/// assert_eq!(execute_path("dbs"), "/_all_dbs");
/// assert_eq!(execute_path("/_up"), "/_up");
/// ```
pub fn execute_path(command: &str) -> String {
    let trimmed = command.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "dbs" | "all_dbs" | "_all_dbs" => "/_all_dbs".to_string(),
        "up" | "_up" => "/_up".to_string(),
        "uuids" => "/_uuids".to_string(),
        other => normalize_path(other),
    }
}

/// Extracts `CouchDB <version>` from the root JSON welcome document.
///
/// # Parameters
///
/// - `body`: `GET /` response body.
///
/// # Returns
///
/// Banner such as `CouchDB 3.3.3`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::couchdb::parse_root_banner;
///
/// let body = r#"{"couchdb":"Welcome","version":"3.3.3"}"#;
/// assert_eq!(parse_root_banner(body).as_deref(), Some("CouchDB 3.3.3"));
/// ```
pub fn parse_root_banner(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let version = value.get("version").and_then(serde_json::Value::as_str)?;
    if version.is_empty() {
        None
    } else {
        Some(format!("CouchDB {version}"))
    }
}

async fn probe_root(ctx: &TargetContext) -> Option<String> {
    let client = target_http_client(ctx).ok()?;
    let url = http_target_url(ctx, "/");
    let response = client.get(&url).send().await.ok()?;
    let status = response.status();
    let body = response.text().await.ok()?;
    if let Some(banner) = parse_root_banner(&body) {
        return Some(banner);
    }
    if status.is_success() || status == StatusCode::UNAUTHORIZED {
        Some("CouchDB".to_string())
    } else {
        None
    }
}

fn trim_body(body: &str) -> String {
    const MAX: usize = 8192;
    let trimmed = body.trim();
    if trimmed.len() > MAX {
        format!("{}\n...", &trimmed[..MAX])
    } else {
        trimmed.to_string()
    }
}

fn success_message(unauthenticated: bool) -> &'static str {
    if unauthenticated {
        "CouchDB unauthorized access!"
    } else {
        "CouchDB access!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_path_maps_shorthand() {
        assert_eq!(execute_path("dbs"), "/_all_dbs");
        assert_eq!(execute_path("/_up"), "/_up");
    }

    #[test]
    fn parse_root_banner_reads_version() {
        let body = r#"{"couchdb":"Welcome","version":"3.3.3"}"#;
        assert_eq!(parse_root_banner(body).as_deref(), Some("CouchDB 3.3.3"));
        assert_eq!(parse_root_banner("not-json"), None);
    }
}
