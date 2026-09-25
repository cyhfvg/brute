//! Elasticsearch login, unauthorized access, and post-auth HTTP API commands.
//!
//! Empty username and password probe `GET /` without an Authorization header.
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

/// Elasticsearch attempt errors split auth failures from post-auth command failures.
type EsAttemptError = crate::protocol::http_attempt::HttpAttemptFailure;

/// Elasticsearch module configuration.
#[derive(Debug, Clone)]
pub struct ElasticsearchModule;

impl ElasticsearchModule {
    /// Creates a new Elasticsearch module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Per-attempt timeout in milliseconds. Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`ElasticsearchModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::elasticsearch::ElasticsearchModule;
    ///
    /// let _module = ElasticsearchModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for ElasticsearchModule {
    fn name(&self) -> &'static str {
        "elasticsearch"
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
            "elasticsearch",
            || success_message(credentials_absent(ctx)),
            attempt_once(ctx),
        )
        .await
    }
}

/// Runs one Elasticsearch login or unauthorized probe, then optional `-x`.
///
/// # Parameters
///
/// - `ctx`: Target, credential, timeout, proxy, and optional execute path.
///
/// # Returns
///
/// [`AttemptSuccess`] when `GET /` accepts the credentials (or anonymous access).
///
/// # Errors
///
/// Returns [`EsAttemptError::Auth`] on HTTP 401, [`EsAttemptError::Transport`] on
/// connect failures, and [`EsAttemptError::Command`] for post-auth API errors.
///
/// # Examples
///
/// ```ignore
/// let success = attempt_once(&ctx).await?;
/// ```
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, EsAttemptError> {
    let unauthenticated = credentials_absent(ctx);
    let client = open_attempt_client(ctx)?;
    let url = http_attempt_url(ctx, "/");
    let mut request = client.get(&url);
    request = with_basic_auth(request, ctx);
    let response = request
        .send()
        .await
        .map_err(|err| EsAttemptError::Transport(err.to_string()))?;
    classify_basic_status(response.status(), HttpForbiddenPolicy::CredentialHit)?;

    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => execute_es_command(&client, ctx, command, message).await,
        None => Ok(AttemptSuccess::new(message)),
    }
}

/// Executes a post-auth Elasticsearch HTTP GET against `-x` as a path.
///
/// # Parameters
///
/// - `client`: Shared reqwest client.
/// - `ctx`: Target host, port, and credentials.
/// - `command`: Path such as `_cat/indices` or `/_cluster/health`.
/// - `success_message`: Login banner.
///
/// # Returns
///
/// [`AttemptSuccess`] with response body preview.
///
/// # Errors
///
/// Returns [`EsAttemptError::Command`] when the API call fails.
async fn execute_es_command(
    client: &reqwest::Client,
    ctx: &AttemptContext,
    command: &str,
    success_message: &str,
) -> Result<AttemptSuccess, EsAttemptError> {
    let path = execute_path(command);
    let url = http_attempt_url(ctx, &path);
    let mut request = client.get(&url);
    request = with_basic_auth(request, ctx);
    let response = request
        .send()
        .await
        .map_err(|err| EsAttemptError::Command(err.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| EsAttemptError::Command(err.to_string()))?;
    if status.is_success() {
        Ok(AttemptSuccess::with_command(
            success_message,
            trim_body(&body),
        ))
    } else {
        Err(EsAttemptError::Command(format!(
            "HTTP {status}: {}",
            trim_body(&body)
        )))
    }
}

/// Normalizes `-x` text into an absolute request path.
///
/// # Parameters
///
/// - `command`: CLI `-x` value (`_cat/indices`, `/_cluster/health`, shorthand `indices`).
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
/// use brute::protocol::elasticsearch::execute_path;
///
/// assert_eq!(execute_path("indices"), "/_cat/indices?v");
/// assert_eq!(execute_path("_cluster/health"), "/_cluster/health");
/// ```
pub fn execute_path(command: &str) -> String {
    let trimmed = command.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "indices" | "cat" | "_cat/indices" => "/_cat/indices?v".to_string(),
        "health" | "_cluster/health" => "/_cluster/health".to_string(),
        "nodes" | "_cat/nodes" => "/_cat/nodes?v".to_string(),
        other => normalize_path(other),
    }
}

/// Probes `GET /` without credentials and formats a version banner.
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
        Some("Elasticsearch".to_string())
    } else {
        None
    }
}

/// Extracts `Elasticsearch <version>` from the root JSON document.
///
/// # Parameters
///
/// - `body`: `GET /` response body.
///
/// # Returns
///
/// Banner such as `Elasticsearch 7.17.28`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::elasticsearch::parse_root_banner;
///
/// let body = r#"{"name":"n1","cluster_name":"docker-cluster","version":{"number":"7.17.28"}}"#;
/// assert_eq!(
///     parse_root_banner(body).as_deref(),
///     Some("Elasticsearch 7.17.28")
/// );
/// ```
pub fn parse_root_banner(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let version = value
        .get("version")
        .and_then(|v| v.get("number"))
        .and_then(serde_json::Value::as_str)?;
    if version.is_empty() {
        None
    } else {
        Some(format!("Elasticsearch {version}"))
    }
}

/// Truncates API bodies for terminal output.
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
        "Elasticsearch unauthorized access!"
    } else {
        "Elasticsearch access!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_path_maps_shorthand() {
        assert_eq!(execute_path("indices"), "/_cat/indices?v");
        assert_eq!(execute_path("/_cluster/health"), "/_cluster/health");
    }

    #[test]
    fn parse_root_banner_reads_version_number() {
        let body = r#"{"version":{"number":"7.17.28"},"tagline":"You Know, for Search"}"#;
        assert_eq!(
            parse_root_banner(body).as_deref(),
            Some("Elasticsearch 7.17.28")
        );
        assert_eq!(parse_root_banner("not-json"), None);
    }
}
