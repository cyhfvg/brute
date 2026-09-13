//! Solr login, unauthorized access, and post-auth HTTP API (`-x`).
//!
//! Empty credentials probe `GET /solr/admin/info/system` without Authorization.
//! Non-empty credentials use HTTP Basic Auth.

use async_trait::async_trait;
use reqwest::StatusCode;

use crate::cli::HttpUrlScheme;
use crate::protocol::http::{build_http_basic_client, normalize_path};

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

/// Solr attempt errors split auth failures from post-auth command failures.
#[derive(Debug)]
enum SolrAttemptError {
    Auth(String),
    Transport(String),
    Command(String),
}

/// Solr module configuration.
#[derive(Debug, Clone)]
pub struct SolrModule;

impl SolrModule {
    /// Creates a new Solr module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`SolrModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::solr::SolrModule;
    ///
    /// let _module = SolrModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for SolrModule {
    fn name(&self) -> &'static str {
        "solr"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_system(ctx)).await {
            Ok(Some(message)) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        match tokio::time::timeout(ctx.timeout(), attempt_once(ctx)).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(SolrAttemptError::Auth(err))) => {
                AttemptOutcome::Failure(format!("solr auth failed: {err}"))
            }
            Ok(Err(SolrAttemptError::Transport(err))) => {
                AttemptOutcome::Error(format!("solr transport failed: {err}"))
            }
            Ok(Err(SolrAttemptError::Command(err))) => {
                let message = success_message(is_unauthenticated(ctx));
                AttemptOutcome::Success(AttemptSuccess::with_command_error(
                    message,
                    format!("solr command execution failed: {err}"),
                ))
            }
            Err(_) => AttemptOutcome::Error("attempt timed out".to_string()),
        }
    }
}

/// Runs one Solr login or unauthorized probe, then optional `-x`.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, SolrAttemptError> {
    let unauthenticated = is_unauthenticated(ctx);
    let client = build_http_basic_client(
        ctx.timeout(),
        HttpUrlScheme::Http,
        ctx.target.proxy.as_ref(),
    )
    .map_err(|err| SolrAttemptError::Transport(err.to_string()))?;
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let url = api_url(&ctx.target_host, port, "/solr/admin/info/system");
    let mut request = client.get(&url);
    if !unauthenticated {
        request = request.basic_auth(
            ctx.credential.username.as_deref().unwrap_or(""),
            Some(ctx.credential.password.as_deref().unwrap_or("")),
        );
    }
    let response = request
        .send()
        .await
        .map_err(|err| SolrAttemptError::Transport(err.to_string()))?;
    classify_status(response.status())?;
    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => execute_command(&client, ctx, command, unauthenticated, message).await,
        None => Ok(AttemptSuccess::new(message)),
    }
}

fn classify_status(status: StatusCode) -> Result<(), SolrAttemptError> {
    if status.is_success() {
        Ok(())
    } else if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        Err(SolrAttemptError::Auth(
            "invalid username or password".to_string(),
        ))
    } else {
        Err(SolrAttemptError::Transport(format!(
            "unexpected HTTP status: {status}"
        )))
    }
}

async fn execute_command(
    client: &reqwest::Client,
    ctx: &AttemptContext,
    command: &str,
    unauthenticated: bool,
    success_message: &str,
) -> Result<AttemptSuccess, SolrAttemptError> {
    let path = execute_path(command);
    let url = api_url(
        &ctx.target_host,
        ctx.target.port.unwrap_or(ctx.protocol.default_port()),
        &path,
    );
    let mut request = client.get(&url);
    if !unauthenticated {
        request = request.basic_auth(
            ctx.credential.username.as_deref().unwrap_or(""),
            Some(ctx.credential.password.as_deref().unwrap_or("")),
        );
    }
    let response = request
        .send()
        .await
        .map_err(|err| SolrAttemptError::Command(err.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| SolrAttemptError::Command(err.to_string()))?;
    if status.is_success() {
        Ok(AttemptSuccess::with_command(
            success_message,
            trim_body(&body),
        ))
    } else {
        Err(SolrAttemptError::Command(format!(
            "HTTP {status}: {}",
            trim_body(&body)
        )))
    }
}

/// Builds `http://host:port{path}` for Solr HTTP.
///
/// # Parameters
///
/// - `host`: Target host.
/// - `port`: Service port.
/// - `path`: Absolute path.
///
/// # Returns
///
/// URL string.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::solr::api_url;
///
/// assert_eq!(
///     api_url("10.0.0.5", 8983, "/solr/admin/cores"),
///     "http://10.0.0.5:8983/solr/admin/cores"
/// );
/// ```
pub fn api_url(host: &str, port: u16, path: &str) -> String {
    format!("http://{host}:{port}{path}")
}

/// Normalizes `-x` text into a Solr admin path.
///
/// # Parameters
///
/// - `command`: CLI `-x` value (`cores`, `system`, or a path).
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
/// use brute::protocol::solr::execute_path;
///
/// assert_eq!(execute_path("cores"), "/solr/admin/cores?wt=json");
/// assert_eq!(execute_path("/solr/admin/info/system"), "/solr/admin/info/system");
/// ```
pub fn execute_path(command: &str) -> String {
    let trimmed = command.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "cores" => "/solr/admin/cores?wt=json".to_string(),
        "system" | "info" => "/solr/admin/info/system?wt=json".to_string(),
        "collections" => "/solr/admin/collections?action=LIST&wt=json".to_string(),
        other => normalize_path(other),
    }
}

/// Extracts `Solr <version>` from the system info JSON.
///
/// # Parameters
///
/// - `body`: `/solr/admin/info/system` body.
///
/// # Returns
///
/// Banner such as `Solr 9.6.1`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::solr::parse_system_banner;
///
/// let body = r#"{"lucene":{"solr-spec-version":"9.6.1"}}"#;
/// assert_eq!(parse_system_banner(body).as_deref(), Some("Solr 9.6.1"));
/// ```
pub fn parse_system_banner(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let version = value
        .get("lucene")
        .and_then(|lucene| lucene.get("solr-spec-version"))
        .and_then(serde_json::Value::as_str)?;
    if version.is_empty() {
        None
    } else {
        Some(format!("Solr {version}"))
    }
}

async fn probe_system(ctx: &TargetContext) -> Option<String> {
    let client = build_http_basic_client(
        ctx.timeout(),
        HttpUrlScheme::Http,
        ctx.target.proxy.as_ref(),
    )
    .ok()?;
    let url = api_url(&ctx.target_host, ctx.port(), "/solr/admin/info/system");
    let response = client.get(&url).send().await.ok()?;
    let status = response.status();
    let body = response.text().await.ok()?;
    if let Some(banner) = parse_system_banner(&body) {
        return Some(banner);
    }
    if status.is_success() || status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN
    {
        Some("Solr".to_string())
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

fn is_unauthenticated(ctx: &AttemptContext) -> bool {
    ctx.credential.username.as_deref().unwrap_or("").is_empty()
        && ctx.credential.password.as_deref().unwrap_or("").is_empty()
}

fn success_message(unauthenticated: bool) -> &'static str {
    if unauthenticated {
        "Solr unauthorized access!"
    } else {
        "Solr access!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_path_maps_shorthand() {
        assert_eq!(execute_path("cores"), "/solr/admin/cores?wt=json");
        assert_eq!(execute_path("system"), "/solr/admin/info/system?wt=json");
    }
}
