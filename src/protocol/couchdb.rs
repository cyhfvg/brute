//! CouchDB login, unauthorized access, and post-auth HTTP API (`-x`).
//!
//! Empty username and password probe `GET /` without Authorization.
//! Non-empty credentials use HTTP Basic Auth against the same endpoint.

use async_trait::async_trait;
use reqwest::StatusCode;

use crate::cli::HttpUrlScheme;
use crate::protocol::http::{build_http_basic_client, normalize_path};

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

/// CouchDB attempt errors split auth failures from post-auth command failures.
#[derive(Debug)]
enum CouchAttemptError {
    Auth(String),
    Transport(String),
    Command(String),
}

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

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_root(ctx)).await {
            Ok(Some(message)) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        match tokio::time::timeout(ctx.timeout(), attempt_once(ctx)).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(CouchAttemptError::Auth(err))) => {
                AttemptOutcome::Failure(format!("couchdb auth failed: {err}"))
            }
            Ok(Err(CouchAttemptError::Transport(err))) => {
                AttemptOutcome::Error(format!("couchdb transport failed: {err}"))
            }
            Ok(Err(CouchAttemptError::Command(err))) => {
                let message = success_message(is_unauthenticated(ctx));
                AttemptOutcome::Success(AttemptSuccess::with_command_error(
                    message,
                    format!("couchdb command execution failed: {err}"),
                ))
            }
            Err(_) => AttemptOutcome::Error("attempt timed out".to_string()),
        }
    }
}

/// Runs one CouchDB login or unauthorized probe, then optional `-x`.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, CouchAttemptError> {
    let unauthenticated = is_unauthenticated(ctx);
    let client = build_http_basic_client(
        ctx.timeout(),
        HttpUrlScheme::Http,
        ctx.target.proxy.as_ref(),
    )
    .map_err(|err| CouchAttemptError::Transport(err.to_string()))?;
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let url = api_url(&ctx.target_host, port, "/");
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
        .map_err(|err| CouchAttemptError::Transport(err.to_string()))?;
    classify_status(response.status())?;
    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => execute_command(&client, ctx, command, unauthenticated, message).await,
        None => Ok(AttemptSuccess::new(message)),
    }
}

fn classify_status(status: StatusCode) -> Result<(), CouchAttemptError> {
    super::http_auth::require_http_auth(
        status,
        super::http_auth::HttpForbiddenPolicy::CredentialHit,
        || CouchAttemptError::Auth("invalid username or password".to_string()),
        |status| CouchAttemptError::Transport(format!("unexpected HTTP status: {status}")),
    )
}

async fn execute_command(
    client: &reqwest::Client,
    ctx: &AttemptContext,
    command: &str,
    unauthenticated: bool,
    success_message: &str,
) -> Result<AttemptSuccess, CouchAttemptError> {
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

/// Builds `http://host:port{path}` for CouchDB HTTP.
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
/// use brute::protocol::couchdb::api_url;
///
/// assert_eq!(api_url("10.0.0.5", 5984, "/_all_dbs"), "http://10.0.0.5:5984/_all_dbs");
/// ```
pub fn api_url(host: &str, port: u16, path: &str) -> String {
    format!("http://{host}:{port}{path}")
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
    let client = build_http_basic_client(
        ctx.timeout(),
        HttpUrlScheme::Http,
        ctx.target.proxy.as_ref(),
    )
    .ok()?;
    let url = api_url(&ctx.target_host, ctx.port(), "/");
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

fn is_unauthenticated(ctx: &AttemptContext) -> bool {
    ctx.credential.username.as_deref().unwrap_or("").is_empty()
        && ctx.credential.password.as_deref().unwrap_or("").is_empty()
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
