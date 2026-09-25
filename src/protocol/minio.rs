//! MinIO console login, unauthorized probe, and post-auth HTTP API (`-x`).
//!
//! Empty credentials probe `GET /minio/health/live` on the S3 port. Non-empty
//! credentials POST JSON login to the console API.

use async_trait::async_trait;
use reqwest::StatusCode;
use reqwest::header;
use serde_json::json;

use crate::cli::HttpUrlScheme;
use crate::protocol::http::{build_http_basic_client, normalize_path};

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

/// MinIO attempt errors split auth failures from post-auth command failures.
#[derive(Debug)]
enum MinioAttemptError {
    Auth(String),
    Transport(String),
    Command(String),
}

/// MinIO module configuration.
#[derive(Debug, Clone)]
pub struct MinioModule;

impl MinioModule {
    /// Creates a new MinIO module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`MinioModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::minio::MinioModule;
    ///
    /// let _module = MinioModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for MinioModule {
    fn name(&self) -> &'static str {
        "minio"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_health(ctx)).await {
            Ok(Some(message)) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        match tokio::time::timeout(ctx.timeout(), attempt_once(ctx)).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(MinioAttemptError::Auth(err))) => {
                AttemptOutcome::Failure(format!("minio auth failed: {err}"))
            }
            Ok(Err(MinioAttemptError::Transport(err))) => {
                AttemptOutcome::Error(format!("minio transport failed: {err}"))
            }
            Ok(Err(MinioAttemptError::Command(err))) => {
                let message = success_message(is_unauthenticated(ctx));
                AttemptOutcome::Success(AttemptSuccess::with_command_error(
                    message,
                    format!("minio command execution failed: {err}"),
                ))
            }
            Err(_) => AttemptOutcome::Error("attempt timed out".to_string()),
        }
    }
}

/// Runs one MinIO console login, then optional `-x`.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, MinioAttemptError> {
    let unauthenticated = is_unauthenticated(ctx);
    let client = build_http_basic_client(
        ctx.timeout(),
        HttpUrlScheme::Http,
        ctx.target.proxy.as_ref(),
    )
    .map_err(|err| MinioAttemptError::Transport(err.to_string()))?;
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());

    let login_url = api_url(&ctx.target_host, port, "/api/v1/login");
    let body = json!({
        "accessKey": ctx.credential.username.as_deref().unwrap_or(""),
        "secretKey": ctx.credential.password.as_deref().unwrap_or(""),
    });
    let response = client
        .post(&login_url)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|err| MinioAttemptError::Transport(err.to_string()))?;
    let status = response.status();
    if super::http_auth::classify_http_auth_status(
        status,
        super::http_auth::HttpForbiddenPolicy::AuthFailure,
    ) == super::http_auth::HttpAuthDecision::AuthFailure
        || status == StatusCode::BAD_REQUEST
    {
        return Err(MinioAttemptError::Auth(
            "invalid access key or secret key".to_string(),
        ));
    }
    if !(status.is_success() || status == StatusCode::NO_CONTENT) {
        return Err(MinioAttemptError::Transport(format!(
            "unexpected HTTP status: {status}"
        )));
    }
    let cookie = response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or(value).trim())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => execute_command(&client, ctx, command, &cookie, message).await,
        None => Ok(AttemptSuccess::new(message)),
    }
}

async fn execute_command(
    client: &reqwest::Client,
    ctx: &AttemptContext,
    command: &str,
    cookie: &str,
    success_message: &str,
) -> Result<AttemptSuccess, MinioAttemptError> {
    let path = execute_path(command);
    let url = api_url(
        &ctx.target_host,
        ctx.target.port.unwrap_or(ctx.protocol.default_port()),
        &path,
    );
    let mut request = client.get(&url);
    if !cookie.is_empty() {
        request = request.header(reqwest::header::COOKIE, cookie);
    }
    let response = request
        .send()
        .await
        .map_err(|err| MinioAttemptError::Command(err.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| MinioAttemptError::Command(err.to_string()))?;
    if status.is_success() {
        Ok(AttemptSuccess::with_command(
            success_message,
            trim_body(&body),
        ))
    } else {
        Err(MinioAttemptError::Command(format!(
            "HTTP {status}: {}",
            trim_body(&body)
        )))
    }
}

/// Builds `http://host:port{path}` for MinIO HTTP.
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
/// use brute::protocol::minio::api_url;
///
/// assert_eq!(
///     api_url("10.0.0.5", 9001, "/api/v1/login"),
///     "http://10.0.0.5:9001/api/v1/login"
/// );
/// ```
pub fn api_url(host: &str, port: u16, path: &str) -> String {
    format!("http://{host}:{port}{path}")
}

/// Normalizes `-x` text into a MinIO console path.
///
/// # Parameters
///
/// - `command`: CLI `-x` value (`buckets`, `info`, or a path).
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
/// use brute::protocol::minio::execute_path;
///
/// assert_eq!(execute_path("buckets"), "/api/v1/buckets");
/// assert_eq!(execute_path("/minio/health/live"), "/minio/health/live");
/// ```
pub fn execute_path(command: &str) -> String {
    let trimmed = command.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "buckets" | "list" => "/api/v1/buckets".to_string(),
        "info" | "admin" => "/api/v1/admin/info".to_string(),
        other => normalize_path(other),
    }
}

async fn probe_health(ctx: &TargetContext) -> Option<String> {
    let client = build_http_basic_client(
        ctx.timeout(),
        HttpUrlScheme::Http,
        ctx.target.proxy.as_ref(),
    )
    .ok()?;
    let port = ctx.port();
    for path in ["/minio/health/live", "/api/v1/login"] {
        let url = api_url(&ctx.target_host, port, path);
        if let Ok(response) = client.get(&url).send().await {
            let status = response.status();
            if status.is_success()
                || status == StatusCode::UNAUTHORIZED
                || status == StatusCode::FORBIDDEN
                || status == StatusCode::METHOD_NOT_ALLOWED
            {
                return Some("MinIO".to_string());
            }
        }
    }
    None
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
        "MinIO unauthorized access!"
    } else {
        "MinIO access!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_path_maps_shorthand() {
        assert_eq!(execute_path("buckets"), "/api/v1/buckets");
        assert_eq!(execute_path("info"), "/api/v1/admin/info");
    }
}
