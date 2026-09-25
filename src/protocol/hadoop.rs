//! Hadoop NameNode UI login, unauthorized probe, and post-auth HTTP API (`-x`).
//!
//! Empty credentials probe `GET /jmx` without Authorization. Non-empty
//! credentials use HTTP Basic Auth against the same endpoint.

use async_trait::async_trait;
use reqwest::StatusCode;

use crate::cli::HttpUrlScheme;
use crate::protocol::http::{build_http_basic_client, normalize_path};

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

/// Hadoop attempt errors split auth failures from post-auth command failures.
#[derive(Debug)]
enum HadoopAttemptError {
    Auth(String),
    Transport(String),
    Command(String),
}

/// Hadoop module configuration.
#[derive(Debug, Clone)]
pub struct HadoopModule;

impl HadoopModule {
    /// Creates a new Hadoop module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`HadoopModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::hadoop::HadoopModule;
    ///
    /// let _module = HadoopModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for HadoopModule {
    fn name(&self) -> &'static str {
        "hadoop"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_jmx(ctx)).await {
            Ok(Some(message)) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        match tokio::time::timeout(ctx.timeout(), attempt_once(ctx)).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(HadoopAttemptError::Auth(err))) => {
                AttemptOutcome::Failure(format!("hadoop auth failed: {err}"))
            }
            Ok(Err(HadoopAttemptError::Transport(err))) => {
                AttemptOutcome::Error(format!("hadoop transport failed: {err}"))
            }
            Ok(Err(HadoopAttemptError::Command(err))) => {
                let message = success_message(is_unauthenticated(ctx));
                AttemptOutcome::Success(AttemptSuccess::with_command_error(
                    message,
                    format!("hadoop command execution failed: {err}"),
                ))
            }
            Err(_) => AttemptOutcome::Error("attempt timed out".to_string()),
        }
    }
}

/// Runs one Hadoop NameNode login or unauthorized probe, then optional `-x`.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, HadoopAttemptError> {
    let unauthenticated = is_unauthenticated(ctx);
    let client = build_http_basic_client(
        ctx.timeout(),
        HttpUrlScheme::Http,
        ctx.target.proxy.as_ref(),
    )
    .map_err(|err| HadoopAttemptError::Transport(err.to_string()))?;
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let url = api_url(&ctx.target_host, port, "/jmx");
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
        .map_err(|err| HadoopAttemptError::Transport(err.to_string()))?;
    classify_status(response.status())?;
    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => execute_command(&client, ctx, command, unauthenticated, message).await,
        None => Ok(AttemptSuccess::new(message)),
    }
}

fn classify_status(status: StatusCode) -> Result<(), HadoopAttemptError> {
    super::http_auth::require_http_auth(
        status,
        super::http_auth::HttpForbiddenPolicy::AuthFailure,
        || HadoopAttemptError::Auth("invalid username or password".to_string()),
        |status| HadoopAttemptError::Transport(format!("unexpected HTTP status: {status}")),
    )
}

async fn execute_command(
    client: &reqwest::Client,
    ctx: &AttemptContext,
    command: &str,
    unauthenticated: bool,
    success_message: &str,
) -> Result<AttemptSuccess, HadoopAttemptError> {
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
        .map_err(|err| HadoopAttemptError::Command(err.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| HadoopAttemptError::Command(err.to_string()))?;
    if status.is_success() {
        Ok(AttemptSuccess::with_command(
            success_message,
            trim_body(&body),
        ))
    } else {
        Err(HadoopAttemptError::Command(format!(
            "HTTP {status}: {}",
            trim_body(&body)
        )))
    }
}

/// Builds `http://host:port{path}` for Hadoop HTTP.
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
/// use brute::protocol::hadoop::api_url;
///
/// assert_eq!(api_url("10.0.0.5", 9870, "/jmx"), "http://10.0.0.5:9870/jmx");
/// ```
pub fn api_url(host: &str, port: u16, path: &str) -> String {
    format!("http://{host}:{port}{path}")
}

/// Normalizes `-x` text into a Hadoop NameNode path.
///
/// # Parameters
///
/// - `command`: CLI `-x` value (`jmx`, `webhdfs`, or a path).
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
/// use brute::protocol::hadoop::execute_path;
///
/// assert_eq!(execute_path("jmx"), "/jmx");
/// assert_eq!(execute_path("webhdfs"), "/webhdfs/v1/?op=LISTSTATUS");
/// ```
pub fn execute_path(command: &str) -> String {
    let trimmed = command.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "jmx" | "status" => "/jmx".to_string(),
        "webhdfs" | "ls" => "/webhdfs/v1/?op=LISTSTATUS".to_string(),
        "info" => "/jmx?qry=Hadoop:service=NameNode,name=NameNodeInfo".to_string(),
        other => normalize_path(other),
    }
}

async fn probe_jmx(ctx: &TargetContext) -> Option<String> {
    let client = build_http_basic_client(
        ctx.timeout(),
        HttpUrlScheme::Http,
        ctx.target.proxy.as_ref(),
    )
    .ok()?;
    let url = api_url(&ctx.target_host, ctx.port(), "/jmx");
    let response = client.get(&url).send().await.ok()?;
    let status = response.status();
    if status.is_success() || status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN
    {
        Some("Hadoop".to_string())
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
        "Hadoop unauthorized access!"
    } else {
        "Hadoop access!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_path_maps_shorthand() {
        assert_eq!(execute_path("jmx"), "/jmx");
        assert_eq!(execute_path("webhdfs"), "/webhdfs/v1/?op=LISTSTATUS");
    }
}
