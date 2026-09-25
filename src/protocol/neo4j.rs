//! Neo4j HTTP login and post-auth Cypher (`-x`).
//!
//! Empty credentials probe `GET /` without Authorization. Non-empty credentials
//! POST `/db/neo4j/tx/commit` with HTTP Basic Auth and `RETURN 1`.

use async_trait::async_trait;
use reqwest::{StatusCode, header};

use super::http_attempt::{
    classify_basic_status, credentials_absent, http_attempt_url, http_target_url,
    open_attempt_client, target_http_client, with_basic_auth,
};
use super::http_auth::HttpForbiddenPolicy;
use super::{AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext};

/// Neo4j attempt errors split auth failures from post-auth command failures.
type Neo4jAttemptError = crate::protocol::http_attempt::HttpAttemptFailure;

/// Neo4j module configuration.
#[derive(Debug, Clone)]
pub struct Neo4jModule;

impl Neo4jModule {
    /// Creates a new Neo4j module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`Neo4jModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::neo4j::Neo4jModule;
    ///
    /// let _module = Neo4jModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for Neo4jModule {
    fn name(&self) -> &'static str {
        "neo4j"
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
            "neo4j",
            || success_message(credentials_absent(ctx)),
            attempt_once(ctx),
        )
        .await
    }
}

/// Runs one Neo4j login or unauthorized probe, then optional `-x` Cypher.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, Neo4jAttemptError> {
    let unauthenticated = credentials_absent(ctx);
    let client = open_attempt_client(ctx)?;
    run_cypher(&client, ctx, "RETURN 1 AS n").await?;
    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => {
            let sql = execute_cypher(command);
            match run_cypher(&client, ctx, &sql).await {
                Ok(body) => Ok(AttemptSuccess::with_command(message, body)),
                Err(Neo4jAttemptError::Command(err)) | Err(Neo4jAttemptError::Transport(err)) => {
                    Ok(AttemptSuccess::with_command_error(message, err))
                }
                Err(Neo4jAttemptError::Auth(err)) => {
                    Ok(AttemptSuccess::with_command_error(message, err))
                }
            }
        }
        None => Ok(AttemptSuccess::new(message)),
    }
}

/// Sends one Cypher statement and returns the trimmed response body.
///
/// Basic Auth is applied only when the attempt has a username or password.
///
/// # Parameters
///
/// - `client`: HTTP client for this attempt.
/// - `ctx`: Attempt target and credentials.
/// - `statement`: Cypher text.
///
/// # Returns
///
/// Trimmed response body.
///
/// # Errors
///
/// Returns [`Neo4jAttemptError::Auth`] for rejected credentials,
/// [`Neo4jAttemptError::Transport`] for client or unexpected status failures,
/// and [`Neo4jAttemptError::Command`] when the response body cannot be read.
///
/// # Examples
///
/// ```ignore
/// let body = run_cypher(&client, ctx, "RETURN 1 AS n").await?;
/// ```
async fn run_cypher(
    client: &reqwest::Client,
    ctx: &AttemptContext,
    statement: &str,
) -> Result<String, Neo4jAttemptError> {
    let url = http_attempt_url(ctx, "/db/neo4j/tx/commit");
    let body = serde_json::json!({ "statements": [{ "statement": statement }] });
    let mut request = client
        .post(&url)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .body(body.to_string());
    request = with_basic_auth(request, ctx);
    let response = request
        .send()
        .await
        .map_err(|err| Neo4jAttemptError::Transport(err.to_string()))?;
    classify_basic_status(response.status(), HttpForbiddenPolicy::AuthFailure)?;
    let text = response
        .text()
        .await
        .map_err(|err| Neo4jAttemptError::Command(err.to_string()))?;
    Ok(trim_body(&text))
}

/// Normalizes `-x` text into Cypher.
///
/// # Parameters
///
/// - `command`: CLI `-x` value (`ping` or a Cypher statement).
///
/// # Returns
///
/// Cypher string.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::neo4j::execute_cypher;
///
/// assert_eq!(execute_cypher("ping"), "RETURN 1 AS n");
/// assert_eq!(execute_cypher("RETURN 2"), "RETURN 2");
/// ```
pub fn execute_cypher(command: &str) -> String {
    let trimmed = command.trim().trim_end_matches(';');
    match trimmed.to_ascii_lowercase().as_str() {
        "ping" | "1" => "RETURN 1 AS n".to_string(),
        "labels" => "CALL db.labels()".to_string(),
        _ => trimmed.to_string(),
    }
}

async fn probe_root(ctx: &TargetContext) -> Option<String> {
    let client = target_http_client(ctx).ok()?;
    let url = http_target_url(ctx, "/");
    let response = client.get(&url).send().await.ok()?;
    if response.status().is_success()
        || response.status() == StatusCode::UNAUTHORIZED
        || response.status() == StatusCode::FORBIDDEN
    {
        Some("Neo4j".to_string())
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
        "Neo4j unauthorized access!"
    } else {
        "Neo4j access!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_cypher_maps_shorthand() {
        assert_eq!(execute_cypher("ping"), "RETURN 1 AS n");
        assert_eq!(execute_cypher("RETURN 2;"), "RETURN 2");
    }
}
