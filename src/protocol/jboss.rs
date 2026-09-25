//! JBoss / WildFly HTTP management login and post-auth operations (`-x`).
//!
//! Empty credentials probe `GET /management` without Authorization. Non-empty
//! credentials retry the same endpoint with HTTP Digest (ManagementRealm).

use async_trait::async_trait;
use openssl::hash::{MessageDigest, hash};
use reqwest::StatusCode;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};

use crate::cli::HttpUrlScheme;
use crate::protocol::http::{build_http_basic_client, normalize_path};

use super::{AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext};

/// JBoss attempt errors split auth failures from post-auth command failures.
type JbossAttemptError = crate::protocol::http_attempt::HttpAttemptFailure;

/// JBoss / WildFly module configuration.
#[derive(Debug, Clone)]
pub struct JbossModule;

impl JbossModule {
    /// Creates a new JBoss module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`JbossModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::jboss::JbossModule;
    ///
    /// let _module = JbossModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for JbossModule {
    fn name(&self) -> &'static str {
        "jboss"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> Option<String> {
        match tokio::time::timeout(ctx.timeout(), probe_management(ctx)).await {
            Ok(Some(message)) => Some(message),
            _ => None,
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        crate::protocol::http_attempt::run_http_attempt(
            ctx.timeout(),
            "jboss",
            || success_message(is_unauthenticated(ctx)),
            attempt_once(ctx),
        )
        .await
    }
}

/// Runs one JBoss management probe or Digest login, then optional `-x`.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, JbossAttemptError> {
    let unauthenticated = is_unauthenticated(ctx);
    let client = build_http_basic_client(ctx.timeout(), ctx.url_scheme, ctx.target.proxy.as_ref())
        .map_err(|err| JbossAttemptError::Transport(err.to_string()))?;
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let url = api_url(ctx.url_scheme, &ctx.target_host, port, "/management");
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|err| JbossAttemptError::Transport(err.to_string()))?;
    if unauthenticated {
        if response.status().is_success() {
            return finish(ctx, &client, None, true).await;
        }
        return Err(JbossAttemptError::Auth(
            "anonymous access is disabled".to_string(),
        ));
    }
    if response.status().is_success() {
        return finish(ctx, &client, None, false).await;
    }
    if response.status() != StatusCode::UNAUTHORIZED {
        return Err(JbossAttemptError::Transport(format!(
            "unexpected HTTP status: {}",
            response.status()
        )));
    }
    let challenge = response
        .headers()
        .get(WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| JbossAttemptError::Transport("missing WWW-Authenticate".to_string()))?;
    let username = ctx.credential.username.as_deref().unwrap_or("");
    let password = ctx.credential.password.as_deref().unwrap_or("");
    let authorization = digest_authorization(challenge, "GET", "/management", username, password)
        .map_err(JbossAttemptError::Transport)?;
    let authed = client
        .get(&url)
        .header(AUTHORIZATION, authorization)
        .send()
        .await
        .map_err(|err| JbossAttemptError::Transport(err.to_string()))?;
    if super::http_auth::classify_http_auth_status(
        authed.status(),
        super::http_auth::HttpForbiddenPolicy::AuthFailure,
    ) == super::http_auth::HttpAuthDecision::AuthFailure
    {
        return Err(JbossAttemptError::Auth(
            "invalid username or password".to_string(),
        ));
    }
    if !authed.status().is_success() {
        return Err(JbossAttemptError::Transport(format!(
            "unexpected HTTP status: {}",
            authed.status()
        )));
    }
    finish(ctx, &client, Some(challenge.to_string()), false).await
}

async fn finish(
    ctx: &AttemptContext,
    client: &reqwest::Client,
    challenge: Option<String>,
    unauthenticated: bool,
) -> Result<AttemptSuccess, JbossAttemptError> {
    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => execute_command(client, ctx, command, challenge.as_deref(), message).await,
        None => Ok(AttemptSuccess::new(message)),
    }
}

async fn execute_command(
    client: &reqwest::Client,
    ctx: &AttemptContext,
    command: &str,
    challenge: Option<&str>,
    success_message: &str,
) -> Result<AttemptSuccess, JbossAttemptError> {
    let (path, body) = execute_request(command);
    let url = api_url(
        ctx.url_scheme,
        &ctx.target_host,
        ctx.target.port.unwrap_or(ctx.protocol.default_port()),
        &path,
    );
    let first = client
        .post(&url)
        .header(CONTENT_TYPE, "application/json")
        .body(body.clone())
        .send()
        .await
        .map_err(|err| JbossAttemptError::Command(err.to_string()))?;
    let response = if first.status() == StatusCode::UNAUTHORIZED && challenge.is_some() {
        let header = first
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| JbossAttemptError::Command("missing WWW-Authenticate".to_string()))?;
        let username = ctx.credential.username.as_deref().unwrap_or("");
        let password = ctx.credential.password.as_deref().unwrap_or("");
        let authorization = digest_authorization(header, "POST", &path, username, password)
            .map_err(JbossAttemptError::Command)?;
        client
            .post(&url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, authorization)
            .body(body)
            .send()
            .await
            .map_err(|err| JbossAttemptError::Command(err.to_string()))?
    } else {
        first
    };
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|err| JbossAttemptError::Command(err.to_string()))?;
    if status.is_success() {
        Ok(AttemptSuccess::with_command(
            success_message,
            trim_body(&text),
        ))
    } else {
        Err(JbossAttemptError::Command(format!(
            "HTTP {status}: {}",
            trim_body(&text)
        )))
    }
}

/// Builds `http://host:port{path}` for JBoss management HTTP.
///
/// # Parameters
///
/// - `scheme`: URL scheme (`http` or `https`).
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
/// use brute::protocol::jboss::api_url;
///
/// assert_eq!(
///     api_url(brute::cli::HttpUrlScheme::Http, "10.0.0.5", 9990, "/management"),
///     "http://10.0.0.5:9990/management"
/// );
/// ```
pub fn api_url(scheme: HttpUrlScheme, host: &str, port: u16, path: &str) -> String {
    super::http::build_http_basic_url(scheme, host, port, path)
}

/// Maps `-x` text to a management path and JSON body.
///
/// # Parameters
///
/// - `command`: CLI `-x` value (`version`, `server-state`, or a path).
///
/// # Returns
///
/// `(path, json_body)`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::jboss::execute_request;
///
/// let (path, body) = execute_request("version");
/// assert_eq!(path, "/management");
/// assert!(body.contains("product-version"));
/// ```
pub fn execute_request(command: &str) -> (String, String) {
    let trimmed = command.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "version" | "product-version" => (
            "/management".to_string(),
            r#"{"operation":"read-attribute","name":"product-version","json.pretty":1}"#
                .to_string(),
        ),
        "state" | "server-state" => (
            "/management".to_string(),
            r#"{"operation":"read-attribute","name":"server-state","json.pretty":1}"#.to_string(),
        ),
        other if other.starts_with('{') => ("/management".to_string(), trimmed.to_string()),
        other => (
            normalize_path(other),
            r#"{"operation":"read-resource","json.pretty":1}"#.to_string(),
        ),
    }
}

/// Builds an HTTP Digest `Authorization` value from a `WWW-Authenticate` challenge.
///
/// # Parameters
///
/// - `challenge`: `WWW-Authenticate` header value.
/// - `method`: HTTP method.
/// - `uri`: Request URI.
/// - `username`: Management username.
/// - `password`: Management password.
///
/// # Returns
///
/// `Digest ...` header value.
///
/// # Errors
///
/// Returns an error when the challenge is missing `realm`/`nonce` or MD5 fails.
///
/// # Examples
///
/// ```
/// use brute::protocol::jboss::digest_authorization;
///
/// let header = digest_authorization(
///     r#"Digest realm="ManagementRealm", nonce="abc", algorithm=MD5, qop="auth""#,
///     "GET",
///     "/management",
///     "admin",
///     "pass",
/// )
/// .unwrap();
/// assert!(header.starts_with("Digest "));
/// ```
pub fn digest_authorization(
    challenge: &str,
    method: &str,
    uri: &str,
    username: &str,
    password: &str,
) -> Result<String, String> {
    let params = parse_auth_params(challenge);
    let realm = params
        .get("realm")
        .ok_or_else(|| "digest challenge missing realm".to_string())?;
    let nonce = params
        .get("nonce")
        .ok_or_else(|| "digest challenge missing nonce".to_string())?;
    let qop = params.get("qop").map(String::as_str);
    let opaque = params.get("opaque");
    let ha1 = md5_hex(format!("{username}:{realm}:{password}").as_bytes())?;
    let ha2 = md5_hex(format!("{method}:{uri}").as_bytes())?;
    let (response, extra) = if qop.is_some() {
        let cnonce = md5_hex(b"brute-jboss")?;
        let nc = "00000001";
        let qop_value = "auth";
        let response =
            md5_hex(format!("{ha1}:{nonce}:{nc}:{cnonce}:{qop_value}:{ha2}").as_bytes())?;
        (
            response,
            format!(r#", qop={qop_value}, nc={nc}, cnonce="{cnonce}""#),
        )
    } else {
        let response = md5_hex(format!("{ha1}:{nonce}:{ha2}").as_bytes())?;
        (response, String::new())
    };
    let mut header = format!(
        r#"Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{response}"{extra}"#
    );
    if let Some(opaque) = opaque {
        header.push_str(&format!(r#", opaque="{opaque}""#));
    }
    if params.get("algorithm").map(String::as_str) == Some("MD5") {
        header.push_str(", algorithm=MD5");
    }
    Ok(header)
}

fn parse_auth_params(challenge: &str) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    let rest = challenge
        .trim()
        .strip_prefix("Digest")
        .unwrap_or(challenge)
        .trim();
    for part in rest.split(',') {
        let part = part.trim();
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_string();
        map.insert(key.trim().to_ascii_lowercase(), value);
    }
    map
}

fn md5_hex(data: &[u8]) -> Result<String, String> {
    let digest = hash(MessageDigest::md5(), data).map_err(|err| err.to_string())?;
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

async fn probe_management(ctx: &TargetContext) -> Option<String> {
    let client =
        build_http_basic_client(ctx.timeout(), ctx.url_scheme, ctx.target.proxy.as_ref()).ok()?;
    let url = api_url(ctx.url_scheme, &ctx.target_host, ctx.port(), "/management");
    let response = client.get(&url).send().await.ok()?;
    let status = response.status();
    if status.is_success() || status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN
    {
        Some("JBoss".to_string())
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
        "JBoss unauthorized access!"
    } else {
        "JBoss access!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_request_maps_version() {
        let (path, body) = execute_request("version");
        assert_eq!(path, "/management");
        assert!(body.contains("product-version"));
    }

    #[test]
    fn digest_authorization_includes_username() {
        let header = digest_authorization(
            r#"Digest realm="ManagementRealm", nonce="abc", algorithm=MD5"#,
            "GET",
            "/management",
            "admin",
            "pass",
        )
        .expect("digest header");
        assert!(header.contains(r#"username="admin""#));
        assert!(header.contains("response="));
    }
}
