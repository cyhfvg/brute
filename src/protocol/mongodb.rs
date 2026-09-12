//! MongoDB login, unauthorized access, and post-auth commands.
//!
//! Empty username and password probe unauthenticated `listDatabases` against `admin`.
//! Non-empty credentials use SCRAM via the official `mongodb` driver.

use std::time::Duration;

use async_trait::async_trait;
use mongodb::bson::{Bson, Document, doc};
use mongodb::error::ErrorKind;
use mongodb::options::ClientOptions;
use mongodb::{Client, error::Error as MongoError};

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

/// MongoDB attempt errors split auth/connect failures from post-auth command failures.
#[derive(Debug)]
enum MongoAttemptError {
    Auth(String),
    Transport(String),
    Command(String),
}

/// MongoDB module configuration.
#[derive(Debug, Clone)]
pub struct MongoDbModule;

impl MongoDbModule {
    /// Creates a new MongoDB module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Per-attempt timeout in milliseconds. Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`MongoDbModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::mongodb::MongoDbModule;
    ///
    /// let _module = MongoDbModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for MongoDbModule {
    fn name(&self) -> &'static str {
        "mongodb"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_hello(ctx)).await {
            Ok(Some(message)) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        match tokio::time::timeout(ctx.timeout(), attempt_once(ctx)).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(MongoAttemptError::Auth(err))) => {
                AttemptOutcome::Failure(format!("mongodb auth failed: {err}"))
            }
            Ok(Err(MongoAttemptError::Transport(err))) => {
                AttemptOutcome::Error(format!("mongodb transport failed: {err}"))
            }
            Ok(Err(MongoAttemptError::Command(err))) => {
                let message = success_message(is_unauthenticated(ctx));
                AttemptOutcome::Success(AttemptSuccess::with_command_error(
                    message,
                    format!("mongodb command execution failed: {err}"),
                ))
            }
            Err(_) => AttemptOutcome::Error("attempt timed out".to_string()),
        }
    }
}

/// Runs one MongoDB login or unauthorized probe, then optional `-x`.
///
/// # Parameters
///
/// - `ctx`: Target, credential, timeout, proxy, and optional execute command.
///
/// # Returns
///
/// [`AttemptSuccess`] when the session is established and any command succeeds.
///
/// # Errors
///
/// Returns [`MongoAttemptError::Auth`] for SCRAM/authorization rejection,
/// [`MongoAttemptError::Transport`] for connect failures, and
/// [`MongoAttemptError::Command`] for post-auth command errors.
///
/// # Examples
///
/// ```ignore
/// let success = attempt_once(&ctx).await?;
/// ```
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, MongoAttemptError> {
    let unauthenticated = is_unauthenticated(ctx);
    let (client, _bridge) = connect_client(ctx, !unauthenticated).await?;
    let admin = client.database("admin");
    let probe = if unauthenticated {
        doc! { "listDatabases": 1 }
    } else {
        doc! { "ping": 1 }
    };
    admin
        .run_command(probe)
        .await
        .map_err(classify_mongo_error)?;

    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => execute_mongo_command(&admin, command, message).await,
        None => Ok(AttemptSuccess::new(message)),
    }
}

/// Opens a MongoDB client, optionally through `--proxy` via a local TCP bridge.
///
/// # Parameters
///
/// - `ctx`: Target, credentials, timeout, and optional proxy.
/// - `with_credentials`: When true, embed username/password and `authSource=admin`.
///
/// # Returns
///
/// Connected [`Client`] plus an optional bridge guard that must outlive the client.
///
/// # Errors
///
/// Returns [`MongoAttemptError::Transport`] or [`MongoAttemptError::Auth`].
///
/// # Examples
///
/// ```ignore
/// let (client, _bridge) = connect_client(&ctx, true).await?;
/// ```
async fn connect_client(
    ctx: &AttemptContext,
    with_credentials: bool,
) -> Result<(Client, Option<crate::proxy::ProxyTcpBridge>), MongoAttemptError> {
    let host = ctx.target_host.as_str();
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let timeout = ctx.timeout();
    let endpoint = crate::proxy::resolve_tcp_endpoint(ctx.target.proxy.as_ref(), host, port)
        .await
        .map_err(MongoAttemptError::Transport)?;
    let (connect_host, connect_port, bridge) = endpoint;
    let uri = build_mongodb_uri(
        &connect_host,
        connect_port,
        if with_credentials {
            ctx.credential.username.as_deref()
        } else {
            None
        },
        if with_credentials {
            ctx.credential.password.as_deref()
        } else {
            None
        },
    );
    let client = client_from_uri(&uri, timeout).await?;
    Ok((client, bridge))
}

/// Builds a direct-connection MongoDB URI.
///
/// # Parameters
///
/// - `host`: Dial host (real target or proxy bridge).
/// - `port`: Dial port.
/// - `username`: Optional username; empty/`None` omits userinfo.
/// - `password`: Optional password.
///
/// # Returns
///
/// `mongodb://[user:pass@]host:port/?directConnection=true[&authSource=admin]`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::mongodb::build_mongodb_uri;
///
/// assert_eq!(
///     build_mongodb_uri("127.0.0.1", 27017, None, None),
///     "mongodb://127.0.0.1:27017/?directConnection=true"
/// );
/// assert_eq!(
///     build_mongodb_uri("127.0.0.1", 27017, Some("admin"), Some("s p")),
///     "mongodb://admin:s%20p@127.0.0.1:27017/?authSource=admin&directConnection=true"
/// );
/// ```
pub fn build_mongodb_uri(
    host: &str,
    port: u16,
    username: Option<&str>,
    password: Option<&str>,
) -> String {
    let user = username.unwrap_or("");
    let pass = password.unwrap_or("");
    if user.is_empty() && pass.is_empty() {
        format!("mongodb://{host}:{port}/?directConnection=true")
    } else {
        format!(
            "mongodb://{}:{}@{host}:{port}/?authSource=admin&directConnection=true",
            percent_encode_userinfo(user),
            percent_encode_userinfo(pass)
        )
    }
}

/// Percent-encodes a URI userinfo component.
///
/// # Parameters
///
/// - `value`: Username or password.
///
/// # Returns
///
/// Percent-encoded string.
///
/// # Errors
///
/// This function does not return errors.
fn percent_encode_userinfo(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

/// Parses a URI and applies connect/server-selection timeouts.
///
/// # Parameters
///
/// - `uri`: MongoDB connection string.
/// - `timeout`: Applied to connect and server selection.
///
/// # Returns
///
/// Connected [`Client`].
///
/// # Errors
///
/// Classifies driver errors as auth or transport.
async fn client_from_uri(uri: &str, timeout: Duration) -> Result<Client, MongoAttemptError> {
    let mut options = ClientOptions::parse(uri)
        .await
        .map_err(classify_mongo_error)?;
    options.connect_timeout = Some(timeout);
    options.server_selection_timeout = Some(timeout);
    options.direct_connection = Some(true);
    Client::with_options(options).map_err(classify_mongo_error)
}

/// Executes a post-auth MongoDB command against `admin`.
///
/// # Parameters
///
/// - `admin`: `admin` database handle.
/// - `command`: JSON document or shorthand (`ping`, `listDatabases`, `serverStatus`, `buildInfo`).
/// - `success_message`: Login banner.
///
/// # Returns
///
/// [`AttemptSuccess`] with formatted command output.
///
/// # Errors
///
/// Returns [`MongoAttemptError::Command`] when the command is invalid or rejected.
async fn execute_mongo_command(
    admin: &mongodb::Database,
    command: &str,
    success_message: &str,
) -> Result<AttemptSuccess, MongoAttemptError> {
    let document = parse_mongo_command(command).map_err(MongoAttemptError::Command)?;
    match admin.run_command(document).await {
        Ok(reply) => Ok(AttemptSuccess::with_command(
            success_message,
            format_document(&reply),
        )),
        Err(err) => Err(MongoAttemptError::Command(err.to_string())),
    }
}

/// Parses `-x` text into a MongoDB command document.
///
/// # Parameters
///
/// - `command`: JSON object or shorthand command name.
///
/// # Returns
///
/// BSON [`Document`].
///
/// # Errors
///
/// Returns an error when JSON is invalid or the command is empty.
///
/// # Examples
///
/// ```
/// use brute::protocol::mongodb::parse_mongo_command;
///
/// let ping = parse_mongo_command("ping").expect("ping");
/// assert_eq!(ping.get_i32("ping").unwrap(), 1);
/// let json = parse_mongo_command("{\"listDatabases\": 1}").expect("json");
/// assert!(json.get("listDatabases").is_some());
/// ```
pub fn parse_mongo_command(command: &str) -> Result<Document, String> {
    let trimmed = command.trim().trim_end_matches(';').trim();
    if trimmed.is_empty() {
        return Err("empty mongodb command".to_string());
    }
    if trimmed.starts_with('{') {
        let value: serde_json::Value =
            serde_json::from_str(trimmed).map_err(|err| format!("invalid mongodb JSON: {err}"))?;
        return json_to_document(&value);
    }
    let name = trimmed.split_whitespace().next().unwrap_or(trimmed);
    match name.to_ascii_lowercase().as_str() {
        "ping" => Ok(doc! { "ping": 1 }),
        "listdatabases" | "list_databases" => Ok(doc! { "listDatabases": 1 }),
        "serverstatus" | "server_status" => Ok(doc! { "serverStatus": 1 }),
        "buildinfo" | "build_info" => Ok(doc! { "buildInfo": 1 }),
        other => Ok(doc! { other: 1 }),
    }
}

/// Converts a JSON value into a BSON document.
///
/// # Parameters
///
/// - `value`: JSON object.
///
/// # Returns
///
/// BSON document.
///
/// # Errors
///
/// Returns an error when the JSON is not an object or cannot be converted.
fn json_to_document(value: &serde_json::Value) -> Result<Document, String> {
    let bson = mongodb::bson::serialize_to_bson(value).map_err(|err| err.to_string())?;
    match bson {
        Bson::Document(document) => Ok(document),
        other => Err(format!(
            "mongodb command must be a JSON object, got {other:?}"
        )),
    }
}

/// Formats a BSON document for terminal output.
///
/// # Parameters
///
/// - `document`: Command reply.
///
/// # Returns
///
/// Pretty JSON, truncated to 8 KiB.
///
/// # Errors
///
/// This function does not return errors.
fn format_document(document: &Document) -> String {
    match serde_json::to_string_pretty(document) {
        Ok(mut text) => {
            const MAX: usize = 8192;
            if text.len() > MAX {
                text.truncate(MAX);
                text.push_str("\n...");
            }
            text
        }
        Err(_) => format!("{document:?}"),
    }
}

/// Sends unauthenticated `hello` and formats a probe banner.
///
/// # Parameters
///
/// - `ctx`: Target host, port, timeout, and optional proxy.
///
/// # Returns
///
/// `Some` version banner when the peer speaks MongoDB.
///
/// # Errors
///
/// This function does not return errors; failures become `None`.
async fn probe_hello(ctx: &TargetContext) -> Option<String> {
    let port = ctx.port();
    let endpoint =
        crate::proxy::resolve_tcp_endpoint(ctx.target.proxy.as_ref(), &ctx.target_host, port)
            .await
            .ok()?;
    let (connect_host, connect_port, _bridge) = endpoint;
    let uri = build_mongodb_uri(&connect_host, connect_port, None, None);
    let client = client_from_uri(&uri, ctx.timeout()).await.ok()?;
    let admin = client.database("admin");
    if let Ok(reply) = admin.run_command(doc! { "buildInfo": 1 }).await {
        return parse_hello_banner(&reply);
    }
    let reply = admin.run_command(doc! { "hello": 1 }).await.ok()?;
    parse_hello_banner(&reply)
}

/// Extracts a compact banner from a `buildInfo` or `hello` reply.
///
/// # Parameters
///
/// - `reply`: Command document that may contain `version`.
///
/// # Returns
///
/// Banner such as `MongoDB 7.0.14`, or `MongoDB` when no version is present.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::mongodb::parse_hello_banner;
/// use mongodb::bson::doc;
///
/// let reply = doc! { "ok": 1, "version": "7.0.14" };
/// assert_eq!(parse_hello_banner(&reply).as_deref(), Some("MongoDB 7.0.14"));
/// ```
pub fn parse_hello_banner(reply: &Document) -> Option<String> {
    match reply.get_str("version") {
        Ok(version) if !version.is_empty() => Some(format!("MongoDB {version}")),
        _ => Some("MongoDB".to_string()),
    }
}

/// Classifies a driver error as auth versus transport.
///
/// # Parameters
///
/// - `err`: Error from connect, ping, or option parse.
///
/// # Returns
///
/// [`MongoAttemptError::Auth`] for authentication/authorization; otherwise transport.
fn classify_mongo_error(err: MongoError) -> MongoAttemptError {
    match err.kind.as_ref() {
        ErrorKind::Authentication { message, .. } => MongoAttemptError::Auth(message.clone()),
        ErrorKind::Command(command) if is_auth_command_code(command.code) => {
            MongoAttemptError::Auth(command.message.clone())
        }
        ErrorKind::ServerSelection { message, .. }
            if message.to_ascii_lowercase().contains("auth") =>
        {
            MongoAttemptError::Auth(message.clone())
        }
        other => MongoAttemptError::Transport(other.to_string()),
    }
}

/// Returns whether a MongoDB error code represents authentication failure.
///
/// # Parameters
///
/// - `code`: Server error code.
///
/// # Returns
///
/// `true` for AuthenticationFailed (18) and Unauthorized (13).
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::mongodb::is_auth_command_code;
///
/// assert!(is_auth_command_code(18));
/// assert!(is_auth_command_code(13));
/// assert!(!is_auth_command_code(1));
/// ```
pub fn is_auth_command_code(code: i32) -> bool {
    matches!(code, 13 | 18)
}

/// Returns whether this attempt is an anonymous unauthorized probe.
fn is_unauthenticated(ctx: &AttemptContext) -> bool {
    ctx.credential.username.as_deref().unwrap_or("").is_empty()
        && ctx.credential.password.as_deref().unwrap_or("").is_empty()
}

/// Returns the success banner for authenticated versus unauthorized access.
fn success_message(unauthenticated: bool) -> &'static str {
    if unauthenticated {
        "MongoDB unauthorized access!"
    } else {
        "MongoDB access!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_mongodb_uri_encodes_password() {
        assert_eq!(
            build_mongodb_uri("10.0.0.5", 27017, Some("admin"), Some("a@b:c")),
            "mongodb://admin:a%40b%3Ac@10.0.0.5:27017/?authSource=admin&directConnection=true"
        );
    }

    #[test]
    fn parse_mongo_command_accepts_shorthand_and_json() {
        assert_eq!(
            parse_mongo_command("ping")
                .unwrap()
                .get_i32("ping")
                .unwrap(),
            1
        );
        let json = parse_mongo_command("{\"listDatabases\":1}").unwrap();
        assert!(json.get("listDatabases").is_some());
    }
}
