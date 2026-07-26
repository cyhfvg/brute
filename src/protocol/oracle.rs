//! Oracle database authentication and post-authentication SQL queries.

use std::{future::Future, time::Duration};

use async_trait::async_trait;
use oracle_rs::{Config, Connection, Error as OracleError, QueryResult, Row};
use tokio::time::timeout;

use super::{AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule};

/// Oracle database module configuration.
#[derive(Debug, Clone)]
pub struct OracleModule {
    service_name: Option<String>,
    sid: Option<String>,
}

impl OracleModule {
    /// Creates an Oracle database module.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Timeout for one attempt. The caller enforces the effective timeout.
    /// - `service_name`: Optional Oracle Service Name for Easy Connect syntax.
    /// - `sid`: Optional Oracle SID for a full Oracle Net connect descriptor.
    ///
    /// # Returns
    ///
    /// A stateless [`OracleModule`] instance.
    pub fn new(_timeout_ms: u64, service_name: Option<String>, sid: Option<String>) -> Self {
        Self { service_name, sid }
    }
}

#[async_trait]
impl BruteModule for OracleModule {
    /// Returns the protocol name used for console output and credential storage.
    fn name(&self) -> &'static str {
        "oracle"
    }

    /// Connects to Oracle with the supplied credentials and optionally runs a SQL query.
    ///
    /// # Parameters
    ///
    /// - `ctx`: Attempt context containing the target, credential, timeout, and optional SQL query.
    ///
    /// # Returns
    ///
    /// An authentication success, authentication failure, timeout, or task error outcome.
    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
        let username = ctx.credential.username.clone().unwrap_or_default();
        let password = ctx.credential.password.clone().unwrap_or_default();
        let config = match oracle_config(
            &ctx.target_host,
            port,
            self.service_name.as_deref(),
            self.sid.as_deref(),
            &username,
            &password,
            ctx.timeout(),
        ) {
            Ok(config) => config,
            Err(error) => return AttemptOutcome::Error(error),
        };

        let connection = match timeout(ctx.timeout(), Connection::connect_with_config(config)).await
        {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => return oracle_connection_outcome(error),
            Err(_) => return AttemptOutcome::Error("oracle connection timed out".to_string()),
        };

        match ctx.execute.as_deref() {
            Some(query) => AttemptOutcome::Success(
                execute_oracle_query(&connection, query, ctx.timeout()).await,
            ),
            None => AttemptOutcome::Success(AttemptSuccess::new("Oracle access!")),
        }
    }
}

/// Builds an oracle-rs connection configuration with exactly one database identifier.
///
/// # Parameters
///
/// - `target_host`: Target host name or IP address.
/// - `port`: Oracle listener port.
/// - `service_name`: Optional Oracle Service Name.
/// - `sid`: Optional Oracle SID.
/// - `username`: Database username for this attempt.
/// - `password`: Database password for this attempt.
/// - `connect_timeout`: Maximum time allowed for the connection handshake.
///
/// # Returns
///
/// An oracle-rs [`Config`] using Service Name or SID addressing.
///
/// # Errors
///
/// Returns an error when neither or both database identifiers are configured.
fn oracle_config(
    target_host: &str,
    port: u16,
    service_name: Option<&str>,
    sid: Option<&str>,
    username: &str,
    password: &str,
    connect_timeout: Duration,
) -> Result<Config, String> {
    match (service_name, sid) {
        (Some(service_name), None) if !service_name.trim().is_empty() => {
            Ok(
                Config::new(target_host, port, service_name, username, password)
                    .connect_timeout(connect_timeout),
            )
        }
        (None, Some(sid)) if !sid.trim().is_empty() => {
            Ok(Config::with_sid(target_host, port, sid, username, password)
                .connect_timeout(connect_timeout))
        }
        _ => Err("oracle requires exactly one non-empty Service Name or SID".to_string()),
    }
}

/// Converts an oracle-rs connection error into a brute attempt outcome.
///
/// # Parameters
///
/// - `error`: Connection error returned by oracle-rs.
///
/// # Returns
///
/// A retryable authentication failure, or a configuration error for a server older than Oracle 11g R2.
///
/// # Examples
///
/// The Oracle module calls this after an unsuccessful `Connection::connect_with_config` attempt.
fn oracle_connection_outcome(error: OracleError) -> AttemptOutcome {
    match error {
        OracleError::ProtocolVersionNotSupported(server, minimum) => {
            AttemptOutcome::Error(format!(
                "unsupported Oracle server protocol version {server}; brute requires Oracle Database 11g R2 (11.2)+ (minimum protocol version {minimum})"
            ))
        }
        OracleError::InvalidLengthIndicator(indicator) => AttemptOutcome::Error(format!(
            "oracle-rs received an unsupported Oracle wire-protocol length indicator ({indicator})"
        )),
        error => AttemptOutcome::Failure(format!("oracle authentication failed: {error}")),
    }
}

/// Removes trailing client-side SQL terminators before Oracle driver execution.
///
/// # Parameters
///
/// - `query`: SQL text supplied through `-x`.
///
/// # Returns
///
/// The original SQL without trailing whitespace or one or more trailing semicolons.
fn normalize_oracle_query(query: &str) -> &str {
    let mut normalized = query.trim_end();
    while let Some(without_semicolon) = normalized.strip_suffix(';') {
        normalized = without_semicolon.trim_end();
    }
    normalized
}

/// Executes a post-authentication Oracle SQL query and formats up to ten result rows.
///
/// # Parameters
///
/// - `connection`: Authenticated Oracle connection.
/// - `query`: SQL query to execute.
/// - `query_timeout`: Maximum time allowed for the query response.
///
/// # Returns
///
/// A success containing a result preview, or a command error that preserves the successful authentication state.
async fn execute_oracle_query(
    connection: &Connection,
    query: &str,
    query_timeout: Duration,
) -> AttemptSuccess {
    let query = normalize_oracle_query(query);
    execute_oracle_query_with_timeout(connection.query(query, &[]), query_timeout).await
}

/// Waits for an Oracle query result and formats up to ten rows.
///
/// # Parameters
///
/// - `query_future`: In-flight Oracle query operation.
/// - `query_timeout`: Maximum time allowed for the query response.
///
/// # Returns
///
/// A success containing a result preview, or a command error that preserves the successful authentication state.
async fn execute_oracle_query_with_timeout<F>(
    query_future: F,
    query_timeout: Duration,
) -> AttemptSuccess
where
    F: Future<Output = oracle_rs::Result<QueryResult>>,
{
    match timeout(query_timeout, query_future).await {
        Err(_) => AttemptSuccess::with_command_error("Oracle access!", "oracle query timed out"),
        Ok(Err(error)) => AttemptSuccess::with_command_error(
            "Oracle access!",
            format!("oracle query execution failed: {error}"),
        ),
        Ok(Ok(result)) => {
            let column_names = result
                .columns
                .iter()
                .map(|column| column.name.clone())
                .collect::<Vec<_>>();
            let formatted_rows = result
                .rows
                .iter()
                .take(10)
                .map(|row| format_oracle_row(row, &column_names))
                .collect::<Vec<_>>();
            AttemptSuccess::with_command("Oracle access!", format_oracle_rows(&formatted_rows))
        }
    }
}

/// Formats one Oracle query result row.
///
/// # Parameters
///
/// - `row`: A result row returned by the Oracle driver.
/// - `column_names`: Column names in the same order as the row values.
///
/// # Returns
///
/// A single line made of `COLUMN=VALUE` fragments.
fn format_oracle_row(row: &Row, column_names: &[String]) -> String {
    column_names
        .iter()
        .zip(row.values())
        .map(|(column_name, value)| format!("{column_name}={value}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Formats an Oracle query result preview for terminal output.
///
/// # Parameters
///
/// - `rows`: Formatted query result rows.
///
/// # Returns
///
/// A zero-row message when empty, or a row count followed by the individual rows.
fn format_oracle_rows(rows: &[String]) -> String {
    if rows.is_empty() {
        return "0 row(s) returned".to_string();
    }

    format!("{} row(s) returned\n{}", rows.len(), rows.join("\n"))
}

#[cfg(test)]
mod tests {
    use crate::protocol::PostAuthResult;

    use super::{
        AttemptOutcome, Connection, Duration, OracleError, QueryResult,
        execute_oracle_query_with_timeout, format_oracle_rows, normalize_oracle_query,
        oracle_config, oracle_connection_outcome,
    };

    #[test]
    /// Verifies oracle-rs configuration with an explicit Oracle Service Name.
    fn builds_service_name_configuration() {
        let config = oracle_config(
            "db.internal",
            1521,
            Some("ORCLPDB1"),
            None,
            "appuser",
            "password",
            Duration::from_secs(5),
        )
        .expect("Service Name configuration must be valid");

        assert_eq!(config.host, "db.internal");
        assert_eq!(config.port, 1521);
        assert_eq!(config.service.service_name(), Some("ORCLPDB1"));
        assert_eq!(config.service.sid(), None);
    }

    #[test]
    /// Verifies oracle-rs configuration with an explicit Oracle SID.
    fn builds_sid_configuration() {
        let config = oracle_config(
            "db.internal",
            1522,
            None,
            Some("ORCL"),
            "appuser",
            "password",
            Duration::from_secs(5),
        )
        .expect("SID configuration must be valid");

        assert_eq!(config.host, "db.internal");
        assert_eq!(config.port, 1522);
        assert_eq!(config.service.service_name(), None);
        assert_eq!(config.service.sid(), Some("ORCL"));
    }

    #[test]
    /// Verifies server protocols older than Oracle 11g R2 are reported as configuration errors.
    fn identifies_unsupported_pre_11g_r2_protocol() {
        let outcome = oracle_connection_outcome(OracleError::ProtocolVersionNotSupported(313, 314));

        match outcome {
            AttemptOutcome::Error(message) => {
                assert!(message.contains("313"));
                assert!(message.contains("314"));
                assert!(message.contains("11g R2"));
            }
            outcome => panic!("unexpected outcome: {outcome:?}"),
        }
    }

    #[test]
    /// Verifies the row count and preview formatting for query results.
    fn formats_query_rows_with_count_and_preview() {
        let rows = vec![
            "OWNER=SYSTEM, TABLE_NAME=USERS".to_string(),
            "OWNER=APP, TABLE_NAME=AUDIT_LOG".to_string(),
        ];

        assert_eq!(
            format_oracle_rows(&rows),
            "2 row(s) returned\nOWNER=SYSTEM, TABLE_NAME=USERS\nOWNER=APP, TABLE_NAME=AUDIT_LOG"
        );
    }

    #[test]
    /// Verifies formatting for an empty query result.
    fn formats_empty_query_result() {
        assert_eq!(format_oracle_rows(&[]), "0 row(s) returned");
    }

    #[test]
    /// Verifies client-side terminators and trailing whitespace are removed before execution.
    fn removes_trailing_oracle_sql_terminators() {
        assert_eq!(
            normalize_oracle_query("select * from dual;"),
            "select * from dual"
        );
        assert_eq!(
            normalize_oracle_query("select * from dual; ;\n\t"),
            "select * from dual"
        );
        assert_eq!(
            normalize_oracle_query("select ';' from dual;"),
            "select ';' from dual"
        );
    }

    #[tokio::test]
    /// Verifies a post-authentication query cannot wait longer than the attempt timeout.
    async fn times_out_slow_oracle_queries() {
        let result = execute_oracle_query_with_timeout(
            async {
                tokio::time::sleep(Duration::from_millis(25)).await;
                Err::<QueryResult, OracleError>(OracleError::InvalidCredentials)
            },
            Duration::from_millis(1),
        )
        .await;

        assert!(matches!(
            result.post_auth_result,
            Some(PostAuthResult::Failed(error)) if error == "oracle query timed out"
        ));
    }

    #[tokio::test]
    #[ignore = "requires an authorized Oracle instance configured with BRUTE_ORACLE_TEST_* variables"]
    /// Verifies a Service Name connection and read-only query against an authorized Oracle 11g test instance.
    async fn connects_to_authorized_oracle_11g_service() {
        let host = std::env::var("BRUTE_ORACLE_TEST_HOST").expect("test host must be configured");
        let port = std::env::var("BRUTE_ORACLE_TEST_PORT")
            .expect("test port must be configured")
            .parse::<u16>()
            .expect("test port must be a valid u16");
        let service_name = std::env::var("BRUTE_ORACLE_TEST_SERVICE_NAME")
            .expect("test Service Name must be configured");
        let username =
            std::env::var("BRUTE_ORACLE_TEST_USERNAME").expect("test username must be configured");
        let password =
            std::env::var("BRUTE_ORACLE_TEST_PASSWORD").expect("test password must be configured");
        let config = oracle_config(
            &host,
            port,
            Some(&service_name),
            None,
            &username,
            &password,
            Duration::from_secs(10),
        )
        .expect("Service Name configuration must be valid");
        let connection = Connection::connect_with_config(config)
            .await
            .expect("authorized Oracle connection must succeed");
        let result = connection
            .query("select 1 from dual", &[])
            .await
            .expect("read-only validation query must succeed");

        assert_eq!(result.rows.len(), 1);
    }
}
