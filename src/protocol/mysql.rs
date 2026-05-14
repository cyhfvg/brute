//! MySQL login attempts.

use async_trait::async_trait;
use mysql::{Conn, OptsBuilder, Row, prelude::Queryable};

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, run_blocking_with_timeout,
};

/// MySQL module configuration.
#[derive(Debug, Clone)]
pub struct MySqlModule;

impl MySqlModule {
    /// Creates a new MySQL module instance.
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for MySqlModule {
    fn name(&self) -> &'static str {
        "mysql"
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        let host = ctx.target_host.clone();
        let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
        let username = ctx.credential.username.clone().unwrap_or_default();
        let password = ctx.credential.password.clone().unwrap_or_default();
        let command = ctx.execute.clone();

        run_blocking_with_timeout(ctx.timeout(), move || {
            let opts = OptsBuilder::default()
                .ip_or_hostname(Some(host))
                .tcp_port(port)
                .user(Some(username))
                .pass(Some(password))
                .stmt_cache_size(Some(0));

            match Conn::new(opts) {
                Ok(mut conn) => {
                    if let Some(command) = command {
                        return execute_mysql_command(&mut conn, &command);
                    }

                    if let Err(err) = conn.query_drop("SELECT 1") {
                        return AttemptOutcome::Error(format!(
                            "mysql post-auth query failed: {err}"
                        ));
                    }
                    AttemptOutcome::Success(AttemptSuccess::new("MySQL access!"))
                }
                Err(err) => AttemptOutcome::Failure(format!("mysql auth failed: {err}")),
            }
        })
        .await
    }
}

/// Executes a SQL command after authentication and formats returned rows.
fn execute_mysql_command(conn: &mut Conn, command: &str) -> AttemptOutcome {
    match conn.query::<Row, _>(command) {
        Ok(rows) => AttemptOutcome::Success(AttemptSuccess::with_command(
            "MySQL access!",
            format_rows(&rows, rows.len()),
        )),
        Err(err) => AttemptOutcome::Error(format!("mysql command execution failed: {err}")),
    }
}

/// Formats a small preview of MySQL rows for terminal output.
fn format_rows(rows: &[Row], row_count: usize) -> String {
    if rows.is_empty() {
        return "0 row(s) returned".to_string();
    }

    let preview = rows
        .iter()
        .take(10)
        .map(|row| format!("{row:?}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("{row_count} row(s) returned\n{preview}")
}
