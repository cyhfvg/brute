//! MySQL login attempts.

use async_trait::async_trait;
use mysql::{Conn, OptsBuilder, Row, Value, prelude::Queryable};

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
                        return AttemptOutcome::Success(execute_mysql_command(&mut conn, &command));
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
fn execute_mysql_command(conn: &mut Conn, command: &str) -> AttemptSuccess {
    match conn.query::<Row, _>(command) {
        Ok(rows) => AttemptSuccess::with_command("MySQL access!", format_rows(&rows, rows.len())),
        Err(err) => AttemptSuccess::with_command_error(
            "MySQL access!",
            format!("mysql command execution failed: {err}"),
        ),
    }
}

/// Formats MySQL rows for terminal output.
fn format_rows(rows: &[Row], row_count: usize) -> String {
    if rows.is_empty() {
        return "0 row(s) returned".to_string();
    }

    let preview = rows.iter().map(format_row).collect::<Vec<_>>().join("\n");
    format!("{row_count} row(s) returned\n{preview}")
}

fn format_row(row: &Row) -> String {
    row.columns_ref()
        .iter()
        .enumerate()
        .map(|(index, column)| {
            let value = row
                .as_ref(index)
                .map(format_value)
                .unwrap_or_else(|| "<taken>".to_string());
            format!("{}={}", column.name_str(), value)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_value(value: &Value) -> String {
    match value {
        Value::NULL => "NULL".to_string(),
        Value::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        Value::Int(value) => value.to_string(),
        Value::UInt(value) => value.to_string(),
        Value::Float(value) => value.to_string(),
        Value::Double(value) => value.to_string(),
        Value::Date(year, month, day, 0, 0, 0, 0) => {
            format!("{year:04}-{month:02}-{day:02}")
        }
        Value::Date(year, month, day, hour, minute, second, 0) => {
            format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
        }
        Value::Date(year, month, day, hour, minute, second, micros) => {
            format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{micros:06}")
        }
        Value::Time(is_negative, days, hours, minutes, seconds, 0) => {
            format_time(*is_negative, *days, *hours, *minutes, *seconds, None)
        }
        Value::Time(is_negative, days, hours, minutes, seconds, micros) => format_time(
            *is_negative,
            *days,
            *hours,
            *minutes,
            *seconds,
            Some(*micros),
        ),
    }
}

fn format_time(
    is_negative: bool,
    days: u32,
    hours: u8,
    minutes: u8,
    seconds: u8,
    micros: Option<u32>,
) -> String {
    let sign = if is_negative { "-" } else { "" };
    let day_prefix = if days == 0 {
        String::new()
    } else {
        format!("{days} ")
    };
    let fraction = micros
        .map(|micros| format!(".{micros:06}"))
        .unwrap_or_default();

    format!("{sign}{day_prefix}{hours:02}:{minutes:02}:{seconds:02}{fraction}")
}

#[cfg(test)]
mod tests {
    use mysql::Value;

    use super::{format_time, format_value};

    #[test]
    fn formats_bytes_without_debug_wrapper_or_truncation() {
        let value = Value::Bytes(b"db_party_long_database_name".to_vec());

        assert_eq!(format_value(&value), "db_party_long_database_name");
    }

    #[test]
    fn formats_mysql_temporal_values_for_display() {
        assert_eq!(
            format_value(&Value::Date(2026, 5, 28, 14, 3, 2, 123)),
            "2026-05-28 14:03:02.000123"
        );
        assert_eq!(format_time(true, 2, 3, 4, 5, Some(6)), "-2 03:04:05.000006");
    }
}
