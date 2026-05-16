//! Redis login attempts.

use async_trait::async_trait;

use super::{AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule};

/// Redis attempt errors split auth/connect failures from post-auth command failures.
#[derive(Debug)]
enum RedisAttemptError {
    Auth(String),
    Command(String),
}

/// Redis module configuration.
#[derive(Debug, Clone)]
pub struct RedisModule;

impl RedisModule {
    /// Creates a new Redis module instance.
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for RedisModule {
    fn name(&self) -> &'static str {
        "redis"
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        let username = ctx.credential.username.clone().unwrap_or_default();
        let password = ctx.credential.password.clone().unwrap_or_default();
        let command = ctx.execute.clone();
        let url = if username.is_empty() {
            format!("redis://:{}@{}/", password, ctx.addr())
        } else {
            format!("redis://{}:{}@{}/", username, password, ctx.addr())
        };

        let attempt = async move {
            let client =
                redis::Client::open(url).map_err(|err| RedisAttemptError::Auth(err.to_string()))?;
            let mut conn = client
                .get_multiplexed_async_connection()
                .await
                .map_err(|err| RedisAttemptError::Auth(err.to_string()))?;
            let pong: String = redis::cmd("PING")
                .query_async(&mut conn)
                .await
                .map_err(|err| RedisAttemptError::Auth(err.to_string()))?;
            if pong.eq_ignore_ascii_case("PONG") {
                if let Some(command) = command {
                    execute_redis_command(&mut conn, &command)
                        .await
                        .map_err(RedisAttemptError::Command)
                } else {
                    Ok::<_, RedisAttemptError>(AttemptSuccess::new("Redis access!"))
                }
            } else {
                Err(RedisAttemptError::Auth(format!(
                    "unexpected ping response: {pong}"
                )))
            }
        };

        match tokio::time::timeout(ctx.timeout(), attempt).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(RedisAttemptError::Auth(err))) => {
                AttemptOutcome::Failure(format!("redis auth failed: {err}"))
            }
            Ok(Err(RedisAttemptError::Command(err))) => {
                AttemptOutcome::Error(format!("redis command execution failed: {err}"))
            }
            Err(_) => AttemptOutcome::Error("attempt timed out".to_string()),
        }
    }
}

/// Executes a Redis command parsed from a shell-like whitespace string.
async fn execute_redis_command(
    conn: &mut redis::aio::MultiplexedConnection,
    command: &str,
) -> Result<AttemptSuccess, String> {
    let parts = split_command(command);
    let Some((name, args)) = parts.split_first() else {
        return Err("empty redis command".to_string());
    };

    let mut redis_command = redis::cmd(name);
    for arg in args {
        redis_command.arg(arg);
    }

    let value: redis::Value = redis_command
        .query_async(conn)
        .await
        .map_err(|err| err.to_string())?;
    Ok(AttemptSuccess::with_command(
        "Redis access!",
        format_redis_value(&value),
    ))
}

/// Formats Redis command responses for terminal output instead of exposing raw protocol debug text.
fn format_redis_value(value: &redis::Value) -> String {
    match value {
        redis::Value::Nil => "(nil)".to_string(),
        redis::Value::Int(value) => value.to_string(),
        redis::Value::BulkString(bytes) => format_redis_bytes(bytes),
        redis::Value::Array(values) => format_redis_sequence(values, "array"),
        redis::Value::SimpleString(value) => normalize_redis_text(value),
        redis::Value::Okay => "OK".to_string(),
        redis::Value::Map(entries) => format_redis_map(entries),
        redis::Value::Attribute { data, attributes } => {
            let mut output = format_redis_value(data);
            if !attributes.is_empty() {
                output.push_str("\n(attributes)\n");
                output.push_str(&format_redis_map(attributes));
            }
            output
        }
        redis::Value::Set(values) => format_redis_sequence(values, "set"),
        redis::Value::Double(value) => value.to_string(),
        redis::Value::Boolean(value) => value.to_string(),
        redis::Value::VerbatimString { text, .. } => normalize_redis_text(text),
        redis::Value::BigNumber(value) => value.to_string(),
        redis::Value::Push { kind, data } => {
            format!(
                "push {kind:?}\n{}",
                format_redis_sequence(data, "push data")
            )
        }
        redis::Value::ServerError(err) => match err.details() {
            Some(details) => format!("{} {}", err.code(), details),
            None => err.code().to_string(),
        },
    }
}

fn format_redis_bytes(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(value) => normalize_redis_text(value),
        Err(_) => {
            let hex = bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            format!("(binary, {} bytes) {hex}", bytes.len())
        }
    }
}

fn normalize_redis_text(value: &str) -> String {
    value.replace("\r\n", "\n").replace('\r', "\n")
}

fn format_redis_sequence(values: &[redis::Value], label: &str) -> String {
    if values.is_empty() {
        return format!("(empty {label})");
    }

    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let formatted = indent_continuation_lines(&format_redis_value(value), "   ");
            format!("{}) {}", index + 1, formatted)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_redis_map(entries: &[(redis::Value, redis::Value)]) -> String {
    if entries.is_empty() {
        return "(empty map)".to_string();
    }

    entries
        .iter()
        .map(|(key, value)| {
            let key = indent_continuation_lines(&format_redis_value(key), "   ");
            let value = indent_continuation_lines(&format_redis_value(value), "   ");
            format!("{key}: {value}")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn indent_continuation_lines(value: &str, indent: &str) -> String {
    let mut lines = value.lines();
    let Some(first) = lines.next() else {
        return String::new();
    };

    let mut output = first.to_string();
    for line in lines {
        output.push('\n');
        output.push_str(indent);
        output.push_str(line);
    }
    output
}

/// Splits simple command strings while preserving quoted whitespace.
fn split_command(command: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quote = None;

    for ch in command.chars() {
        match (ch, quote) {
            ('\'' | '"', None) => quote = Some(ch),
            (c, Some(q)) if c == q => quote = None,
            (c, None) if c.is_whitespace() => {
                if !current.is_empty() {
                    parts.push(std::mem::take(&mut current));
                }
            }
            (c, _) => current.push(c),
        }
    }

    if !current.is_empty() {
        parts.push(current);
    }

    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_bulk_string_as_readable_text() {
        let value = redis::Value::BulkString(b"# Server\r\nredis_version:7.4.9\r\n".to_vec());

        assert_eq!(
            format_redis_value(&value),
            "# Server\nredis_version:7.4.9\n"
        );
    }

    #[test]
    fn formats_arrays_with_numbered_items() {
        let value = redis::Value::Array(vec![
            redis::Value::BulkString(b"key".to_vec()),
            redis::Value::Int(42),
        ]);

        assert_eq!(format_redis_value(&value), "1) key\n2) 42");
    }

    #[test]
    fn formats_binary_bulk_strings_as_hex() {
        let value = redis::Value::BulkString(vec![0xff, 0x00, 0x41]);

        assert_eq!(format_redis_value(&value), "(binary, 3 bytes) ff 00 41");
    }
}
