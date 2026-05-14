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
        format!("{value:?}"),
    ))
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
