//! RabbitMQ AMQP 0-9-1 login and post-auth queue declare (`-x`).
//!
//! Empty username and password probe `guest`/`guest`. Non-empty credentials use SASL PLAIN.

use amqprs::channel::QueueDeclareArguments;
use amqprs::connection::{Connection, OpenConnectionArguments};
use async_trait::async_trait;

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

/// RabbitMQ module configuration.
#[derive(Debug, Clone)]
pub struct RabbitMqModule;

impl RabbitMqModule {
    /// Creates a new RabbitMQ module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`RabbitMqModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::rabbitmq::RabbitMqModule;
    ///
    /// let _module = RabbitMqModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for RabbitMqModule {
    fn name(&self) -> &'static str {
        "rabbitmq"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_amqp(ctx)).await {
            Ok(true) => TargetProbe::Ready(Some("RabbitMQ AMQP".to_string())),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        match tokio::time::timeout(ctx.timeout(), attempt_once(ctx)).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(err)) if is_auth_error(&err) => {
                AttemptOutcome::Failure(format!("rabbitmq auth failed: {err}"))
            }
            Ok(Err(err)) => AttemptOutcome::Error(format!("rabbitmq transport failed: {err}")),
            Err(_) => AttemptOutcome::Error("attempt timed out".to_string()),
        }
    }
}

/// Runs one AMQP login, then optional queue.declare.
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, String> {
    let unauthenticated = is_unauthenticated(ctx);
    let username = if unauthenticated {
        "guest"
    } else {
        ctx.credential.username.as_deref().unwrap_or("")
    };
    let password = if unauthenticated {
        "guest"
    } else {
        ctx.credential.password.as_deref().unwrap_or("")
    };
    let host = ctx.target_host.as_str();
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let endpoint =
        crate::proxy::resolve_tcp_endpoint(ctx.target.proxy.as_ref(), host, port).await?;
    let (connect_host, connect_port, _bridge) = endpoint;
    let args = OpenConnectionArguments::new(&connect_host, connect_port, username, password);
    let connection = Connection::open(&args)
        .await
        .map_err(|err| err.to_string())?;
    let message = if unauthenticated {
        "RabbitMQ unauthorized access!"
    } else {
        "RabbitMQ access!"
    };
    let success = match ctx.execute.as_deref() {
        Some(command) => {
            let channel = connection
                .open_channel(None)
                .await
                .map_err(|err| err.to_string())?;
            let queue = if command.trim().is_empty() {
                "brute"
            } else {
                command.trim()
            };
            match channel
                .queue_declare(QueueDeclareArguments::new(queue))
                .await
            {
                Ok(Some((name, messages, consumers))) => AttemptSuccess::with_command(
                    message,
                    format!("queue={name} messages={messages} consumers={consumers}"),
                ),
                Ok(None) => AttemptSuccess::with_command(message, format!("declared {queue}")),
                Err(err) => AttemptSuccess::with_command_error(
                    message,
                    format!("rabbitmq command execution failed: {err}"),
                ),
            }
        }
        None => AttemptSuccess::new(message),
    };
    let _ = connection.close().await;
    Ok(success)
}

/// Returns whether an AMQP error represents authentication failure.
///
/// # Parameters
///
/// - `err`: Driver error text.
///
/// # Returns
///
/// `true` for ACCESS-REFUSED / 403 / authentication wording.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::rabbitmq::is_auth_error;
///
/// assert!(is_auth_error("ACCESS_REFUSED - Login was refused"));
/// assert!(!is_auth_error("connection refused"));
/// ```
pub fn is_auth_error(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    if lower.contains("connection refused")
        || lower.contains("network unreachable")
        || lower.contains("timed out")
        || lower.contains("timeout")
    {
        return false;
    }
    lower.contains("access_refused")
        || lower.contains("access-refused")
        || lower.contains("login was refused")
        || lower.contains("authentication")
        || lower.contains("403")
        || lower.contains("peer shutdown")
        || lower.contains("connection reset")
}

fn is_unauthenticated(ctx: &AttemptContext) -> bool {
    ctx.credential.username.as_deref().unwrap_or("").is_empty()
        && ctx.credential.password.as_deref().unwrap_or("").is_empty()
}

async fn probe_amqp(ctx: &TargetContext) -> bool {
    TcpProbe::connect(&ctx.target_host, ctx.port()).await
}

struct TcpProbe;

impl TcpProbe {
    async fn connect(host: &str, port: u16) -> bool {
        tokio::net::TcpStream::connect((host, port)).await.is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn is_auth_error_detects_access_refused() {
        assert!(is_auth_error(
            "ACCESS-REFUSED - Login was refused using authentication mechanism PLAIN"
        ));
        assert!(is_auth_error("AMQP network error: peer shutdown"));
        assert!(!is_auth_error("connection refused"));
    }
}
