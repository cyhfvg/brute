//! Telnet login, unauthorized shell probe, and post-auth command execution (`-x`).
//!
//! Empty username and password probe whether the peer drops into a shell without
//! a login prompt. Non-empty credentials answer classic `login:` / `Password:`
//! prompts after a minimal IAC option-refusal handshake.

mod prompt;

pub use prompt::{
    is_auth_failure, is_login_prompt, is_password_prompt, is_shell_prompt, process_iac, strip_ansi,
};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

/// Telnet module configuration.
#[derive(Debug, Clone)]
pub struct TelnetModule;

impl TelnetModule {
    /// Creates a new Telnet module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`TelnetModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::telnet::TelnetModule;
    ///
    /// let _module = TelnetModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for TelnetModule {
    fn name(&self) -> &'static str {
        "telnet"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        match tokio::time::timeout(ctx.timeout(), probe_banner(ctx)).await {
            Ok(Some(message)) => TargetProbe::Ready(Some(message)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        match tokio::time::timeout(ctx.timeout(), attempt_once(ctx)).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(err)) if err.starts_with("auth:") => AttemptOutcome::Failure(format!(
                "telnet auth failed: {}",
                err.trim_start_matches("auth:")
            )),
            Ok(Err(err)) => AttemptOutcome::Error(format!("telnet transport failed: {err}")),
            Err(_) => AttemptOutcome::Error("attempt timed out".to_string()),
        }
    }
}

/// Runs one Telnet login or unauthorized shell probe, then optional `-x`.
///
/// # Parameters
///
/// - `ctx`: Target, credential, timeout, proxy, and optional execute command.
///
/// # Returns
///
/// [`AttemptSuccess`] when a shell prompt is reached.
///
/// # Errors
///
/// Returns `auth:...` on login failure and a transport string on I/O errors.
///
/// # Examples
///
/// ```ignore
/// let success = attempt_once(&ctx).await?;
/// ```
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, String> {
    let unauthenticated = is_unauthenticated(ctx);
    let mut session = TelnetSession::connect(
        &ctx.target_host,
        ctx.target.port.unwrap_or(ctx.protocol.default_port()),
        ctx.target.proxy.as_ref(),
    )
    .await?;
    session
        .reach_shell(
            ctx.credential.username.as_deref().unwrap_or(""),
            ctx.credential.password.as_deref().unwrap_or(""),
            unauthenticated,
        )
        .await?;
    let message = success_message(unauthenticated);
    match ctx.execute.as_deref() {
        Some(command) => match session.run_command(command).await {
            Ok(output) => Ok(AttemptSuccess::with_command(message, output)),
            Err(err) => Ok(AttemptSuccess::with_command_error(
                message,
                format!("telnet command execution failed: {err}"),
            )),
        },
        None => Ok(AttemptSuccess::new(message)),
    }
}

struct TelnetSession {
    stream: TcpStream,
    pending: Vec<u8>,
    text: String,
}

impl TelnetSession {
    async fn connect(
        host: &str,
        port: u16,
        proxy: Option<&crate::proxy::ProxyConfig>,
    ) -> Result<Self, String> {
        let stream = connect_stream(host, port, proxy).await?;
        let _ = stream.set_nodelay(true);
        Ok(Self {
            stream,
            pending: Vec::new(),
            text: String::new(),
        })
    }

    async fn reach_shell(
        &mut self,
        username: &str,
        password: &str,
        unauthenticated: bool,
    ) -> Result<(), String> {
        let mut user_sent = false;
        let mut pass_sent = false;
        for _ in 0..64 {
            self.read_more().await?;
            if is_auth_failure(&self.text) {
                return Err("auth:invalid username or password".to_string());
            }
            if is_shell_prompt(&self.text) && (pass_sent || unauthenticated) {
                return Ok(());
            }
            if unauthenticated {
                if is_login_prompt(&self.text) || is_password_prompt(&self.text) {
                    return Err("auth:login required".to_string());
                }
                continue;
            }
            if !user_sent && is_login_prompt(&self.text) {
                self.send_line(username).await?;
                user_sent = true;
                self.text.clear();
                continue;
            }
            if user_sent && !pass_sent && is_password_prompt(&self.text) {
                self.send_line(password).await?;
                pass_sent = true;
                self.text.clear();
            }
        }
        if pass_sent && !is_auth_failure(&self.text) && is_shell_prompt(&self.text) {
            return Ok(());
        }
        if unauthenticated {
            return Err("auth:login required".to_string());
        }
        Err("auth:no shell prompt".to_string())
    }

    async fn run_command(&mut self, command: &str) -> Result<String, String> {
        self.text.clear();
        self.send_line(command).await?;
        for _ in 0..32 {
            self.read_more().await?;
            if is_shell_prompt(&self.text) {
                return Ok(trim_command_output(&self.text, command));
            }
        }
        if self.text.trim().is_empty() {
            Err("no command output".to_string())
        } else {
            Ok(trim_command_output(&self.text, command))
        }
    }

    async fn send_line(&mut self, line: &str) -> Result<(), String> {
        self.stream
            .write_all(line.as_bytes())
            .await
            .map_err(|err| err.to_string())?;
        self.stream
            .write_all(b"\r\n")
            .await
            .map_err(|err| err.to_string())
    }

    async fn read_more(&mut self) -> Result<(), String> {
        let mut buf = [0u8; 1024];
        let n = self
            .stream
            .read(&mut buf)
            .await
            .map_err(|err| err.to_string())?;
        if n == 0 {
            if is_auth_failure(&self.text) {
                return Err("auth:invalid username or password".to_string());
            }
            return Err("connection closed".to_string());
        }
        self.pending.extend_from_slice(&buf[..n]);
        let (replies, text, consumed) = process_iac(&self.pending);
        self.pending.drain(..consumed);
        if !replies.is_empty() {
            self.stream
                .write_all(&replies)
                .await
                .map_err(|err| err.to_string())?;
        }
        if text.contains("\u{1b}[6n") {
            self.stream
                .write_all(b"\x1b[1;1R")
                .await
                .map_err(|err| err.to_string())?;
        }
        self.text.push_str(&strip_ansi(&text));
        Ok(())
    }
}

async fn connect_stream(
    host: &str,
    port: u16,
    proxy: Option<&crate::proxy::ProxyConfig>,
) -> Result<TcpStream, String> {
    match proxy {
        Some(proxy) => crate::proxy::connect_async(proxy, host, port).await,
        None => TcpStream::connect((host, port))
            .await
            .map_err(|err| err.to_string()),
    }
}

fn trim_command_output(text: &str, command: &str) -> String {
    let normalized = text.replace('\r', "");
    let without_echo = normalized
        .strip_prefix(command)
        .unwrap_or(&normalized)
        .trim_start_matches(['\n', ' ']);
    let mut lines: Vec<&str> = without_echo.lines().collect();
    if let Some(last) = lines.last()
        && is_shell_prompt(last)
    {
        lines.pop();
    }
    let joined = lines.join("\n");
    const MAX: usize = 8192;
    let trimmed = joined.trim();
    if trimmed.len() > MAX {
        format!("{}\n...", &trimmed[..MAX])
    } else {
        trimmed.to_string()
    }
}

async fn probe_banner(ctx: &TargetContext) -> Option<String> {
    let mut session =
        TelnetSession::connect(&ctx.target_host, ctx.port(), ctx.target.proxy.as_ref())
            .await
            .ok()?;
    for _ in 0..8 {
        if session.read_more().await.is_err() {
            break;
        }
        if is_login_prompt(&session.text) || is_shell_prompt(&session.text) {
            return Some("Telnet".to_string());
        }
    }
    if session.text.is_empty() {
        None
    } else {
        Some("Telnet".to_string())
    }
}

fn is_unauthenticated(ctx: &AttemptContext) -> bool {
    ctx.credential.username.as_deref().unwrap_or("").is_empty()
        && ctx.credential.password.as_deref().unwrap_or("").is_empty()
}

fn success_message(unauthenticated: bool) -> &'static str {
    if unauthenticated {
        "Telnet unauthorized access!"
    } else {
        "Telnet shell access!"
    }
}
