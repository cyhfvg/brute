//! SSH login attempts using the pure-Rust `russh` client.

use std::{
    io::{BufRead, BufReader},
    net::{TcpStream, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use russh::{ChannelMsg, Disconnect, MethodKind, client};
use tokio::time::sleep;

use super::{
    AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext, TargetProbe,
};

/// SSH module configuration.
#[derive(Debug, Clone)]
pub struct SshModule;

impl SshModule {
    /// Creates a new SSH module instance.
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

/// Minimal SSH client handler that accepts host keys for credential verification workflows.
struct ClientHandler;

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    /// Accepts any server host key, matching scanner-style login verification behavior.
    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[async_trait]
impl BruteModule for SshModule {
    fn name(&self) -> &'static str {
        "ssh"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> TargetProbe {
        let addr = ctx.addr();
        let timeout = ctx.timeout();

        match tokio::time::timeout(
            timeout,
            tokio::task::spawn_blocking(move || read_ssh_banner(&addr, timeout)),
        )
        .await
        {
            Ok(Ok(Some(banner))) => TargetProbe::Ready(Some(banner)),
            _ => TargetProbe::Ready(None),
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        let addr = ctx.addr();
        let username = ctx.credential.username.clone().unwrap_or_default();
        let password = ctx.credential.password.clone().unwrap_or_default();
        let command = ctx.execute.clone();
        let retries = ctx.target.retries;
        let per_try_timeout = ctx.timeout();

        for attempt in 0..=retries {
            let result = tokio::time::timeout(
                per_try_timeout,
                try_ssh_login_once(
                    addr.clone(),
                    username.clone(),
                    password.clone(),
                    command.clone(),
                    per_try_timeout,
                ),
            )
            .await;

            match result {
                Ok(Ok(outcome)) => return outcome,
                Ok(Err(_)) | Err(_) if attempt < retries => {
                    let delay_ms = 150 * (attempt as u64 + 1);
                    sleep(Duration::from_millis(delay_ms)).await;
                }
                Ok(Err(_)) | Err(_) => {
                    return AttemptOutcome::Error("ssh transport failed".to_string());
                }
            }
        }

        AttemptOutcome::Error("ssh transport failed".to_string())
    }
}

/// Performs one SSH login attempt; transport errors are intentionally hidden from output.
async fn try_ssh_login_once(
    addr: String,
    username: String,
    password: String,
    command: Option<String>,
    timeout: Duration,
) -> Result<AttemptOutcome, ()> {
    let config = client::Config {
        inactivity_timeout: Some(timeout),
        nodelay: true,
        ..Default::default()
    };
    let mut session = client::connect(Arc::new(config), addr, ClientHandler)
        .await
        .map_err(|_| ())?;

    if !authenticate_ssh_password(&mut session, &username, &password)
        .await
        .map_err(|_| ())?
    {
        let _ = session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await;
        return Ok(AttemptOutcome::Failure("ssh auth failed".to_string()));
    }

    let outcome = match command {
        Some(command) => execute_ssh_command(&mut session, &command).await,
        None => AttemptOutcome::Success(AttemptSuccess::new("Linux - Shell access!")),
    };

    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await;

    Ok(outcome)
}

/// Authenticates with password auth first, then falls back to keyboard-interactive password prompts.
async fn authenticate_ssh_password(
    session: &mut client::Handle<ClientHandler>,
    username: &str,
    password: &str,
) -> Result<bool, russh::Error> {
    let auth = session.authenticate_password(username, password).await?;
    if auth.success() {
        return Ok(true);
    }

    let russh::client::AuthResult::Failure {
        remaining_methods, ..
    } = auth
    else {
        return Ok(false);
    };

    if !remaining_methods.contains(&MethodKind::KeyboardInteractive) {
        return Ok(false);
    }

    authenticate_keyboard_interactive_password(session, username, password).await
}

async fn authenticate_keyboard_interactive_password(
    session: &mut client::Handle<ClientHandler>,
    username: &str,
    password: &str,
) -> Result<bool, russh::Error> {
    let mut response = session
        .authenticate_keyboard_interactive_start(username, None)
        .await?;

    loop {
        match response {
            client::KeyboardInteractiveAuthResponse::Success => return Ok(true),
            client::KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            client::KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let responses = prompts
                    .iter()
                    .map(|prompt| {
                        keyboard_interactive_response(&prompt.prompt, prompt.echo, password)
                    })
                    .collect();
                response = session
                    .authenticate_keyboard_interactive_respond(responses)
                    .await?;
            }
        }
    }
}

fn keyboard_interactive_response(prompt: &str, echo: bool, password: &str) -> String {
    let prompt = prompt.to_ascii_lowercase();
    if !echo || prompt.contains("password") || prompt.contains("passcode") {
        password.to_string()
    } else {
        String::new()
    }
}

/// Reads a single SSH service banner without attempting authentication.
fn read_ssh_banner(addr: &str, timeout: Duration) -> Option<String> {
    let mut last_stream = None;
    for socket_addr in addr.to_socket_addrs().ok()? {
        match TcpStream::connect_timeout(&socket_addr, timeout) {
            Ok(stream) => {
                last_stream = Some(stream);
                break;
            }
            Err(_) => continue,
        }
    }

    let stream = last_stream?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let mut reader = BufReader::new(stream);

    // RFC 4253 allows servers to send pre-banner lines before the SSH identification string.
    for _ in 0..10 {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }

        let banner = line.trim_end_matches(['\r', '\n']);
        if banner.starts_with("SSH-") {
            return Some(banner.to_string());
        }
    }

    None
}

/// Runs a remote SSH command and formats stdout/stderr for the success line.
async fn execute_ssh_command(
    session: &mut client::Handle<ClientHandler>,
    command: &str,
) -> AttemptOutcome {
    let mut channel = match session.channel_open_session().await {
        Ok(channel) => channel,
        Err(err) => return AttemptOutcome::Error(format!("ssh channel creation failed: {err}")),
    };

    if let Err(err) = channel.exec(true, command).await {
        return AttemptOutcome::Error(format!("ssh command execution failed: {err}"));
    }

    let mut exit_status = None;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus {
                exit_status: status,
            } => exit_status = Some(status),
            _ => {}
        }
    }

    let output = format_command_output(exit_status, stdout, stderr);
    AttemptOutcome::Success(AttemptSuccess::with_command(
        "Linux - Shell access!",
        output,
    ))
}

/// Builds command output for NetExec-style follow-up lines.
fn format_command_output(exit_status: Option<u32>, stdout: Vec<u8>, stderr: Vec<u8>) -> String {
    let stdout = String::from_utf8_lossy(&stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&stderr).trim().to_string();

    match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => match exit_status {
            Some(status) => format!("exit status: {status}"),
            None => "exit status: unknown".to_string(),
        },
        (false, true) => stdout,
        (true, false) => format!("stderr: {stderr}"),
        (false, false) => format!("{stdout}\nstderr: {stderr}"),
    }
}
