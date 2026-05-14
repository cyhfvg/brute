//! FTP login attempts using an async client.

use async_trait::async_trait;
use suppaftp::{Status, tokio::AsyncRustlsFtpStream};

use super::{AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule};

/// FTP attempt errors split auth/connect failures from post-auth command failures.
#[derive(Debug)]
enum FtpAttemptError {
    Auth(String),
    Command(String),
}

/// FTP module configuration.
#[derive(Debug, Clone)]
pub struct FtpModule;

impl FtpModule {
    /// Creates a new FTP module instance.
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for FtpModule {
    fn name(&self) -> &'static str {
        "ftp"
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        let username = ctx
            .credential
            .username
            .clone()
            .unwrap_or_else(|| "anonymous".to_string());
        let password = ctx.credential.password.clone().unwrap_or_default();
        let addr = ctx.addr();
        let command = ctx.execute.clone();

        let future = async move {
            let mut stream = AsyncRustlsFtpStream::connect(addr)
                .await
                .map_err(|err| FtpAttemptError::Auth(err.to_string()))?;
            stream
                .login(&username, &password)
                .await
                .map_err(|err| FtpAttemptError::Auth(err.to_string()))?;
            let message = if let Some(command) = command {
                execute_ftp_command(&mut stream, &command)
                    .await
                    .map_err(FtpAttemptError::Command)?
            } else {
                AttemptSuccess::new("FTP access!")
            };
            let _ = stream.quit().await;
            Ok::<_, FtpAttemptError>(message)
        };

        match tokio::time::timeout(ctx.timeout(), future).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(FtpAttemptError::Auth(err))) => {
                AttemptOutcome::Failure(format!("ftp auth failed: {err}"))
            }
            Ok(Err(FtpAttemptError::Command(err))) => {
                AttemptOutcome::Error(format!("ftp command execution failed: {err}"))
            }
            Err(_) => AttemptOutcome::Error("attempt timed out".to_string()),
        }
    }
}

/// Executes an FTP command after authentication and returns a compact response.
async fn execute_ftp_command(
    stream: &mut AsyncRustlsFtpStream,
    command: &str,
) -> Result<AttemptSuccess, String> {
    let trimmed = command.trim();
    let upper = trimmed.to_ascii_uppercase();

    if upper == "LIST" || upper.starts_with("LIST ") {
        let path = trimmed
            .get(4..)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let lines = stream.list(path).await.map_err(|err| err.to_string())?;
        return Ok(AttemptSuccess::with_command(
            "FTP access!",
            format_lines(&lines, lines.len()),
        ));
    }

    if upper == "NLST" || upper.starts_with("NLST ") {
        let path = trimmed
            .get(4..)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let lines = stream.nlst(path).await.map_err(|err| err.to_string())?;
        return Ok(AttemptSuccess::with_command(
            "FTP access!",
            format_lines(&lines, lines.len()),
        ));
    }

    if upper == "PWD" {
        let pwd = stream.pwd().await.map_err(|err| err.to_string())?;
        return Ok(AttemptSuccess::with_command("FTP access!", pwd));
    }

    let response = stream
        .custom_command(trimmed, &positive_completion_statuses())
        .await
        .map_err(|err| err.to_string())?;
    Ok(AttemptSuccess::with_command(
        "FTP access!",
        response.to_string(),
    ))
}

/// Returns FTP status codes considered successful for custom control commands.
fn positive_completion_statuses() -> [Status; 15] {
    [
        Status::CommandOk,
        Status::CommandNotImplemented,
        Status::System,
        Status::Directory,
        Status::File,
        Status::Help,
        Status::Name,
        Status::Closing,
        Status::DataConnectionOpen,
        Status::ClosingDataConnection,
        Status::LoggedIn,
        Status::LoggedOut,
        Status::LogoutAck,
        Status::AuthOk,
        Status::RequestedFileActionOk,
    ]
}

/// Formats a short preview of FTP data-command lines.
fn format_lines(lines: &[String], line_count: usize) -> String {
    if lines.is_empty() {
        return "0 item(s) returned".to_string();
    }

    format!(
        "{line_count} item(s) returned\n{}",
        lines
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    )
}
