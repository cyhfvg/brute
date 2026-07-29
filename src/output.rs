//! NetExec-style console rendering helpers.

use colored::{ColoredString, Colorize};

use crate::protocol::{AttemptContext, AttemptOutcome, PostAuthResult, TargetContext};

/// Lightweight terminal output wrapper.
#[derive(Debug)]
pub struct Console {
    no_color: bool,
}

impl Console {
    /// Constructs a console writer.
    pub fn new(no_color: bool) -> Self {
        Self { no_color }
    }

    /// Prints a single attempt result using fixed NetExec-like columns.
    pub fn print_attempt(&self, ctx: &AttemptContext, outcome: &AttemptOutcome) {
        let prefix = self.prefix(ctx);
        let credential = ctx.credential.display();

        match outcome {
            AttemptOutcome::Success(success) => {
                println!(
                    "{} {} {}  {}",
                    prefix,
                    self.paint("[+]", "green"),
                    self.paint(&credential, "green"),
                    success.message
                );

                if let Some(post_auth_result) = &success.post_auth_result {
                    match post_auth_result {
                        PostAuthResult::Output(output) => {
                            // Command modules keep the NetExec-style execute banner; SMB
                            // `--shares` and other non-execute post-auth details only print body lines.
                            if ctx.execute.is_some() {
                                println!(
                                    "{} {} Executed command",
                                    prefix,
                                    self.paint("[+]", "green")
                                );
                            }
                            for line in output.lines() {
                                println!("{} {}", prefix, line);
                            }
                        }
                        PostAuthResult::Failed(error) => {
                            let label = if ctx.execute.is_some() {
                                "Command execution failed"
                            } else {
                                "Post-auth operation failed"
                            };
                            println!(
                                "{} {} {}: {}",
                                prefix,
                                self.paint("[!]", "yellow"),
                                label,
                                error
                            );
                        }
                    }
                }
            }
            AttemptOutcome::Failure(_reason) => {
                println!("{} {} {}", prefix, self.paint("[-]", "red"), credential);
            }
            AttemptOutcome::Error(message) => {
                println!(
                    "{} {} {} {}",
                    prefix,
                    self.paint("[!]", "yellow"),
                    credential,
                    message
                );
            }
        }
    }

    /// Prints one successful target-level probe result.
    pub fn print_probe(&self, ctx: &TargetContext, message: &str) {
        println!(
            "{} {} {}",
            self.target_prefix(ctx),
            self.paint("[*]", "cyan"),
            message
        );
    }

    /// Builds the fixed-width output prefix used by every console line.
    fn prefix(&self, ctx: &AttemptContext) -> String {
        self.target_prefix(&TargetContext::from(ctx))
    }

    /// Builds the fixed-width three-column prefix for a target-level line.
    ///
    /// # Arguments
    ///
    /// * ctx - The protocol and target information to render.
    ///
    /// # Returns
    ///
    /// A prefix containing the protocol, target, and effective port. The target is rendered once
    /// because the currently supported protocols do not provide a reliable, shared remote-hostname
    /// field.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Example
    ///
    /// Produces a prefix such as SSH 192.168.5.5 22.
    fn target_prefix(&self, ctx: &TargetContext) -> String {
        format!(
            "{:<10} {:<15} {:<6}",
            format!("{:?}", ctx.protocol).to_uppercase(),
            ctx.target_host,
            ctx.port()
        )
    }

    /// Applies a best-effort terminal color.
    fn paint(&self, value: &str, color: &str) -> ColoredString {
        if self.no_color {
            return value.normal();
        }

        match color {
            "green" => value.green().bold(),
            "red" => value.red().bold(),
            "yellow" => value.yellow().bold(),
            "cyan" => value.cyan().bold(),
            _ => value.normal(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cli::{CommonArgs, Protocol},
        protocol::TargetContext,
    };

    use super::Console;

    /// Verifies that target prefixes display the target only once.
    #[test]
    fn target_prefix_omits_the_redundant_hostname_column() {
        let ctx = TargetContext {
            protocol: Protocol::Ssh,
            target_host: "192.168.5.5".to_string(),
            target: CommonArgs {
                targets: vec!["192.168.5.5".to_string()],
                usernames: vec!["admin".to_string()],
                passwords: vec!["123456".to_string()],
                credential_id: None,
                port: None,
                threads: 16,
                retries: 3,
                timeout_ms: 5_000,
                continue_on_success: false,
            },
        };

        assert_eq!(
            Console::new(true).target_prefix(&ctx),
            "SSH        192.168.5.5     22    "
        );
    }
}
