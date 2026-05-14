//! NetExec-style console rendering helpers.

use colored::{ColoredString, Colorize};

use crate::protocol::{AttemptContext, AttemptOutcome, TargetContext};

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

                if let Some(output) = success.command_output.as_deref() {
                    println!("{} {} Executed command", prefix, self.paint("[+]", "green"));
                    for line in output.lines() {
                        println!("{} {}", prefix, line);
                    }
                }
            }
            AttemptOutcome::Failure(_) => {
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

    /// Builds the fixed-width output prefix for a target-level line.
    fn target_prefix(&self, ctx: &TargetContext) -> String {
        format!(
            "{:<24} {:<15} {:<6} {:<15}",
            format!("{:?}", ctx.protocol).to_uppercase(),
            ctx.target_host,
            ctx.port(),
            ctx.target_host
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
