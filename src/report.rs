//! Machine-readable report serialization and file export.
//!
//! The `-o/--output` flag writes only successful credentials so the file can be
//! handed to a report, review, or downstream tool without carrying failed
//! attempts. The SQLite credential store remains the source of truth.

use std::{fs, path::Path};

use anyhow::{Context, Result};

use crate::cli::OutputFileFormat;
use crate::engine::AttemptRecord;

/// Writes successful attempts to `path` in the requested format.
///
/// # Parameters
///
/// - `path`: Destination file. An existing file is replaced.
/// - `format`: `json` (JSON array), `csv` (header plus one row per success), or
///   `text` (one `protocol://user:pass@host:port` line per success).
/// - `successes`: Successful attempts to export.
///
/// # Returns
///
/// `Ok(())` after the file is written.
///
/// # Errors
///
/// Returns an error when JSON encoding or filesystem write fails.
///
/// # Examples
///
/// ```ignore
/// report::write_success_file(path, OutputFileFormat::Json, &report.successes)?;
/// ```
pub fn write_success_file(
    path: &Path,
    format: OutputFileFormat,
    successes: &[AttemptRecord],
) -> Result<()> {
    let content = match format {
        OutputFileFormat::Json => serde_json::to_string_pretty(successes)?,
        OutputFileFormat::Csv => to_csv(successes),
        OutputFileFormat::Text => to_text(successes),
    };
    fs::write(path, content)
        .with_context(|| format!("failed to write output file: {}", path.display()))
}

/// Serializes successes as a CSV document with a header row.
fn to_csv(successes: &[AttemptRecord]) -> String {
    let mut csv = String::from("protocol,host,port,username,password,service_name,sid\n");
    for record in successes {
        csv.push_str(&csv_row(&[
            &record.protocol,
            &record.host,
            &record.port.to_string(),
            record.username.as_deref().unwrap_or(""),
            record.password.as_deref().unwrap_or(""),
            record.service_name.as_deref().unwrap_or(""),
            record.sid.as_deref().unwrap_or(""),
        ]));
        csv.push('\n');
    }
    csv
}

/// Renders one CSV row with RFC 4180-style quoting.
fn csv_row(fields: &[&str]) -> String {
    fields
        .iter()
        .map(|field| {
            let needs_quoting = field
                .chars()
                .any(|ch| matches!(ch, ',' | '"' | '\n' | '\r'));
            if needs_quoting {
                format!("\"{}\"", field.replace('"', "\"\""))
            } else {
                (*field).to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Serializes successes as scanner-friendly connection URLs.
fn to_text(successes: &[AttemptRecord]) -> String {
    successes
        .iter()
        .map(|record| {
            format!(
                "{}://{}:{}@{}:{}",
                record.protocol,
                record.username.as_deref().unwrap_or(""),
                record.password.as_deref().unwrap_or(""),
                record.host,
                record.port
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::OutputFileFormat;

    fn sample() -> AttemptRecord {
        AttemptRecord {
            protocol: "ssh".to_string(),
            host: "192.168.5.5".to_string(),
            port: 22,
            username: Some("root".to_string()),
            password: Some("s3,cret\"x".to_string()),
            service_name: None,
            sid: None,
            status: crate::engine::AttemptStatus::Success,
            fault_class: None,
            message: "SSH access!".to_string(),
            post_auth: None,
        }
    }

    #[test]
    fn csv_quotes_fields_with_commas_and_quotes() {
        let csv = to_csv(&[sample()]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "protocol,host,port,username,password,service_name,sid");
        assert!(
            lines[1].contains("\"s3,cret\"\"x\""),
            "password must be RFC 4180 quoted:\n{}",
            lines[1]
        );
    }

    #[test]
    fn text_emits_connection_urls_per_line() {
        let text = to_text(&[sample()]);
        assert_eq!(text, "ssh://root:s3,cret\"x@192.168.5.5:22");
    }

    #[test]
    fn write_success_file_replaces_existing_file() {
        let path = std::env::temp_dir().join(format!(
            "brute-report-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        write_success_file(&path, OutputFileFormat::Json, &[sample()])
            .expect("write json file");
        let content = std::fs::read_to_string(&path).expect("read json file");
        let _ = std::fs::remove_file(&path);
        let parsed: serde_json::Value = serde_json::from_str(&content).expect("valid json");
        assert_eq!(parsed[0]["host"], "192.168.5.5");
    }
}
