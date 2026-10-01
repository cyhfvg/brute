//! Saved-credential CLI commands.

use std::{
    fs,
    io::{self, Read},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::cli::{
    CredsAction, CredsArgs, CredsDeleteArgs, CredsExportArgs, CredsFormat, CredsImportArgs,
    CredsListArgs,
};
use crate::credentials::CredentialSet;
use crate::database::CredentialDatabase;
use crate::engine::{CredentialRecord, delete_credentials, parse_protocol, query_credentials};

/// Executes `creds list`, `creds delete`, `creds export`, or `creds import`.
///
/// # Parameters
///
/// - `database`: Open credential database.
/// - `args`: Parsed `creds` subcommand.
///
/// # Returns
///
/// `Ok(())` when the command finishes. A requested id that was not deleted is an error.
///
/// # Errors
///
/// Returns an error when the query or delete fails, the delete is unscoped, a
/// requested credential id was not found, or an import/export source is invalid.
///
/// # Examples
///
/// ```ignore
/// creds::run(&database, args)?;
/// ```
pub fn run(database: &CredentialDatabase, args: CredsArgs) -> Result<()> {
    match args.action {
        CredsAction::List(args) => list(database, args),
        CredsAction::Delete(args) => delete(database, args),
        CredsAction::Export(args) => export(database, args),
        CredsAction::Import(args) => import(database, args),
    }
}

/// Prints saved credentials in the current workspace.
///
/// # Parameters
///
/// - `database`: Open credential database.
/// - `args`: Parsed `creds list` arguments. The workspace is always the current one.
///
/// # Returns
///
/// `Ok(())` after the table is printed.
///
/// # Errors
///
/// Returns an error when the current workspace cannot be read or the query fails.
///
/// # Examples
///
/// ```ignore
/// list(&database, args)?;
/// ```
fn list(database: &CredentialDatabase, args: CredsListArgs) -> Result<()> {
    let workspace = database.current_workspace()?;
    let credentials = query_credentials(
        database,
        Some(workspace.as_str()),
        args.protocol,
        args.host.as_deref(),
        args.username.as_deref(),
    )?;
    println!("current workspace: {workspace}");
    print_saved_credentials(&credentials, args.conn_url);
    Ok(())
}

/// Deletes saved credentials in the current workspace and prints that workspace.
///
/// # Parameters
///
/// - `database`: Open credential database.
/// - `args`: Parsed `creds delete` arguments. The workspace is always the current one.
///
/// # Returns
///
/// `Ok(())` when every requested id was deleted, or when a filter delete finishes.
///
/// # Errors
///
/// Returns an error when the delete is unscoped, the database call fails, or a
/// requested credential id was not found in the current workspace.
///
/// # Examples
///
/// ```ignore
/// delete(&database, args)?;
/// ```
fn delete(database: &CredentialDatabase, args: CredsDeleteArgs) -> Result<()> {
    let report = delete_credentials(
        database,
        None,
        args.protocol,
        args.host.as_deref(),
        &args.ids,
        args.all,
    )?;
    println!("current workspace: {}", report.workspace);
    for credential in &report.deleted {
        println!(
            "deleted credential: {} {} {}@{}:{}",
            credential.id,
            credential.protocol,
            display_username(credential.username.as_deref()),
            credential.host,
            credential.port
        );
    }
    let count = report.deleted.len();
    if count == 1 {
        println!("deleted 1 credential");
    } else {
        println!("deleted {count} credentials");
    }
    if report.missing_ids.is_empty() {
        return Ok(());
    }
    let missing = report
        .missing_ids
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    bail!("credential not found: {missing}")
}

/// Portable credential record used by `creds export` and `creds import`.
///
/// It carries only the fields a credential needs to move between machines or
/// tools. Workspace, id, and connection URL are derived locally on import.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PortableCredential {
    protocol: String,
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

impl From<&CredentialRecord> for PortableCredential {
    fn from(record: &CredentialRecord) -> Self {
        Self {
            protocol: record.protocol.clone(),
            host: record.host.clone(),
            port: record.port,
            username: record.username.clone(),
            password: record.password.clone(),
        }
    }
}

/// Exports every credential in the current workspace.
fn export(database: &CredentialDatabase, args: CredsExportArgs) -> Result<()> {
    let workspace = database.current_workspace()?;
    let credentials = query_credentials(database, Some(workspace.as_str()), None, None, None)?;
    let portable: Vec<PortableCredential> =
        credentials.iter().map(PortableCredential::from).collect();
    let content = match args.format {
        CredsFormat::Json => serde_json::to_string_pretty(&portable)?,
        CredsFormat::Csv => portable_to_csv(&portable),
    };
    write_export(&content, args.output.as_deref())
}

/// Imports credentials into the current workspace.
fn import(database: &CredentialDatabase, args: CredsImportArgs) -> Result<()> {
    let workspace = database.current_workspace()?;
    let text = read_source(&args.source)?;
    let portable = match args.format {
        CredsFormat::Json => serde_json::from_str::<Vec<PortableCredential>>(&text)
            .with_context(|| "failed to parse JSON credential import")?,
        CredsFormat::Csv => parse_portable_csv(&text)?,
    };

    for record in &portable {
        let protocol = parse_protocol(&record.protocol)?;
        let credential = CredentialSet {
            username: record.username.clone(),
            password: record.password.clone(),
            service_name: None,
            sid: None,
        };
        database.save_success(&workspace, protocol, &record.host, record.port, &credential)?;
    }

    let count = portable.len();
    if count == 1 {
        println!("imported 1 credential into workspace: {workspace}");
    } else {
        println!("imported {count} credentials into workspace: {workspace}");
    }
    Ok(())
}

/// Writes export content to a file, or to stdout when `output` is `None` or `-`.
fn write_export(content: &str, output: Option<&str>) -> Result<()> {
    match output {
        None | Some("-") => {
            println!("{content}");
            Ok(())
        }
        Some(path) => {
            fs::write(path, content).with_context(|| format!("failed to write export file: {path}"))
        }
    }
}

/// Reads an import source that is either `-` (stdin) or a file path.
fn read_source(source: &str) -> Result<String> {
    if source == "-" {
        let mut text = String::new();
        io::stdin()
            .read_to_string(&mut text)
            .context("failed to read stdin")?;
        Ok(text)
    } else {
        fs::read_to_string(source)
            .with_context(|| format!("failed to read import file: {source}"))
    }
}

/// CSV header shared by `creds export --format csv` and its importer.
const PORTABLE_CSV_HEADER: &str = "protocol,host,port,username,password";

/// Serializes portable credentials as CSV.
fn portable_to_csv(records: &[PortableCredential]) -> String {
    let mut csv = String::from(PORTABLE_CSV_HEADER);
    csv.push('\n');
    for record in records {
        csv.push_str(&crate::csv::row(&[
            &record.protocol,
            &record.host,
            &record.port.to_string(),
            record.username.as_deref().unwrap_or(""),
            record.password.as_deref().unwrap_or(""),
        ]));
        csv.push('\n');
    }
    csv
}

/// Parses portable credentials from CSV text.
fn parse_portable_csv(text: &str) -> Result<Vec<PortableCredential>> {
    let mut records = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if index == 0 && line.trim() == PORTABLE_CSV_HEADER {
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        let fields = crate::csv::parse_line(line)?;
        if fields.len() != 5 {
            bail!(
                "expected 5 CSV columns (protocol,host,port,username,password), got {}",
                fields.len()
            );
        }
        let port: u16 = fields[2]
            .parse()
            .with_context(|| format!("invalid port in CSV row {}: {:?}", index + 1, fields[2]))?;
        records.push(PortableCredential {
            protocol: fields[0].clone(),
            host: fields[1].clone(),
            port,
            username: none_if_empty(fields[3].clone()),
            password: none_if_empty(fields[4].clone()),
        });
    }
    Ok(records)
}

/// Converts an empty string into `None`, matching the saved-credential convention.
fn none_if_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

/// Renders an empty username as `-`.
fn display_username(username: Option<&str>) -> &str {
    match username {
        Some(value) if !value.is_empty() => value,
        _ => "-",
    }
}

/// Prints saved credentials as a simple list table.
fn print_saved_credentials(credentials: &[CredentialRecord], show_conn_url: bool) {
    if show_conn_url {
        println!("{:<6} {:<12} CONN_URL", "ID", "PROTOCOL");
    } else {
        println!(
            "{:<6} {:<16} {:<12} {:<20} {:<6} {:<20} PASSWORD",
            "ID", "WORKSPACE", "PROTOCOL", "HOST", "PORT", "USERNAME"
        );
    }

    for credential in credentials {
        let username = credential.username.as_deref().unwrap_or("");
        let password = credential.password.as_deref().unwrap_or("");

        if show_conn_url {
            println!(
                "{:<6} {:<12} {}",
                credential.id, credential.protocol, credential.conn_url
            );
        } else {
            println!(
                "{:<6} {:<16} {:<12} {:<20} {:<6} {:<20} {}",
                credential.id,
                credential.workspace,
                credential.protocol,
                credential.host,
                credential.port,
                username,
                password
            );
        }
    }
}
