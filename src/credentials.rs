//! Credential source parsing and cartesian-product expansion.

use std::{fs, path::Path};

use anyhow::{Context, Result};

use crate::cli::CommonArgs;

/// One username/password combination to test.
#[derive(Debug, Clone)]
pub struct CredentialSet {
    pub username: Option<String>,
    pub password: Option<String>,
}

impl CredentialSet {
    /// Formats the credential pair for console output.
    pub fn display(&self) -> String {
        match (&self.username, &self.password) {
            (Some(user), Some(pass)) => format!("{user}:{pass}"),
            (Some(user), None) => user.to_string(),
            (None, Some(pass)) => format!("<empty>:{pass}"),
            (None, None) => "<empty>:<empty>".to_string(),
        }
    }
}

/// Loaded username and password sources.
#[derive(Debug, Clone)]
pub struct LoadedCredentials {
    pub usernames: Vec<String>,
    pub passwords: Vec<String>,
}

impl LoadedCredentials {
    /// Expands the loaded sources into a cartesian product of login attempts.
    pub fn expand(&self) -> Vec<CredentialSet> {
        self.usernames
            .clone()
            .into_iter()
            .flat_map(|username| {
                self.passwords
                    .iter()
                    .cloned()
                    .map(move |password| CredentialSet {
                        username: if username.is_empty() {
                            None
                        } else {
                            Some(username.clone())
                        },
                        password: if password.is_empty() {
                            None
                        } else {
                            Some(password)
                        },
                    })
            })
            .collect()
    }
}

/// Loads usernames and passwords from inline values and file paths.
pub fn load_credentials(args: &CommonArgs) -> Result<LoadedCredentials> {
    let usernames = expand_sources(args.usernames.clone(), "username")?;
    let passwords = expand_sources(args.passwords.clone(), "password")?;

    Ok(LoadedCredentials {
        usernames,
        passwords,
    })
}

/// Expands a source list by treating existing paths as line-based wordlists.
fn expand_sources(entries: Vec<String>, kind: &str) -> Result<Vec<String>> {
    let mut values = Vec::new();

    for entry in entries {
        let path = Path::new(&entry);
        if path.exists() && path.is_file() {
            let content = fs::read_to_string(path)
                .with_context(|| format!("failed to read {kind} file: {}", path.display()))?;
            values.extend(
                content
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .map(ToOwned::to_owned),
            );
        } else {
            values.push(entry);
        }
    }

    Ok(values)
}
