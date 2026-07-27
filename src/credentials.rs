//! Credential source parsing and cartesian-product expansion.

use std::{fs, path::Path};

use anyhow::{Context, Result};

use crate::cli::CommonArgs;

/// One login attempt combination to test.
///
/// For most protocols this is a username/password pair. Oracle Service Name
/// enumeration may also attach an optional `service_name` so the scheduler can
/// expand `service × user × password` combinations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialSet {
    pub username: Option<String>,
    pub password: Option<String>,
    /// Oracle Service Name for this attempt; `None` for non-Oracle protocols or SID mode.
    pub service_name: Option<String>,
}

impl CredentialSet {
    /// Formats the credential combination for console output.
    ///
    /// # Returns
    ///
    /// `user:pass` for ordinary credentials, or `service/user:pass` when a Service Name is set.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let set = CredentialSet {
    ///     username: Some("APPUSER".into()),
    ///     password: Some("secret".into()),
    ///     service_name: Some("XE".into()),
    /// };
    /// assert_eq!(set.display(), "XE/APPUSER:secret");
    /// ```
    pub fn display(&self) -> String {
        let user_pass = match (&self.username, &self.password) {
            (Some(user), Some(pass)) => format!("{user}:{pass}"),
            (Some(user), None) => user.to_string(),
            (None, Some(pass)) => format!("<empty>:{pass}"),
            (None, None) => "<empty>:<empty>".to_string(),
        };

        match &self.service_name {
            Some(service) if !service.is_empty() => format!("{service}/{user_pass}"),
            _ => user_pass,
        }
    }
}

/// Loaded username, password, and optional Oracle Service Name sources.
#[derive(Debug, Clone)]
pub struct LoadedCredentials {
    pub usernames: Vec<String>,
    pub passwords: Vec<String>,
    /// Empty when Service Name is not part of the attempt space (all non-Oracle modules, Oracle SID mode).
    pub service_names: Vec<String>,
}

impl LoadedCredentials {
    /// Expands the loaded sources into a cartesian product of login attempts.
    ///
    /// # Returns
    ///
    /// When `service_names` is empty, expands `usernames × passwords` and leaves
    /// `CredentialSet::service_name` as `None`. When non-empty, expands
    /// `service_names × usernames × passwords`.
    ///
    /// Empty username or password strings become `None` on the resulting set.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let loaded = LoadedCredentials {
    ///     usernames: vec!["a".into()],
    ///     passwords: vec!["1".into(), "2".into()],
    ///     service_names: vec!["XE".into(), "ORCL".into()],
    /// };
    /// assert_eq!(loaded.expand().len(), 4);
    /// ```
    pub fn expand(&self) -> Vec<CredentialSet> {
        let service_layer: Vec<Option<String>> = if self.service_names.is_empty() {
            vec![None]
        } else {
            self.service_names
                .iter()
                .cloned()
                .map(Some)
                .collect()
        };

        let capacity = service_layer
            .len()
            .saturating_mul(self.usernames.len())
            .saturating_mul(self.passwords.len());
        let mut combinations = Vec::with_capacity(capacity);

        for service_name in &service_layer {
            for username in &self.usernames {
                for password in &self.passwords {
                    combinations.push(CredentialSet {
                        username: if username.is_empty() {
                            None
                        } else {
                            Some(username.clone())
                        },
                        password: if password.is_empty() {
                            None
                        } else {
                            Some(password.clone())
                        },
                        service_name: service_name.clone(),
                    });
                }
            }
        }

        combinations
    }
}

/// Loads usernames and passwords from inline values and file paths.
///
/// # Parameters
///
/// - `args`: Shared CLI options containing `-u` / `-p` sources.
///
/// # Returns
///
/// A [`LoadedCredentials`] value with empty `service_names` (caller may fill Oracle services later).
///
/// # Errors
///
/// Returns an error when a listed file path cannot be read.
///
/// # Examples
///
/// ```ignore
/// let loaded = load_credentials(&common_args)?;
/// let attempts = loaded.expand();
/// ```
pub fn load_credentials(args: &CommonArgs) -> Result<LoadedCredentials> {
    let usernames = expand_sources(&args.usernames, "username")?;
    let passwords = expand_sources(&args.passwords, "password")?;

    Ok(LoadedCredentials {
        usernames,
        passwords,
        service_names: Vec::new(),
    })
}

/// Loads Oracle Service Name values from inline values and file paths.
///
/// # Parameters
///
/// - `entries`: CLI `--service-name` arguments (literals and/or wordlist paths).
///
/// # Returns
///
/// Expanded Service Name strings with empty lines removed.
///
/// # Errors
///
/// Returns an error when a listed file path cannot be read.
///
/// # Examples
///
/// ```ignore
/// let services = load_service_names(&["XE".into(), "services.txt".into()])?;
/// ```
pub fn load_service_names(entries: &[String]) -> Result<Vec<String>> {
    expand_sources(entries, "service-name")
}

/// Expands a source list by treating existing paths as line-based wordlists.
///
/// # Parameters
///
/// - `entries`: Inline values and/or filesystem paths.
/// - `kind`: Human-readable label used in I/O error messages (`username`, `password`, `service-name`).
///
/// # Returns
///
/// Flattened values: file contents contribute one non-empty trimmed line each; non-file entries are kept as-is.
///
/// # Errors
///
/// Returns an error when an existing file cannot be read as UTF-8 text.
///
/// # Examples
///
/// ```ignore
/// let values = expand_sources(&["admin".into(), "users.txt".into()], "username")?;
/// ```
pub(crate) fn expand_sources(entries: &[String], kind: &str) -> Result<Vec<String>> {
    let mut values = Vec::new();

    for entry in entries {
        let path = Path::new(entry);
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
            values.push(entry.clone());
        }
    }

    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::{CredentialSet, LoadedCredentials, expand_sources};
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    /// Verifies username × password expansion when Service Names are absent.
    fn expands_two_dimensional_credentials_without_service_names() {
        let loaded = LoadedCredentials {
            usernames: vec!["a".to_string(), "b".to_string()],
            passwords: vec!["1".to_string(), "2".to_string()],
            service_names: Vec::new(),
        };

        let expanded = loaded.expand();
        assert_eq!(expanded.len(), 4);
        assert!(expanded.iter().all(|set| set.service_name.is_none()));
        assert_eq!(
            expanded[0],
            CredentialSet {
                username: Some("a".to_string()),
                password: Some("1".to_string()),
                service_name: None,
            }
        );
    }

    #[test]
    /// Verifies full service × user × password cartesian expansion.
    fn expands_three_dimensional_oracle_combinations() {
        let loaded = LoadedCredentials {
            usernames: vec!["APPUSER".to_string(), "SYSTEM".to_string()],
            passwords: vec!["p1".to_string(), "p2".to_string()],
            service_names: vec!["XE".to_string(), "ORCL".to_string()],
        };

        let expanded = loaded.expand();
        assert_eq!(expanded.len(), 8);
        assert_eq!(
            expanded
                .iter()
                .filter(|set| set.service_name.as_deref() == Some("XE"))
                .count(),
            4
        );
        assert!(expanded.iter().any(|set| {
            set.service_name.as_deref() == Some("ORCL")
                && set.username.as_deref() == Some("SYSTEM")
                && set.password.as_deref() == Some("p2")
        }));
    }

    #[test]
    /// Verifies console display includes the Service Name prefix when present.
    fn display_includes_service_name_prefix() {
        let with_service = CredentialSet {
            username: Some("APPUSER".to_string()),
            password: Some("secret".to_string()),
            service_name: Some("XE".to_string()),
        };
        let without_service = CredentialSet {
            username: Some("APPUSER".to_string()),
            password: Some("secret".to_string()),
            service_name: None,
        };

        assert_eq!(with_service.display(), "XE/APPUSER:secret");
        assert_eq!(without_service.display(), "APPUSER:secret");
    }

    #[test]
    /// Verifies wordlist files are expanded line-by-line and empty lines are dropped.
    fn expand_sources_reads_wordlist_files() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "brute-service-wordlist-{}-{nanos}.txt",
            std::process::id()
        ));
        fs::write(
            &path,
            "XE\n\n  ORCL  \n# not filtered as comment for service lists\n",
        )
        .expect("write wordlist");

        let values = expand_sources(
            &["INLINE".to_string(), path.to_string_lossy().into_owned()],
            "service-name",
        );
        let _ = fs::remove_file(&path);
        let values = values.expect("expand");

        assert_eq!(
            values,
            vec![
                "INLINE".to_string(),
                "XE".to_string(),
                "ORCL".to_string(),
                "# not filtered as comment for service lists".to_string(),
            ]
        );
    }
}
