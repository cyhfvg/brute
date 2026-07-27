//! Credential source parsing and cartesian-product expansion.

use std::{fs, path::Path};

use anyhow::{Context, Result};

use crate::cli::CommonArgs;

/// One login attempt combination to test.
///
/// For most protocols this is a username/password pair. Oracle Service Name or
/// SID enumeration may also attach an optional database identifier so the
/// scheduler can expand `identifier × user × password` combinations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialSet {
    pub username: Option<String>,
    pub password: Option<String>,
    /// Oracle Service Name for this attempt; `None` when unused.
    pub service_name: Option<String>,
    /// Oracle SID for this attempt; `None` when unused.
    pub sid: Option<String>,
}

impl CredentialSet {
    /// Formats the credential combination for console output.
    ///
    /// # Returns
    ///
    /// - Ordinary credentials: `user:pass`
    /// - Service Name mode: `service/user:pass`
    /// - SID mode: `sid:SID/user:pass`
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let set = CredentialSet {
    ///     username: Some("APPUSER".into()),
    ///     password: Some("secret".into()),
    ///     service_name: None,
    ///     sid: Some("ORCL".into()),
    /// };
    /// assert_eq!(set.display(), "sid:ORCL/APPUSER:secret");
    /// ```
    pub fn display(&self) -> String {
        let user_pass = match (&self.username, &self.password) {
            (Some(user), Some(pass)) => format!("{user}:{pass}"),
            (Some(user), None) => user.to_string(),
            (None, Some(pass)) => format!("<empty>:{pass}"),
            (None, None) => "<empty>:<empty>".to_string(),
        };

        if let Some(service) = &self.service_name
            && !service.is_empty()
        {
            return format!("{service}/{user_pass}");
        }

        if let Some(sid) = &self.sid
            && !sid.is_empty()
        {
            return format!("sid:{sid}/{user_pass}");
        }

        user_pass
    }
}

/// Loaded username, password, and optional Oracle identifier sources.
#[derive(Debug, Clone)]
pub struct LoadedCredentials {
    pub usernames: Vec<String>,
    pub passwords: Vec<String>,
    /// Empty when Service Name is not part of the attempt space.
    pub service_names: Vec<String>,
    /// Empty when SID is not part of the attempt space.
    pub sids: Vec<String>,
}

impl LoadedCredentials {
    /// Expands the loaded sources into a cartesian product of login attempts.
    ///
    /// # Returns
    ///
    /// - When both `service_names` and `sids` are empty: `usernames × passwords`
    /// - When `service_names` is non-empty: `service_names × usernames × passwords`
    /// - When `sids` is non-empty: `sids × usernames × passwords`
    ///
    /// Callers must not populate both `service_names` and `sids` at once (CLI enforces
    /// mutual exclusion). Empty username or password strings become `None` on the set.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let loaded = LoadedCredentials {
    ///     usernames: vec!["a".into()],
    ///     passwords: vec!["1".into(), "2".into()],
    ///     service_names: Vec::new(),
    ///     sids: vec!["XE".into(), "ORCL".into()],
    /// };
    /// assert_eq!(loaded.expand().len(), 4);
    /// ```
    pub fn expand(&self) -> Vec<CredentialSet> {
        debug_assert!(
            self.service_names.is_empty() || self.sids.is_empty(),
            "service_names and sids must not both be non-empty"
        );

        enum Identifier {
            None,
            Service(String),
            Sid(String),
        }

        let identifiers: Vec<Identifier> = if !self.service_names.is_empty() {
            self.service_names
                .iter()
                .cloned()
                .map(Identifier::Service)
                .collect()
        } else if !self.sids.is_empty() {
            self.sids.iter().cloned().map(Identifier::Sid).collect()
        } else {
            vec![Identifier::None]
        };

        let capacity = identifiers
            .len()
            .saturating_mul(self.usernames.len())
            .saturating_mul(self.passwords.len());
        let mut combinations = Vec::with_capacity(capacity);

        for identifier in &identifiers {
            for username in &self.usernames {
                for password in &self.passwords {
                    let (service_name, sid) = match identifier {
                        Identifier::None => (None, None),
                        Identifier::Service(service) => (Some(service.clone()), None),
                        Identifier::Sid(sid) => (None, Some(sid.clone())),
                    };
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
                        service_name,
                        sid,
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
/// A [`LoadedCredentials`] value with empty Oracle identifier lists (caller may fill later).
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
        sids: Vec::new(),
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

/// Loads Oracle SID values from inline values and file paths.
///
/// # Parameters
///
/// - `entries`: CLI `--sid` arguments (literals and/or wordlist paths).
///
/// # Returns
///
/// Expanded SID strings with empty lines removed.
///
/// # Errors
///
/// Returns an error when a listed file path cannot be read.
///
/// # Examples
///
/// ```ignore
/// let sids = load_sids(&["ORCL".into(), "sids.txt".into()])?;
/// ```
pub fn load_sids(entries: &[String]) -> Result<Vec<String>> {
    expand_sources(entries, "sid")
}

/// Expands a source list by treating existing paths as line-based wordlists.
///
/// # Parameters
///
/// - `entries`: Inline values and/or filesystem paths.
/// - `kind`: Human-readable label used in I/O error messages (`username`, `password`, `service-name`, `sid`).
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

    fn empty_identifiers() -> (Vec<String>, Vec<String>) {
        (Vec::new(), Vec::new())
    }

    #[test]
    /// Verifies username × password expansion when Oracle identifiers are absent.
    fn expands_two_dimensional_credentials_without_identifiers() {
        let (service_names, sids) = empty_identifiers();
        let loaded = LoadedCredentials {
            usernames: vec!["a".to_string(), "b".to_string()],
            passwords: vec!["1".to_string(), "2".to_string()],
            service_names,
            sids,
        };

        let expanded = loaded.expand();
        assert_eq!(expanded.len(), 4);
        assert!(expanded.iter().all(|set| set.service_name.is_none()));
        assert!(expanded.iter().all(|set| set.sid.is_none()));
        assert_eq!(
            expanded[0],
            CredentialSet {
                username: Some("a".to_string()),
                password: Some("1".to_string()),
                service_name: None,
                sid: None,
            }
        );
    }

    #[test]
    /// Verifies full service × user × password cartesian expansion.
    fn expands_three_dimensional_service_name_combinations() {
        let loaded = LoadedCredentials {
            usernames: vec!["APPUSER".to_string(), "SYSTEM".to_string()],
            passwords: vec!["p1".to_string(), "p2".to_string()],
            service_names: vec!["XE".to_string(), "ORCL".to_string()],
            sids: Vec::new(),
        };

        let expanded = loaded.expand();
        assert_eq!(expanded.len(), 8);
        assert!(expanded.iter().all(|set| set.sid.is_none()));
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
    /// Verifies full sid × user × password cartesian expansion.
    fn expands_three_dimensional_sid_combinations() {
        let loaded = LoadedCredentials {
            usernames: vec!["APPUSER".to_string(), "SYSTEM".to_string()],
            passwords: vec!["p1".to_string(), "p2".to_string()],
            service_names: Vec::new(),
            sids: vec!["XE".to_string(), "ORCL".to_string()],
        };

        let expanded = loaded.expand();
        assert_eq!(expanded.len(), 8);
        assert!(expanded.iter().all(|set| set.service_name.is_none()));
        assert_eq!(
            expanded
                .iter()
                .filter(|set| set.sid.as_deref() == Some("XE"))
                .count(),
            4
        );
        assert!(expanded.iter().any(|set| {
            set.sid.as_deref() == Some("ORCL")
                && set.username.as_deref() == Some("SYSTEM")
                && set.password.as_deref() == Some("p2")
        }));
    }

    #[test]
    /// Verifies console display prefixes for Service Name and SID modes.
    fn display_includes_oracle_identifier_prefix() {
        let with_service = CredentialSet {
            username: Some("APPUSER".to_string()),
            password: Some("secret".to_string()),
            service_name: Some("XE".to_string()),
            sid: None,
        };
        let with_sid = CredentialSet {
            username: Some("APPUSER".to_string()),
            password: Some("secret".to_string()),
            service_name: None,
            sid: Some("ORCL".to_string()),
        };
        let plain = CredentialSet {
            username: Some("APPUSER".to_string()),
            password: Some("secret".to_string()),
            service_name: None,
            sid: None,
        };

        assert_eq!(with_service.display(), "XE/APPUSER:secret");
        assert_eq!(with_sid.display(), "sid:ORCL/APPUSER:secret");
        assert_eq!(plain.display(), "APPUSER:secret");
    }

    #[test]
    /// Verifies wordlist files are expanded line-by-line and empty lines are dropped.
    fn expand_sources_reads_wordlist_files() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "brute-sid-wordlist-{}-{nanos}.txt",
            std::process::id()
        ));
        fs::write(
            &path,
            "XE\n\n  ORCL  \n# not filtered as comment for sid lists\n",
        )
        .expect("write wordlist");

        let values = expand_sources(
            &["INLINE".to_string(), path.to_string_lossy().into_owned()],
            "sid",
        );
        let _ = fs::remove_file(&path);
        let values = values.expect("expand");

        assert_eq!(
            values,
            vec![
                "INLINE".to_string(),
                "XE".to_string(),
                "ORCL".to_string(),
                "# not filtered as comment for sid lists".to_string(),
            ]
        );
    }
}
