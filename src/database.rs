//! SQLite-backed workspace and credential storage.

use std::{
    env, fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{cli::Protocol, credentials::CredentialSet};

/// Default workspace name used when the database is first created.
pub const DEFAULT_WORKSPACE: &str = "default";

/// Database path relative to the user's home directory (`~/.config/brute/brute.db`).
const DEFAULT_DATABASE_RELATIVE_PATH: &str = ".config/brute/brute.db";

/// Local SQLite database wrapper.
#[derive(Debug, Clone)]
pub struct CredentialDatabase {
    path: PathBuf,
}

/// One workspace record.
#[derive(Debug, Clone)]
pub struct WorkspaceRecord {
    pub name: String,
    pub is_current: bool,
}

/// One saved credential record.
#[derive(Debug, Clone)]
pub struct SavedCredential {
    pub id: i64,
    pub workspace: String,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub conn_url: String,
}

impl CredentialDatabase {
    /// Returns the default SQLite database path under `~/.config/brute/brute.db`.
    ///
    /// # Parameters
    ///
    /// None. The path is derived from the `HOME` environment variable.
    ///
    /// # Returns
    ///
    /// Absolute path to `~/.config/brute/brute.db`.
    ///
    /// # Errors
    ///
    /// Returns an error when `HOME` is unset.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use brute::database::CredentialDatabase;
    ///
    /// let path = CredentialDatabase::default_path().expect("HOME must be set");
    /// assert!(path.ends_with(".config/brute/brute.db"));
    /// ```
    pub fn default_path() -> Result<PathBuf> {
        let home = env::var_os("HOME").context("HOME environment variable is not set")?;
        Ok(PathBuf::from(home).join(DEFAULT_DATABASE_RELATIVE_PATH))
    }

    /// Opens the default SQLite database and reports whether it had to be initialized.
    ///
    /// # Parameters
    ///
    /// None. Uses [`Self::default_path`].
    ///
    /// # Returns
    ///
    /// `(database, initialized)` where `initialized` is `true` when the file did not exist
    /// before this call and was created during open.
    ///
    /// # Errors
    ///
    /// Returns an error when the default path cannot be resolved, the parent directory cannot
    /// be created, or the SQLite schema cannot be applied.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use brute::database::CredentialDatabase;
    ///
    /// let (database, initialized) = CredentialDatabase::open_default()?;
    /// if initialized {
    ///     println!("created {}", database.path().display());
    /// }
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn open_default() -> Result<(Self, bool)> {
        let path = Self::default_path()?;
        let initialized = !path.exists();
        let database = Self::open(path)?;
        Ok((database, initialized))
    }

    /// Opens or creates the SQLite database and restricts Unix store permissions.
    ///
    /// # Parameters
    ///
    /// - `path`: Database file path. Missing parent directories are created.
    ///
    /// # Returns
    ///
    /// An open [`CredentialDatabase`]. On Unix a parent directory created by this
    /// call is `0o700`. An existing private parent loses mode bits outside `0o700`.
    /// Shared parents such as `/tmp` are left unchanged. A new database file is
    /// `0o600`; an existing file loses mode bits outside `0o600`. Windows skips
    /// Unix mode bits.
    ///
    /// # Errors
    ///
    /// Returns an error when the parent directory cannot be created, permissions
    /// cannot be applied, or the SQLite schema cannot be initialized.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let database = CredentialDatabase::open("/tmp/brute-store/brute.db")?;
    /// ```
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let database = Self { path: path.into() };
        let created_dir = prepare_store_directory(&database.path)?;
        restrict_store_directory(&database.path, created_dir)?;
        let created_file = !database.path.exists();
        let conn = database.connect()?;
        database.init_schema(&conn)?;
        database.ensure_workspace(&conn, DEFAULT_WORKSPACE)?;
        database.ensure_current_workspace(&conn)?;
        restrict_database_file(&database.path, created_file)?;
        Ok(database)
    }

    /// Returns the database path.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Returns the currently selected workspace.
    pub fn current_workspace(&self) -> Result<String> {
        let conn = self.connect()?;
        self.ensure_current_workspace(&conn)
    }

    /// Marks an existing workspace as current.
    pub fn set_current_workspace(&self, name: &str) -> Result<()> {
        let conn = self.connect()?;
        let workspace_id = conn
            .query_row(
                "SELECT id FROM workspaces WHERE name = ?1",
                params![name],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;

        if workspace_id.is_none() {
            bail!("workspace '{name}' does not exist; create it with `brute workspace new {name}`");
        }

        conn.execute("UPDATE workspaces SET is_current = 0", [])?;
        conn.execute(
            "UPDATE workspaces SET is_current = 1 WHERE name = ?1",
            params![name],
        )?;
        Ok(())
    }

    /// Creates a workspace and returns true when it was newly inserted.
    pub fn create_workspace(&self, name: &str) -> Result<bool> {
        if name.trim().is_empty() {
            bail!("workspace name cannot be empty");
        }

        let conn = self.connect()?;
        let changes = conn.execute(
            "INSERT OR IGNORE INTO workspaces (name, is_current) VALUES (?1, 0)",
            params![name],
        )?;
        Ok(changes > 0)
    }

    /// Deletes a workspace and its saved credentials.
    pub fn delete_workspace(&self, name: &str) -> Result<bool> {
        if name == DEFAULT_WORKSPACE {
            bail!("default workspace cannot be deleted");
        }

        let conn = self.connect()?;
        let is_current = conn
            .query_row(
                "SELECT is_current FROM workspaces WHERE name = ?1",
                params![name],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;

        let Some(is_current) = is_current else {
            return Ok(false);
        };

        conn.execute("DELETE FROM workspaces WHERE name = ?1", params![name])?;

        if is_current == 1 {
            conn.execute("UPDATE workspaces SET is_current = 0", [])?;
            conn.execute(
                "UPDATE workspaces SET is_current = 1 WHERE name = ?1",
                params![DEFAULT_WORKSPACE],
            )?;
        }

        Ok(true)
    }

    /// Lists all workspaces.
    pub fn list_workspaces(&self) -> Result<Vec<WorkspaceRecord>> {
        let conn = self.connect()?;
        let mut stmt =
            conn.prepare("SELECT name, is_current FROM workspaces ORDER BY is_current DESC, name")?;
        let rows = stmt.query_map([], |row| {
            Ok(WorkspaceRecord {
                name: row.get(0)?,
                is_current: row.get::<_, i64>(1)? == 1,
            })
        })?;

        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Saves a successful credential in the selected workspace.
    pub fn save_success(
        &self,
        workspace: &str,
        protocol: Protocol,
        host: &str,
        port: u16,
        credential: &CredentialSet,
    ) -> Result<()> {
        let conn = self.connect()?;
        let workspace_id = self.ensure_workspace(&conn, workspace)?;
        let protocol_name = protocol.as_str();
        let conn_url = build_conn_url(protocol_name, credential, host, port);

        conn.execute(
            r#"
            INSERT INTO credentials (
                workspace_id, protocol, host, port, username, password, conn_url, created_at, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, datetime('now'), datetime('now'))
            ON CONFLICT(workspace_id, protocol, host, port, username, password)
            DO UPDATE SET conn_url = excluded.conn_url, updated_at = datetime('now')
            "#,
            params![
                workspace_id,
                protocol_name,
                host,
                port,
                credential.username.as_deref().unwrap_or_default(),
                credential.password.as_deref().unwrap_or_default(),
                conn_url
            ],
        )?;

        Ok(())
    }

    /// Loads one saved credential by id within the selected workspace.
    pub fn get_credential(&self, id: i64, workspace: &str) -> Result<SavedCredential> {
        let conn = self.connect()?;
        let credential = conn
            .query_row(
                r#"
                SELECT c.id, w.name, c.protocol, c.host, c.port, c.username, c.password, c.conn_url
                FROM credentials c
                JOIN workspaces w ON w.id = c.workspace_id
                WHERE c.id = ?1 AND w.name = ?2
                "#,
                params![id, workspace],
                saved_credential_from_row,
            )
            .optional()?;

        credential
            .with_context(|| format!("credential id {id} was not found in workspace '{workspace}'"))
    }

    /// Lists saved credentials with optional workspace and protocol filters.
    pub fn list_credentials(
        &self,
        workspace: &str,
        protocol: Option<Protocol>,
        host: Option<&str>,
    ) -> Result<Vec<SavedCredential>> {
        let conn = self.connect()?;
        query_saved(&conn, workspace, protocol, host, &[])
    }

    /// Deletes saved credentials in one workspace.
    ///
    /// # Parameters
    ///
    /// - `workspace`: Workspace name. Rows in other workspaces are never deleted.
    /// - `protocol`: Optional protocol filter. `None` matches every protocol.
    /// - `host`: Optional exact host filter. `None` matches every host.
    /// - `ids`: Credential ids to delete. An empty slice does not filter by id.
    ///
    /// # Returns
    ///
    /// Credentials that were deleted, ordered by id. Requested ids that do not
    /// match the workspace and filters are omitted.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be opened or the delete
    /// transaction fails.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let deleted = database.delete_credentials("default", Some(Protocol::Ssh), None, &[3])?;
    /// ```
    pub fn delete_credentials(
        &self,
        workspace: &str,
        protocol: Option<Protocol>,
        host: Option<&str>,
        ids: &[i64],
    ) -> Result<Vec<SavedCredential>> {
        let mut conn = self.connect()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let matched = query_saved(&tx, workspace, protocol, host, ids)?;
        for row in &matched {
            tx.execute("DELETE FROM credentials WHERE id = ?1", params![row.id])?;
        }
        tx.commit()?;
        Ok(matched)
    }

    /// Opens a SQLite connection with a small busy timeout for concurrent success writes.
    fn connect(&self) -> Result<Connection> {
        let conn = Connection::open(&self.path)
            .with_context(|| format!("failed to open database: {}", self.path.display()))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(Duration::from_secs(5))?;
        Ok(conn)
    }

    /// Creates the required database schema if it does not exist.
    fn init_schema(&self, conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r#"
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS workspaces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                is_current INTEGER NOT NULL DEFAULT 0 CHECK (is_current IN (0, 1)),
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_workspaces_one_current
            ON workspaces(is_current)
            WHERE is_current = 1;

            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                protocol TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
                username TEXT,
                password TEXT,
                conn_url TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(workspace_id, protocol, host, port, username, password)
            );

            CREATE INDEX IF NOT EXISTS idx_credentials_lookup
            ON credentials(workspace_id, protocol, host, port);
            "#,
        )?;
        Ok(())
    }

    /// Ensures a workspace exists and returns its id.
    fn ensure_workspace(&self, conn: &Connection, name: &str) -> Result<i64> {
        if name.trim().is_empty() {
            bail!("workspace name cannot be empty");
        }

        conn.execute(
            "INSERT OR IGNORE INTO workspaces (name, is_current) VALUES (?1, 0)",
            params![name],
        )?;

        conn.query_row(
            "SELECT id FROM workspaces WHERE name = ?1",
            params![name],
            |row| row.get(0),
        )
        .map_err(Into::into)
    }

    /// Ensures exactly one current workspace exists and returns its name.
    fn ensure_current_workspace(&self, conn: &Connection) -> Result<String> {
        let current = conn
            .query_row(
                "SELECT name FROM workspaces WHERE is_current = 1 LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(current) = current {
            return Ok(current);
        }

        conn.execute(
            "UPDATE workspaces SET is_current = 1 WHERE name = ?1",
            params![DEFAULT_WORKSPACE],
        )?;
        Ok(DEFAULT_WORKSPACE.to_string())
    }
}

/// Builds a scanner-friendly connection URL for saved credentials.
fn build_conn_url(protocol: &str, credential: &CredentialSet, host: &str, port: u16) -> String {
    let username = encode_userinfo_component(credential.username.as_deref().unwrap_or_default());
    let password = encode_userinfo_component(credential.password.as_deref().unwrap_or_default());
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };

    format!("{protocol}://{username}:{password}@{host}:{port}")
}

/// Percent-encodes a username or password for use in URL user-info.
fn encode_userinfo_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

/// Maps a SQLite row into a saved credential record.
fn saved_credential_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SavedCredential> {
    let port: u16 = row.get(4)?;
    Ok(SavedCredential {
        id: row.get(0)?,
        workspace: row.get(1)?,
        protocol: row.get(2)?,
        host: row.get(3)?,
        port,
        username: row.get(5)?,
        password: row.get(6)?,
        conn_url: row.get(7)?,
    })
}

/// Lists saved credentials on an existing connection.
///
/// # Parameters
///
/// - `conn`: Open SQLite connection or transaction.
/// - `workspace`: Workspace name to search.
/// - `protocol`: Optional protocol filter.
/// - `host`: Optional exact host filter.
/// - `ids`: Optional id allow-list. Empty means do not filter by id.
///
/// # Returns
///
/// Matching credentials ordered by id.
///
/// # Errors
///
/// Returns an error when the query cannot be prepared or a row cannot be read.
fn query_saved(
    conn: &Connection,
    workspace: &str,
    protocol: Option<Protocol>,
    host: Option<&str>,
    ids: &[i64],
) -> Result<Vec<SavedCredential>> {
    let mut sql = String::from(
        r#"
        SELECT c.id, w.name, c.protocol, c.host, c.port, c.username, c.password, c.conn_url
        FROM credentials c
        JOIN workspaces w ON w.id = c.workspace_id
        WHERE w.name = ?1
          AND (?2 IS NULL OR c.protocol = ?2)
          AND (?3 IS NULL OR c.host = ?3)
        "#,
    );
    if !ids.is_empty() {
        sql.push_str(" AND c.id IN (");
        for index in 0..ids.len() {
            if index > 0 {
                sql.push(',');
            }
            sql.push('?');
        }
        sql.push(')');
    }
    sql.push_str(" ORDER BY c.id");

    let protocol_name = protocol.map(|protocol| protocol.as_str().to_string());
    let host_value = host.map(str::to_owned);
    let mut values = vec![
        rusqlite::types::Value::Text(workspace.to_owned()),
        match protocol_name {
            Some(name) => rusqlite::types::Value::Text(name),
            None => rusqlite::types::Value::Null,
        },
        match host_value {
            Some(host) => rusqlite::types::Value::Text(host),
            None => rusqlite::types::Value::Null,
        },
    ];
    for id in ids {
        values.push(rusqlite::types::Value::Integer(*id));
    }

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        rusqlite::params_from_iter(values.iter()),
        saved_credential_from_row,
    )?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

/// Creates the database parent directory when the path has one.
///
/// # Parameters
///
/// - `path`: Database file path.
///
/// # Returns
///
/// `true` when this call created the immediate parent directory.
///
/// # Errors
///
/// Returns an error when `create_dir_all` fails.
///
/// # Examples
///
/// ```ignore
/// let created = prepare_store_directory(Path::new("/tmp/brute-store/brute.db"))?;
/// ```
fn prepare_store_directory(path: &Path) -> Result<bool> {
    let Some(parent) = store_parent(path) else {
        return Ok(false);
    };
    let created = !parent.exists();
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create database directory: {}", parent.display()))?;
    Ok(created)
}

/// Applies owner-only permissions to the credential-store directory on Unix.
///
/// # Parameters
///
/// - `path`: Database file path whose immediate parent may be restricted.
/// - `created`: Whether this process just created that parent.
///
/// # Returns
///
/// Nothing. Shared directories such as the process temp dir are skipped.
///
/// # Errors
///
/// Returns an error when reading or setting the directory mode fails.
///
/// # Examples
///
/// ```ignore
/// restrict_store_directory(Path::new("/tmp/brute-store/brute.db"), true)?;
/// ```
fn restrict_store_directory(path: &Path, created: bool) -> Result<()> {
    let Some(parent) = store_parent(path) else {
        return Ok(());
    };
    if !created && is_shared_directory(parent) {
        return Ok(());
    }
    apply_unix_mode(parent, 0o700, created)
}

/// Applies owner-only permissions to the database file and SQLite sidecars.
///
/// # Parameters
///
/// - `path`: Database file path.
/// - `created`: Whether the file did not exist before this open.
///
/// # Returns
///
/// Nothing. Missing sidecars are ignored.
///
/// # Errors
///
/// Returns an error when reading or setting a file mode fails.
///
/// # Examples
///
/// ```ignore
/// restrict_database_file(Path::new("/tmp/brute-store/brute.db"), true)?;
/// ```
fn restrict_database_file(path: &Path, created: bool) -> Result<()> {
    apply_unix_mode(path, 0o600, created)?;
    for suffix in ["-wal", "-shm"] {
        let sidecar = sidecar_path(path, suffix);
        if sidecar.exists() {
            apply_unix_mode(&sidecar, 0o600, false)?;
        }
    }
    Ok(())
}

fn store_parent(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

fn is_shared_directory(path: &Path) -> bool {
    if path == Path::new("/") {
        return true;
    }
    if path == env::temp_dir() {
        return true;
    }
    matches!(
        path.to_str(),
        Some("/tmp" | "/var/tmp" | "/dev/shm" | "/private/tmp")
    )
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut owned = path.as_os_str().to_os_string();
    owned.push(suffix);
    PathBuf::from(owned)
}

fn apply_unix_mode(path: &Path, mask: u32, exact: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(path)
            .with_context(|| format!("failed to read permissions: {}", path.display()))?;
        let current = metadata.permissions().mode() & 0o777;
        let next = if exact { mask } else { current & mask };
        if next != current {
            let mut permissions = metadata.permissions();
            permissions.set_mode(next);
            fs::set_permissions(path, permissions)
                .with_context(|| format!("failed to set permissions on {}", path.display()))?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mask, exact);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, time::SystemTime};

    use rusqlite::Connection;

    use super::*;

    /// Creates a unique temporary database path for SQLite tests.
    fn temp_database_path() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("brute-test-{suffix}.sqlite"))
    }

    #[test]
    fn saves_and_lists_credentials_by_workspace_and_protocol() -> Result<()> {
        let path = temp_database_path();
        let database = CredentialDatabase::open(path.clone())?;

        assert_eq!(database.current_workspace()?, DEFAULT_WORKSPACE);
        database.create_workspace("audit")?;
        database.set_current_workspace("audit")?;
        assert_eq!(database.current_workspace()?, "audit");

        let credential = CredentialSet {
            username: Some("admin".to_string()),
            password: Some("123456".to_string()),
            service_name: None,
            sid: None,
        };
        database.save_success("audit", Protocol::Ssh, "192.168.5.5", 22, &credential)?;

        let credentials = database.list_credentials("audit", Some(Protocol::Ssh), None)?;
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].protocol, "ssh");
        assert_eq!(credentials[0].conn_url, "ssh://admin:123456@192.168.5.5:22");

        let credentials = database.list_credentials("audit", None, Some("192.168.5.5"))?;
        assert_eq!(credentials.len(), 1);

        let saved = database.get_credential(credentials[0].id, "audit")?;
        assert_eq!(saved.username.as_deref(), Some("admin"));
        assert_eq!(saved.password.as_deref(), Some("123456"));

        assert!(database.delete_workspace("audit")?);
        let raw_connection = Connection::open(&path)?;
        let remaining_credentials: i64 =
            raw_connection.query_row("SELECT COUNT(*) FROM credentials", [], |row| row.get(0))?;
        assert_eq!(remaining_credentials, 0);
        assert_eq!(database.current_workspace()?, DEFAULT_WORKSPACE);
        assert!(
            database
                .list_credentials("audit", Some(Protocol::Ssh), None)?
                .is_empty()
        );

        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn deletes_credentials_without_crossing_workspaces() -> Result<()> {
        let path = temp_database_path();
        let _ = fs::remove_file(&path);
        let database = CredentialDatabase::open(&path)?;
        database.create_workspace("audit")?;
        let credential = CredentialSet {
            username: Some("admin".to_string()),
            password: Some("123456".to_string()),
            service_name: None,
            sid: None,
        };
        database.save_success("default", Protocol::Ssh, "10.0.0.8", 22, &credential)?;
        database.save_success("default", Protocol::Smb, "10.0.0.9", 445, &credential)?;
        database.save_success("audit", Protocol::Ssh, "10.0.0.8", 22, &credential)?;

        let default_rows = database.list_credentials("default", None, None)?;
        let ssh_id = default_rows
            .iter()
            .find(|row| row.protocol == "ssh")
            .expect("ssh row")
            .id;
        let audit_id = database.list_credentials("audit", None, None)?[0].id;

        let deleted = database.delete_credentials("default", None, None, &[ssh_id, audit_id])?;
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].id, ssh_id);
        assert!(database.get_credential(audit_id, "audit").is_ok());

        let deleted =
            database.delete_credentials("default", Some(Protocol::Smb), Some("10.0.0.9"), &[])?;
        assert_eq!(deleted.len(), 1);
        assert!(database.list_credentials("default", None, None)?.is_empty());
        assert_eq!(database.list_credentials("audit", None, None)?.len(), 1);

        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn connection_url_encodes_user_info_and_brackets_ipv6_hosts() {
        let credential = CredentialSet {
            username: Some("admin@example.com".to_string()),
            password: Some("p@ss".to_string()),
            service_name: None,
            sid: None,
        };

        assert_eq!(
            build_conn_url("ssh", &credential, "2001:db8::1", 22),
            "ssh://admin%40example.com:p%40ss@[2001:db8::1]:22"
        );
    }

    #[test]
    fn default_database_relative_path_is_under_config_brute() {
        assert_eq!(DEFAULT_DATABASE_RELATIVE_PATH, ".config/brute/brute.db");
        let joined = PathBuf::from("/home/example").join(DEFAULT_DATABASE_RELATIVE_PATH);
        assert_eq!(
            joined,
            PathBuf::from("/home/example/.config/brute/brute.db")
        );
    }

    #[cfg(unix)]
    #[test]
    fn open_restricts_private_store_and_leaves_shared_temp_dir() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let private = std::env::temp_dir().join(format!(
            "brute-store-{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("system time before unix epoch")
                .as_nanos()
        ));
        fs::create_dir(&private)?;
        let mut loose_dir = fs::metadata(&private)?.permissions();
        loose_dir.set_mode(0o755);
        fs::set_permissions(&private, loose_dir)?;
        let existing = private.join("creds.sqlite");
        fs::write(&existing, [])?;
        let mut loose_file = fs::metadata(&existing)?.permissions();
        loose_file.set_mode(0o644);
        fs::set_permissions(&existing, loose_file)?;

        let _database = CredentialDatabase::open(&existing)?;
        assert_eq!(unix_mode(&private), 0o700);
        assert_eq!(unix_mode(&existing), 0o600);

        let fresh_parent = std::env::temp_dir().join(format!(
            "brute-store-fresh-{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("system time before unix epoch")
                .as_nanos()
        ));
        let fresh = fresh_parent.join("brute.db");
        let _created = CredentialDatabase::open(&fresh)?;
        assert_eq!(unix_mode(&fresh_parent), 0o700);
        assert_eq!(unix_mode(&fresh), 0o600);

        let shared = temp_database_path();
        let temp_before = unix_mode(&std::env::temp_dir());
        let _shared_db = CredentialDatabase::open(&shared)?;
        assert_eq!(unix_mode(&shared), 0o600);
        assert_eq!(unix_mode(&std::env::temp_dir()), temp_before);

        let _ = fs::remove_dir_all(&private);
        let _ = fs::remove_dir_all(&fresh_parent);
        let _ = fs::remove_file(shared);
        Ok(())
    }

    #[cfg(unix)]
    fn unix_mode(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }
}
