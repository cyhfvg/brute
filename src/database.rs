//! SQLite-backed workspace and credential storage.

use std::{env, fs, path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};

use crate::{cli::Protocol, credentials::CredentialSet};

/// Default workspace name used when the database is first created.
pub const DEFAULT_WORKSPACE: &str = "default";

/// Database path relative to the user's home directory.
const DEFAULT_DATABASE_RELATIVE_PATH: &str = ".brute/brute.db";

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
    /// Returns the default SQLite database path.
    pub fn default_path() -> Result<PathBuf> {
        let home = env::var_os("HOME").context("HOME environment variable is not set")?;
        Ok(PathBuf::from(home).join(DEFAULT_DATABASE_RELATIVE_PATH))
    }

    /// Opens the default SQLite database and reports whether it had to be initialized.
    pub fn open_default() -> Result<(Self, bool)> {
        let path = Self::default_path()?;
        let initialized = !path.exists();
        let database = Self::open(path)?;
        Ok((database, initialized))
    }

    /// Opens or creates the SQLite database and applies the schema.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let database = Self { path: path.into() };
        if let Some(parent) = database.path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create database directory: {}", parent.display())
            })?;
        }
        let conn = database.connect()?;
        database.init_schema(&conn)?;
        database.ensure_workspace(&conn, DEFAULT_WORKSPACE)?;
        database.ensure_current_workspace(&conn)?;
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
        let mut stmt = conn.prepare(
            r#"
            SELECT c.id, w.name, c.protocol, c.host, c.port, c.username, c.password, c.conn_url
            FROM credentials c
            JOIN workspaces w ON w.id = c.workspace_id
            WHERE w.name = ?1
              AND (?2 IS NULL OR c.protocol = ?2)
              AND (?3 IS NULL OR c.host = ?3)
            ORDER BY c.id
            "#,
        )?;
        let protocol_name = protocol.map(|protocol| protocol.as_str().to_string());
        let rows = stmt.query_map(
            params![workspace, protocol_name, host],
            saved_credential_from_row,
        )?;

        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Opens a SQLite connection with a small busy timeout for concurrent success writes.
    fn connect(&self) -> Result<Connection> {
        let conn = Connection::open(&self.path)
            .with_context(|| format!("failed to open database: {}", self.path.display()))?;
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
                port INTEGER NOT NULL,
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
    let username = credential.username.as_deref().unwrap_or_default();
    let password = credential.password.as_deref().unwrap_or_default();
    format!("{protocol}://{username}:{password}@{host}:{port}")
}

/// Maps a SQLite row into a saved credential record.
fn saved_credential_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SavedCredential> {
    let port: i64 = row.get(4)?;
    Ok(SavedCredential {
        id: row.get(0)?,
        workspace: row.get(1)?,
        protocol: row.get(2)?,
        host: row.get(3)?,
        port: port as u16,
        username: row.get(5)?,
        password: row.get(6)?,
        conn_url: row.get(7)?,
    })
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, time::SystemTime};

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
        assert_eq!(database.current_workspace()?, DEFAULT_WORKSPACE);
        assert!(
            database
                .list_credentials("audit", Some(Protocol::Ssh), None)?
                .is_empty()
        );

        let _ = fs::remove_file(path);
        Ok(())
    }
}
