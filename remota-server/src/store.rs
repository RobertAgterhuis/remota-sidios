//! Remota's own data on the server (`remota.db`): each user's folders, connections, and trust
//! records. No secret is ever stored here; nodes refer to credentials by the ID webOS gave them.
//!
//! Every read and write goes through [`UserStore`], which is bound to one user key, so a handler
//! cannot reach another user's rows by forgetting a filter.

use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS folders (
  id TEXT PRIMARY KEY,
  user_key TEXT NOT NULL,
  parent_id TEXT,
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  icon TEXT,
  position INTEGER NOT NULL DEFAULT 0,
  inherited TEXT NOT NULL DEFAULT '{}',
  deleted_at INTEGER,
  trash_parent_id TEXT
);
CREATE INDEX IF NOT EXISTS folders_user_idx ON folders(user_key, parent_id);

CREATE TABLE IF NOT EXISTS connections (
  id TEXT PRIMARY KEY,
  user_key TEXT NOT NULL,
  folder_id TEXT,
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  protocol TEXT NOT NULL CHECK (protocol IN ('ssh', 'rdp')),
  host TEXT NOT NULL CHECK (length(host) BETWEEN 1 AND 253),
  port INTEGER CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
  overrides TEXT NOT NULL DEFAULT '{}',
  position INTEGER NOT NULL DEFAULT 0,
  deleted_at INTEGER,
  trash_parent_id TEXT
);
CREATE INDEX IF NOT EXISTS connections_user_idx ON connections(user_key, folder_id);

CREATE TABLE IF NOT EXISTS trust_records (
  user_key TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  protocol TEXT NOT NULL CHECK (protocol IN ('ssh', 'rdp')),
  fingerprint TEXT NOT NULL,
  accepted_at INTEGER NOT NULL,
  PRIMARY KEY (user_key, host, port, protocol)
);
"#;

#[derive(Debug)]
pub struct StoreError(pub String);

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self(error.to_string())
    }
}

pub type StoreResult<T> = Result<T, StoreError>;

/// The shared database handle; cheap to clone.
#[derive(Clone)]
pub struct Store {
    connection: Arc<Mutex<Connection>>,
}

impl Store {
    pub fn open(path: &Path) -> StoreResult<Self> {
        Self::from_connection(Connection::open(path)?)
    }

    pub fn open_in_memory() -> StoreResult<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(connection: Connection) -> StoreResult<Self> {
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "busy_timeout", 5000)?;
        connection.execute_batch(SCHEMA)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// The only way to reach stored rows: everything it does is limited to `user_key`.
    pub fn for_user(&self, user_key: &str) -> UserStore<'_> {
        UserStore {
            store: self,
            user_key: user_key.to_owned(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        // A panic while holding the lock leaves SQLite consistent (statements are atomic).
        self.connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderRow {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub icon: Option<String>,
    pub position: i64,
    pub inherited: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionRow {
    pub id: String,
    pub folder_id: Option<String>,
    pub name: String,
    pub protocol: String,
    pub host: String,
    pub port: Option<u16>,
    pub position: i64,
    pub overrides: serde_json::Value,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Tree {
    pub folders: Vec<FolderRow>,
    pub connections: Vec<ConnectionRow>,
}

pub struct NewFolder<'a> {
    pub id: &'a str,
    pub parent_id: Option<&'a str>,
    pub name: &'a str,
}

pub struct NewConnection<'a> {
    pub id: &'a str,
    pub folder_id: Option<&'a str>,
    pub name: &'a str,
    pub protocol: &'a str,
    pub host: &'a str,
    pub port: Option<u16>,
}

/// One user's view of the store.
pub struct UserStore<'a> {
    store: &'a Store,
    user_key: String,
}

impl UserStore<'_> {
    /// The user's active (not trashed) folders and connections.
    pub fn tree(&self) -> StoreResult<Tree> {
        let connection = self.store.lock();
        Ok(Tree {
            folders: folders(&connection, &self.user_key)?,
            connections: connections(&connection, &self.user_key)?,
        })
    }

    /// Creates a folder; a parent must be one of this user's active folders.
    pub fn add_folder(&self, folder: &NewFolder) -> StoreResult<()> {
        let connection = self.store.lock();
        self.check_parent(&connection, folder.parent_id)?;
        connection.execute(
            "INSERT INTO folders (id, user_key, parent_id, name) VALUES (?1, ?2, ?3, ?4)",
            params![folder.id, self.user_key, folder.parent_id, folder.name],
        )?;
        Ok(())
    }

    /// Creates a connection; its folder must be one of this user's active folders.
    pub fn add_connection(&self, new: &NewConnection) -> StoreResult<()> {
        let connection = self.store.lock();
        self.check_parent(&connection, new.folder_id)?;
        connection.execute(
            "INSERT INTO connections (id, user_key, folder_id, name, protocol, host, port)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                new.id,
                self.user_key,
                new.folder_id,
                new.name,
                new.protocol,
                new.host,
                new.port
            ],
        )?;
        Ok(())
    }

    fn check_parent(&self, connection: &Connection, parent: Option<&str>) -> StoreResult<()> {
        let Some(parent) = parent else { return Ok(()) };
        let found: Option<i64> = connection
            .query_row(
                "SELECT 1 FROM folders WHERE id = ?1 AND user_key = ?2 AND deleted_at IS NULL",
                params![parent, self.user_key],
                |row| row.get(0),
            )
            .optional()?;
        found
            .map(|_| ())
            .ok_or_else(|| StoreError("parent_not_found".to_owned()))
    }
}

fn folders(connection: &Connection, user_key: &str) -> StoreResult<Vec<FolderRow>> {
    let mut statement = connection.prepare(
        "SELECT id, parent_id, name, icon, position, inherited FROM folders
         WHERE user_key = ?1 AND deleted_at IS NULL ORDER BY position, name, id",
    )?;
    let rows = statement.query_map([user_key], |row| {
        Ok(FolderRow {
            id: row.get(0)?,
            parent_id: row.get(1)?,
            name: row.get(2)?,
            icon: row.get(3)?,
            position: row.get(4)?,
            inherited: json_column(row.get::<_, String>(5)?),
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn connections(connection: &Connection, user_key: &str) -> StoreResult<Vec<ConnectionRow>> {
    let mut statement = connection.prepare(
        "SELECT id, folder_id, name, protocol, host, port, position, overrides FROM connections
         WHERE user_key = ?1 AND deleted_at IS NULL ORDER BY position, name, id",
    )?;
    let rows = statement.query_map([user_key], |row| {
        Ok(ConnectionRow {
            id: row.get(0)?,
            folder_id: row.get(1)?,
            name: row.get(2)?,
            protocol: row.get(3)?,
            host: row.get(4)?,
            port: row.get(5)?,
            position: row.get(6)?,
            overrides: json_column(row.get::<_, String>(7)?),
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn json_column(text: String) -> serde_json::Value {
    serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADA: &str = "0123456789abcdef01234567";
    const BOB: &str = "76543210fedcba9876543210";

    fn folder<'a>(id: &'a str, parent_id: Option<&'a str>) -> NewFolder<'a> {
        NewFolder {
            id,
            parent_id,
            name: id,
        }
    }

    fn ssh<'a>(id: &'a str, folder_id: Option<&'a str>) -> NewConnection<'a> {
        NewConnection {
            id,
            folder_id,
            name: id,
            protocol: "ssh",
            host: "10.20.0.5",
            port: Some(22),
        }
    }

    #[test]
    fn each_user_sees_only_their_own_tree() {
        let store = Store::open_in_memory().unwrap();
        store
            .for_user(ADA)
            .add_folder(&folder("lab", None))
            .unwrap();
        store
            .for_user(ADA)
            .add_connection(&ssh("web", Some("lab")))
            .unwrap();
        store
            .for_user(BOB)
            .add_connection(&ssh("bob-box", None))
            .unwrap();

        let ada = store.for_user(ADA).tree().unwrap();
        assert_eq!(
            ada.folders
                .iter()
                .map(|f| f.id.as_str())
                .collect::<Vec<_>>(),
            ["lab"]
        );
        assert_eq!(
            ada.connections
                .iter()
                .map(|c| c.id.as_str())
                .collect::<Vec<_>>(),
            ["web"]
        );
        let bob = store.for_user(BOB).tree().unwrap();
        assert!(bob.folders.is_empty());
        assert_eq!(
            bob.connections
                .iter()
                .map(|c| c.id.as_str())
                .collect::<Vec<_>>(),
            ["bob-box"]
        );
    }

    #[test]
    fn a_user_cannot_put_nodes_into_another_users_folder() {
        let store = Store::open_in_memory().unwrap();
        store
            .for_user(ADA)
            .add_folder(&folder("lab", None))
            .unwrap();

        assert!(store
            .for_user(BOB)
            .add_folder(&folder("sneaky", Some("lab")))
            .is_err());
        assert!(store
            .for_user(BOB)
            .add_connection(&ssh("sneaky", Some("lab")))
            .is_err());
        assert!(store.for_user(ADA).tree().unwrap().connections.is_empty());
    }

    #[test]
    fn a_user_cannot_take_over_another_users_node_id() {
        let store = Store::open_in_memory().unwrap();
        store
            .for_user(ADA)
            .add_connection(&ssh("web", None))
            .unwrap();

        assert!(store
            .for_user(BOB)
            .add_connection(&ssh("web", None))
            .is_err());
        assert_eq!(store.for_user(ADA).tree().unwrap().connections[0].id, "web");
    }

    #[test]
    fn opens_a_database_file_and_keeps_its_rows() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("remota.db");
        Store::open(&path)
            .unwrap()
            .for_user(ADA)
            .add_folder(&folder("lab", None))
            .unwrap();

        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.for_user(ADA).tree().unwrap().folders.len(), 1);
    }
}
