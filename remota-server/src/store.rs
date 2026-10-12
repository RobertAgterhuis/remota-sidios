//! Remota's own data on the server (`remota.db`): each user's connection tree (one document per
//! user, in upstream Remota's shape) and trusted host keys and certificates. No secret is ever
//! stored here; nodes refer to credentials by the ID the SidiOS vault gave them.
//!
//! Every read and write goes through [`UserStore`], which is bound to one user key, so a handler
//! cannot reach another user's rows by forgetting a filter.

use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::{params, Connection, OptionalExtension};

use crate::model::{Document, Protocol, TreeError};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS documents (
  user_key TEXT PRIMARY KEY CHECK (length(user_key) = 24),
  document TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS trust_records (
  user_key TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  protocol TEXT NOT NULL CHECK (protocol IN ('ssh', 'rdp', 'ftps')),
  fingerprint TEXT NOT NULL,
  accepted_at INTEGER NOT NULL,
  PRIMARY KEY (user_key, host, port, protocol)
);
"#;

/// Databases created before FTPS (SidiOS US8) only accept SSH and RDP trust records; their table
/// is rebuilt once with the current definition, keeping every record.
fn upgrade_trust_protocols(connection: &Connection) -> rusqlite::Result<()> {
    let definition: String = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'trust_records'",
        [],
        |row| row.get(0),
    )?;
    if definition.contains("'ftps'") {
        return Ok(());
    }
    connection.execute_batch(
        "BEGIN;
         ALTER TABLE trust_records RENAME TO trust_records_old;",
    )?;
    let rebuilt = connection
        .execute_batch(SCHEMA)
        .and_then(|()| {
            connection.execute_batch(
                "INSERT INTO trust_records SELECT * FROM trust_records_old;
                 DROP TABLE trust_records_old;
                 COMMIT;",
            )
        });
    if rebuilt.is_err() {
        let _ = connection.execute_batch("ROLLBACK;");
    }
    rebuilt
}

#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    Tree(TreeError),
    Database(String),
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error.to_string())
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Database(error.to_string())
    }
}

impl From<TreeError> for StoreError {
    fn from(error: TreeError) -> Self {
        Self::Tree(error)
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
        upgrade_trust_protocols(&connection)?;
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

/// One user's view of the store.
pub struct UserStore<'a> {
    store: &'a Store,
    user_key: String,
}

impl UserStore<'_> {
    pub fn document(&self) -> StoreResult<Document> {
        load(&self.store.lock(), &self.user_key)
    }

    /// Applies `change` to the user's tree and saves it only if the change succeeds, all under
    /// one lock, so concurrent changes never overwrite each other.
    pub fn update<T>(
        &self,
        change: impl FnOnce(&mut Document) -> Result<T, TreeError>,
    ) -> StoreResult<(T, Document)> {
        let connection = self.store.lock();
        let mut document = load(&connection, &self.user_key)?;
        let result = change(&mut document)?;
        connection.execute(
            "INSERT INTO documents (user_key, document, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(user_key) DO UPDATE SET document = excluded.document,
               updated_at = excluded.updated_at",
            params![self.user_key, serde_json::to_string(&document)?, now()],
        )?;
        Ok((result, document))
    }

    /// The fingerprint the user accepted for this host, port, and protocol, if any.
    pub fn trusted(
        &self,
        host: &str,
        port: u16,
        protocol: Protocol,
    ) -> StoreResult<Option<String>> {
        Ok(self
            .store
            .lock()
            .query_row(
                "SELECT fingerprint FROM trust_records
                 WHERE user_key = ?1 AND host = ?2 AND port = ?3 AND protocol = ?4",
                params![self.user_key, host, port, protocol.as_str()],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Records a first-seen fingerprint. A different fingerprint is never replaced here; the user
    /// must forget the old one first.
    pub fn trust(
        &self,
        host: &str,
        port: u16,
        protocol: Protocol,
        fingerprint: &str,
    ) -> StoreResult<bool> {
        let changed = self.store.lock().execute(
            "INSERT OR IGNORE INTO trust_records
             (user_key, host, port, protocol, fingerprint, accepted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                self.user_key,
                host,
                port,
                protocol.as_str(),
                fingerprint,
                now()
            ],
        )?;
        Ok(changed == 1)
    }

    pub fn forget(&self, host: &str, port: u16, protocol: Protocol) -> StoreResult<bool> {
        let changed = self.store.lock().execute(
            "DELETE FROM trust_records
             WHERE user_key = ?1 AND host = ?2 AND port = ?3 AND protocol = ?4",
            params![self.user_key, host, port, protocol.as_str()],
        )?;
        Ok(changed == 1)
    }
}

fn load(connection: &Connection, user_key: &str) -> StoreResult<Document> {
    let text: Option<String> = connection
        .query_row(
            "SELECT document FROM documents WHERE user_key = ?1",
            [user_key],
            |row| row.get(0),
        )
        .optional()?;
    match text {
        Some(text) => Ok(serde_json::from_str(&text)?),
        None => Ok(Document::default()),
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Connection as Conn, Credentials, Node};

    const ADA: &str = "0123456789abcdef01234567";
    const BOB: &str = "76543210fedcba9876543210";

    #[test]
    fn upgrades_an_older_trust_table_and_keeps_its_records() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(&SCHEMA.replace("'ssh', 'rdp', 'ftps'", "'ssh', 'rdp'"))
            .unwrap();
        connection
            .execute(
                "INSERT INTO trust_records VALUES (?1, 'h', 22, 'ssh', 'SHA256:kept', 1)",
                params![ADA],
            )
            .unwrap();
        let store = Store::from_connection(connection).unwrap();
        let records = store.for_user(ADA);
        assert_eq!(
            records.trusted("h", 22, Protocol::Ssh).unwrap().as_deref(),
            Some("SHA256:kept")
        );
        assert!(records.trust("f", 21, Protocol::Ftps, "SHA256:new").unwrap());
        // A second start leaves the upgraded table alone.
        let again = store.lock();
        upgrade_trust_protocols(&again).unwrap();
    }

    fn ssh(id: &str) -> Node {
        Node::Connection {
            id: id.into(),
            name: id.into(),
            conn: Conn {
                protocol: Protocol::Ssh,
                host: "10.20.0.5".into(),
                port: Some(22),
                credentials: Credentials::default(),
                gateway: None,
            },
        }
    }

    #[test]
    fn each_user_sees_only_their_own_tree() {
        let store = Store::open_in_memory().unwrap();
        store
            .for_user(ADA)
            .update(|doc| doc.upsert(None, ssh("web")))
            .unwrap();
        store
            .for_user(BOB)
            .update(|doc| doc.upsert(None, ssh("bob-box")))
            .unwrap();

        assert!(store
            .for_user(ADA)
            .document()
            .unwrap()
            .find("web")
            .is_some());
        assert!(store
            .for_user(ADA)
            .document()
            .unwrap()
            .find("bob-box")
            .is_none());
        assert!(store
            .for_user(BOB)
            .document()
            .unwrap()
            .find("web")
            .is_none());
    }

    #[test]
    fn a_failed_change_saves_nothing() {
        let store = Store::open_in_memory().unwrap();
        let user = store.for_user(ADA);
        user.update(|doc| doc.upsert(None, ssh("web"))).unwrap();
        let result = user.update(|doc| {
            doc.upsert(None, ssh("second"))?;
            doc.upsert(Some("missing"), ssh("third"))
        });
        assert!(result.is_err());
        assert!(user.document().unwrap().find("second").is_none());
    }

    #[test]
    fn trust_records_are_per_user_and_never_silently_replaced() {
        let store = Store::open_in_memory().unwrap();
        let ada = store.for_user(ADA);
        assert!(ada.trust("h", 22, Protocol::Ssh, "SHA256:one").unwrap());
        assert!(!ada.trust("h", 22, Protocol::Ssh, "SHA256:two").unwrap());
        assert_eq!(
            ada.trusted("h", 22, Protocol::Ssh).unwrap().as_deref(),
            Some("SHA256:one")
        );
        assert_eq!(
            store.for_user(BOB).trusted("h", 22, Protocol::Ssh).unwrap(),
            None
        );
        assert!(ada.forget("h", 22, Protocol::Ssh).unwrap());
        assert_eq!(ada.trusted("h", 22, Protocol::Ssh).unwrap(), None);
    }

    #[test]
    fn opens_a_database_file_and_keeps_its_rows() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("remota.db");
        Store::open(&path)
            .unwrap()
            .for_user(ADA)
            .update(|doc| doc.upsert(None, ssh("web")))
            .unwrap();

        let reopened = Store::open(&path).unwrap();
        assert!(reopened
            .for_user(ADA)
            .document()
            .unwrap()
            .find("web")
            .is_some());
    }
}
