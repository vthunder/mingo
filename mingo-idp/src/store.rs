//! SQLite-backed account + session store.
//!
//! An account is keyed by the user's verified *external* identity (the email the
//! broker authenticated). A handle, once claimed, maps 1:1 to an account and
//! yields the `<handle>@mingo.place` identity this IdP issues certs for.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

/// How long a mingo session stays valid. Matches the cookie's max-age so cookie
/// and server session expire together; expired sessions are pruned on read.
const SESSION_TTL_SECS: i64 = 30 * 24 * 60 * 60; // 30 days

pub struct Store {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct Account {
    pub id: i64,
    pub external_email: String,
    pub handle: Option<String>,
}

impl Store {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS accounts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                external_email  TEXT NOT NULL UNIQUE,
                handle          TEXT UNIQUE,
                created_at      INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id          TEXT PRIMARY KEY,
                account_id  INTEGER NOT NULL,
                csrf        TEXT NOT NULL,
                created_at  INTEGER NOT NULL
            );
            "#,
        )?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    /// Find the account for an external email, creating it if absent.
    pub fn find_or_create_account(&self, external_email: &str) -> rusqlite::Result<Account> {
        let email = external_email.to_lowercase();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO accounts (external_email, handle, created_at) VALUES (?1, NULL, ?2)",
            params![email, Self::now()],
        )?;
        conn.query_row(
            "SELECT id, external_email, handle FROM accounts WHERE external_email = ?1",
            params![email],
            |r| Ok(Account { id: r.get(0)?, external_email: r.get(1)?, handle: r.get(2)? }),
        )
    }

    pub fn get_account(&self, id: i64) -> rusqlite::Result<Option<Account>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, external_email, handle FROM accounts WHERE id = ?1",
            params![id],
            |r| Ok(Account { id: r.get(0)?, external_email: r.get(1)?, handle: r.get(2)? }),
        )
        .optional()
    }

    /// Which account (if any) owns a handle.
    pub fn account_id_for_handle(&self, handle: &str) -> rusqlite::Result<Option<i64>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id FROM accounts WHERE handle = ?1",
            params![handle.to_lowercase()],
            |r| r.get(0),
        )
        .optional()
    }

    /// Claim a handle for an account. Returns Ok(false) if the handle is taken by
    /// another account. Idempotent if the account already owns it.
    pub fn set_handle(&self, account_id: i64, handle: &str) -> rusqlite::Result<bool> {
        let handle = handle.to_lowercase();
        let conn = self.conn.lock().unwrap();
        let owner: Option<i64> = conn
            .query_row(
                "SELECT id FROM accounts WHERE handle = ?1",
                params![handle],
                |r| r.get(0),
            )
            .optional()?;
        match owner {
            Some(id) if id == account_id => Ok(true), // idempotent
            Some(_) => Ok(false),                     // taken by someone else
            None => {
                conn.execute(
                    "UPDATE accounts SET handle = ?1 WHERE id = ?2",
                    params![handle, account_id],
                )?;
                Ok(true)
            }
        }
    }

    pub fn create_session(&self, account_id: i64) -> rusqlite::Result<(String, String)> {
        let id = uuid::Uuid::new_v4().to_string();
        let csrf = uuid::Uuid::new_v4().to_string();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sessions (id, account_id, csrf, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![id, account_id, csrf, Self::now()],
        )?;
        Ok((id, csrf))
    }

    /// Delete an account (by external email) and all its sessions. Returns the
    /// number of accounts removed (0 or 1). Used to reset an identity for testing
    /// the registration/handle-chooser flow.
    pub fn delete_account(&self, external_email: &str) -> rusqlite::Result<usize> {
        let email = external_email.to_lowercase();
        let conn = self.conn.lock().unwrap();
        if let Some(id) = conn
            .query_row(
                "SELECT id FROM accounts WHERE external_email = ?1",
                params![email],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
        {
            conn.execute("DELETE FROM sessions WHERE account_id = ?1", params![id])?;
        }
        conn.execute("DELETE FROM accounts WHERE external_email = ?1", params![email])
    }

    /// Invalidate a single session (logout). Idempotent.
    pub fn delete_session(&self, session_id: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM sessions WHERE id = ?1", params![session_id])?;
        Ok(())
    }

    /// Invalidate ALL of an account's sessions — thorough "sign out" so stale
    /// sessions can't linger and keep authorizing /cert_key.
    pub fn delete_account_sessions(&self, account_id: i64) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM sessions WHERE account_id = ?1", params![account_id])?;
        Ok(())
    }

    /// Resolve a session id to its account id, enforcing a TTL. An expired session
    /// is deleted and treated as absent, so old sessions can't authorize writes
    /// (mingo session hygiene) and don't accumulate unbounded.
    pub fn account_for_session(&self, session_id: &str) -> rusqlite::Result<Option<i64>> {
        let conn = self.conn.lock().unwrap();
        let row: Option<(i64, i64)> = conn
            .query_row(
                "SELECT account_id, created_at FROM sessions WHERE id = ?1",
                params![session_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match row {
            Some((account_id, created_at)) if Self::now() - created_at <= SESSION_TTL_SECS => {
                Ok(Some(account_id))
            }
            Some(_) => {
                // Expired — clean it up and report no session.
                conn.execute("DELETE FROM sessions WHERE id = ?1", params![session_id])?;
                Ok(None)
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        // In-memory DB per test.
        Store { conn: Mutex::new(Connection::open_in_memory().unwrap()) }
            .init_schema()
    }

    impl Store {
        fn init_schema(self) -> Self {
            self.conn
                .lock()
                .unwrap()
                .execute_batch(
                    "CREATE TABLE accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, external_email TEXT NOT NULL UNIQUE, handle TEXT UNIQUE, created_at INTEGER NOT NULL);
                     CREATE TABLE sessions (id TEXT PRIMARY KEY, account_id INTEGER NOT NULL, csrf TEXT NOT NULL, created_at INTEGER NOT NULL);",
                )
                .unwrap();
            self
        }
    }

    #[test]
    fn find_or_create_is_idempotent_and_case_insensitive() {
        let s = store();
        let a = s.find_or_create_account("Dan@Sandmill.org").unwrap();
        let b = s.find_or_create_account("dan@sandmill.org").unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(a.external_email, "dan@sandmill.org");
        assert!(a.handle.is_none());
    }

    #[test]
    fn handle_is_unique_but_idempotent_for_owner() {
        let s = store();
        let a = s.find_or_create_account("a@x.com").unwrap();
        let b = s.find_or_create_account("b@x.com").unwrap();
        assert!(s.set_handle(a.id, "dan").unwrap());
        assert!(s.set_handle(a.id, "dan").unwrap()); // idempotent for owner
        assert!(!s.set_handle(b.id, "dan").unwrap()); // taken by someone else
        assert_eq!(s.account_id_for_handle("dan").unwrap(), Some(a.id));
    }

    #[test]
    fn sessions_resolve_to_accounts() {
        let s = store();
        let a = s.find_or_create_account("a@x.com").unwrap();
        let (sid, _csrf) = s.create_session(a.id).unwrap();
        assert_eq!(s.account_for_session(&sid).unwrap(), Some(a.id));
        assert_eq!(s.account_for_session("nope").unwrap(), None);
    }

    #[test]
    fn session_ttl_expires_and_prunes() {
        let s = store();
        let a = s.find_or_create_account("a@x.com").unwrap();
        let (sid, _) = s.create_session(a.id).unwrap();
        assert_eq!(s.account_for_session(&sid).unwrap(), Some(a.id));
        // Age it beyond the TTL (child module can reach the private conn).
        s.conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE sessions SET created_at = created_at - ?1 WHERE id = ?2",
                params![SESSION_TTL_SECS + 10, sid],
            )
            .unwrap();
        // Expired → treated as absent and pruned on read.
        assert_eq!(s.account_for_session(&sid).unwrap(), None);
        assert_eq!(s.account_for_session(&sid).unwrap(), None);
    }

    #[test]
    fn delete_account_sessions_clears_all() {
        let s = store();
        let a = s.find_or_create_account("a@x.com").unwrap();
        let (s1, _) = s.create_session(a.id).unwrap();
        let (s2, _) = s.create_session(a.id).unwrap();
        s.delete_account_sessions(a.id).unwrap();
        assert_eq!(s.account_for_session(&s1).unwrap(), None);
        assert_eq!(s.account_for_session(&s2).unwrap(), None);
    }

    #[test]
    fn delete_session_invalidates_it() {
        let s = store();
        let a = s.find_or_create_account("a@x.com").unwrap();
        let (sid, _csrf) = s.create_session(a.id).unwrap();
        assert_eq!(s.account_for_session(&sid).unwrap(), Some(a.id));
        s.delete_session(&sid).unwrap();
        assert_eq!(s.account_for_session(&sid).unwrap(), None, "logout must invalidate the session");
        // Idempotent.
        s.delete_session(&sid).unwrap();
    }
}
