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
    /// How the user chose to be identified: `"handle"` (a `<handle>@mingo.place`
    /// pseudonym), `"email"` (their external address, used publicly), or `None`
    /// (undecided — a new account that hasn't picked yet). Lets returning users
    /// skip the chooser.
    pub identity_mode: Option<String>,
}

/// An agent identity `<name>@<domain>` minted via the provisioning API. Shares
/// the handle namespace with human handles (one `@<domain>` local-part space).
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    pub name: String,
    pub account_id: i64,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

impl AgentIdentity {
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

/// Schema, shared by `open()` and the in-memory test constructor.
const SCHEMA: &str = r#"
    CREATE TABLE IF NOT EXISTS accounts (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        external_email  TEXT NOT NULL UNIQUE,
        handle          TEXT UNIQUE,
        identity_mode   TEXT,
        created_at      INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
        id          TEXT PRIMARY KEY,
        account_id  INTEGER NOT NULL,
        csrf        TEXT NOT NULL,
        created_at  INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS agent_identities (
        name        TEXT PRIMARY KEY,
        account_id  INTEGER NOT NULL,
        created_at  INTEGER NOT NULL,
        revoked_at  INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_agent_identities_account ON agent_identities(account_id);
"#;

impl Store {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        // Migration for pre-existing DBs: add identity_mode if absent. SQLite
        // has no ADD COLUMN IF NOT EXISTS, so add-and-ignore the dup error.
        let _ = conn.execute("ALTER TABLE accounts ADD COLUMN identity_mode TEXT", []);
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// In-memory store (tests).
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
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
            "SELECT id, external_email, handle, identity_mode FROM accounts WHERE external_email = ?1",
            params![email],
            account_from_row,
        )
    }

    pub fn get_account(&self, id: i64) -> rusqlite::Result<Option<Account>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, external_email, handle, identity_mode FROM accounts WHERE id = ?1",
            params![id],
            account_from_row,
        )
        .optional()
    }

    /// Record the user's identity choice (`"handle"` or `"email"`). Idempotent.
    pub fn set_identity_mode(&self, account_id: i64, mode: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE accounts SET identity_mode = ?1 WHERE id = ?2",
            params![mode, account_id],
        )?;
        Ok(())
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
    /// another account — or by an agent identity: human handles and agent names
    /// share one `<local>@<domain>` namespace, so each must check the other.
    /// Idempotent if the account already owns it.
    pub fn set_handle(&self, account_id: i64, handle: &str) -> rusqlite::Result<bool> {
        let handle = handle.to_lowercase();
        let conn = self.conn.lock().unwrap();
        let agent_taken: Option<i64> = conn
            .query_row(
                "SELECT account_id FROM agent_identities WHERE name = ?1",
                params![handle],
                |r| r.get(0),
            )
            .optional()?;
        if agent_taken.is_some() {
            return Ok(false);
        }
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

    /// The CSRF token bound to a session (TTL not re-checked here; callers
    /// resolve the session via `account_for_session` first).
    pub fn session_csrf(&self, session_id: &str) -> rusqlite::Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT csrf FROM sessions WHERE id = ?1",
            params![session_id],
            |r| r.get(0),
        )
        .optional()
    }

    // ------------------------------------------------------------------
    // Agent identities (one namespace with human handles)
    // ------------------------------------------------------------------

    /// Create an agent identity. Returns Ok(false) if the name is taken —
    /// by any human handle or by an agent identity (including a revoked one:
    /// revoked names are never recycled).
    pub fn create_agent_identity(&self, account_id: i64, name: &str) -> rusqlite::Result<bool> {
        let name = name.to_lowercase();
        let conn = self.conn.lock().unwrap();
        let handle_taken: Option<i64> = conn
            .query_row("SELECT id FROM accounts WHERE handle = ?1", params![name], |r| r.get(0))
            .optional()?;
        if handle_taken.is_some() {
            return Ok(false);
        }
        let rows = conn.execute(
            "INSERT OR IGNORE INTO agent_identities (name, account_id, created_at) VALUES (?1, ?2, ?3)",
            params![name, account_id, Self::now()],
        )?;
        Ok(rows > 0)
    }

    pub fn get_agent_identity(&self, name: &str) -> rusqlite::Result<Option<AgentIdentity>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT name, account_id, created_at, revoked_at FROM agent_identities WHERE name = ?1",
            params![name.to_lowercase()],
            agent_identity_from_row,
        )
        .optional()
    }

    pub fn list_agent_identities(&self, account_id: i64) -> rusqlite::Result<Vec<AgentIdentity>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT name, account_id, created_at, revoked_at FROM agent_identities
             WHERE account_id = ?1 ORDER BY created_at, name",
        )?;
        let ids = stmt
            .query_map(params![account_id], agent_identity_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ids)
    }

    pub fn count_active_agent_identities(&self, account_id: i64) -> rusqlite::Result<usize> {
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM agent_identities WHERE account_id = ?1 AND revoked_at IS NULL",
            params![account_id],
            |r| r.get(0),
        )?;
        Ok(n as usize)
    }

    /// Soft-revoke an agent identity: re-mints fail from now on; the name is
    /// never recycled. Idempotent.
    pub fn revoke_agent_identity(&self, name: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE agent_identities SET revoked_at = COALESCE(revoked_at, ?1) WHERE name = ?2",
            params![Self::now(), name.to_lowercase()],
        )?;
        Ok(())
    }
}

fn agent_identity_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<AgentIdentity> {
    Ok(AgentIdentity {
        name: r.get(0)?,
        account_id: r.get(1)?,
        created_at: r.get(2)?,
        revoked_at: r.get(3)?,
    })
}

fn account_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Account> {
    Ok(Account {
        id: r.get(0)?,
        external_email: r.get(1)?,
        handle: r.get(2)?,
        identity_mode: r.get(3)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        // In-memory DB per test, real schema.
        Store::open_in_memory().unwrap()
    }

    #[test]
    fn find_or_create_is_idempotent_and_case_insensitive() {
        let s = store();
        let a = s.find_or_create_account("Dan@Sandmill.org").unwrap();
        let b = s.find_or_create_account("dan@sandmill.org").unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(a.external_email, "dan@sandmill.org");
        assert!(a.handle.is_none());
        assert!(a.identity_mode.is_none(), "new account is undecided");
    }

    #[test]
    fn identity_mode_records_the_choice() {
        let s = store();
        let a = s.find_or_create_account("dan@sandmill.org").unwrap();
        assert!(a.identity_mode.is_none());

        // Choosing the external email records "email" without a handle.
        s.set_identity_mode(a.id, "email").unwrap();
        let a = s.get_account(a.id).unwrap().unwrap();
        assert_eq!(a.identity_mode.as_deref(), Some("email"));
        assert!(a.handle.is_none());

        // A different account claims a handle → mode not set by the store layer
        // directly, but set_identity_mode("handle") records it.
        let b = s.find_or_create_account("bob@x.com").unwrap();
        assert!(s.set_handle(b.id, "bob").unwrap());
        s.set_identity_mode(b.id, "handle").unwrap();
        let b = s.get_account(b.id).unwrap().unwrap();
        assert_eq!(b.identity_mode.as_deref(), Some("handle"));
        assert_eq!(b.handle.as_deref(), Some("bob"));
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
    fn agent_identities_share_the_handle_namespace() {
        let s = store();
        let a = s.find_or_create_account("a@x.com").unwrap();
        let b = s.find_or_create_account("b@x.com").unwrap();

        // Human handle blocks an agent name…
        assert!(s.set_handle(a.id, "dan").unwrap());
        assert!(!s.create_agent_identity(b.id, "dan").unwrap());
        // …and an agent name blocks a human handle.
        assert!(s.create_agent_identity(a.id, "attestor").unwrap());
        assert!(!s.set_handle(b.id, "attestor").unwrap());

        // Duplicate agent name (any account, even the owner) is not re-creatable.
        assert!(!s.create_agent_identity(a.id, "attestor").unwrap());
        assert!(!s.create_agent_identity(b.id, "attestor").unwrap());

        // Quota counting + revocation semantics.
        assert_eq!(s.count_active_agent_identities(a.id).unwrap(), 1);
        s.revoke_agent_identity("attestor").unwrap();
        assert_eq!(s.count_active_agent_identities(a.id).unwrap(), 0);
        assert!(!s.get_agent_identity("attestor").unwrap().unwrap().is_active());
        // Revoked names are never recycled.
        assert!(!s.create_agent_identity(a.id, "attestor").unwrap());
        assert!(!s.set_handle(b.id, "attestor").unwrap());
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
