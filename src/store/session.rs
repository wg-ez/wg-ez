//! CRUD SQL des sessions.
//!
//! - Cookie `wg-ez` = token aleatoire 256 bits ; seul son SHA-256 hex est
//!   stocke (`tokenHash`, jamais le clair).
//! - Le cookie est toujours un cookie de session navigateur (sans `Max-Age`) :
//!   fermer le navigateur l'oublie.

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

/// Ligne `sessions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// SHA-256 hex du token.
    pub token_hash: String,
    pub user_id: i64,
    /// ISO-8601 de fin de validite.
    pub expires_at: String,
}

fn map(row: &rusqlite::Row<'_>) -> Result<Session, rusqlite::Error> {
    Ok(Session {
        token_hash: row.get("tokenHash")?,
        user_id: row.get("userId")?,
        expires_at: row.get("expiresAt")?,
    })
}

pub fn create(
    conn: &Connection,
    token_hash: &str,
    user_id: i64,
    expires_at: &str,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO sessions (tokenHash, userId, expiresAt) VALUES (?1, ?2, ?3)",
        rusqlite::params![token_hash, user_id, expires_at],
    )?;
    Ok(())
}

pub fn get_by_hash(
    conn: &Connection,
    token_hash: &str,
) -> Result<Option<Session>, rusqlite::Error> {
    conn.query_row(
        "SELECT tokenHash, userId, expiresAt FROM sessions WHERE tokenHash = ?1",
        [token_hash],
        map,
    )
    .optional()
}

/// Destruction (logout).
pub fn delete_by_hash(conn: &Connection, token_hash: &str) -> Result<bool, rusqlite::Error> {
    let n = conn.execute("DELETE FROM sessions WHERE tokenHash = ?1", [token_hash])?;
    Ok(n > 0)
}

/// Supprime toutes les sessions d'un user.
pub fn delete_for_user(conn: &Connection, user_id: i64) -> Result<usize, rusqlite::Error> {
    let n = conn.execute("DELETE FROM sessions WHERE userId = ?1", [user_id])?;
    Ok(n)
}

/// Purge les sessions expirees.
pub fn delete_expired(conn: &Connection, now: &str) -> Result<usize, rusqlite::Error> {
    let n = conn.execute("DELETE FROM sessions WHERE expiresAt <= ?1", [now])?;
    Ok(n)
}
