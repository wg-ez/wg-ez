//! CRUD SQL des liens a usage unique (OTL).
//!
//! Conforme aux migrations `src/migrations/*.sql` :
//! table `one_time_links` (`id` = `clientId`, `token` UNIQUE, `expiresAt`
//! TEXT ISO-8601), `ON DELETE CASCADE` vers `clients`.
//! - Une ligne par client (`INSERT ... ON CONFLICT DO UPDATE`).
//! - Token : 128 bits aleatoires en base64url sans padding (jamais CRC32).
//!   La generation vit en couche web/auth. Comme les sessions, seul son
//!   SHA-256 hex est persiste dans la colonne `token` ; les API publiques
//!   prennent le token clair et hachent en interne ([`hash_token`]).
//! - `expiresAt` = creation + 5 min. Le telechargement raccourcit l'expiry
//!   a `now + 10 s` (anti-double-requete) **une seule fois**, tant que la
//!   ligne est encore au TTL initial ; un polling repete ne peut donc pas
//!   maintenir le lien vivant. La purge suit (sans `Tunnel::apply`).
//! - La generation OTL est la seule mutation sans `Tunnel::apply` ;
//!   la purge des expires se fait sans toucher a WireGuard.

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

/// Ligne `one_time_links`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimeLink {
    /// = `clientId`.
    pub client_id: i64,
    /// SHA-256 hex du token clair (seule forme persistee).
    pub token: String,
    /// ISO-8601 d'expiration.
    pub expires_at: String,
}

fn map(row: &rusqlite::Row<'_>) -> Result<OneTimeLink, rusqlite::Error> {
    Ok(OneTimeLink {
        client_id: row.get("id")?,
        token: row.get("token")?,
        expires_at: row.get("expiresAt")?,
    })
}

/// SHA-256 lowercase hex of the clear OTL token, the only form stored at rest
/// (`one_time_links.token`), mirroring the session-token hygiene
/// ([`crate::auth::session::sha256_hex`]). The clear token is returned to the
/// user and is the secret; the hash is an opaque unique lookup key that never
/// leaves the DB.
pub fn hash_token(token: &str) -> String {
    crate::auth::session::sha256_hex(token.as_bytes())
}

/// Cree ou renouvelle le lien d'un client (une seule ligne par client).
/// `token` est le token clair ; seul son SHA-256 hex est persiste.
pub fn upsert(
    conn: &Connection,
    client_id: i64,
    token: &str,
    expires_at: &str,
) -> Result<(), rusqlite::Error> {
    let token_hash = hash_token(token);
    conn.execute(
        "INSERT INTO one_time_links (id, token, expiresAt) VALUES (?1, ?2, ?3) \
         ON CONFLICT(id) DO UPDATE SET token = excluded.token, expiresAt = excluded.expiresAt",
        rusqlite::params![client_id, token_hash, expires_at],
    )?;
    Ok(())
}

/// Cherche par token clair (hache en interne avant la requete).
pub fn get_by_token(
    conn: &Connection,
    token: &str,
) -> Result<Option<OneTimeLink>, rusqlite::Error> {
    let token_hash = hash_token(token);
    conn.query_row(
        "SELECT id, token, expiresAt FROM one_time_links WHERE token = ?1",
        rusqlite::params![token_hash],
        map,
    )
    .optional()
}

pub fn get_for_client(
    conn: &Connection,
    client_id: i64,
) -> Result<Option<OneTimeLink>, rusqlite::Error> {
    conn.query_row(
        "SELECT id, token, expiresAt FROM one_time_links WHERE id = ?1",
        [client_id],
        map,
    )
    .optional()
}

/// Raccourcit l'expiry (fenetre anti-double-requete lors du telechargement).
/// La couche appelante n'invoque ceci que pour la premiere requete, tant que
/// la ligne est encore au TTL initial (cf. `crate::otl::consume_for_download`) :
/// un polling ne peut donc pas prolonger le lien.
pub fn touch(conn: &Connection, client_id: i64, expires_at: &str) -> Result<bool, rusqlite::Error> {
    let n = conn.execute(
        "UPDATE one_time_links SET expiresAt = ?1 WHERE id = ?2",
        rusqlite::params![expires_at, client_id],
    )?;
    Ok(n > 0)
}

/// Purge les liens expires (cron 60 s, sans `Tunnel::apply`).
pub fn delete_expired(conn: &Connection, now: &str) -> Result<usize, rusqlite::Error> {
    let n = conn.execute("DELETE FROM one_time_links WHERE expiresAt <= ?1", [now])?;
    Ok(n)
}
