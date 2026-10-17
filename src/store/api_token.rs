//! CRUD SQL des jetons d'API longue durée (`api_tokens`).
//!
//! Conforme à la migration `005_api_tokens.sql` :
//! - seul le SHA-256 hex du token clair est persisté (`tokenHash UNIQUE`,
//!   jamais le clair) ;
//! - `expiresAt` NULL = permanent ; `enabled` 0 = révoqué/désactivé ;
//! - dates en TEXT ISO-8601 canonique, booléens en INTEGER 0/1 (helpers
//!   `db::bool_int`, `db::int_bool`).
//! - la génération du clair vit en couche web/backend ; comme les sessions et
//!   les OTL, les API publiques prennent le token clair et hachent en interne
//!   ([`hash_token`]).
//! - la purge/désactivation des expirés se fait sans `Tunnel::apply` (cron) ;
//! - une rotation de mot de passe supprime tous les jetons du compte
//!   ([`delete_for_user`]), comme les sessions.

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::db::{bool_int, int_bool};

/// Ligne `api_tokens`.
#[derive(Clone, Serialize, Deserialize)]
pub struct ApiToken {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    /// SHA-256 hex du token clair (seule forme persistée).
    pub token_hash: String,
    /// ISO-8601 d'expiration, `None` = permanent.
    pub expires_at: Option<String>,
    /// ISO-8601 de dernière utilisation, `None` = jamais utilisé.
    pub last_used_at: Option<String>,
    /// ISO-8601 de création.
    pub created_at: String,
    pub enabled: bool,
}

/// Debug manuel : `token_hash` est la clé de recherche opaque, jamais exposée,
/// même si un `{:?}` (log, panic, message d'erreur) atteint cette struct.
impl std::fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiToken")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("name", &self.name)
            .field("token_hash", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("last_used_at", &self.last_used_at)
            .field("created_at", &self.created_at)
            .field("enabled", &self.enabled)
            .finish()
    }
}

const COLUMNS: &str = "id, userId, name, tokenHash, expiresAt, lastUsedAt, createdAt, enabled";

fn map(row: &rusqlite::Row<'_>) -> Result<ApiToken, rusqlite::Error> {
    Ok(ApiToken {
        id: row.get("id")?,
        user_id: row.get("userId")?,
        name: row.get("name")?,
        token_hash: row.get("tokenHash")?,
        expires_at: row.get("expiresAt")?,
        last_used_at: row.get("lastUsedAt")?,
        created_at: row.get("createdAt")?,
        enabled: int_bool(row.get::<_, i64>("enabled")?),
    })
}

/// SHA-256 lowercase hex du token clair, seule forme stockée (`tokenHash`),
/// miroir de l'hygiène des sessions ([`crate::auth::session::sha256_hex`]).
pub fn hash_token(token: &str) -> String {
    crate::auth::session::sha256_hex(token.as_bytes())
}

/// Crée un jeton (`token_hash` = SHA-256 hex du clair, jamais le clair).
/// `expires_at` = `None` pour un jeton permanent. Retourne l'id inséré.
pub fn create(
    conn: &Connection,
    user_id: i64,
    name: &str,
    token_hash: &str,
    expires_at: Option<&str>,
    created_at: &str,
) -> Result<i64, rusqlite::Error> {
    conn.execute(
        "INSERT INTO api_tokens (userId, name, tokenHash, expiresAt, lastUsedAt, createdAt, enabled) \
         VALUES (?1, ?2, ?3, ?4, NULL, ?5, 1)",
        rusqlite::params![user_id, name, token_hash, expires_at, created_at],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn get(conn: &Connection, id: i64) -> Result<Option<ApiToken>, rusqlite::Error> {
    let sql = format!("SELECT {COLUMNS} FROM api_tokens WHERE id = ?1");
    conn.query_row(&sql, [id], map).optional()
}

/// Recherche par token clair (haché en interne avant la requête).
/// Échoue fermée (`None`) sur token inconnu : aucun oracle.
pub fn find_by_hash(
    conn: &Connection,
    token_hash: &str,
) -> Result<Option<ApiToken>, rusqlite::Error> {
    let sql = format!("SELECT {COLUMNS} FROM api_tokens WHERE tokenHash = ?1");
    conn.query_row(&sql, [token_hash], map).optional()
}

/// Recherche par token clair (haché en interne avant la requête).
pub fn get_by_token(conn: &Connection, token: &str) -> Result<Option<ApiToken>, rusqlite::Error> {
    find_by_hash(conn, &hash_token(token))
}

/// Jetons d'un utilisateur, par création croissante.
pub fn list_for_user(conn: &Connection, user_id: i64) -> Result<Vec<ApiToken>, rusqlite::Error> {
    let sql = format!("SELECT {COLUMNS} FROM api_tokens WHERE userId = ?1 ORDER BY id");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([user_id], map)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Tous les jetons (vue ADMIN), par utilisateur puis création.
pub fn list_all(conn: &Connection) -> Result<Vec<ApiToken>, rusqlite::Error> {
    let sql = format!("SELECT {COLUMNS} FROM api_tokens ORDER BY userId, id");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], map)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Suppression (révocation) par id, quel que soit le propriétaire (ADMIN).
pub fn delete(conn: &Connection, id: i64) -> Result<bool, rusqlite::Error> {
    let n = conn.execute("DELETE FROM api_tokens WHERE id = ?1", [id])?;
    Ok(n > 0)
}

/// Suppression scopée : un non-ADMIN ne révoque que ses propres jetons.
/// Retourne `false` quand l'id est inconnu OU appartient à autrui (même
/// réponse : anti-énumération).
pub fn delete_scoped(conn: &Connection, user_id: i64, id: i64) -> Result<bool, rusqlite::Error> {
    let n = conn.execute(
        "DELETE FROM api_tokens WHERE id = ?1 AND userId = ?2",
        rusqlite::params![id, user_id],
    )?;
    Ok(n > 0)
}

/// Suppression de TOUS les jetons d'un utilisateur (rotation de mot de
/// passe). Miroir de [`crate::store::session::delete_for_user`] : un jeton
/// d'API est une credentiel longue durée de la même famille qu'une session,
/// donc il doit survivre ni plus longtemps qu'elle. Les jetons des autres
/// utilisateurs ne sont pas touchés (le `WHERE` est scopé sur `userId`).
pub fn delete_for_user(conn: &Connection, user_id: i64) -> Result<usize, rusqlite::Error> {
    let n = conn.execute("DELETE FROM api_tokens WHERE userId = ?1", [user_id])?;
    Ok(n)
}

/// Active/désactive un jeton (révocation douce).
pub fn set_enabled(conn: &Connection, id: i64, enabled: bool) -> Result<bool, rusqlite::Error> {
    let n = conn.execute(
        "UPDATE api_tokens SET enabled = ?1 WHERE id = ?2",
        rusqlite::params![bool_int(enabled), id],
    )?;
    Ok(n > 0)
}

/// Horodate la dernière utilisation (best-effort : l'appelant ignore l'échec
/// pour ne jamais faire échouer une authentification valide).
pub fn touch_last_used(conn: &Connection, id: i64, now: &str) -> Result<bool, rusqlite::Error> {
    let n = conn.execute(
        "UPDATE api_tokens SET lastUsedAt = ?1 WHERE id = ?2",
        rusqlite::params![now, id],
    )?;
    Ok(n > 0)
}

/// Désactive les jetons expirés (`enabled = 0` quand `expiresAt` dépassé).
/// `expiresAt IS NOT NULL` : les jetons permanents ne sont jamais touchés.
/// Cron 60 s, sans `Tunnel::apply`.
pub fn disable_expired(conn: &Connection, now: &str) -> Result<usize, rusqlite::Error> {
    let n = conn.execute(
        "UPDATE api_tokens SET enabled = 0 \
         WHERE enabled = 1 AND expiresAt IS NOT NULL AND expiresAt <= ?1",
        [now],
    )?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::memdb;

    fn seed_user(conn: &Connection) -> i64 {
        crate::store::user::create(conn, "alice", None, "Alice").expect("user")
    }

    fn sample(conn: &Connection, user_id: i64, name: &str) -> ApiToken {
        let id = create(
            conn,
            user_id,
            name,
            &hash_token(&format!("clear-{name}")),
            Some("2999-01-01T00:00:00Z"),
            "2026-01-01T00:00:00Z",
        )
        .expect("create");
        get(conn, id).expect("get").expect("row")
    }

    #[test]
    fn token_hash_is_sha256_hex_and_clear_never_stored() {
        let conn = memdb();
        let user_id = seed_user(&conn);
        let row = sample(&conn, user_id, "ci");
        assert_eq!(row.token_hash.len(), 64);
        assert_eq!(row.token_hash, hash_token("clear-ci"));
        // Le clair ne figure dans aucune colonne texte persistée.
        let raw: String = conn
            .query_row(
                "SELECT name || '|' || tokenHash FROM api_tokens WHERE id = ?1",
                [row.id],
                |r| r.get(0),
            )
            .expect("raw");
        assert!(
            !raw.contains("clear-ci"),
            "le clair ne doit pas être stocké"
        );
    }

    #[test]
    fn find_by_token_hashes_internally_and_fails_closed() {
        let conn = memdb();
        let user_id = seed_user(&conn);
        sample(&conn, user_id, "ci");
        assert!(get_by_token(&conn, "clear-ci").expect("lookup").is_some());
        assert!(
            get_by_token(&conn, "wrong-token")
                .expect("lookup")
                .is_none()
        );
        assert!(get_by_token(&conn, "").expect("lookup").is_none());
    }

    #[test]
    fn list_is_scoped_per_user_and_delete_scoped_is_anti_enumeration() {
        let conn = memdb();
        let alice = seed_user(&conn);
        let bob = crate::store::user::create(&conn, "bob", None, "Bob").expect("bob");
        let a = sample(&conn, alice, "a1");
        sample(&conn, bob, "b1");
        assert_eq!(list_for_user(&conn, alice).expect("list").len(), 1);
        assert_eq!(list_all(&conn).expect("all").len(), 2);
        // Bob ne peut pas révoquer le jeton d'Alice : même réponse qu'un id inconnu.
        assert!(!delete_scoped(&conn, bob, a.id).expect("scoped"));
        assert!(!delete_scoped(&conn, bob, 999_999).expect("unknown"));
        assert!(get(&conn, a.id).expect("get").is_some());
        // Le propriétaire, si ; l'ADMIN (non scopé) peut tout révoquer.
        assert!(delete_scoped(&conn, alice, a.id).expect("owner"));
        let b = get_by_token(&conn, "clear-b1")
            .expect("lookup")
            .expect("b1");
        assert!(delete(&conn, b.id).expect("admin"));
        assert!(list_all(&conn).expect("all").is_empty());
    }

    #[test]
    fn delete_for_user_purges_every_token_of_that_user_only() {
        let conn = memdb();
        let alice = seed_user(&conn);
        let bob = crate::store::user::create(&conn, "bob", None, "Bob").expect("bob");
        let a1 = sample(&conn, alice, "a1");
        sample(&conn, alice, "a2");
        let b1 = sample(&conn, bob, "b1");

        // Alice's rotation: both of her tokens go, Bob's is untouched.
        assert_eq!(delete_for_user(&conn, alice).expect("purge"), 2);
        assert!(get(&conn, a1.id).expect("get").is_none());
        assert!(list_for_user(&conn, alice).expect("list").is_empty());
        assert!(get(&conn, b1.id).expect("get").is_some());

        // Idempotent: a second rotation has nothing left to purge.
        assert_eq!(delete_for_user(&conn, alice).expect("re-purge"), 0);
        assert_eq!(delete_for_user(&conn, 999_999).expect("unknown user"), 0);
        // Bob's token still resolves.
        assert!(
            get_by_token(&conn, "clear-b1").expect("lookup").is_some(),
            "le purge d'un autre compte ne doit pas casser celui-ci"
        );
    }

    #[test]
    fn set_enabled_touch_and_disable_expired() {
        let conn = memdb();
        let user_id = seed_user(&conn);
        let row = sample(&conn, user_id, "ci");
        assert!(set_enabled(&conn, row.id, false).expect("disable"));
        assert!(!get(&conn, row.id).expect("get").expect("row").enabled);
        assert!(set_enabled(&conn, row.id, true).expect("enable"));
        assert!(touch_last_used(&conn, row.id, "2026-06-01T00:00:00Z").expect("touch"));
        assert_eq!(
            get(&conn, row.id)
                .expect("get")
                .expect("row")
                .last_used_at
                .as_deref(),
            Some("2026-06-01T00:00:00Z")
        );
        // Expiré -> désactivé ; permanent -> intact.
        conn.execute(
            "UPDATE api_tokens SET expiresAt = '2000-01-01T00:00:00Z' WHERE id = ?1",
            [row.id],
        )
        .expect("expire");
        let perm = create(
            &conn,
            user_id,
            "perm",
            &hash_token("clear-perm"),
            None,
            "2026-01-01T00:00:00Z",
        )
        .expect("perm");
        assert_eq!(
            disable_expired(&conn, "2026-01-01T00:00:00Z").expect("cron"),
            1
        );
        assert!(!get(&conn, row.id).expect("get").expect("row").enabled);
        assert!(get(&conn, perm).expect("get").expect("row").enabled);
        // Second tick : rien à faire (déjà désactivé).
        assert_eq!(
            disable_expired(&conn, "2026-01-01T00:00:00Z").expect("cron"),
            0
        );
    }

    #[test]
    fn debug_redacts_token_hash() {
        let conn = memdb();
        let user_id = seed_user(&conn);
        let row = sample(&conn, user_id, "ci");
        let debug = format!("{row:?}");
        assert!(debug.contains("<redacted>"), "{debug}");
        assert!(!debug.contains(&row.token_hash), "{debug}");
    }
}
