//! CRUD SQL des utilisateurs.
//!
//! - Le premier utilisateur cree recoit le role ADMIN, les suivants CLIENT.
//! - `password` NULL interdit le login par mot de passe ; le hash Argon2id est
//!   verifie en couche auth (avec hash factice si user inconnu, anti-timing).
//! - Aucune colonne OAuth en V1.

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::db::{bool_int, int_bool};

/// Role ADMIN : toutes les permissions sans restriction.
pub const ROLE_ADMIN: i64 = 1;
/// Role CLIENT : lecture/modif/suppression de ses propres clients et profil.
pub const ROLE_CLIENT: i64 = 2;

/// Ligne `users`.
#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    /// Hash Argon2id ou `None` = login password interdit.
    pub password: Option<String>,
    pub name: String,
    pub role: i64,
    pub totp_key: Option<String>,
    pub totp_verified: bool,
    /// Dernier pas TOTP (`floor(unix/30)`) consomme avec succes. `None` tant
    /// qu'aucun code n'a ete accepte. Sert de garde anti-rejeu : un code dont
    /// le pas est `<= totp_last_counter` est refuse, meme dans la fenetre.
    pub totp_last_counter: Option<i64>,
    pub enabled: bool,
}

/// Debug manuel : `password` (hash Argon2id) et `totp_key` (secret TOTP) sont
/// des secrets, jamais exposes, meme si un `{:?}` (log, panic, message
/// d'erreur) atteint cette struct. Les autres champs restent lisibles pour le
/// diagnostic.
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("name", &self.name)
            .field("role", &self.role)
            .field("totp_key", &"<redacted>")
            .field("totp_verified", &self.totp_verified)
            .field("totp_last_counter", &self.totp_last_counter)
            .field("enabled", &self.enabled)
            .finish()
    }
}

impl User {
    /// Vrai si ADMIN (toutes permissions).
    pub fn is_admin(&self) -> bool {
        self.role == ROLE_ADMIN
    }
}

const COLUMNS: &str =
    "id, username, password, name, role, totpKey, totpVerified, totpLastCounter, enabled";

fn map(row: &rusqlite::Row<'_>) -> Result<User, rusqlite::Error> {
    Ok(User {
        id: row.get("id")?,
        username: row.get("username")?,
        password: row.get("password")?,
        name: row.get("name")?,
        role: row.get("role")?,
        totp_key: row.get("totpKey")?,
        totp_verified: int_bool(row.get::<_, i64>("totpVerified")?),
        totp_last_counter: row.get("totpLastCounter")?,
        enabled: int_bool(row.get::<_, i64>("enabled")?),
    })
}

/// Nombre d'utilisateurs (0 = prochain cree = ADMIN).
pub fn count(conn: &Connection) -> Result<i64, rusqlite::Error> {
    conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
}

pub fn get(conn: &Connection, id: i64) -> Result<Option<User>, rusqlite::Error> {
    let sql = format!("SELECT {COLUMNS} FROM users WHERE id = ?1");
    conn.query_row(&sql, [id], map).optional()
}

pub fn get_by_username(conn: &Connection, username: &str) -> Result<Option<User>, rusqlite::Error> {
    let sql = format!("SELECT {COLUMNS} FROM users WHERE username = ?1");
    conn.query_row(&sql, [username], map).optional()
}

pub fn list(conn: &Connection) -> Result<Vec<User>, rusqlite::Error> {
    let sql = format!("SELECT {COLUMNS} FROM users ORDER BY id");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], map)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Creation avec role auto : ADMIN si table vide, sinon CLIENT.
///
/// ```rust
/// # fn main() -> Result<(), wgez::db::DbError> {
/// let conn = rusqlite::Connection::open_in_memory()?;
/// conn.execute_batch("PRAGMA foreign_keys=ON;")?;
/// wgez::db::run_migrations(&conn)?;
/// let first = wgez::store::user::create(&conn, "admin", None, "Admin")?;
/// let second = wgez::store::user::create(&conn, "bob", None, "Bob")?;
/// let admin = wgez::store::user::get(&conn, first)?.filter(|u| u.is_admin());
/// assert!(admin.is_some());
/// let bob = wgez::store::user::get(&conn, second)?.filter(|u| !u.is_admin());
/// assert!(bob.is_some());
/// # Ok(())
/// # }
/// ```
pub fn create(
    conn: &Connection,
    username: &str,
    password_hash: Option<&str>,
    name: &str,
) -> Result<i64, rusqlite::Error> {
    let role = if count(conn)? == 0 {
        ROLE_ADMIN
    } else {
        ROLE_CLIENT
    };
    create_with_role(conn, username, password_hash, name, role)
}

/// Insertion avec rôle explicite, sans recomptage de la table.
///
/// Indispensable au bootstrap du setup (I5) : le rôle ne doit jamais être
/// recalculé depuis un `COUNT(users)` lu hors transaction, sinon deux
/// créations concurrentes observeraient toutes deux une table vide et
/// mintraient deux ADMIN. Le setup passe donc `ROLE_ADMIN` explicitement,
/// à l'intérieur d'une transaction `IMMEDIATE` (voir
/// `crate::setup::complete_step2`).
pub fn create_with_role(
    conn: &Connection,
    username: &str,
    password_hash: Option<&str>,
    name: &str,
    role: i64,
) -> Result<i64, rusqlite::Error> {
    conn.execute(
        "INSERT INTO users (username, password, name, role, totpVerified, enabled) \
         VALUES (?1, ?2, ?3, ?4, 0, 1)",
        rusqlite::params![username, password_hash, name, role],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Mise a jour du profil personnel (nom).
pub fn update_profile(conn: &Connection, id: i64, name: &str) -> Result<bool, rusqlite::Error> {
    let n = conn.execute(
        "UPDATE users SET name = ?1 WHERE id = ?2",
        rusqlite::params![name, id],
    )?;
    Ok(n > 0)
}

/// Remplace le nom de connexion. Un doublon (`username TEXT NOT NULL UNIQUE`)
/// remonte l'erreur SQLite brute : le backend la mappe en `400 conflict`
/// generique via `db_err`, sans jamais divulguer le schema (M10).
pub fn set_username(conn: &Connection, id: i64, username: &str) -> Result<bool, rusqlite::Error> {
    let n = conn.execute(
        "UPDATE users SET username = ?1 WHERE id = ?2",
        rusqlite::params![username, id],
    )?;
    Ok(n > 0)
}

/// Remplace le hash Argon2id (`None` = interdit le login password).
pub fn set_password_hash(
    conn: &Connection,
    id: i64,
    hash: Option<&str>,
) -> Result<bool, rusqlite::Error> {
    let n = conn.execute(
        "UPDATE users SET password = ?1 WHERE id = ?2",
        rusqlite::params![hash, id],
    )?;
    Ok(n > 0)
}

/// Regle la 2FA (secret + flag verifie). La suppression exige le mot de passe
/// courant en couche web ; ici simple ecriture.
///
/// `totpLastCounter` est remis a `NULL` : un nouveau secret (ou une
/// desactivation) rend obsolete tout pas deja consomme, et la confirmation
/// d'enrolement reinscrira le pas du code de confirmation. Sans cette remise a
/// zero, une re-enrolement dans le meme pas de temps que l'ancien secret
/// verrait le code de confirmation refuse comme un rejeu.
pub fn set_totp(
    conn: &Connection,
    id: i64,
    key: Option<&str>,
    verified: bool,
) -> Result<bool, rusqlite::Error> {
    let n = conn.execute(
        "UPDATE users SET totpKey = ?1, totpVerified = ?2, totpLastCounter = NULL WHERE id = ?3",
        rusqlite::params![key, bool_int(verified), id],
    )?;
    Ok(n > 0)
}

/// Consomme un pas TOTP de facon **atomique** (garde anti-rejeu).
///
/// L'UPDATE n'aboutit que si `counter` est strictement plus recent que le pas
/// deja stocke (ou qu'aucun ne l'est). Un `UPDATE` a 0 ligne signifie qu'une
/// requete concurrente a deja consomme ce pas ou un pas ulterieur : c'est un
/// rejeu, a refuser. Le predicat SQL rend la decision atomique cote SQLite et
/// couvre la course entre deux sessions presentant le meme code.
pub fn set_totp_last_counter(
    conn: &Connection,
    id: i64,
    counter: i64,
) -> Result<bool, rusqlite::Error> {
    let n = conn.execute(
        "UPDATE users SET totpLastCounter = ?1 \
         WHERE id = ?2 AND (totpLastCounter IS NULL OR totpLastCounter < ?1)",
        rusqlite::params![counter, id],
    )?;
    Ok(n == 1)
}

pub fn delete(conn: &Connection, id: i64) -> Result<bool, rusqlite::Error> {
    let n = conn.execute("DELETE FROM users WHERE id = ?1", [id])?;
    Ok(n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_with_secrets() -> User {
        User {
            id: 1,
            username: "admin".to_string(),
            password: Some("$argon2id$SECRET-HASH".to_string()),
            name: "Admin".to_string(),
            role: ROLE_ADMIN,
            totp_key: Some("JBSWY3DPEHPK3PXP".to_string()),
            totp_verified: true,
            totp_last_counter: Some(42),
            enabled: true,
        }
    }

    #[test]
    fn user_debug_redacts_password_and_totp_key() {
        let debug = format!("{:?}", user_with_secrets());
        assert!(
            debug.contains("<redacted>"),
            "secret fields are redacted: {debug}"
        );
        assert!(
            !debug.contains("SECRET-HASH"),
            "password hash must never leak through Debug: {debug}"
        );
        assert!(
            !debug.contains("JBSWY3DPEHPK3PXP"),
            "totp key must never leak through Debug: {debug}"
        );
        // Les champs non sensibles restent lisibles pour le diagnostic.
        assert!(debug.contains("admin"));
        assert!(debug.contains("42"));
    }

    /// La redaction est constante : meme non renseignes, les deux champs
    /// sensibles affichent le marqueur (jamais `None`, qui revelerait leur
    /// presence/absence a un lecteur de log).
    #[test]
    fn user_debug_redacts_unset_secrets_too() {
        let user = User {
            password: None,
            totp_key: None,
            ..user_with_secrets()
        };
        let debug = format!("{user:?}");
        assert_eq!(
            debug.matches("<redacted>").count(),
            2,
            "password and totp_key are always redacted: {debug}"
        );
    }
}
