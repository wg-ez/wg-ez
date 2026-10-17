#![forbid(unsafe_code)]

//! Jetons d'API longue durée pour [`super::SqliteBackend`].
//!
//! - Token clair : 32 octets aléatoires (256 bits, comme les sessions),
//!   base64url sans padding (43 caractères). Seul le SHA-256 hex est persisté
//!   (`tokenHash`).
//! - Auth (`auth_api_token_inner`) : lookup par hash, `enabled`, propriétaire
//!   existant et activé, `expiresAt` futur (comparaison lexicographique sur la
//!   forme canonique), puis `lastUsedAt` best-effort (un échec du touch ne
//!   fait jamais échouer une authentification valide). Fail-closed : tout état
//!   inattendu répond `None`.
//! - Tout passe par `with_db` (`spawn_blocking`, runtime `current_thread`).

use base64::Engine as _;

use super::SqliteBackend;
use super::common::{db_err, now_iso, user_view};
use crate::web::ctx::{ApiTokenCreated, ApiTokenView, UserView, WebError};

/// Entropie du clair : 256 bits, comme les tokens de session.
const TOKEN_BYTES: usize = 32;

fn generate_clear_token() -> String {
    let bytes: [u8; TOKEN_BYTES] = rand::random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn token_view(row: &crate::store::api_token::ApiToken) -> ApiTokenView {
    ApiTokenView {
        id: row.id,
        user_id: row.user_id,
        name: row.name.clone(),
        expires_at: row.expires_at.clone(),
        last_used_at: row.last_used_at.clone(),
        created_at: row.created_at.clone(),
        enabled: row.enabled,
    }
}

/// Nom de jeton : 1-64 caractères, sans contrôles ni clé de pollution
/// prototype (même garde que les autres champs libres).
fn check_name(name: &str) -> Result<String, WebError> {
    let name = name.trim().to_string();
    let len = name.chars().count();
    if !(1..=64).contains(&len) {
        return Err(WebError::bad_request("token name must be 1-64 chars"));
    }
    crate::validate::check_plain_string(&name).map_err(|e| WebError::bad_request(e.to_string()))?;
    Ok(name)
}

/// Normalise `expiresAt` : `None`/vide = permanent, sinon RFC 3339 ou date
/// humaine `JJ-MM-AAAA` (même système que les clients : minuit UTC), remis en
/// forme canonique UTC secondes entières (seule forme comparable
/// lexicographiquement). Une date passée est refusée (400) : créer un jeton
/// déjà expiré n'a aucun sens et masquerait un bug d'appelant.
fn normalize_expires_at(expires_at: Option<&str>, now: &str) -> Result<Option<String>, WebError> {
    let Some(raw) = expires_at.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let parsed = time::OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339)
        .or_else(|_| {
            const HUMAN: &[time::format_description::FormatItem<'_>] =
                time::macros::format_description!("[day]-[month]-[year]");
            time::Date::parse(raw, HUMAN).map(|d| d.with_time(time::Time::MIDNIGHT).assume_utc())
        })
        .map_err(|_| WebError::bad_request("expiresAt must be ISO-8601 or DD-MM-YYYY"))?;
    let canonical =
        crate::db::format_iso8601(parsed).map_err(|e| WebError::internal(format!("db: {e}")))?;
    if canonical.as_str() <= now {
        return Err(WebError::bad_request("expiresAt must be in the future"));
    }
    Ok(Some(canonical))
}

impl SqliteBackend {
    pub(crate) async fn create_api_token_inner(
        &self,
        user_id: i64,
        name: &str,
        expires_at: Option<&str>,
    ) -> Result<ApiTokenCreated, WebError> {
        let name = check_name(name)?;
        let expires_at = expires_at.map(str::to_string);
        self.with_db(move |conn| {
            let now = now_iso()?;
            let expires = normalize_expires_at(expires_at.as_deref(), &now)?;
            // Le jeton n'est créé que pour un compte existant et activé.
            let user = crate::store::user::get(&conn, user_id)
                .map_err(db_err)?
                .ok_or_else(|| WebError::not_found("user not found"))?;
            if !user.enabled {
                return Err(WebError::forbidden("user disabled"));
            }
            // Deux essais : collision SHA-256 (~2^-256) ou id réutilisé.
            for _ in 0..2 {
                let token = generate_clear_token();
                let hash = crate::store::api_token::hash_token(&token);
                match crate::store::api_token::create(
                    &conn,
                    user_id,
                    &name,
                    &hash,
                    expires.as_deref(),
                    &now,
                ) {
                    Ok(id) => {
                        return Ok(ApiTokenCreated {
                            id,
                            name: name.clone(),
                            token,
                            expires_at: expires.clone(),
                            created_at: now,
                        });
                    }
                    Err(e) if crate::db::is_unique_violation(&e) => continue,
                    Err(e) => return Err(db_err(e)),
                }
            }
            Err(WebError::internal("token uniqueness retry exhausted"))
        })
        .await
    }

    pub(crate) async fn list_api_tokens_inner(
        &self,
        user_id: i64,
    ) -> Result<Vec<ApiTokenView>, WebError> {
        self.with_db(move |conn| {
            let rows = crate::store::api_token::list_for_user(&conn, user_id).map_err(db_err)?;
            Ok(rows.iter().map(token_view).collect())
        })
        .await
    }

    pub(crate) async fn list_all_api_tokens_inner(&self) -> Result<Vec<ApiTokenView>, WebError> {
        self.with_db(move |conn| {
            let rows = crate::store::api_token::list_all(&conn).map_err(db_err)?;
            Ok(rows.iter().map(token_view).collect())
        })
        .await
    }

    pub(crate) async fn delete_api_token_inner(
        &self,
        caller_id: i64,
        is_admin: bool,
        id: i64,
    ) -> Result<bool, WebError> {
        self.with_db(move |conn| {
            let deleted = if is_admin {
                crate::store::api_token::delete(&conn, id)
            } else {
                crate::store::api_token::delete_scoped(&conn, caller_id, id)
            }
            .map_err(db_err)?;
            Ok(deleted)
        })
        .await
    }

    pub(crate) async fn auth_api_token_inner(
        &self,
        token_hash_hex: &str,
    ) -> Result<Option<UserView>, WebError> {
        let hash = token_hash_hex.to_string();
        self.with_db(move |conn| {
            let now = now_iso()?;
            let Some(row) = crate::store::api_token::find_by_hash(&conn, &hash).map_err(db_err)?
            else {
                return Ok(None);
            };
            if !row.enabled {
                return Ok(None);
            }
            if row
                .expires_at
                .as_deref()
                .is_some_and(|exp| exp <= now.as_str())
            {
                return Ok(None);
            }
            let user = crate::store::user::get(&conn, row.user_id).map_err(db_err)?;
            let Some(user) = user.filter(|u| u.enabled) else {
                return Ok(None);
            };
            // Best-effort : un échec du touch ne fait jamais échouer une
            // authentification valide (le jeton reste utilisable).
            let _ = crate::store::api_token::touch_last_used(&conn, row.id, &now);
            Ok(Some(user_view(&user)))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::backend::common::db_err;

    const PASSWORD: &str = "correct-horse-battery";

    fn temp_backend(tag: &str) -> SqliteBackend {
        let dir = std::env::temp_dir();
        let db = dir.join(format!("wgez-apitoken-{tag}-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&db);
        let config = crate::config::AppConfig {
            host: "0.0.0.0".to_string(),
            port: 51821,
            insecure: true,
            disable_ipv6: false,
            disable_ipv4: false,
            disable_password_auth: false,
            wg_interface: "wg0".to_string(),
            trusted_proxies: Vec::new(),
            db_path: db.display().to_string(),
            wg_conf_dir: dir.display().to_string(),
            init: None,
        };
        SqliteBackend::new(config).expect("backend")
    }

    async fn seed_user(backend: &SqliteBackend, username: &str, role: i64) -> i64 {
        let hash = crate::auth::password::hash_password_blocking(PASSWORD).expect("hash");
        let username = username.to_string();
        backend
            .with_db(move |conn| {
                crate::store::user::create_with_role(&conn, &username, Some(&hash), &username, role)
                    .map_err(db_err)
            })
            .await
            .expect("seed user")
    }

    async fn disable_user(backend: &SqliteBackend, user_id: i64) {
        backend
            .with_db(move |conn| {
                conn.execute("UPDATE users SET enabled = 0 WHERE id = ?1", [user_id])
                    .map_err(db_err)?;
                Ok(())
            })
            .await
            .expect("disable user");
    }

    #[test]
    fn normalize_expires_at_accepts_iso_and_human_dates() {
        let now = "2026-01-01T00:00:00Z";
        assert_eq!(normalize_expires_at(None, now).expect("none"), None);
        assert_eq!(normalize_expires_at(Some("  "), now).expect("blank"), None);
        assert_eq!(
            normalize_expires_at(Some("2031-12-25T00:00:00Z"), now).expect("rfc"),
            Some("2031-12-25T00:00:00Z".to_string())
        );
        // Même système que les clients : `JJ-MM-AAAA` = minuit UTC.
        assert_eq!(
            normalize_expires_at(Some("25-12-2031"), now).expect("human"),
            Some("2031-12-25T00:00:00Z".to_string())
        );
        assert!(normalize_expires_at(Some("2000-01-01T00:00:00Z"), now).is_err());
        assert!(normalize_expires_at(Some("01-01-2000"), now).is_err());
        assert!(normalize_expires_at(Some("n'importe quoi"), now).is_err());
    }

    #[tokio::test]
    async fn create_returns_clear_once_and_lists_hide_secrets() {
        let backend = temp_backend("create-list");
        let alice = seed_user(&backend, "alice", 1).await;
        let created = backend
            .create_api_token_inner(alice, "ci", Some("2999-01-01T00:00:00Z"))
            .await
            .expect("create");
        assert_eq!(created.token.len(), 43, "32 octets -> 43 chars base64url");
        // La liste ne contient ni le clair ni le hash.
        let list = backend.list_api_tokens_inner(alice).await.expect("list");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "ci");
        let body = serde_json::to_string(&list).expect("json");
        assert!(
            !body.contains(&created.token),
            "le clair ne doit pas fuiter"
        );
        assert!(!body.contains("tokenHash"), "le hash ne doit pas fuiter");
        // Nom invalide : 400 (vide, trop long).
        assert!(
            backend
                .create_api_token_inner(alice, "", None)
                .await
                .is_err()
        );
        assert!(
            backend
                .create_api_token_inner(alice, &"x".repeat(65), None)
                .await
                .is_err()
        );
        // Expiration passée ou mal formée : 400.
        assert!(
            backend
                .create_api_token_inner(alice, "old", Some("2000-01-01T00:00:00Z"))
                .await
                .is_err()
        );
        assert!(
            backend
                .create_api_token_inner(alice, "bad", Some("not-a-date"))
                .await
                .is_err()
        );
        // Permanent : `expiresAt` absent.
        let perm = backend
            .create_api_token_inner(alice, "perm", None)
            .await
            .expect("permanent");
        assert!(perm.expires_at.is_none());
    }

    #[tokio::test]
    async fn revoke_is_scoped_per_user_but_admin_revokes_any() {
        let backend = temp_backend("revoke-scope");
        let admin = seed_user(&backend, "admin", 1).await;
        let bob = seed_user(&backend, "bob", 2).await;
        let mine = backend
            .create_api_token_inner(bob, "mine", None)
            .await
            .expect("bob token");
        let other = backend
            .create_api_token_inner(admin, "other", None)
            .await
            .expect("admin token");
        // Bob ne révoque pas le jeton de l'admin : même réponse qu'un inconnu.
        assert!(
            !backend
                .delete_api_token_inner(bob, false, other.id)
                .await
                .expect("no")
        );
        assert!(
            !backend
                .delete_api_token_inner(bob, false, 999_999)
                .await
                .expect("unknown")
        );
        assert_eq!(
            backend
                .list_all_api_tokens_inner()
                .await
                .expect("all")
                .len(),
            2
        );
        // Le propriétaire, si ; l'ADMIN révoque n'importe lequel.
        assert!(
            backend
                .delete_api_token_inner(bob, false, mine.id)
                .await
                .expect("owner")
        );
        assert!(
            backend
                .delete_api_token_inner(admin, true, other.id)
                .await
                .expect("admin")
        );
        assert!(
            backend
                .list_all_api_tokens_inner()
                .await
                .expect("all")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn auth_valid_expired_disabled_user_disabled_bad_token() {
        let backend = temp_backend("auth-cases");
        let alice = seed_user(&backend, "alice", 1).await;
        let valid = backend
            .create_api_token_inner(alice, "valid", Some("2999-01-01T00:00:00Z"))
            .await
            .expect("valid");
        let hash = crate::store::api_token::hash_token(&valid.token);
        // Valide : résout l'utilisateur et horodate la dernière utilisation.
        let user = backend
            .auth_api_token_inner(&hash)
            .await
            .expect("auth")
            .expect("user");
        assert_eq!(user.id, alice);
        let list = backend.list_api_tokens_inner(alice).await.expect("list");
        assert!(
            list[0].last_used_at.is_some(),
            "lastUsedAt doit être horodaté après usage"
        );
        // Mauvais token : fail-closed, sans erreur 500.
        assert!(
            backend
                .auth_api_token_inner(&"0".repeat(64))
                .await
                .expect("bad")
                .is_none()
        );
        // Expiré : crée puis fait vieillir la ligne (création passée refusée).
        let short = backend
            .create_api_token_inner(alice, "short", Some("2999-01-01T00:00:00Z"))
            .await
            .expect("short");
        let short_hash = crate::store::api_token::hash_token(&short.token);
        backend
            .with_db(move |conn| {
                conn.execute(
                    "UPDATE api_tokens SET expiresAt = '2000-01-01T00:00:00Z' WHERE tokenHash = ?1",
                    [short_hash],
                )
                .map_err(db_err)?;
                Ok(())
            })
            .await
            .expect("expire row");
        assert!(
            backend
                .auth_api_token_inner(&crate::store::api_token::hash_token(&short.token))
                .await
                .expect("expired")
                .is_none()
        );
        // Désactivé : refusé.
        let hash_by_value = hash.clone();
        backend
            .with_db(move |conn| {
                conn.execute(
                    "UPDATE api_tokens SET enabled = 0 WHERE tokenHash = ?1",
                    [hash_by_value],
                )
                .map_err(db_err)?;
                Ok(())
            })
            .await
            .expect("disable row");
        assert!(
            backend
                .auth_api_token_inner(&hash)
                .await
                .expect("disabled")
                .is_none()
        );
        // Compte désactivé : refusé même avec un jeton valide.
        let fresh = backend
            .create_api_token_inner(alice, "fresh", None)
            .await
            .expect("fresh");
        disable_user(&backend, alice).await;
        assert!(
            backend
                .auth_api_token_inner(&crate::store::api_token::hash_token(&fresh.token))
                .await
                .expect("user disabled")
                .is_none()
        );
    }
}
