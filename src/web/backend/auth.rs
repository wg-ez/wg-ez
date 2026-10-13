#![forbid(unsafe_code)]

//! Auth / session / "me" / TOTP operations for [`super::SqliteBackend`].
//!
//! Behavior notes:
//! - dummy Argon2 verification when the user is unknown (no account oracle);
//! - sessions store only the SHA-256 hex of the 256-bit token;
//! - Basic auth returns the user so the guard can refuse a 2FA account with
//!   the same 401 as a wrong password (no password-validity oracle).

use super::SqliteBackend;
use super::common::{db_err, now_iso, user_view};
use crate::web::ctx::{LoginOutcome, TotpSetup, UserView, WebError};

impl SqliteBackend {
    pub(crate) async fn password_auth_allowed_inner(&self) -> Result<bool, WebError> {
        Ok(!self.config.disable_password_auth)
    }

    pub(crate) async fn login_password_inner(
        &self,
        username: &str,
        password: &str,
    ) -> Result<LoginOutcome, WebError> {
        if self.config.disable_password_auth {
            return Err(
                WebError::unauthorized("password authentication is disabled")
                    .with_seclog("password"),
            );
        }
        let username = username.to_string();
        let password = password.to_string();
        self.with_db(move |conn| {
            let Some(user) = authenticate_password(&conn, &username, &password)? else {
                return Err(WebError::unauthorized("invalid credentials").with_seclog("password"));
            };
            if user.totp_key.is_some() && user.totp_verified {
                return Ok(LoginOutcome::TotpRequired {
                    user_id: user.id,
                    username: user.username.clone(),
                });
            }
            // Password login mints the session here (browser-session cookie);
            // the 2FA path mints it later in `create_session_inner`.
            let token = create_session_row(&conn, user.id)?;
            Ok(LoginOutcome::Ok {
                user: user_view(&user),
                token,
            })
        })
        .await
    }

    pub(crate) async fn get_user_inner(&self, user_id: i64) -> Result<UserView, WebError> {
        self.with_db(move |conn| {
            let user = user_row(&conn, user_id)?;
            Ok(user_view(&user))
        })
        .await
    }

    pub(crate) async fn verify_totp_inner(
        &self,
        user_id: i64,
        code: &str,
    ) -> Result<bool, WebError> {
        let code = code.to_string();
        self.with_db(move |conn| {
            let user = user_row(&conn, user_id)?;
            consume_totp_code(&conn, &user, &code, crate::auth::totp::now_unix_secs())
        })
        .await
    }

    pub(crate) async fn create_session_inner(&self, user_id: i64) -> Result<String, WebError> {
        self.with_db(move |conn| create_session_row(&conn, user_id))
            .await
    }

    pub(crate) async fn lookup_session_inner(
        &self,
        token_hash_hex: &str,
    ) -> Result<Option<UserView>, WebError> {
        let hash = token_hash_hex.to_string();
        self.with_db(move |conn| {
            let now = now_iso()?;
            let session = crate::store::session::get_by_hash(&conn, &hash).map_err(db_err)?;
            let Some(session) = session else {
                return Ok(None);
            };
            if session.expires_at.as_str() <= now.as_str() {
                let _ = crate::store::session::delete_by_hash(&conn, &hash);
                return Ok(None);
            }
            let user = crate::store::user::get(&conn, session.user_id).map_err(db_err)?;
            Ok(user.filter(|u| u.enabled).map(|u| user_view(&u)))
        })
        .await
    }

    pub(crate) async fn destroy_session_inner(&self, token_hash_hex: &str) -> Result<(), WebError> {
        let hash = token_hash_hex.to_string();
        self.with_db(move |conn| {
            let _ = crate::store::session::delete_by_hash(&conn, &hash).map_err(db_err)?;
            Ok(())
        })
        .await
    }

    pub(crate) async fn login_basic_inner(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<UserView>, WebError> {
        if self.config.disable_password_auth {
            return Ok(None);
        }
        let username = username.to_string();
        let password = password.to_string();
        self.with_db(move |conn| {
            // A 2FA account is refused upstream with the same 401 as a wrong
            // password; still return the user so the guard can apply the
            // identical (non-oracle) answer.
            Ok(authenticate_password(&conn, &username, &password)?.map(|u| user_view(&u)))
        })
        .await
    }

    pub(crate) async fn update_me_inner(
        &self,
        user_id: i64,
        name: &str,
    ) -> Result<UserView, WebError> {
        let name = name.trim().to_string();
        if name.is_empty() || name.chars().count() > 128 {
            return Err(WebError::bad_request("bad name"));
        }
        crate::validate::check_plain_string(&name)
            .map_err(|e| WebError::bad_request(e.to_string()))?;
        self.with_db(move |conn| {
            if !crate::store::user::update_profile(&conn, user_id, &name).map_err(db_err)? {
                return Err(WebError::not_found("user not found"));
            }
            let user = user_row(&conn, user_id)?;
            Ok(user_view(&user))
        })
        .await
    }

    /// Change the caller's login username. The current-password guard lives
    /// here (shared [`require_current_password`]), not in the handler, so the
    /// JSON API and the UI cannot drift. `validate_username` is the single
    /// validation source (2+ chars, control chars, `__proto__`); a duplicate
    /// travels through [`db_err`] as a generic `400 conflict`.
    pub(crate) async fn change_username_inner(
        &self,
        user_id: i64,
        current: &str,
        username: &str,
    ) -> Result<UserView, WebError> {
        let username = username.trim().to_string();
        crate::validate::validate_username(&username)
            .map_err(|e| WebError::bad_request(e.to_string()))?;
        let current = current.to_string();
        self.with_db(move |conn| {
            let user = user_row(&conn, user_id)?;
            require_current_password(&user, &current)?;
            if !crate::store::user::set_username(&conn, user_id, &username).map_err(db_err)? {
                return Err(WebError::not_found("user not found"));
            }
            let user = user_row(&conn, user_id)?;
            Ok(user_view(&user))
        })
        .await
    }

    pub(crate) async fn change_password_inner(
        &self,
        user_id: i64,
        current: &str,
        next: &str,
    ) -> Result<(), WebError> {
        crate::validate::validate_password(next)
            .map_err(|e| WebError::bad_request(e.to_string()))?;
        let current = current.to_string();
        let next = next.to_string();
        self.with_db(move |conn| {
            let user = user_row(&conn, user_id)?;
            require_current_password(&user, &current)?;
            let hash = crate::auth::password::hash_password_blocking(&next)
                .map_err(|e| WebError::internal(e.to_string()))?;
            crate::store::user::set_password_hash(&conn, user_id, Some(hash.as_str()))
                .map_err(db_err)?;
            // Revoke every existing session: a token stolen before the
            // password change must not survive the rotation. The caller is
            // logged out and re-authenticates.
            crate::store::session::delete_for_user(&conn, user_id).map_err(db_err)?;
            Ok(())
        })
        .await
    }

    pub(crate) async fn totp_setup_start_inner(
        &self,
        user_id: i64,
        password: &str,
    ) -> Result<TotpSetup, WebError> {
        let password = password.to_string();
        self.with_db(move |conn| totp_start(&conn, user_id, &password))
            .await
    }

    pub(crate) async fn totp_setup_confirm_inner(
        &self,
        user_id: i64,
        code: &str,
        password: &str,
    ) -> Result<(), WebError> {
        let code = code.to_string();
        let password = password.to_string();
        self.with_db(move |conn| {
            confirm_totp(
                &conn,
                user_id,
                &code,
                crate::auth::totp::now_unix_secs(),
                &password,
            )
        })
        .await
    }

    pub(crate) async fn totp_remove_inner(
        &self,
        user_id: i64,
        password: &str,
    ) -> Result<(), WebError> {
        let password = password.to_string();
        self.with_db(move |conn| {
            let user = user_row(&conn, user_id)?;
            require_current_password(&user, &password)?;
            crate::store::user::set_totp(&conn, user_id, None, false).map_err(db_err)?;
            Ok(())
        })
        .await
    }
}

/// Prove the current password for a sensitive self-service change (password,
/// username, 2FA). Runs the same Argon2 work whether or not the account has a
/// password (`verify_or_dummy_blocking`) and maps a mismatch to the canonical
/// `401` + seclog `password`. Single guard shared by every call site so the
/// check can never drift between them.
fn require_current_password(
    user: &crate::store::user::User,
    password: &str,
) -> Result<(), WebError> {
    // Borne anti-flood Argon2 avant tout calcul : un secret ne dépasse jamais
    // 1024 o (même borne que le login).
    if password.len() > 1024 {
        return Err(WebError::unauthorized("password is wrong").with_seclog("password"));
    }
    let ok = crate::auth::password::verify_or_dummy_blocking(user.password.as_deref(), password)
        .map_err(|e| WebError::internal(e.to_string()))?;
    if !ok {
        return Err(WebError::unauthorized("password is wrong").with_seclog("password"));
    }
    Ok(())
}

/// Start (or restart) TOTP enrollment.
///
/// La preuve du mot de passe courant est TOUJOURS exigée — y compris pour le
/// premier enrôlement — exactement comme [`SqliteBackend::totp_remove_inner`]
/// et les changements de mot de passe / nom. Sans cela, un cookie de session
/// volé suffirait à enrôler une 2FA connue de l'attaquant, qui survivrait à
/// l'expiration de la session et à la rotation du mot de passe (les sessions
/// sont révoquées, pas la 2FA). Le mot de passe est seulement comparé, jamais
/// journalisé ni renvoyé.
fn totp_start(
    conn: &rusqlite::Connection,
    user_id: i64,
    password: &str,
) -> Result<TotpSetup, WebError> {
    let user = user_row(conn, user_id)?;
    require_current_password(&user, password)?;
    let secret =
        crate::auth::totp::generate_secret().map_err(|e| WebError::internal(e.to_string()))?;
    let secret_b32 = crate::auth::totp::base32_encode(&secret);
    crate::store::user::set_totp(conn, user_id, Some(secret_b32.as_str()), false)
        .map_err(db_err)?;
    let url = crate::auth::totp::provisioning_uri(&user.username, "wg-ez", &secret_b32);
    let svg = crate::web::qr::render_qr_svg(url.as_bytes())
        .map_err(|e| WebError::internal(format!("qr: {e}")))?;
    Ok(TotpSetup {
        secret: secret_b32,
        otpauth_url: url,
        qr_svg: svg,
    })
}

/// Load a user row by id, or answer 404.
fn user_row(
    conn: &rusqlite::Connection,
    user_id: i64,
) -> Result<crate::store::user::User, WebError> {
    crate::store::user::get(conn, user_id)
        .map_err(db_err)?
        .ok_or_else(|| WebError::not_found("user not found"))
}

/// Verify a TOTP code against a base32 secret at an explicit instant, treating
/// any error as failure. Returns the exact step counter that matched.
fn verify_totp_key_counter(key: &str, code: &str, now: u64) -> Option<u64> {
    let secret = crate::auth::totp::base32_decode(key).ok()?;
    crate::auth::totp::verify_totp_counter(&secret, code.trim(), now)
        .ok()
        .flatten()
}

/// Verify a login TOTP code and **consume** its step atomically.
///
/// Returns `true` only when either (a) the step was strictly newer than the
/// stored [`crate::store::user::User::totp_last_counter`] and the conditional
/// `UPDATE` succeeded, or (b) it was consumed for free because no counter was
/// stored yet. A code whose step is `<=` the stored counter, or whose atomic
/// consume loses a concurrent race (`0` rows updated), is a replay and yields
/// `false`. Comparing the counter *before* the `UPDATE` is only a fast path;
/// the SQL predicate is the actual race-free guard.
fn consume_totp_code(
    conn: &rusqlite::Connection,
    user: &crate::store::user::User,
    code: &str,
    now: u64,
) -> Result<bool, WebError> {
    let Some(key) = user.totp_key.as_deref() else {
        return Ok(false);
    };
    let Some(counter) = verify_totp_key_counter(key, code, now) else {
        return Ok(false);
    };
    // `counter` is bounded by `now/30 + 1`, so the `i64` conversion is exact.
    let counter = i64::try_from(counter).map_err(|e| WebError::internal(e.to_string()))?;
    if user.totp_last_counter.is_some_and(|last| counter <= last) {
        return Ok(false);
    }
    crate::store::user::set_totp_last_counter(conn, user.id, counter).map_err(db_err)
}

/// Confirm TOTP enrollment: verify `code` against the pending secret, enable
/// 2FA, and persist the matched step so the confirmation code cannot be
/// replayed at login inside its `±1` window. The current password is required
/// (same step-up proof as `start`): confirming an attacker-known secret must
/// not be possible with a stolen session alone.
fn confirm_totp(
    conn: &rusqlite::Connection,
    user_id: i64,
    code: &str,
    now: u64,
    password: &str,
) -> Result<(), WebError> {
    let user = user_row(conn, user_id)?;
    require_current_password(&user, password)?;
    let Some(key) = user.totp_key else {
        return Err(WebError::bad_request("totp not started"));
    };
    let Some(counter) = verify_totp_key_counter(&key, code, now) else {
        return Err(WebError::unauthorized("invalid code").with_seclog("2fa"));
    };
    crate::store::user::set_totp(conn, user_id, Some(key.as_str()), true).map_err(db_err)?;
    let counter = i64::try_from(counter).map_err(|e| WebError::internal(e.to_string()))?;
    crate::store::user::set_totp_last_counter(conn, user_id, counter).map_err(db_err)?;
    Ok(())
}

/// Verify a username/password pair. Performs the Argon2 work even when the
/// user is unknown (no timing oracle). Returns the user only if it is enabled
/// and the password matches.
fn authenticate_password(
    conn: &rusqlite::Connection,
    username: &str,
    password: &str,
) -> Result<Option<crate::store::user::User>, WebError> {
    let user = crate::store::user::get_by_username(conn, username.trim()).map_err(db_err)?;
    let hash = user.as_ref().and_then(|u| u.password.clone());
    let ok = crate::auth::password::verify_or_dummy_blocking(hash.as_deref(), password)
        .map_err(|e| WebError::internal(e.to_string()))?;
    Ok(user.filter(|u| u.enabled && ok))
}

/// Shared session creation for password login and setup/2FA logins.
///
/// Reads `sessionTimeout` (default 3600 s) for the server-side `expiresAt`;
/// the cookie itself is always a browser-session cookie (no `Max-Age`).
fn create_session_row(conn: &rusqlite::Connection, user_id: i64) -> Result<String, WebError> {
    let timeout = crate::store::general::get(conn)
        .map_err(db_err)?
        .map(|g| g.session_timeout)
        .unwrap_or(3600);
    let secs: u64 = match u64::try_from(timeout) {
        Ok(v) if v > 0 => v,
        _ => 3600,
    };
    let (token, _stored) = crate::auth::session::generate_token_pair()
        .map_err(|e| WebError::internal(e.to_string()))?;
    // The web layer looks sessions up via `guards::hash_token`
    // (SHA-256 of the cookie string): persist exactly that form.
    let stored = crate::web::guards::hash_token(&token);
    let expires = crate::otl::expiry_after_secs(secs as i64)
        .map_err(|e| WebError::internal(e.to_string()))?;
    crate::store::session::create(conn, &stored, user_id, &expires).map_err(db_err)?;
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::memdb;

    const PASSWORD: &str = "correct-horse-battery";
    const OLD_SECRET: &str = "OLD32SECRET";

    /// Insert an enabled ADMIN with a known password; `verified` seeds an
    /// active (already verified) 2FA secret.
    fn seeded_user(conn: &rusqlite::Connection, verified: bool) -> i64 {
        let hash = crate::auth::password::hash_password_blocking(PASSWORD).expect("hash argon2id");
        let id = crate::store::user::create_with_role(conn, "alice", Some(&hash), "Alice", 1)
            .expect("insert user");
        if verified {
            crate::store::user::set_totp(conn, id, Some(OLD_SECRET), true).expect("seed totp");
        }
        id
    }

    fn row(conn: &rusqlite::Connection, id: i64) -> crate::store::user::User {
        crate::store::user::get(conn, id)
            .expect("query user")
            .expect("user exists")
    }

    /// RFC 4226 Appendix D secret, base32-encoded (the DB storage format).
    const RFC_SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    /// Create a user with a valid, decodable 2FA secret attached.
    fn seeded_totp_user(conn: &rusqlite::Connection, verified: bool) -> i64 {
        let id = crate::store::user::create(conn, "totp-user", None, "Totp").expect("insert user");
        crate::store::user::set_totp(conn, id, Some(RFC_SECRET_B32), verified).expect("seed totp");
        id
    }

    /// Comme `seeded_totp_user`, mais avec un mot de passe connu (la
    /// confirmation exige désormais la preuve du mot de passe courant).
    fn seeded_password_totp_user(conn: &rusqlite::Connection, verified: bool) -> i64 {
        let hash = crate::auth::password::hash_password_blocking(PASSWORD).expect("hash argon2id");
        let id = crate::store::user::create(conn, "totp-user", Some(&hash), "Totp")
            .expect("insert user");
        crate::store::user::set_totp(conn, id, Some(RFC_SECRET_B32), verified).expect("seed totp");
        id
    }

    /// The 6-digit code for an explicit step of [`RFC_SECRET_B32`].
    fn code_for(counter: u64) -> String {
        let secret = crate::auth::totp::base32_decode(RFC_SECRET_B32).expect("decode");
        crate::auth::totp::totp_code(&secret, counter).expect("code")
    }

    /// (a) A code accepted once is refused inside the same `±1` window: the
    /// step is persisted and cannot open a second session.
    #[test]
    fn consumed_totp_code_is_refused_within_window() {
        let conn = memdb();
        let id = seeded_totp_user(&conn, true);
        let code = code_for(1);

        // t=59 -> counter 1; first use is accepted and consumed.
        let user = row(&conn, id);
        assert!(consume_totp_code(&conn, &user, &code, 59).expect("first use"));
        assert_eq!(row(&conn, id).totp_last_counter, Some(1));

        // t=89 still covers counter 1: the same code is a replay.
        let user = row(&conn, id);
        assert!(!consume_totp_code(&conn, &user, &code, 89).expect("replay refused"));
        assert_eq!(
            row(&conn, id).totp_last_counter,
            Some(1),
            "counter unchanged"
        );
    }

    /// (c) The consume is guarded by a conditional `UPDATE`: even a stale
    /// in-memory user (counter still `NULL`) loses the race and is refused.
    #[test]
    fn conditional_update_refuses_replay_of_stale_snapshot() {
        let conn = memdb();
        let id = seeded_totp_user(&conn, true);
        let code = code_for(1);

        let stale = row(&conn, id);
        assert!(consume_totp_code(&conn, &stale, &code, 59).expect("first use"));
        // `stale` still carries `totp_last_counter = None`, so only the SQL
        // predicate can save us; it updates 0 rows -> replay refused.
        assert!(!consume_totp_code(&conn, &stale, &code, 59).expect("race refused"));
        assert_eq!(row(&conn, id).totp_last_counter, Some(1));
    }

    /// (b) A strictly newer step is still accepted after a consumption.
    #[test]
    fn newer_totp_step_is_accepted_after_consumption() {
        let conn = memdb();
        let id = seeded_totp_user(&conn, true);

        let user = row(&conn, id);
        assert!(consume_totp_code(&conn, &user, &code_for(1), 59).expect("counter 1"));
        // t=89 -> window covers 1..=3; counter 2 is strictly newer.
        let user = row(&conn, id);
        assert!(consume_totp_code(&conn, &user, &code_for(2), 89).expect("counter 2"));
        assert_eq!(row(&conn, id).totp_last_counter, Some(2));
    }

    /// The conditional store call itself refuses equal/older counters and
    /// accepts a newer one.
    #[test]
    fn conditional_counter_update_refuses_equal_or_older() {
        let conn = memdb();
        let id = seeded_totp_user(&conn, true);
        assert!(crate::store::user::set_totp_last_counter(&conn, id, 100).expect("set"));
        assert!(!crate::store::user::set_totp_last_counter(&conn, id, 100).expect("equal"));
        assert!(!crate::store::user::set_totp_last_counter(&conn, id, 99).expect("older"));
        assert!(crate::store::user::set_totp_last_counter(&conn, id, 101).expect("newer"));
        assert_eq!(row(&conn, id).totp_last_counter, Some(101));
    }

    /// Confirming enrollment consumes the confirmation step, so the very same
    /// code cannot be replayed at login inside its window.
    #[test]
    fn confirm_totp_consumes_code_before_login() {
        let conn = memdb();
        let id = seeded_password_totp_user(&conn, false);
        let code = code_for(1);

        confirm_totp(&conn, id, &code, 59, PASSWORD).expect("confirm");
        let user = row(&conn, id);
        assert!(user.totp_verified, "2FA is now active");
        assert_eq!(user.totp_last_counter, Some(1));

        assert!(
            !consume_totp_code(&conn, &user, &code, 59).expect("login replay"),
            "the confirmation code must not open a session"
        );
    }

    /// I2: a session holder with no password cannot disable/overwrite an
    /// active 2FA: the secret and the `verified` flag are left untouched.
    #[test]
    fn start_on_active_2fa_without_password_is_refused_and_keeps_state() {
        let conn = memdb();
        let id = seeded_user(&conn, true);

        let err = totp_start(&conn, id, "").expect_err("start must be refused");
        assert_eq!(err.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(err.seclog, Some("password"), "must log a password failure");

        let user = row(&conn, id);
        assert_eq!(user.totp_key.as_deref(), Some(OLD_SECRET));
        assert!(user.totp_verified, "2FA must stay active");
    }

    /// I2: a wrong password is refused exactly like a missing one (401 +
    /// seclog `password`) and never rotates nor de-verifies the secret.
    #[test]
    fn start_on_active_2fa_with_wrong_password_is_refused_and_keeps_state() {
        let conn = memdb();
        let id = seeded_user(&conn, true);

        let err = totp_start(&conn, id, "definitely-wrong").expect_err("must be refused");
        assert_eq!(err.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(err.seclog, Some("password"));

        let user = row(&conn, id);
        assert_eq!(user.totp_key.as_deref(), Some(OLD_SECRET));
        assert!(user.totp_verified);
    }

    /// I2: proving the current password lets an active 2FA be re-enrolled: a
    /// fresh secret is issued and `verified` drops to false (2FA disabled
    /// until the new code is confirmed).
    #[test]
    fn start_on_active_2fa_with_correct_password_issues_fresh_unverified_secret() {
        let conn = memdb();
        let id = seeded_user(&conn, true);

        let setup = totp_start(&conn, id, PASSWORD).expect("correct password accepted");
        assert!(!setup.secret.is_empty());

        let user = row(&conn, id);
        assert_eq!(user.totp_key.as_deref(), Some(setup.secret.as_str()));
        assert_ne!(user.totp_key.as_deref(), Some(OLD_SECRET));
        assert!(!user.totp_verified, "the new secret must start unverified");
    }

    /// Premier enrôlement : la preuve du mot de passe courant est exigée comme
    /// pour toute porte sensible. Sans elle (session volée), aucun secret
    /// n'est persisté ; avec elle, le secret est émis et régénérable.
    #[test]
    fn start_without_password_is_refused_even_for_first_enrollment() {
        let conn = memdb();
        let id = seeded_user(&conn, false);

        let err = totp_start(&conn, id, "").expect_err("first start without password");
        assert_eq!(err.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(err.seclog, Some("password"), "must log a password failure");
        assert!(
            row(&conn, id).totp_key.is_none(),
            "no secret must be persisted"
        );

        let first = totp_start(&conn, id, PASSWORD).expect("first start with password");
        assert!(!first.secret.is_empty());
        assert!(!row(&conn, id).totp_verified);

        let second = totp_start(&conn, id, PASSWORD).expect("pending secret regeneration");
        assert_ne!(first.secret, second.secret, "pending secret is regenerated");
        assert!(!row(&conn, id).totp_verified);
    }

    /// La confirmation exige elle aussi le mot de passe courant : un code
    /// valide présenté avec une session volée (sans mot de passe) n'active
    /// pas la 2FA, le secret reste en attente.
    #[test]
    fn confirm_totp_without_password_is_refused_and_keeps_pending() {
        let conn = memdb();
        let id = seeded_password_totp_user(&conn, false);
        let code = code_for(1);

        let err = confirm_totp(&conn, id, &code, 59, "mauvais-mot-de-passe")
            .expect_err("confirm without password");
        assert_eq!(err.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(err.seclog, Some("password"));
        let user = row(&conn, id);
        assert!(!user.totp_verified, "2FA must stay pending");
        assert_eq!(user.totp_last_counter, None, "no step consumed");
    }

    /// Real `SqliteBackend` on a fresh temp DB: password login persists an
    /// actual session row, so the connection-only `memdb` is not enough.
    fn temp_backend(tag: &str) -> SqliteBackend {
        let dir = std::env::temp_dir();
        let db = dir.join(format!("wgez-auth-{}-{tag}.db", std::process::id()));
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

    /// Seed an enabled ADMIN (with a known password) in the backend's DB.
    async fn seed_password_user(backend: &SqliteBackend) {
        let hash = crate::auth::password::hash_password_blocking(PASSWORD).expect("hash argon2id");
        backend
            .with_db(move |conn| {
                crate::store::user::create_with_role(&conn, "alice", Some(&hash), "Alice", 1)
                    .map_err(db_err)?;
                Ok(())
            })
            .await
            .expect("seed user");
    }

    /// A non-2FA password login mints a token and persists a session row
    /// (browser-session cookie, no `Max-Age`).
    #[tokio::test]
    async fn password_login_mints_session_row() {
        let backend = temp_backend("session-cookie");
        seed_password_user(&backend).await;

        let outcome = backend
            .login_password_inner("alice", PASSWORD)
            .await
            .expect("valid credentials");
        let token = match outcome {
            LoginOutcome::Ok { token, .. } => token,
            other => panic!("expected a session, got {other:?}"),
        };

        let stored = crate::web::guards::hash_token(&token);
        backend
            .with_db(move |conn| {
                crate::store::session::get_by_hash(&conn, &stored)
                    .map_err(db_err)?
                    .expect("session row");
                Ok(())
            })
            .await
            .expect("check session row");
    }
}
