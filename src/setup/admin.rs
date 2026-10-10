#![forbid(unsafe_code)]

//! Step 2: admin creation (`POST /api/setup/2` -> step 3).
//!
//! Atomicity (I5): [`complete_step2`] runs inside a `BEGIN IMMEDIATE`
//! transaction and re-checks `setupStep == 1` + `COUNT(users) == 0` under the
//! write lock *before* inserting. Two concurrent requests then serialize: the
//! loser observes a non-empty table (or an advanced step) and fails without
//! ever minting a second admin.
//!
//! Residual accepted risk: before step 2 completes the route is open ("trust
//! on first use") — anyone reaching an exposed, unconfigured instance can
//! claim the first admin, so expose the instance only on a trusted network
//! until setup finishes.

use super::{ADMIN_DISPLAY_NAME, SetupError};
use crate::auth::password;

/// Validate the username and hash the password (12+ chars policy enforced by
/// [`crate::auth::password::hash_password_blocking`]). Kept outside the
/// write lock: Argon2 is slow and must not extend the `IMMEDIATE` window.
fn prepare_admin(username: &str, password: &str) -> Result<(String, String), SetupError> {
    let username = username.trim().to_string();
    crate::validate::validate_username(&username)?;
    let hash = password::hash_password_blocking(password)?;
    Ok((username, hash))
}

/// Create an ADMIN user (auto-role never used here: the role is explicit so a
/// racy `COUNT(users)` can never downgrade it to CLIENT). Returns the new id.
///
/// Used by the non-interactive boot setup (`INIT_*`) and by tests; the HTTP
/// bootstrap goes through [`complete_step2`] for the transactional re-check.
pub fn create_admin(
    conn: &rusqlite::Connection,
    username: &str,
    password: &str,
) -> Result<i64, SetupError> {
    let (username, hash) = prepare_admin(username, password)?;
    if crate::store::user::get_by_username(conn, &username)?.is_some() {
        return Err(SetupError::State("user already exists".to_string()));
    }
    Ok(crate::store::user::create_with_role(
        conn,
        &username,
        Some(hash.as_str()),
        ADMIN_DISPLAY_NAME,
        crate::store::user::ROLE_ADMIN,
    )?)
}

/// Raw `setupStep` transition (the `general` store only exposes the
/// finish transition; intermediate steps belong to the setup flow).
pub fn set_setup_step(conn: &rusqlite::Connection, step: i64) -> Result<(), SetupError> {
    let n = conn.execute("UPDATE general SET setupStep = ?1 WHERE id = 1", [step])?;
    if n == 0 {
        return Err(SetupError::State("general row missing".to_string()));
    }
    Ok(())
}

/// Finish step 2 atomically: admin created -> move to step 3.
///
/// `BEGIN IMMEDIATE` acquires the write lock up front, so the re-check of
/// `setupStep == 1` and `COUNT(users) == 0` is the authoritative one: two
/// concurrent callers cannot both pass it. The loser gets
/// [`SetupError::State`] (mapped to 400 by the web layer) and no user is
/// inserted — in particular no CLIENT is ever created from the setup flow.
pub fn complete_step2(
    conn: &mut rusqlite::Connection,
    username: &str,
    password: &str,
) -> Result<i64, SetupError> {
    let (username, hash) = prepare_admin(username, password)?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    // Re-verify under the write lock (I5). `Transaction` derefs to
    // `Connection`, so the read helpers and the INSERT share the same lock.
    let step = crate::store::general::get(&tx)?
        .map(|g| g.setup_step)
        .unwrap_or(1);
    if step != 1 {
        return Err(SetupError::State("setup already advanced".to_string()));
    }
    if crate::store::user::count(&tx)? != 0 {
        return Err(SetupError::State("a user already exists".to_string()));
    }
    if crate::store::user::get_by_username(&tx, &username)?.is_some() {
        return Err(SetupError::State("user already exists".to_string()));
    }
    let id = crate::store::user::create_with_role(
        &tx,
        &username,
        Some(hash.as_str()),
        ADMIN_DISPLAY_NAME,
        crate::store::user::ROLE_ADMIN,
    )?;
    set_setup_step(&tx, 3)?;
    tx.commit()?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::memdb;

    #[test]
    fn create_admin_is_always_admin() {
        let conn = memdb();
        let a = create_admin(&conn, "admin", "long-enough-12").expect("admin");
        let role: i64 = conn
            .query_row("SELECT role FROM users WHERE id = ?1", [a], |r| r.get(0))
            .expect("role");
        assert_eq!(role, crate::store::user::ROLE_ADMIN);
        // A second call creates another ADMIN (never a CLIENT): the function
        // is explicitly an admin factory, unlike `store::user::create`.
        let b = create_admin(&conn, "bob", "long-enough-12").expect("bob");
        let role: i64 = conn
            .query_row("SELECT role FROM users WHERE id = ?1", [b], |r| r.get(0))
            .expect("role");
        assert_eq!(role, crate::store::user::ROLE_ADMIN);
        assert!(create_admin(&conn, "admin", "long-enough-12").is_err());
        assert!(create_admin(&conn, "x", "long-enough-12").is_err());
        assert!(create_admin(&conn, "new", "short").is_err());
    }

    #[test]
    fn step2_moves_to_3() {
        let mut conn = memdb();
        complete_step2(&mut conn, "admin", "long-enough-12").expect("step2");
        let step: i64 = conn
            .query_row("SELECT setupStep FROM general WHERE id = 1", [], |r| {
                r.get(0)
            })
            .expect("step");
        assert_eq!(step, 3);
    }

    /// I5: a second `complete_step2` (setup already advanced to 3) must fail
    /// and leave exactly one user, which stays ADMIN. No CLIENT is ever
    /// created by a repeated / racing setup call.
    #[test]
    fn step2_is_single_admin_never_client() {
        let mut conn = memdb();
        let id = complete_step2(&mut conn, "admin", "long-enough-12").expect("first");
        let role: i64 = conn
            .query_row("SELECT role FROM users WHERE id = ?1", [id], |r| r.get(0))
            .expect("role");
        assert_eq!(role, crate::store::user::ROLE_ADMIN);

        assert!(
            complete_step2(&mut conn, "bob", "long-enough-12").is_err(),
            "a second step2 must be rejected"
        );
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
            .expect("count");
        assert_eq!(total, 1, "only the first admin exists");
        let clients: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM users WHERE role = ?1",
                [crate::store::user::ROLE_CLIENT],
                |r| r.get(0),
            )
            .expect("clients");
        assert_eq!(clients, 0, "setup must never create a CLIENT");
        let step: i64 = conn
            .query_row("SELECT setupStep FROM general WHERE id = 1", [], |r| {
                r.get(0)
            })
            .expect("step");
        assert_eq!(step, 3);
    }

    /// La revérification échoue aussi si un utilisateur existe déjà alors que
    /// `setupStep` est resté à 1 (état incohérent) : aucun admin n'est ajouté.
    #[test]
    fn step2_rejects_when_a_user_already_exists() {
        let mut conn = memdb();
        crate::store::user::create_with_role(
            &conn,
            "pre",
            Some("hash"),
            "Pre",
            crate::store::user::ROLE_ADMIN,
        )
        .expect("seed");
        assert!(complete_step2(&mut conn, "admin", "long-enough-12").is_err());
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
            .expect("count");
        assert_eq!(total, 1);
    }
}
