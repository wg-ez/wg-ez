#![forbid(unsafe_code)]

//! Argon2id password hashing and verification.
//!
//! Parameters are fixed: memory `m = 19456` KiB, time `t = 2`,
//! parallelism `p = 1` (the server runs on a single-thread runtime).
//! All blocking work runs in `tokio::task::spawn_blocking`.
//!
//! Unknown users are verified against a dummy hash so that the timing of
//! a login failure does not reveal whether the account exists.

use argon2::password_hash::phc::PasswordHash;
use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};
use std::sync::OnceLock;

/// Minimum password length in characters.
pub const MIN_PASSWORD_LEN: usize = 12;
/// Argon2 memory cost in KiB.
pub const ARGON2_M_COST: u32 = 19_456;
/// Argon2 time cost.
pub const ARGON2_T_COST: u32 = 2;
/// Argon2 parallelism (matches the single-thread runtime).
pub const ARGON2_P_COST: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("password must contain at least 12 characters")]
    TooShort,
    #[error("password hash error: {0}")]
    Hash(String),
}

fn argon2() -> Result<Argon2<'static>, PasswordError> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None)
        .map_err(|e| PasswordError::Hash(e.to_string()))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Enforce the 12-character minimum policy.
pub fn validate_password_policy(password: &str) -> Result<(), PasswordError> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(PasswordError::TooShort);
    }
    Ok(())
}

/// Blocking Argon2id hash (call from `spawn_blocking`, tests or the CLI).
/// A fresh random salt is generated internally per hash.
pub fn hash_password_blocking(password: &str) -> Result<String, PasswordError> {
    validate_password_policy(password)?;
    argon2()?
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| PasswordError::Hash(e.to_string()))
}

/// Blocking verify: `Ok(false)` on mismatch, `Err` on an unparsable hash.
pub fn verify_password_blocking(hash: &str, password: &str) -> Result<bool, PasswordError> {
    let parsed = PasswordHash::new(hash).map_err(|e| PasswordError::Hash(e.to_string()))?;
    Ok(argon2()?
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// Lazily created dummy hash (same Argon2 params, random salt per boot).
fn dummy_hash() -> Result<String, PasswordError> {
    static DUMMY: OnceLock<String> = OnceLock::new();
    if let Some(cached) = DUMMY.get() {
        return Ok(cached.clone());
    }
    let fresh = hash_password_blocking("dummy-password-that-never-matches-0000")?;
    let _ = DUMMY.set(fresh.clone());
    Ok(fresh)
}

/// Verify against the stored hash, or against the dummy hash when the user
/// is unknown (`None`). Always returns `Ok(false)` in the unknown case,
/// after doing the same amount of Argon2 work.
pub fn verify_or_dummy_blocking(
    stored_hash: Option<&str>,
    password: &str,
) -> Result<bool, PasswordError> {
    match stored_hash {
        Some(hash) => verify_password_blocking(hash, password),
        None => {
            let dummy = dummy_hash()?;
            let _ = verify_password_blocking(&dummy, password)?;
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_rejects_short_passwords() {
        assert!(matches!(
            validate_password_policy("short"),
            Err(PasswordError::TooShort)
        ));
        assert!(validate_password_policy("twelve-chars").is_ok());
    }

    #[test]
    fn roundtrip_hash_verify() -> Result<(), String> {
        let hash = hash_password_blocking("a-very-long-password").map_err(|e| e.to_string())?;
        assert!(
            verify_password_blocking(&hash, "a-very-long-password").map_err(|e| e.to_string())?
        );
        assert!(
            !verify_password_blocking(&hash, "a-very-long-passwore").map_err(|e| e.to_string())?
        );
        Ok(())
    }

    #[test]
    fn unknown_user_costs_argon2_but_fails() -> Result<(), String> {
        assert!(!verify_or_dummy_blocking(None, "whatever-password").map_err(|e| e.to_string())?);
        let hash = hash_password_blocking("correct-horse-pwrd").map_err(|e| e.to_string())?;
        assert!(
            verify_or_dummy_blocking(Some(&hash), "correct-horse-pwrd")
                .map_err(|e| e.to_string())?
        );
        assert!(
            !verify_or_dummy_blocking(Some(&hash), "wrong-password12").map_err(|e| e.to_string())?
        );
        Ok(())
    }
}
