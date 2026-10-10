#![forbid(unsafe_code)]

//! Sessions: token generation/hashing and cookie header building.
//!
//! - Session token: 256 random bits, transported as base64url in the
//!   `wg-ez` cookie; only its SHA-256 hex is stored in DB.
//! - Cookie flags: `HttpOnly`, `SameSite=Lax`, `Path=/`,
//!   `Secure` iff `!INSECURE`. The session cookie is always a
//!   browser-session cookie (no `Max-Age`): closing the browser forgets it.
//!
//! The pending 2FA login store lives in the web layer
//! (`crate::web::ctx::PendingLogin`).

use base64::Engine as _;
use sha2::{Digest, Sha256};

/// Session cookie name.
pub const SESSION_COOKIE_NAME: &str = "wg-ez";
/// Session token length in bytes (256 bits).
pub const SESSION_TOKEN_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("rng failure: {0}")]
    Rng(String),
}

/// Fill a buffer from the OS RNG.
fn random_bytes<const N: usize>() -> Result<[u8; N], SessionError> {
    use rand::{TryRng as _, rngs::SysRng};
    let mut buf = [0u8; N];
    SysRng
        .try_fill_bytes(&mut buf)
        .map_err(|e| SessionError::Rng(e.to_string()))?;
    Ok(buf)
}

/// Fresh 256-bit token from the OS RNG.
pub fn generate_raw_token() -> Result<[u8; SESSION_TOKEN_LEN], SessionError> {
    random_bytes()
}

/// base64url (no padding) encoding for transport in the cookie.
pub fn encode_token(raw: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

/// SHA-256 as lowercase hex (the only form ever stored in DB).
pub fn sha256_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Generate a `(cookie_value, stored_hash)` pair. The stored hash is the
/// SHA-256 of the **cookie string**, exactly what
/// [`crate::web::guards::hash_token`] recomputes on lookup (single source of
/// truth: `guards::hash_token` delegates to [`sha256_hex`]).
pub fn generate_token_pair() -> Result<(String, String), SessionError> {
    let raw = generate_raw_token()?;
    let cookie = encode_token(&raw);
    let stored = sha256_hex(cookie.as_bytes());
    Ok((cookie, stored))
}

/// Build a `Set-Cookie` header value with the shared hardening attributes
/// (`HttpOnly`, `SameSite=Lax`, `Secure` iff `secure`) for an arbitrary cookie
/// name, `Path` and optional `Max-Age`.
///
/// Single source of truth for the session cookie *and* the pending-2FA
/// cookie, so their flags can never diverge. `Secure` must be `!INSECURE`.
pub fn build_cookie(
    name: &str,
    value: &str,
    path: &str,
    secure: bool,
    max_age: Option<u64>,
) -> String {
    let mut cookie = format!("{name}={value}; Path={path}; HttpOnly; SameSite=Lax");
    if secure {
        cookie.push_str("; Secure");
    }
    if let Some(max_age) = max_age {
        cookie.push_str(&format!("; Max-Age={max_age}"));
    }
    cookie
}

/// Build the `wg-ez` `Set-Cookie` header value. Always a browser-session
/// cookie (no `Max-Age`): closing the browser forgets it. `secure` must be
/// `!INSECURE`.
pub fn build_set_cookie(token_b64: &str, secure: bool) -> String {
    build_cookie(SESSION_COOKIE_NAME, token_b64, "/", secure, None)
}

/// Cookie-clearing `Set-Cookie` value used on logout.
pub fn build_clear_cookie(secure: bool) -> String {
    let mut cookie = format!("{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_pair_roundtrip() -> Result<(), String> {
        let (cookie, stored) = generate_token_pair().map_err(|e| e.to_string())?;
        assert_eq!(cookie.len(), 43); // 32 bytes -> 43 base64url chars
        assert_eq!(stored.len(), 64);
        assert_eq!(sha256_hex(cookie.as_bytes()), stored);
        Ok(())
    }

    #[test]
    fn cookie_flags_follow_insecure() {
        let secured = build_cookie("wg-ez", "tok", "/", true, None);
        assert!(secured.contains("; Secure"));
        assert!(!secured.contains("Max-Age"));
        assert!(secured.contains("HttpOnly"));
        let session = build_set_cookie("tok", false);
        assert!(!session.contains("Secure"));
        assert!(!session.contains("Max-Age"));
        let clear = build_clear_cookie(true);
        assert!(clear.contains("Max-Age=0"));
    }
}
