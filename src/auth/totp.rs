#![forbid(unsafe_code)]

//! Hand-rolled TOTP (RFC 6238, RFC 4226 truncation).
//!
//! This is the single allowed use of SHA-1 in the codebase: the TOTP
//! standard mandates HMAC-SHA1. Do not use SHA-1 anywhere else.
//!
//! Parameters: 6 digits, 30 s period, 20-byte secret (base32), acceptance
//! window of one step (`±1`).

use hmac::{Hmac, KeyInit, Mac};
use subtle::ConstantTimeEq;

/// Number of digits in a code.
pub const TOTP_DIGITS: usize = 6;
/// Validity period of one step in seconds.
pub const TOTP_PERIOD_SECS: u64 = 30;
/// Secret length in bytes.
pub const TOTP_SECRET_LEN: usize = 20;
/// Accepted step drift in either direction.
pub const TOTP_WINDOW: i64 = 1;

const TOTP_MOD: u32 = 1_000_000;
const B32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Debug, thiserror::Error)]
pub enum TotpError {
    #[error("invalid base32 secret: {0}")]
    InvalidSecret(String),
    #[error("totp code must be exactly 6 digits")]
    InvalidCode,
    #[error("rng failure: {0}")]
    Rng(String),
}

/// Generate a fresh 20-byte secret from the OS RNG.
pub fn generate_secret() -> Result<[u8; TOTP_SECRET_LEN], TotpError> {
    use rand::{TryRng as _, rngs::SysRng};
    let mut secret = [0u8; TOTP_SECRET_LEN];
    SysRng
        .try_fill_bytes(&mut secret)
        .map_err(|e| TotpError::Rng(e.to_string()))?;
    Ok(secret)
}

/// RFC 4648 base32 encode (uppercase, no padding), e.g. for QR provisioning.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buf = (buf << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32_ALPHABET[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32_ALPHABET[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn b32_value(byte: u8) -> Result<u32, TotpError> {
    match byte {
        b'A'..=b'Z' => Ok(u32::from(byte - b'A')),
        b'2'..=b'7' => Ok(u32::from(byte - b'2') + 26),
        _ => Err(TotpError::InvalidSecret("unexpected character".to_string())),
    }
}

/// RFC 4648 base32 decode. Accepts lowercase and trailing `=` padding.
pub fn base32_decode(secret: &str) -> Result<Vec<u8>, TotpError> {
    let upper = secret.trim().to_ascii_uppercase();
    let trimmed = upper.trim_end_matches('=');
    if trimmed.is_empty() {
        return Err(TotpError::InvalidSecret("empty secret".to_string()));
    }
    let mut out = Vec::with_capacity(trimmed.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for byte in trimmed.bytes() {
        buf = (buf << 5) | b32_value(byte)?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    if bits > 0 && buf != 0 {
        return Err(TotpError::InvalidSecret(
            "non-zero trailing bits".to_string(),
        ));
    }
    if out.is_empty() {
        return Err(TotpError::InvalidSecret("empty secret".to_string()));
    }
    Ok(out)
}

/// Compute the 6-digit code for an explicit counter value.
pub fn totp_code(secret: &[u8], counter: u64) -> Result<String, TotpError> {
    if secret.is_empty() {
        return Err(TotpError::InvalidSecret("empty secret".to_string()));
    }
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(secret)
        .map_err(|e| TotpError::InvalidSecret(e.to_string()))?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]) % TOTP_MOD;
    Ok(format!("{binary:06}"))
}

/// The code must be exactly 6 ASCII digits.
pub fn validate_code_format(code: &str) -> Result<(), TotpError> {
    if code.len() == TOTP_DIGITS && code.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(TotpError::InvalidCode)
    }
}

/// Verify a code against `now_unix_secs`, accepting counters
/// `now/30 - 1`, `now/30`, `now/30 + 1`. Comparison is constant-time.
///
/// Returns the exact step counter that matched (`Ok(Some(counter))`) or
/// `Ok(None)` when no candidate matches. Callers that must prevent replaying
/// a code within its `±1` window use this counter to persist the consumed step.
pub fn verify_totp_counter(
    secret: &[u8],
    code: &str,
    now_unix_secs: u64,
) -> Result<Option<u64>, TotpError> {
    validate_code_format(code)?;
    let center = (now_unix_secs / TOTP_PERIOD_SECS) as i64;
    for drift in -TOTP_WINDOW..=TOTP_WINDOW {
        let counter = center + drift;
        if counter < 0 {
            continue;
        }
        let candidate = totp_code(secret, counter as u64)?;
        if bool::from(candidate.as_bytes().ct_eq(code.as_bytes())) {
            return Ok(Some(counter as u64));
        }
    }
    Ok(None)
}

/// Verify a code against `now_unix_secs`, accepting counters
/// `now/30 - 1`, `now/30`, `now/30 + 1`. Comparison is constant-time.
///
/// Stateless boolean wrapper over [`verify_totp_counter`]; call sites that
/// must refuse a replay store the returned counter instead.
pub fn verify_totp(secret: &[u8], code: &str, now_unix_secs: u64) -> Result<bool, TotpError> {
    Ok(verify_totp_counter(secret, code, now_unix_secs)?.is_some())
}

/// Current Unix time in seconds (clock skew tolerated via the ±1 window).
///
/// Delegates to [`crate::db::now_unix_secs`], the canonical implementation.
pub fn now_unix_secs() -> u64 {
    crate::db::now_unix_secs()
}

/// `otpauth://` URI for QR provisioning.
pub fn provisioning_uri(account: &str, issuer: &str, secret_b32: &str) -> String {
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
    let account = utf8_percent_encode(account, NON_ALPHANUMERIC);
    let issuer = utf8_percent_encode(issuer, NON_ALPHANUMERIC);
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret_b32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4226 Appendix D secret.
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc4226_vectors_truncated_to_6_digits() -> Result<(), String> {
        // Counter 0 -> HOTP 755224; counter 1 -> HOTP 287082
        // (RFC 6238 8-digit vectors 84755224 / 94287082 mod 10^6).
        assert_eq!(
            totp_code(RFC_SECRET, 0).map_err(|e| e.to_string())?,
            "755224"
        );
        assert_eq!(
            totp_code(RFC_SECRET, 1).map_err(|e| e.to_string())?,
            "287082"
        );
        Ok(())
    }

    #[test]
    fn window_accepts_pm1_step() -> Result<(), String> {
        // t=59 -> counter 1.
        assert!(verify_totp(RFC_SECRET, "287082", 59).map_err(|e| e.to_string())?);
        // t=89 -> counter 2, window covers counter 1.
        assert!(verify_totp(RFC_SECRET, "287082", 89).map_err(|e| e.to_string())?);
        // t=120 -> counter 4, counter 1 out of window.
        assert!(!verify_totp(RFC_SECRET, "287082", 120).map_err(|e| e.to_string())?);
        // Wrong code never matches.
        assert!(!verify_totp(RFC_SECRET, "000000", 59).map_err(|e| e.to_string())?);
        Ok(())
    }

    /// `verify_totp_counter` reports the exact matched step and stays
    /// consistent with the boolean [`verify_totp`] wrapper.
    #[test]
    fn verify_counter_reports_matched_step() -> Result<(), String> {
        // t=59 -> counter 1 exactly.
        assert_eq!(
            verify_totp_counter(RFC_SECRET, "287082", 59).map_err(|e| e.to_string())?,
            Some(1)
        );
        // t=89 -> code of counter 1 is still inside the window.
        assert_eq!(
            verify_totp_counter(RFC_SECRET, "287082", 89).map_err(|e| e.to_string())?,
            Some(1)
        );
        // t=120 -> out of window.
        assert_eq!(
            verify_totp_counter(RFC_SECRET, "287082", 120).map_err(|e| e.to_string())?,
            None
        );
        // Wrong shape/code is never a match.
        assert_eq!(
            verify_totp_counter(RFC_SECRET, "000000", 59).map_err(|e| e.to_string())?,
            None
        );
        assert!(verify_totp_counter(RFC_SECRET, "12", 59).is_err());
        Ok(())
    }

    #[test]
    fn malformed_codes_rejected() {
        assert!(validate_code_format("12345").is_err());
        assert!(validate_code_format("1234567").is_err());
        assert!(validate_code_format("12345a").is_err());
        assert!(validate_code_format("").is_err());
        assert!(validate_code_format("123456").is_ok());
    }

    #[test]
    fn base32_roundtrip() -> Result<(), String> {
        let encoded = base32_encode(RFC_SECRET);
        assert_eq!(encoded, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(
            base32_decode(&encoded).map_err(|e| e.to_string())?,
            RFC_SECRET
        );
        assert_eq!(
            base32_decode("gezdgnbvgy3tqojqgezdgnbvgy3tqojq====").map_err(|e| e.to_string())?,
            RFC_SECRET
        );
        assert!(base32_decode("!!!!").is_err());
        assert!(base32_decode("").is_err());
        Ok(())
    }

    #[test]
    fn generated_secret_has_expected_shape() -> Result<(), String> {
        let secret = generate_secret().map_err(|e| e.to_string())?;
        assert_eq!(secret.len(), TOTP_SECRET_LEN);
        assert_eq!(base32_encode(&secret).len(), 32);
        Ok(())
    }
}
