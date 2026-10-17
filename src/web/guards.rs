#![forbid(unsafe_code)]

//! Auth guards: session cookie / API-token Bearer + permission checks.
//!
//! - Auth source: `wg-ez` session cookie (via `axum-extra` `CookieJar`), or
//!   `Authorization: Bearer` `<api-token>` (long-lived token created under
//!   `/api/me/tokens`; only its SHA-256 hex is stored). There is no password
//!   fallback on API routes: automation must use explicit revocable Bearer
//!   tokens (list/revoke under `/api/me/tokens`), never `user:pass`.
//!   Bearer tokens stay valid on 2FA accounts (documented in `docs/api.md`).
//!   Unknown Bearer tokens answer `401` with the same seclog (no oracle).
//! - Bearer **failures** share the 10/min/IP throttle (successes are never
//!   counted: the token rides on every API request and a polling client
//!   must not be throttled). At the limit the request is refused `429` before
//!   any DB lookup. The clear Bearer token is never logged.
//! - The `Bearer` scheme is case-insensitive (RFC 6750 §2.1); the credential
//!   itself is trimmed and length-capped before hashing.
//! - Permissions: `clients.view|update|create|delete|custom`, `admin.any`,
//!   `me.update`. ADMIN has everything; CLIENT is scoped to its own
//!   clients/profile. Unknown permission strings -> 500 (anti-forget rule).
//! - Handlers resolve the principal with [`authenticate`] then call
//!   [`check`]; tests exercise the guards through the real axum router,
//!   never by calling handlers directly.
//!
//! NOTE: the cookie name and SHA-256 token hashing must stay aligned with the
//! canonical `auth::session` module. [`hash_token`] delegates to it directly,
//! so only `SESSION_COOKIE`/`PENDING_COOKIE` can drift.

use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{HeaderMap, header, request::Parts},
};
use axum_extra::extract::CookieJar;

use super::ctx::{AppState, Backend, Principal, WebError};

/// Session cookie name.
pub const SESSION_COOKIE: &str = "wg-ez";
/// Pending-2FA opaque id cookie name (id only, secret stays server-side).
pub const PENDING_COOKIE: &str = "wg-ez-pending";
/// Language + theme cookies (non-sensitive UI prefs).
pub const LANG_COOKIE: &str = "lang";
pub const THEME_COOKIE: &str = "theme";

/// SHA-256 hex of the clear session token (the only form stored in DB).
/// Delegates to `auth::session::sha256_hex` so the login/session code and
/// this guard can never diverge.
pub fn hash_token(token: &str) -> String {
    crate::auth::session::sha256_hex(token.as_bytes())
}

/// Bearer credential from `Authorization: <scheme> <token>`. The scheme is
/// case-insensitive (RFC 6750 §2.1 : `Bearer`, `bearer`, …) ; returns the
/// trimmed, non-empty token. The caller hashes it before lookup and never
/// logs it. Shared with the metrics guard so both Bearer parsers accept the
/// same shapes.
pub(crate) fn bearer_credential(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = raw.split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_owned())
}

/// Resolve the request principal: session cookie first, then Bearer API
/// token. Missing/invalid credentials -> 401; backend failure -> 500.
///
/// `ip` is the trusted-proxy-aware client IP used to throttle Bearer
/// credential failures. It is optional so a caller without `ConnectInfo`
/// (e.g. a direct unit call) **fails open** — no throttling — instead of
/// refusing a legitimate request.
pub async fn authenticate<B: Backend>(
    state: &AppState<B>,
    jar: &CookieJar,
    headers: &HeaderMap,
    ip: Option<IpAddr>,
) -> Result<Principal, WebError> {
    // 1. Session cookie.
    if let Some(token) = jar.get(SESSION_COOKIE).map(|c| c.value().to_owned()) {
        if token.len() > 512 {
            return Err(WebError::unauthorized("bad session"));
        }
        let hash = hash_token(&token);
        match state.backend.lookup_session(&hash).await {
            Ok(Some(user)) => {
                return Ok(Principal {
                    user_id: user.id,
                    username: user.username,
                    role: user.role,
                    totp_verified: user.totp_verified,
                });
            }
            Ok(None) => return Err(WebError::unauthorized("session expired")),
            Err(e) => return Err(e),
        }
    }
    // 2. Bearer API-token fallback (explicit revocable credential: valid
    // even on 2FA accounts). Failures share the 10/min/IP credential bucket
    // (failures only) so a Bearer flood cannot bypass the DB guard. The
    // clear token is never logged.
    if let Some(token) = bearer_credential(headers) {
        if token.len() > 512 {
            return Err(WebError::unauthorized("bad token"));
        }
        if let Some(ip) = ip
            && !state.limits.check_credential(ip).await
        {
            return Err(WebError::rate_limited("too many credential failures"));
        }
        match state.backend.auth_api_token(&hash_token(&token)).await {
            Ok(Some(u)) => Ok(Principal {
                user_id: u.id,
                username: u.username,
                role: u.role,
                totp_verified: false,
            }),
            // Unknown / revoked / expired / disabled token: 401 + seclog,
            // so Bearer cannot probe token validity.
            Ok(None) => {
                if let Some(ip) = ip {
                    state.limits.record_credential_failure(ip).await;
                }
                Err(WebError::unauthorized("bad token").with_seclog("password"))
            }
            Err(e) => Err(e),
        }
    } else {
        Err(WebError::unauthorized("authentication required"))
    }
}

/// Permission check. Returns `Ok(())` when granted, 403 when the role is
/// insufficient, and **500 for unknown permission names** so a typo or a
/// forgotten check can never silently open a route.
pub fn check(
    auth: &Principal,
    permission: &str,
    owner_user_id: Option<i64>,
) -> Result<(), WebError> {
    const KNOWN: [&str; 7] = [
        "clients.view",
        "clients.update",
        "clients.create",
        "clients.delete",
        "clients.custom",
        "admin.any",
        "me.update",
    ];
    if !KNOWN.contains(&permission) {
        return Err(WebError::missing_check());
    }
    if auth.is_admin() {
        return Ok(());
    }
    match permission {
        // CLIENT scope: own clients (`clients.*`) / own profile (`me.update`) only.
        "clients.view" | "clients.update" | "clients.delete" | "clients.custom" | "me.update" => {
            match owner_user_id {
                Some(id) if id == auth.user_id => Ok(()),
                _ => Err(WebError::forbidden("insufficient role")),
            }
        }
        // `clients.create` and `admin.any` are ADMIN-only.
        _ => Err(WebError::forbidden("insufficient role")),
    }
}

/// Axum extractor resolving the principal from the session cookie or
/// Bearer API token. Declared BEFORE any body extractor it guarantees
/// "unauthenticated -> 401" even with a missing/malformed body, because
/// axum extracts all `FromRequestParts` before the single `FromRequest`.
pub struct Auth(pub Principal);

impl<B: Backend> FromRequestParts<AppState<B>> for Auth {
    type Rejection = WebError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState<B>,
    ) -> Result<Self, Self::Rejection> {
        // Direct peer (injected by `into_make_service_with_connect_info`)
        // resolved through the trusted-proxy chain. Missing `ConnectInfo`
        // (e.g. a direct unit call) fails open: no credential throttling.
        let direct = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0);
        let ip = direct.map(|addr| super::handlers::client_ip(state, addr, &parts.headers));
        let jar = CookieJar::from_request_parts(parts, state)
            .await
            .map_err(|_| WebError::unauthorized("authentication required"))?;
        Ok(Auth(authenticate(state, &jar, &parts.headers, ip).await?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin() -> Principal {
        Principal {
            user_id: 1,
            username: "admin".into(),
            role: 1,
            totp_verified: false,
        }
    }

    fn client() -> Principal {
        Principal {
            user_id: 7,
            username: "bob".into(),
            role: 2,
            totp_verified: false,
        }
    }

    #[test]
    fn admin_has_everything() {
        for p in [
            "clients.view",
            "clients.update",
            "clients.create",
            "clients.delete",
            "clients.custom",
            "admin.any",
            "me.update",
        ] {
            assert!(check(&admin(), p, None).is_ok(), "{p}");
        }
    }

    #[test]
    fn client_scoped_to_own() {
        assert!(check(&client(), "clients.view", Some(7)).is_ok());
        assert!(check(&client(), "clients.view", Some(8)).is_err());
        assert!(check(&client(), "clients.create", Some(7)).is_err());
        assert!(check(&client(), "admin.any", Some(7)).is_err());
        assert!(check(&client(), "me.update", Some(7)).is_ok());
        assert!(check(&client(), "me.update", Some(1)).is_err());
    }

    #[test]
    fn unknown_permission_is_500() {
        use axum::http::StatusCode;
        let e = check(&admin(), "clients.destroy", None).unwrap_err();
        assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let e2 = check(&admin(), "", None).unwrap_err();
        assert_eq!(e2.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// `Authorization` scheme parsing: `Bearer` case-insensitive, exactly one
    /// whitespace run separating scheme and credential, credential trimmed,
    /// empty credential rejected (fail closed).
    #[test]
    fn bearer_credential_parses_scheme_case_insensitively() {
        fn h(v: &str) -> HeaderMap {
            let mut m = HeaderMap::new();
            m.insert(header::AUTHORIZATION, v.parse().expect("header"));
            m
        }
        for scheme in ["Bearer", "bearer", "BEARER", "bEaReR"] {
            assert_eq!(
                bearer_credential(&h(&format!("{scheme} abc123"))).as_deref(),
                Some("abc123"),
                "schéma {scheme}"
            );
            // Tabs / multiple spaces before the credential are trimmed.
            assert_eq!(
                bearer_credential(&h(&format!("{scheme}\t  abc123  "))).as_deref(),
                Some("abc123")
            );
        }
        // Wrong scheme, missing scheme, or empty credential -> None.
        for value in ["Token abc123", "abc123", "Bearer", "Bearer   ", ""] {
            assert!(
                bearer_credential(&h(value)).is_none(),
                "`{value}` doit être refusé"
            );
        }
        // Missing header entirely.
        assert!(bearer_credential(&HeaderMap::new()).is_none());
    }
}
