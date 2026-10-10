#![forbid(unsafe_code)]

//! Auth guards: session cookie / Basic Auth + permission checks.
//!
//! - Auth source: `wg-ez` session cookie (via `axum-extra` `CookieJar`)
//!   or `Authorization: Basic` `user:pass` (base64). Basic is refused when
//!   the account has 2FA active (`totpVerified`), so 2FA cannot be bypassed
//!   via API. A wrong password and a correct password on a 2FA account are
//!   answered **identically** (`401` + `Security failure type=password`), so
//!   Basic is never a password-validity oracle.
//! - Basic **failures** are throttled at 10/min/IP (successes are never
//!   counted: Basic rides on every API request and a polling client must not
//!   be throttled). At the limit the request is refused `429` before Argon2.
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
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

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

fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = raw.strip_prefix("Basic ")?;
    let decoded = B64.decode(b64.trim()).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (u, p) = s.split_once(':')?;
    Some((u.to_owned(), p.to_owned()))
}

/// Resolve the request principal: session cookie first, Basic fallback.
/// Missing/invalid credentials -> 401; backend failure -> 500.
///
/// `ip` is the trusted-proxy-aware client IP used to throttle Basic
/// **failures**. It is optional so a caller without `ConnectInfo` (e.g. a
/// direct unit call) **fails open** — no throttling — instead of refusing a
/// legitimate request.
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
    // 2. Basic Auth fallback (refused when 2FA is active on the account).
    if let Some((user, pass)) = basic_credentials(headers) {
        // Pre-check WITHOUT recording: refuse a saturated IP with 429 before
        // paying for Argon2. Successes never count (Basic is sent on every
        // API request), only failures below do.
        if let Some(ip) = ip
            && !state.limits.check_basic(ip).await
        {
            return Err(WebError::rate_limited("too many basic auth failures"));
        }
        match state.backend.login_basic(&user, &pass).await {
            Ok(Some(u)) if !u.totp_verified => Ok(Principal {
                user_id: u.id,
                username: u.username,
                role: u.role,
                totp_verified: false,
            }),
            // Wrong password OR correct password on a 2FA account: the same
            // 401 + seclog, so Basic cannot be used to probe password validity.
            Ok(Some(_)) | Ok(None) => {
                if let Some(ip) = ip {
                    state.limits.record_basic_failure(ip).await;
                }
                Err(WebError::unauthorized("bad credentials").with_seclog("password"))
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
/// Basic Auth. Declared BEFORE any body extractor it guarantees
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
        // (e.g. a direct unit call) fails open: no Basic throttling.
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
}
