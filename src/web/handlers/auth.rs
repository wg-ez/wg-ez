#![forbid(unsafe_code)]

//! Public auth routes.
//!
//! Bodies accept JSON (API) or urlencoded (htmx forms) via [`JsonOrForm`].
//! htmx callers navigate through `HX-Redirect` (`/` on success,
//! `/login/2fa` for 2FA, `/login` after cancel). The 2FA pending id is never
//! placed in the URL: the browser carries it in the `wg-ez-pending` cookie
//! (Path `/api/auth`, HttpOnly), and the JSON body keeps `pending` for API
//! clients (the v15 contract).
//!
//! - `GET /api/auth/methods` -> `{ passwordDisabled, oauthEnabled: false }`.
//! - `POST /api/auth/password`: dummy-hash timing protection lives in the
//!   backend; failures log `Security failure type=password`. A 2FA account
//!   answers `TOTP_REQUIRED` (JSON) with an opaque id for the 5-min
//!   in-memory pending; the id is also set as the `wg-ez-pending` cookie so
//!   the browser flow needs no URL parameter.
//! - `GET /api/auth/pending` checks the pending still exists.
//! - `POST /api/auth/verify-2fa` validates the 6-digit code (`type=2fa`
//!   on failure) and creates the session. The pending is verified **before**
//!   being consumed, so a wrong code is retryable (anti-DoS on a known id);
//!   five wrong codes invalidate it, and a valid code is single-use (no
//!   replay / no second session).
//! - `POST /api/auth/cancel` drops the pending.
//!
//! Rate limit (M1, double bound): `password` requires **both** a fine bucket
//! of 10/min for `(client-IP, username)` and a coarse bucket of 50/min for the
//! client IP across all usernames. `verify-2fa` only runs the coarse IP bucket
//! because the username is not resolved before the pending lookup; the code
//! brute-force is already bounded by the per-pending attempt budget (M2).
//! Session cookie: `wg-ez`, `secure = !INSECURE`, always a
//! browser-session cookie (no `Max-Age`): closing the browser forgets it.

use std::time::{Duration, Instant};

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, header},
    response::{AppendHeaders, IntoResponse, Json, Response},
};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::web::{
    ctx::{
        AppState, Backend, JsonOrForm, LoginOutcome, PendingLogin, WebError, insert_pending,
        with_hx,
    },
    guards::PENDING_COOKIE,
};

/// Opaque 128-bit pending id (base64url, never the secret itself).
///
/// Reuses the OTL token generator so both share a single CSPRNG-backed
/// 128-bit/base64url implementation (`rand::random`).
fn new_pending_id() -> String {
    crate::otl::generate_token()
}

pub async fn methods<B: Backend>(
    State(state): State<AppState<B>>,
) -> Result<Json<Value>, WebError> {
    let allowed = state.backend.password_auth_allowed().await?;
    Ok(Json(
        json!({ "passwordDisabled": !allowed, "oauthEnabled": false }),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordBody {
    pub username: String,
    pub password: String,
}

fn session_cookie(token: &str, insecure: bool) -> String {
    crate::auth::session::build_set_cookie(token, !insecure)
}

/// Pending 2FA login lifetime: the in-memory `PendingLogin` and its cookie
/// expire together.
const PENDING_TTL_SECS: u64 = 300;

/// Pending-2FA cookie: same hardening as the session cookie (`Secure` iff
/// `!INSECURE`), scoped to `/api/auth` and expiring with the pending.
///
/// Shares [`crate::auth::session::build_cookie`] with `build_set_cookie` so the
/// `Secure` flag can never diverge and leak the opaque id over cleartext on an
/// HTTPS deployment (M8).
fn pending_cookie(id: &str, insecure: bool) -> String {
    crate::auth::session::build_cookie(
        PENDING_COOKIE,
        id,
        "/api/auth",
        !insecure,
        Some(PENDING_TTL_SECS),
    )
}

/// `Set-Cookie` that removes the pending-2FA cookie. Same name/`Path`/`Secure`
/// policy as [`pending_cookie`] but `Max-Age=0`, so the opaque id never lingers
/// in the browser once the pending is consumed (`verify-2fa`) or abandoned
/// (`cancel`).
fn clear_pending_cookie(insecure: bool) -> String {
    crate::auth::session::build_cookie(PENDING_COOKIE, "", "/api/auth", !insecure, Some(0))
}

pub async fn password<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    JsonOrForm(body): JsonOrForm<PasswordBody>,
) -> Result<Response, WebError> {
    // M1: two independent bounds. The fine `(IP, username)` bucket means an
    // attacker cannot lock out other accounts from a shared origin; the
    // coarse per-IP bucket bounds spraying across many usernames. Behind an
    // undeclared proxy both keys collapse to the proxy IP (set
    // `TRUSTED_PROXIES` to recover per-client granularity).
    let ip = super::client_ip(&state, addr, &headers);
    if !state.limits.check_login_user(ip, &body.username).await
        || !state.limits.check_login_ip(ip).await
    {
        return Err(WebError::rate_limited("too many login attempts"));
    }
    if body.username.len() > crate::validate::MAX_USERNAME_LEN || body.password.len() > 1024 {
        return Err(WebError::unauthorized("invalid credentials").with_seclog("password"));
    }
    match state
        .backend
        .login_password(&body.username, &body.password)
        .await?
    {
        LoginOutcome::Ok { user: _, token } => {
            let hdr = session_cookie(&token, state.backend.insecure());
            let resp = ([(header::SET_COOKIE, hdr)], Json(json!({ "ok": true }))).into_response();
            Ok(with_hx(resp, &headers, Some("/"), None))
        }
        LoginOutcome::TotpRequired { user_id, username } => {
            let id = new_pending_id();
            {
                let mut map = state.pending.lock().await;
                let now = Instant::now();
                map.retain(|_, p| p.expires_at > now);
                // Strict bound: never let the map outgrow `MAX_PENDING`; the
                // earliest-expiring pending is evicted first (see
                // `insert_pending`).
                insert_pending(
                    &mut map,
                    id.clone(),
                    PendingLogin {
                        user_id,
                        username,
                        expires_at: now + Duration::from_secs(PENDING_TTL_SECS),
                        failed_attempts: 0,
                    },
                );
            }
            let resp = (
                [(
                    header::SET_COOKIE,
                    pending_cookie(&id, state.backend.insecure()),
                )],
                Json(json!({ "totpRequired": true, "pending": id })),
            )
                .into_response();
            // The opaque id travels in the `wg-ez-pending` cookie only, so
            // the browser flow keeps it out of the URL (history, proxy logs,
            // `Referer`). API clients still get it in the JSON body.
            Ok(with_hx(resp, &headers, Some("/login/2fa"), None))
        }
    }
}

pub async fn pending<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<Value>, WebError> {
    // This route is a public pending-id validity oracle: bound it before any
    // lookup with a dedicated per-IP bucket (never the login budget).
    if !state
        .limits
        .check_pending(super::client_ip(&state, addr, &headers))
        .await
    {
        return Err(WebError::rate_limited("too many requests"));
    }
    let Some(i) = pending_id_from(&headers) else {
        return Err(WebError::bad_request("missing pending id"));
    };
    let ok = state
        .pending
        .lock()
        .await
        .get(&i)
        .is_some_and(|p| p.expires_at > Instant::now());
    Ok(Json(json!({ "pending": ok })))
}

pub(crate) fn pending_id_from(headers: &HeaderMap) -> Option<String> {
    // `X-Pending` header (htmx pages) or `wg-ez-pending` cookie.
    if let Some(v) = headers.get("x-pending").and_then(|v| v.to_str().ok())
        && !v.is_empty()
        && v.len() <= 128
    {
        return Some(v.to_owned());
    }
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        if let Some((k, v)) = part.trim().split_once('=')
            && k.trim() == PENDING_COOKIE
            && !v.trim().is_empty()
            && v.trim().len() <= 128
        {
            return Some(v.trim().to_owned());
        }
    }
    None
}

#[derive(Debug, Deserialize)]
pub struct VerifyBody {
    pub code: String,
    // v15 clients send `id`; our own password flow returns `pending`.
    #[serde(default, alias = "id")]
    pub pending: Option<String>,
}

pub async fn verify_2fa<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    JsonOrForm(body): JsonOrForm<VerifyBody>,
) -> Result<Response, WebError> {
    // M1: the username is only resolved *after* the pending lookup, so this
    // route keeps the coarse per-IP bound. Brute-forcing a code is separately
    // capped at `PendingLogin::MAX_FAILED_ATTEMPTS` per pending (M2).
    if !state
        .limits
        .check_login_ip(super::client_ip(&state, addr, &headers))
        .await
    {
        return Err(WebError::rate_limited("too many login attempts"));
    }
    if crate::validate::validate_totp_code(&body.code).is_err() {
        return Err(WebError::bad_request("invalid code").with_seclog("2fa"));
    }
    let id = body
        .pending
        // An empty field (legacy form with no id) is not a pending: fall back
        // to the `X-Pending` header / `wg-ez-pending` cookie.
        .filter(|s| !s.is_empty())
        .or_else(|| pending_id_from(&headers))
        .ok_or_else(|| WebError::unauthorized("no pending login"))?;
    if id.len() != 22 {
        // Opaque 128-bit ids are always 22 base64url chars (`new_pending_id`);
        // anything else is malformed, never "unknown".
        return Err(WebError::bad_request("invalid pending id").with_seclog("2fa"));
    }
    let pend = {
        // Peek without consuming: a wrong code must leave the pending usable
        // for a legitimate retry, and a known pending id must not be a
        // one-shot DoS against the user (M2).
        let mut map = state.pending.lock().await;
        let now = Instant::now();
        match map.get(&id) {
            Some(p) if p.expires_at > now => p.clone(),
            Some(_) => {
                // Expired: drop it (as before) and refuse.
                map.remove(&id);
                return Err(WebError::unauthorized("pending expired"));
            }
            None => return Err(WebError::unauthorized("pending expired")),
        }
    };
    if !state.backend.verify_totp(pend.user_id, &body.code).await? {
        // Wrong code: keep the pending unless the attempt budget is spent.
        let mut map = state.pending.lock().await;
        let exhausted = map
            .get_mut(&id)
            .is_some_and(|p| p.expires_at > Instant::now() && p.register_failure());
        if exhausted {
            map.remove(&id);
        }
        return Err(WebError::unauthorized("invalid code").with_seclog("2fa"));
    }
    // Success: consume atomically **before** minting the session. A concurrent
    // replay of the same valid code finds `None` and is refused, so a valid
    // code is never usable twice.
    let pend = {
        let mut map = state.pending.lock().await;
        match map.remove(&id) {
            Some(p) if p.expires_at > Instant::now() => p,
            _ => return Err(WebError::unauthorized("pending expired")),
        }
    };
    let token = state.backend.create_session(pend.user_id).await?;
    let resp = (
        AppendHeaders([
            (
                header::SET_COOKIE,
                session_cookie(&token, state.backend.insecure()),
            ),
            (
                header::SET_COOKIE,
                clear_pending_cookie(state.backend.insecure()),
            ),
        ]),
        Json(json!({ "ok": true })),
    )
        .into_response();
    Ok(with_hx(resp, &headers, Some("/"), None))
}

pub async fn cancel<B: Backend>(
    State(state): State<AppState<B>>,
    _jar: CookieJar,
    headers: HeaderMap,
) -> Result<Response, WebError> {
    if let Some(id) = pending_id_from(&headers) {
        state.pending.lock().await.remove(&id);
    }
    // Drop the opaque id from the browser too, not just from the map: the
    // cookie must not outlive the pending it names.
    let resp = (
        [(
            header::SET_COOKIE,
            clear_pending_cookie(state.backend.insecure()),
        )],
        Json(json!({ "ok": true })),
    )
        .into_response();
    Ok(with_hx(resp, &headers, Some("/login"), None))
}
