#![forbid(unsafe_code)]

//! Setup wizard API. Valid ONLY during setup, per step
//! (verified against v15 `defineSetupEventHandler`: step 2 lives at
//! `setupStep = 1`, step 3 at `setupStep = 3`).
//!
//! Bodies accept JSON or urlencoded ([`JsonOrForm`]); htmx callers navigate
//! via `HX-Redirect` to the next step.
//!
//! - `POST /api/setup/2` creates the admin (12+ chars), advances to step 3
//!   and **mints the admin session cookie** on the same response so the
//!   wizard's browser is authenticated for the endpoint step. This route
//!   stays open (bootstrap) when `setupStep == 1`: there is no session to
//!   require yet.
//! - `GET /api/setup/3` suggests public IPs/hostnames.
//! - `POST /api/setup/3` stores host + port, finishes (`setupStep = 0`).
//!
//! I5: after step 2 an admin exists, so the endpoint step must run
//! authenticated: [`Auth`] + [`check`]`("admin.any")` on top of
//! [`require_setup`]. The unauthenticated caller gets 401 and a non-admin
//! 403, even if the step is otherwise valid. (Because the `Auth` extractor
//! runs before the handler body, an unauthenticated call answers 401
//! regardless of the step.)
//!
//! Residual accepted risk: step 2 itself is "trust on first use".
//! On an already-reachable unconfigured instance, anyone can claim the first
//! admin. The mitigation is operational — do not expose the instance before
//! setup finishes. This is NOT fixed in-process (no local-bind token).
//!
//! Rate limit: 20/min/IP on `/api/setup/*` -> 429.

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Json, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::setup::{RequestedSetupStep, check_setup_step};
use crate::web::ctx::{AppState, Backend, JsonOrForm, WebError, with_hx};
use crate::web::guards::{Auth, check};

/// v15 `ValidSetupSteps`: `{ 1: [2], 3: [3] }`. Anything else (finished
/// setup `0`, or the wrong step) answers 400 like v15.
///
/// Delegates to [`check_setup_step`] (single source of truth); every
/// [`SetupError`](crate::setup::SetupError) collapses to the same 400.
async fn require_setup<B: Backend>(state: &AppState<B>, step: i64) -> Result<(), WebError> {
    let at = state.backend.setup_step().await?;
    let requested = match step {
        2 => RequestedSetupStep::Step2,
        3 => RequestedSetupStep::Step3,
        _ => return Err(WebError::bad_request("invalid setup step")),
    };
    check_setup_step(at, requested).map_err(|_| WebError::bad_request("invalid setup step"))
}

/// `wg-ez` `Set-Cookie` value for a freshly minted session (always a
/// browser-session cookie, `secure = !INSECURE`). Reuses the canonical
/// [`crate::auth::session::build_set_cookie`] used by `auth::password`.
fn session_cookie(token: &str, insecure: bool) -> String {
    crate::auth::session::build_set_cookie(token, !insecure)
}

#[derive(Debug, Deserialize)]
pub struct AdminBody {
    pub username: String,
    pub password: String,
}

pub async fn step2<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    JsonOrForm(body): JsonOrForm<AdminBody>,
) -> Result<Response, WebError> {
    if !state
        .limits
        .check_setup(super::client_ip(&state, addr, &headers))
        .await
    {
        return Err(WebError::rate_limited("too many setup attempts"));
    }
    require_setup(&state, 2).await?;
    if body.username.trim().len() < 2 {
        return Err(WebError::bad_request("username too short"));
    }
    if body.password.len() < 12 {
        return Err(WebError::bad_request(
            "password must be at least 12 characters",
        ));
    }
    let admin_id = state
        .backend
        .setup_create_admin(body.username.trim(), &body.password)
        .await?;
    // Authenticate the wizard's browser immediately: the endpoint step is
    // admin-gated.
    let token = state.backend.create_session(admin_id).await?;
    let resp = (
        [(
            header::SET_COOKIE,
            session_cookie(&token, state.backend.insecure()),
        )],
        Json(json!({ "ok": true, "step": 3 })),
    )
        .into_response();
    Ok(with_hx(resp, &headers, Some("/setup/3"), None))
}

/// `GET /api/setup/3`: read-only suggestions, admin-gated (`Auth` runs
/// before [`require_setup`], so an anonymous call answers 401).
pub async fn suggest<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    auth: Auth,
    headers: HeaderMap,
) -> Result<Json<Value>, WebError> {
    if !state
        .limits
        .check_setup(super::client_ip(&state, addr, &headers))
        .await
    {
        return Err(WebError::rate_limited("too many setup attempts"));
    }
    require_setup(&state, 3).await?;
    check(&auth.0, "admin.any", None)?;
    Ok(Json(state.backend.setup_suggest().await?))
}

#[derive(Debug, Deserialize)]
pub struct HostBody {
    pub host: String,
    pub port: u16,
}

/// `POST /api/setup/3`: admin-gated (I5). An unauthenticated caller is
/// rejected by the [`Auth`] extractor with 401 before the body is even read;
/// a non-admin gets 403 from [`check`].
pub async fn step3<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    auth: Auth,
    headers: HeaderMap,
    JsonOrForm(body): JsonOrForm<HostBody>,
) -> Result<Response, WebError> {
    if !state
        .limits
        .check_setup(super::client_ip(&state, addr, &headers))
        .await
    {
        return Err(WebError::rate_limited("too many setup attempts"));
    }
    require_setup(&state, 3).await?;
    check(&auth.0, "admin.any", None)?;
    if body.host.trim().is_empty() || body.host.len() > 253 {
        return Err(WebError::bad_request("bad host"));
    }
    state
        .backend
        .setup_set_host(body.host.trim(), body.port)
        .await?;
    Ok(with_hx(
        Json(json!({ "ok": true, "step": 0 })).into_response(),
        &headers,
        Some("/"),
        None,
    ))
}
