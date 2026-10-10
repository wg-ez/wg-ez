#![forbid(unsafe_code)]

//! `GET /api/status/stream`: htmx long-poll that drives live grid refreshes
//! and the live topbar peer count.
//!
//! The handler holds the request open until the shared watcher
//! ([`crate::web::watcher`]) observes a live-status change, or until
//! [`LONG_POLL`] elapses, then answers `200` with the current connected-peer
//! count as its body plus a `HX-Trigger` payload:
//!
//! - change: `{"refreshGridLive": true, "pollAgain": true}` — the grid
//!   re-renders at once and the watcher element re-arms;
//! - timeout: `{"pollAgain": true}` — only the watcher re-arms.
//!
//! The body is swapped into the topbar count element (`hx-swap="innerHTML"`),
//! so it always carries the count, including on timeout. The endpoint never
//! touches the DB nor renders a template: the grid refresh stays on `GET /`,
//! triggered by the same `refreshGridLive` event the page already understood.
//! It only waits on a `watch` receiver, so parked requests cost nothing. A
//! dead session answers `401` + `HX-Redirect` like the UI pages, so htmx
//! navigates instead of looping on an error toast. Concurrent parked
//! subscriptions are capped (global + per-IP); over the cap the handler
//! answers `429` without holding the connection (M5).

use std::time::Duration;

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use serde_json::json;

use crate::web::{
    ctx::{AppState, Backend, WebError},
    guards::authenticate,
    handlers::ui::chrome::login_redirect,
};

/// Upper bound before the client re-arms (kept below common proxy timeouts).
pub const LONG_POLL: Duration = Duration::from_secs(25);

pub async fn stream<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Response, WebError> {
    let ip = super::client_ip(&state, addr, &headers);
    if authenticate(&state, &jar, &headers, Some(ip))
        .await
        .is_err()
    {
        return Ok(login_redirect(&headers, &[]));
    }
    // Bound concurrent parked long-polls (M5): once the global or per-IP cap
    // is reached, refuse with 429 instead of holding the connection open.
    let Some(mut sub) = state.watcher.subscribe(ip) else {
        return Err(WebError::rate_limited("too many status streams"));
    };
    let changed = matches!(
        tokio::time::timeout(LONG_POLL, sub.changed()).await,
        Ok(Ok(()))
    );
    // The topbar element swaps this body (`hx-swap="innerHTML"`), so it must
    // always carry the CURRENT count — including on timeout, or the count
    // would blank every 25 s.
    let trigger = if changed {
        json!({ "refreshGridLive": true, "pollAgain": true })
    } else {
        json!({ "pollAgain": true })
    };
    let mut resp = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        sub.connected().to_string(),
    )
        .into_response();
    if let Ok(value) = trigger.to_string().parse() {
        resp.headers_mut().insert("hx-trigger", value);
    }
    Ok(resp)
}
