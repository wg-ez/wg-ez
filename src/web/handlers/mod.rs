#![forbid(unsafe_code)]

//! HTTP handlers, one module per domain.
//!
//! Effect rule: every client/admin POST|DELETE calls
//! `Backend::apply_tunnel` (full `Tunnel::apply`) **except**
//! `POST /api/client/:id/generateOneTimeLink`. The single place this is
//! allowed to be skipped is [`client::generate_otl`].

use axum::http::HeaderMap;
use axum::response::IntoResponse;

use super::ctx::{AppState, Backend, ClientView, WebError};

/// Client IP for rate limiting: the direct peer unless it is a trusted proxy,
/// in which case `X-Forwarded-For` is walked right-to-left. Single
/// implementation shared by the auth / metrics / cnf handlers
/// (`AppState::client_ip`).
pub(crate) fn client_ip<B: Backend>(
    state: &AppState<B>,
    addr: std::net::SocketAddr,
    headers: &HeaderMap,
) -> std::net::IpAddr {
    let fwd = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    state.client_ip(Some(addr.ip()), fwd).unwrap_or(addr.ip())
}

/// Refuse (429) an authenticated tunnel mutation once the origin IP has
/// exceeded the generous [`super::ctx::RateLimits::check_mutation`] bound
/// (120/min/IP).
///
/// Called as the first statement of every handler whose effect runs a full
/// `Tunnel::apply` (client/admin POST|DELETE); the OTL generation is the one
/// mutation deliberately **not** covered because it has no kernel effect.
pub(crate) async fn check_mutation_limit<B: Backend>(
    state: &AppState<B>,
    addr: std::net::SocketAddr,
    headers: &HeaderMap,
) -> Result<(), WebError> {
    let ip = client_ip(state, addr, headers);
    if !state.limits.check_mutation(ip).await {
        return Err(WebError::rate_limited("too many mutations"));
    }
    Ok(())
}

/// Sanitize a `.conf` download basename: keep `[A-Za-z0-9._-]`, fold anything
/// else to `_`, force the `.conf` suffix and cap the result at 32 bytes.
/// Shared by the authenticated download (`client`) and the public one-time
/// link (`cnf`).
pub(crate) fn sanitize_conf_filename(name: &mut String) {
    let clean: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let clean = clean.trim_matches('.').to_owned();
    let mut out = if clean.is_empty() {
        "client.conf".to_owned()
    } else {
        clean
    };
    if !out.ends_with(".conf") {
        out.push_str(".conf");
    }
    if out.len() > 32 {
        let keep = 32 - ".conf".len();
        out = format!("{}{}", &out[..keep], ".conf");
    }
    *name = out;
}

/// Downloadable `.conf` response (name already sanitized). Shared by the
/// authenticated download (`client::configuration`) and the public one-time
/// link (`cnf::download`); headers are kept byte-for-byte identical.
///
/// `Cache-Control: no-store` is set explicitly (defense in depth, I7): this
/// body contains the client private key, so it must never be written to a
/// browser or proxy cache even if the global middleware were bypassed.
pub(crate) fn conf_attachment(name: &str, conf: String) -> axum::response::Response {
    (
        [
            (
                "content-type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            ),
            (
                "content-disposition".to_string(),
                format!("attachment; filename=\"{name}\""),
            ),
            ("cache-control".to_string(), "no-store".to_string()),
        ],
        conf,
    )
        .into_response()
}

/// Shared client listing pipeline for the JSON API (`client::list`) and the
/// UI grid (`ui::cards::load_cards`): ownership scoping, name substring
/// filter then sort.
///
/// `owner` is `(user_id, is_admin)`: an ADMIN keeps every row, a CLIENT keeps
/// only its own, and `None` (no principal) clears the list. `filter` is a
/// case-insensitive substring match on the name. `sort` accepts
/// `-name` (desc), `created` (oldest first), `-created` (newest first) and
/// falls back to `name` ascending for anything else. `created_at` is an
/// RFC 3339 UTC string, so lexicographic order is chronological order.
pub(crate) fn filter_and_sort_clients(
    clients: &mut Vec<ClientView>,
    owner: Option<(i64, bool)>,
    filter: Option<&str>,
    sort: Option<&str>,
) {
    match owner {
        Some((uid, is_admin)) => {
            if !is_admin {
                clients.retain(|c| c.user_id == uid);
            }
        }
        None => clients.clear(),
    }
    if let Some(f) = filter {
        // Filtre substring : ignore un filtre portant des contrôles ou une
        // clé de pollution prototype au lieu de le chercher tel quel.
        if crate::validate::check_plain_string(f).is_ok() {
            let needle = f.to_lowercase();
            clients.retain(|c| c.name.to_lowercase().contains(&needle));
        }
    }
    if sort == Some("-name") {
        clients.sort_by_key(|a| std::cmp::Reverse(a.name.to_lowercase()));
    } else if sort == Some("created") {
        // Plus anciens d'abord (date de CREATION, jamais updatedAt).
        clients.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    } else if sort == Some("-created") {
        // Plus recents d'abord.
        clients.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    } else {
        clients.sort_by_key(|a| a.name.to_lowercase());
    }
}

pub mod admin;
pub mod api_tokens;
pub mod auth;
pub mod client;
pub mod cnf;
pub mod information;
pub mod metrics;
pub mod session;
pub mod setup;
pub mod status;
pub mod ui;
