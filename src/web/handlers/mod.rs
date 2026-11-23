#![forbid(unsafe_code)]

//! HTTP handlers, one module per domain.
//!
//! Effect rule: every client/admin POST|DELETE calls
//! `Backend::apply_tunnel` (full `Tunnel::apply`) **except**
//! `POST /api/client/:id/generateOneTimeLink`. The single place this is
//! allowed to be skipped is [`client::generate_otl`].

use axum::http::{HeaderMap, header};
use axum::response::IntoResponse;

use super::ctx::{AppState, Backend, ClientView, WebError};

/// Scheme the browser used for this request, read from the request metadata
/// the browser itself controls: `Origin` on fetch/form mutations, `Referer`
/// as a fallback. `None` when neither is present or the origin is opaque
/// (`Origin: null`).
///
/// This is deliberately *not* `X-Forwarded-Proto`: TLS terminates at the
/// reverse proxy, so the browser-visible scheme is the one that decides
/// whether the browser will accept a `Secure` cookie, and `Origin` is set by
/// the browser (page JS cannot forge it).
fn browser_https(headers: &HeaderMap) -> Option<bool> {
    fn parse(value: &str) -> Option<bool> {
        let value = value.trim();
        if value.len() >= 8 && value[..8].eq_ignore_ascii_case("https://") {
            Some(true)
        } else if value.len() >= 7 && value[..7].eq_ignore_ascii_case("http://") {
            Some(false)
        } else {
            None
        }
    }
    [header::ORIGIN, header::REFERER]
        .iter()
        .find_map(|name| headers.get(name)?.to_str().ok().and_then(parse))
}

/// `Secure` flag for the session and pending-2FA cookies.
///
/// The flag follows the scheme the browser reports: dropping `Secure` when it
/// says `http://` is what makes login/setup work on plain HTTP, while an HTTPS
/// browser (direct or behind a reverse proxy) keeps the flag. Unknown scheme
/// keeps `Secure`, so a client that sends neither `Origin` nor `Referer`
/// cannot downgrade a real HTTPS deployment.
pub(crate) fn cookie_secure(headers: &HeaderMap) -> bool {
    browser_https(headers) != Some(false)
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
) -> Result<(), WebError> {
    if !state.limits.check_mutation(addr.ip()).await {
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
