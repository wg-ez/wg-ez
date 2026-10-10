#![forbid(unsafe_code)]

//! Route tables: `/api/*` plus public `/cnf`, `/metrics` and UI pages.

use axum::{
    Router,
    extract::{DefaultBodyLimit, Request},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use tower_http::trace::TraceLayer;

use super::middleware::{csrf_guard, security_headers, setup_guard};
use crate::web::{
    ctx::{AppState, Backend},
    handlers::{admin, auth, client, cnf, information, metrics, session, setup, status, ui},
};

/// Maximum request body size, applied uniformly to every route through
/// [`DefaultBodyLimit`] (M12).
///
/// Legitimate bodies are a few hundred bytes (patches, login, setup), so
/// 1 MiB leaves ample headroom while halving axum's 2 MiB default — which
/// matters on the single-thread runtime where the whole body is buffered in
/// memory. Over-limit bodies get `413 Payload Too Large`.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Collapse duplicate slashes and trim a trailing slash (except root) via
/// `308 Permanent Redirect`, so `/api//information` and `/api/information/`
/// reach the canonical handler. An internal rewrite does not work because
/// route matching happens before outer axum middleware observes the mutated
/// URI.
///
/// Note: `http::Uri` parses a leading `//` as an authority
/// (`//api//information` -> authority `api`, path `//information`), so the
/// raw target is reconstructed first when there is an authority but no
/// scheme (origin-form can never carry an authority otherwise).
async fn normalize_path(req: Request, next: middleware::Next) -> Response {
    let uri = req.uri().clone();
    let raw = if uri.scheme().is_none() {
        match uri.authority() {
            Some(auth) => format!("//{auth}{}", uri.path()),
            None => uri.path().to_owned(),
        }
    } else {
        uri.path().to_owned()
    };
    let mut norm = String::with_capacity(raw.len());
    let mut prev_slash = false;
    for c in raw.chars() {
        if c == '/' {
            if prev_slash {
                continue;
            }
            prev_slash = true;
        } else {
            prev_slash = false;
        }
        norm.push(c);
    }
    if norm.len() > 1 && norm.ends_with('/') {
        norm.pop();
    }
    if norm == raw {
        return next.run(req).await.into_response();
    }
    // API-style paths are strict like v15 (trailing slash -> 404, never a
    // redirect); only `//` doubling still redirects to the canonical form.
    // UI pages keep the trailing-slash redirect (UX + audit O section).
    let trailing_only = !raw.contains("//");
    if trailing_only
        && (raw.starts_with("/api/")
            || raw == "/api"
            || raw.starts_with("/metrics/")
            || raw == "/metrics"
            || raw.starts_with("/cnf/"))
    {
        return next.run(req).await.into_response();
    }
    let loc = match uri.query() {
        Some(q) => format!("{norm}?{q}"),
        None => norm,
    };
    (
        axum::http::StatusCode::PERMANENT_REDIRECT,
        [(axum::http::header::LOCATION, loc)],
        "",
    )
        .into_response()
}

fn api_routes<B: Backend>() -> Router<AppState<B>> {
    Router::new()
        .route("/information", get(information::information))
        .route("/status/stream", get(status::stream))
        .route("/auth/methods", get(auth::methods))
        .route("/auth/password", post(auth::password))
        .route("/auth/pending", get(auth::pending))
        .route("/auth/verify-2fa", post(auth::verify_2fa))
        .route("/auth/cancel", post(auth::cancel))
        .route("/session", get(session::get).delete(session::delete))
        .route("/me", post(session::update_me))
        .route("/me/username", post(session::change_username))
        .route("/me/password", post(session::change_password))
        .route("/me/totp", post(session::totp))
        .route("/client", get(client::list).post(client::create))
        .route(
            "/client/{id}",
            get(client::get).post(client::update).delete(client::delete),
        )
        .route("/client/{id}/enable", post(client::enable))
        .route("/client/{id}/disable", post(client::disable))
        .route(
            "/client/{id}/psk",
            post(client::generate_psk).delete(client::remove_psk),
        )
        .route("/client/{id}/rotateKeys", post(client::rotate_keys))
        .route(
            "/client/{id}/generateOneTimeLink",
            post(client::generate_otl),
        )
        .route("/client/{id}/configuration", get(client::configuration))
        .route("/client/{id}/qrcode.svg", get(client::qrcode))
        .route(
            "/admin/general",
            get(admin::get_general).post(admin::set_general),
        )
        .route("/admin/hooks", get(admin::get_hooks).post(admin::set_hooks))
        .route(
            "/admin/interface",
            get(admin::get_interface).post(admin::set_interface),
        )
        .route(
            "/admin/userconfig",
            get(admin::get_userconfig).post(admin::set_userconfig),
        )
        .route("/admin/interface/cidr", post(admin::change_cidr))
        .route("/admin/interface/restart", post(admin::restart))
        .route("/admin/ip-info", get(admin::ip_info))
        .route("/setup/2", post(setup::step2))
        .route("/setup/3", get(setup::suggest).post(setup::step3))
}

/// Full application router (API + public `/cnf`, `/metrics` + UI pages).
/// Returns a plain `Router` so `main.rs` can serve it directly with
/// `axum::serve` (which injects `ConnectInfo`); path normalization is an
/// internal middleware, usable with `oneshot` in tests.
pub fn build_router<B: Backend>(state: AppState<B>) -> Router {
    Router::new()
        .nest("/api", api_routes())
        .route("/cnf/{token}", get(cnf::download))
        .route("/metrics/prometheus", get(metrics::prometheus))
        .route("/metrics/json", get(metrics::json))
        .route("/", get(ui::index))
        .route("/clients/{id}", get(ui::client_detail))
        .route("/me", get(ui::me))
        .route("/login", get(ui::login))
        .route("/login/2fa", get(ui::login_2fa))
        .route("/admin", get(ui::admin_page))
        // Alias historiques : l'admin est une page unique, plus d'onglets.
        .route("/admin/general", get(ui::admin_page))
        .route("/admin/config", get(ui::admin_page))
        .route("/admin/interface", get(ui::admin_page))
        .route("/admin/hooks", get(ui::admin_page))
        .route("/setup/1", get(ui::setup1))
        .route("/setup/2", get(ui::setup2))
        .route("/setup/3", get(ui::setup3))
        .route("/setup", get(ui::setup1))
        .route("/static/{*path}", get(ui::static_file))
        .fallback(ui::not_found)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(normalize_path))
        .layer(middleware::from_fn_with_state(state.clone(), setup_guard))
        .layer(middleware::from_fn(csrf_guard))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request| {
                // Never record `uri`: `/cnf/<token>` carries a one-time secret.
                // Only the method is kept (span level DEBUG, subscriber INFO,
                // so nothing is emitted by default).
                tracing::debug_span!("http", method = %request.method())
            }),
        )
        .with_state(state)
}
