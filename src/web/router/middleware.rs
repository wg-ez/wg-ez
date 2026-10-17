#![forbid(unsafe_code)]

//! Router middleware: CSP + hardening headers and the setup guard.

use axum::{
    extract::{Request, State},
    http::{HeaderName, HeaderValue, Method, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::web::ctx::{AppState, Backend, WebError};

/// Security + hardening headers on every response. CSP `script-src 'self'`,
/// zero inline script/style (all JS in `static/js/app.js`), policy from the
/// shared constant in [`crate::validate`].
///
/// Needs the shared state only to read the `INSECURE` flag backing
/// [`Backend::insecure`]: HSTS makes sense only when TLS terminates in front,
/// so it is omitted on plain HTTP (`INSECURE=true`).
///
/// Cache policy (I7): every dynamic response is `no-store` so no proxy or
/// browser can retain an authenticated page, a JSON body or the `.conf`
/// carrying the client private key. The static asset handler sets its own
/// `Cache-Control`, which is left untouched so its `304` revalidation keeps
/// working; `Vary: Cookie` travels with the `no-store`.
pub(crate) async fn security_headers<B: Backend>(
    State(state): State<AppState<B>>,
    req: Request,
    next: Next,
) -> Response {
    let insecure = state.backend.insecure();
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(crate::validate::CONTENT_SECURITY_POLICY),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    // HSTS only when TLS is in play; on plain HTTP it would pin the browser
    // to HTTPS and break the deployment.
    if !insecure {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    // Deny browser features the app never uses (`()` = no origin, so frames
    // cannot re-enable them either).
    h.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), \
             magnetometer=(), microphone=(), payment=(), usb=()",
        ),
    );
    // Cross-origin isolation: no opener leakage and no cross-origin embedding
    // of our responses.
    h.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    // `static_files` already chose a cacheable directive: leave it (and any
    // `304`) untouched. Everything else is dynamic and must never be stored.
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
        h.entry(header::VARY)
            .or_insert_with(|| header::HeaderValue::from_static("Cookie"));
    }
    res
}

/// While setup is unfinished, page routes redirect to `/setup/<step>`.
/// (API `/api/setup/*` routes enforce this themselves with 403.)
/// Only `GET`/`HEAD` are redirected: other methods fall through so e.g.
/// `TRACE /` answers `405` instead of a misleading `303`.
pub(crate) async fn setup_guard<B: Backend>(
    State(state): State<AppState<B>>,
    req: Request,
    next: Next,
) -> Response {
    let is_page_method =
        req.method() == axum::http::Method::GET || req.method() == axum::http::Method::HEAD;
    let path = req.uri().path().to_owned();
    let needs_guard = path == "/"
        || path.starts_with("/clients")
        || path == "/me"
        || path.starts_with("/admin")
        || path == "/login";
    if is_page_method
        && needs_guard
        && let Ok(step) = state.backend.setup_step().await
        && let Some(location) = crate::setup::setup_page_redirect(step, &path)
    {
        return (
            axum::http::StatusCode::SEE_OTHER,
            [(header::LOCATION, location)],
            "setup",
        )
            .into_response();
    }
    next.run(req).await
}

/// CSRF defense-in-depth for state-changing requests, keyed on the
/// browser-computed `Sec-Fetch-Site` metadata header.
///
/// `SameSite=Lax` on the session cookie (M8) is the primary defense, but Lax
/// still permits top-level cross-site `POST` navigations, so a second
/// independent signal helps. `Sec-Fetch-Site` is derived by the browser from
/// the initiator's origin and cannot be forged by page JS, which makes it more
/// robust here than comparing `Origin`/`Referer` to `Host`: TLS typically
/// terminates at a reverse proxy, so the externally visible host is not the
/// one the server sees.
///
/// Policy:
/// - only mutating methods (`POST`/`PUT`/`PATCH`/`DELETE`) are checked; safe
///   methods pass so assets, the htmx long-poll and the audit keep working;
/// - header **absent** -> allow (non-browser clients such as `curl`, the
///   Bearer API or webhooks are not CSRF targets);
/// - `same-origin` / `none` -> allow (normal app fetch/navigation and direct
///   address-bar or bookmark requests, reported as `none`);
/// - anything else (`cross-site`, `same-site`, unknown) -> `403` before the
///   handler runs.
pub(crate) async fn csrf_guard(req: Request, next: Next) -> Response {
    let is_mutating = req.method() == Method::POST
        || req.method() == Method::PUT
        || req.method() == Method::PATCH
        || req.method() == Method::DELETE;
    if is_mutating && let Some(value) = req.headers().get(HeaderName::from_static("sec-fetch-site"))
    {
        let v = value.as_bytes();
        if v != b"same-origin" && v != b"none" {
            return WebError::forbidden("cross-site request blocked").into_response();
        }
    }
    next.run(req).await
}
