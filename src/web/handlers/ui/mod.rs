#![forbid(unsafe_code)]

//! Server-rendered UI pages, static assets and language handling.
//!
//! - Askama templates, no inline `<script>` / `style=` anywhere (CSP
//!   `script-src 'self'`); all JS lives in `static/js/app.js` (< 3 Ko),
//!   htmx is vendorised (`static/vendor/htmx.min.js`, no CDN).
//! - `/` refreshes by htmx long-poll (push on status change, 30 s
//!   fallback), search debounces 300 ms; cards carry
//!   initials avatars and a pulsing dot for handshakes < 2 min;
//!   enable/disable fire `refreshGrid` so the grid re-renders at once.
//! - QR is SVG server-side (`client::qrcode`); the browser converts to
//!   PNG 1000 px via canvas for download/clipboard.
//! - `firewallIps` is only rendered when the firewall is active.
//! - Language: `?lang=` > `lang` cookie > `Accept-Language` > `en`.
//!
//! Split by concern; everything is re-exported so `ui::*` paths
//! (handlers, page structs, prefs) keep working unchanged:
//! [`pages`] full pages, [`partials`] htmx fragments, [`admin`] admin
//! pages, [`setup`] wizard, [`static_files`] assets, [`errors`] fallback,
//! [`chrome`] shared prefs/chrome, [`cards`] card view-model.

pub mod admin;
pub mod cards;
pub mod chrome;
pub mod errors;
pub mod pages;
pub mod partials;
pub mod setup;
pub mod static_files;

pub use admin::{AdminPage, admin_page};
pub use cards::Card;
pub use chrome::{Base, LangQuery, Prefs, PrefsQuery, Tr, page_prefs};
pub use errors::{ErrorPage, internal_page, not_found};
pub use pages::{
    ClientPage, IndexPage, Login2faPage, LoginPage, MePage, client_detail, index, login, login_2fa,
    me,
};
pub use partials::{GridPartial, TotpStartPartial};
pub use setup::{Setup1, Setup2, Setup3, setup1, setup2, setup3};
pub use static_files::static_file;

use askama::Template;
use axum::response::{Html, IntoResponse, Response};

use crate::web::ctx::WebError;

use self::chrome::with_pref_cookies;

/// Rend un template Askama ; un echec devient un 500 (`tpl: …`) au lieu de
/// remonter brut a l'appelant.
pub(crate) fn render_html<T: Template>(page: &T) -> Result<String, WebError> {
    page.render()
        .map_err(|e| WebError::internal(format!("tpl: {e}")))
}

/// Rend une page complete : corps HTML + cookies de preferences.
pub(crate) fn render_page<T: Template>(page: &T, set: &[String]) -> Result<Response, WebError> {
    Ok(with_pref_cookies(
        Html(render_html(page)?).into_response(),
        set,
    ))
}

/// Rend un fragment htmx : corps HTML seul, jamais de cookies de preferences.
pub(crate) fn render_fragment<T: Template>(page: &T) -> Result<Response, WebError> {
    Ok(Html(render_html(page)?).into_response())
}
