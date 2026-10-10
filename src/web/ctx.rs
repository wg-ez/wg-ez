#![forbid(unsafe_code)]

//! Shared web context.
//!
//! Integration contract: the backend agents (`config`, `store/*`, `auth/*`,
//! `tunnel`, `wg/*`) wire this layer by implementing [`Backend`] (one method
//! per domain) and building [`AppState`] in `main.rs` (`serve`). The web
//! layer never touches SQLite, argon2, `wg` or iptables itself: every
//! blocking call stays inside the `Backend` implementation, which must use
//! `tokio::task::spawn_blocking` (single-thread `current_thread` runtime).
//!
//! `AppState` is generic over `B: Backend` (static dispatch, no
//! `async-trait` dependency, zero runtime cost).
//!
//! Rules enforced here:
//! - `null` = inheritance: `allowedIps`/`dns` fall back to the global
//!   default, `firewallIps` falls back to `allowedIps` then the global
//!   default. `None` always means "inherit", never `[]`.
//! - Every client/admin POST|DELETE handler calls
//!   [`Backend::apply_tunnel`] (full `Tunnel::apply`) except OTL generation.
//! - Locale priority: `?lang=` > `lang` cookie > `Accept-Language` > `en`.
//!
//! Layout: this file is only a compatibility hub (`pub mod` + re-exports
//! so every `crate::web::ctx::X` import keeps working). The implementation
//! lives in `src/web/ctx/`:
//! - `errors.rs`: [`WebError`] (security-failure logging via
//!   [`WebError::with_seclog`]).
//! - `locales.rs`: [`Locales`], [`SUPPORTED_LANGS`].
//! - `views.rs`: [`Principal`], [`ClientView`], [`UserView`] and the other
//!   DTOs.
//! - `backend_trait.rs`: [`Backend`].
//! - `state.rs`: [`AppState`], [`PendingLogin`], [`RateLimits`].
//! - `forms.rs`: [`JsonOrForm`], [`PatchBody`], [`coerce_patch`] and the
//!   htmx helpers.

pub mod backend_trait;
pub mod errors;
pub mod forms;
pub mod locales;
pub mod state;
pub mod views;

pub use backend_trait::{Backend, StatusSignal};
pub use errors::WebError;
pub use forms::{
    JsonOrForm, PatchBody, coerce_patch, is_hx, normalize_bools, with_hx, with_hx_trigger,
};
pub use locales::{Locales, SUPPORTED_LANGS};
pub use state::{AppState, PendingLogin, RateLimits, insert_pending};
pub use views::{
    ClientView, GlobalDefaults, Kv, LoginOutcome, MetricsSnapshot, OtlOutcome, OtlView, PeerMetric,
    Principal, TotpSetup, UserView,
};
