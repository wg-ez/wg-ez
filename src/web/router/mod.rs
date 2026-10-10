#![forbid(unsafe_code)]

//! Axum router: every API route under `/api`, plus the public `/cnf/*` and
//! `/metrics/*`.
//!
//! Required Cargo features: `axum`, `axum-extra`, `tower` (default-features
//! off), `tower-http`, `hyper`, `http`, and a single-thread `tokio` runtime.
//!
//! Layers: path normalization, http tracing, CSP + hardening headers (no
//! inline script/style), and the setup-guard redirect (`/setup/<step>` while
//! unfinished).
//!
//! Auth: `wg-ez` cookie or `Authorization: Basic` (refused when 2FA is
//! active); the public and setup-only routes are enumerated in [`routes`].
//!
//! Layout: [`routes`] (route tables + [`build_router`](routes::build_router)),
//! [`middleware`] (CSP headers, setup guard), [`tests`] (guard tests via the
//! real axum router, never handlers directly).

mod middleware;
mod routes;

#[cfg(test)]
pub(crate) mod tests;

pub use routes::build_router;

#[cfg(test)]
pub use tests::TestBackend;
