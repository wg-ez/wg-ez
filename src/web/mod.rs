#![forbid(unsafe_code)]

//! Web layer: axum router + guards + handlers + templates context.
//!
//! Everything API is under `/api` except `/cnf/*` and `/metrics/*`.
//! Single-thread `current_thread` tokio runtime with one worker; blocking
//! work stays in `Backend` via `spawn_blocking`.
//!
//! Crate features assumed (see `router.rs`): axum http1/query/form/json/
//! tokio/matched-path/original-uri, axum-extra cookies, tower (no default
//! features), tower-http trace + normalize-path.

pub mod backend;
pub mod ctx;
pub mod guards;
pub mod handlers;
pub mod metrics_dto;
pub mod qr;
pub mod router;
pub mod watcher;

pub use backend::SqliteBackend;
pub use ctx::{AppState, Backend, Locales, WebError};
pub use router::build_router;
