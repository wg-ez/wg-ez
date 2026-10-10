#![forbid(unsafe_code)]

//! Public `GET /cnf/:token` one-time-link download.
//!
//! - Unknown token -> 404 + `Security failure type=one-time-link`.
//! - Expired token -> 410 Gone.
//! - Success extends expiry by 10 s (anti-double-request) then purges,
//!   served as a `.conf` attachment (sanitized, <= 32 chars).
//! - Rate limit: 20/min/IP -> 429.

use axum::{
    extract::{ConnectInfo, Path, State},
    http::HeaderMap,
    response::IntoResponse,
};
use serde_json::json;

use crate::web::ctx::{AppState, Backend, OtlOutcome, WebError};

pub async fn download<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Result<impl IntoResponse, WebError> {
    let ip = super::client_ip(&state, addr, &headers);
    if !state.limits.check_cnf(ip).await {
        return Err(WebError::rate_limited("too many requests"));
    }
    if token.len() > 128
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(WebError::not_found("unknown link").with_seclog("one-time-link"));
    }
    match state.backend.consume_otl(&token).await? {
        OtlOutcome::Ok { file_name, conf } => {
            let mut name = file_name;
            super::sanitize_conf_filename(&mut name);
            Ok(super::conf_attachment(&name, conf))
        }
        OtlOutcome::Unknown => {
            Err(WebError::not_found(json!("unknown link").to_string()).with_seclog("one-time-link"))
        }
        OtlOutcome::Expired => Err(WebError::gone("link expired").with_seclog("one-time-link")),
    }
}
