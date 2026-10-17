#![forbid(unsafe_code)]

//! `GET /metrics/prometheus` + `GET /metrics/json`.
//!
//! - Each endpoint is active only when its flag (`metricsPrometheus` /
//!   `metricsJson`) is true, else 404.
//! - A Bearer token is required when `metricsPassword` is set in DB.
//! - The text format is handwritten in `metrics_dto.rs` (no Prometheus
//!   crate); JSON carries the same numbers plus the client table.

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Json},
};
use serde_json::{Value, json};

use crate::web::{
    ctx::{AppState, Backend, WebError},
    guards::bearer_credential,
    metrics_dto::{MetricsJson, render_prometheus},
};

/// v15 order (verified from `defineMetricsHandler`): the Bearer password
/// is checked FIRST (401 when missing/wrong while `metricsPassword` is
/// set), then the per-endpoint enabled flag (400 when off).
///
/// Only **failed** Bearer checks are rate-limited (30/min/IP). The pre-check
/// is read-only and runs BEFORE Argon2: a saturated IP is refused `429`
/// without paying for the memory-hard verification, so an unauthenticated
/// flood cannot force a stream of Argon2 hashes. A working scraper is never
/// throttled because successes are never recorded.
async fn guard<B: Backend>(
    state: &AppState<B>,
    addr: std::net::SocketAddr,
    headers: &HeaderMap,
    want: &str,
) -> Result<(), WebError> {
    let ip = super::client_ip(state, addr, headers);
    // Refuse a saturated IP with 429 before the expensive check. Records
    // nothing: only failures below consume quota.
    if state.limits.metrics_saturated(ip).await {
        return Err(WebError::rate_limited("too many metrics auth attempts"));
    }
    if !state
        .backend
        .metrics_check(bearer_credential(headers).as_deref())
        .await?
    {
        state.limits.record_metrics_failure(ip).await;
        return Err(WebError::unauthorized("metrics auth required"));
    }
    let (prom, js) = state.backend.metrics_enabled().await?;
    let on = if want == "prometheus" { prom } else { js };
    if !on {
        // v15 answers 400 (not 404) when the endpoint is disabled.
        return Err(WebError::bad_request("metrics disabled"));
    }
    Ok(())
}

pub async fn prometheus<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebError> {
    guard(&state, addr, &headers, "prometheus").await?;
    let snap = state.backend.metrics_snapshot().await?;
    Ok((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        render_prometheus(&snap),
    ))
}

pub async fn json<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<Value>, WebError> {
    guard(&state, addr, &headers, "json").await?;
    let snap = state.backend.metrics_snapshot().await?;
    let dto = MetricsJson::from(&snap);
    Ok(Json(json!(dto)))
}
