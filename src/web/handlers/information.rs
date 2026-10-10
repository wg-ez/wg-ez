#![forbid(unsafe_code)]

//! `GET /api/information` (public).
//!
//! Returns version, feature flags and the (V1-constant) `release` field.
//! There is no in-process GitHub check: the V1 stack ships no TLS client
//! (TLS terminates at the reverse proxy), so `release` is always `null`.
//! The key is kept for shape parity with v15.

use axum::{extract::State, response::Json};
use serde_json::{Value, json};

use crate::web::ctx::{AppState, Backend, WebError};

pub async fn information<B: Backend>(
    State(state): State<AppState<B>>,
) -> Result<Json<Value>, WebError> {
    let step = state.backend.setup_step().await?;
    let prometheus = state
        .backend
        .metrics_enabled()
        .await
        .unwrap_or((false, false))
        .0;
    Ok(Json(json!({
        "version": state.backend.app_version(),
        "setup": step != 0,
        "setupStep": step,
        "insecure": state.backend.insecure(),
        "metricsPrometheus": prometheus,
        "oauthEnabled": false,
        // V1 has no in-process TLS client: always null (shape parity with v15).
        "release": Value::Null,
    })))
}
