#![forbid(unsafe_code)]

//! Typed web errors -> HTTP status mapping.

use axum::{
    extract::Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

/// Typed web error. `check()` forgetfulness in a handler must surface 500.
///
/// A security failure (`password` | `2fa` | `one-time-link`) is carried by
/// [`WebError::with_seclog`] and logged exactly once from
/// [`IntoResponse`] via the `seclog` field.
#[derive(Debug)]
pub struct WebError {
    status: StatusCode,
    message: String,
    /// Security log type: `password` | `2fa` | `one-time-link`.
    pub seclog: Option<&'static str>,
}

impl WebError {
    pub fn new(status: StatusCode, msg: impl Into<String>) -> Self {
        Self {
            status,
            message: msg.into(),
            seclog: None,
        }
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg)
    }

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, msg)
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, msg)
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, msg)
    }

    pub fn gone(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::GONE, msg)
    }

    pub fn unprocessable(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, msg)
    }

    pub fn rate_limited(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, msg)
    }

    /// Body larger than the configured limit (M12): answered with a short,
    /// controlled message, never an extractor/internal detail.
    pub fn payload_too_large(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, msg)
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, msg)
    }

    /// A forgotten permission `check()` in a handler is a 500 by design.
    pub fn missing_check() -> Self {
        Self::internal("permission check missing")
    }

    pub fn with_seclog(mut self, kind: &'static str) -> Self {
        self.seclog = Some(kind);
        self
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }
}

impl std::fmt::Display for WebError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for WebError {}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        if let Some(kind) = self.seclog {
            tracing::warn!("Security failure type={} detail={}", kind, self.message);
        }
        // 500s stay generic (no stacktrace / internals leak); other codes
        // carry a short JSON error for the UI toasts.
        let body = if self.status == StatusCode::INTERNAL_SERVER_ERROR {
            json!({ "error": "internal error" })
        } else {
            json!({ "error": self.message })
        };
        (self.status, Json(body)).into_response()
    }
}
