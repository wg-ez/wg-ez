#![forbid(unsafe_code)]

//! Session + self-service profile.
//!
//! Bodies accept JSON or urlencoded ([`JsonOrForm`]); htmx callers get
//! `HX-Redirect` / `HX-Trigger {"toast"}` on success.
//!
//! - `GET /api/session` -> profile or 401.
//! - `DELETE /api/session` -> logout (clears the `wg-ez` cookie).
//! - `POST /api/me` updates the display name (`me.update`, own profile only).
//! - `POST /api/me/username` changes the login username (current password
//!   required, validated + uniqueness enforced by the backend).
//! - `POST /api/me/password` changes the password (12+ chars enforced).
//! - `POST /api/me/totp` manages setup/confirm/remove of TOTP.

use axum::{
    extract::State,
    http::{HeaderMap, header},
    response::{IntoResponse, Json, Response},
};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::web::{
    ctx::{AppState, Backend, JsonOrForm, WebError, with_hx, with_hx_trigger},
    guards::{Auth, SESSION_COOKIE, check, hash_token},
};

pub async fn get<B: Backend>(
    State(state): State<AppState<B>>,
    Auth(auth): Auth,
) -> Result<Json<Value>, WebError> {
    let user = state.backend.get_user(auth.user_id).await?;
    Ok(Json(json!(user)))
}

pub async fn delete<B: Backend>(
    State(state): State<AppState<B>>,
    jar: CookieJar,
    headers: HeaderMap,
    Auth(auth): Auth,
) -> Result<Response, WebError> {
    let _ = auth;
    if let Some(token) = jar.get(SESSION_COOKIE).map(|c| c.value().to_owned()) {
        state.backend.destroy_session(&hash_token(&token)).await?;
    }
    let c = crate::auth::session::build_clear_cookie(!state.backend.insecure());
    let resp = ([(header::SET_COOKIE, c)], Json(json!({ "ok": true }))).into_response();
    Ok(with_hx(resp, &headers, Some("/login"), None))
}

#[derive(Debug, Deserialize)]
pub struct MeBody {
    pub name: String,
}

pub async fn update_me<B: Backend>(
    State(state): State<AppState<B>>,
    Auth(auth): Auth,
    headers: HeaderMap,
    JsonOrForm(body): JsonOrForm<MeBody>,
) -> Result<Response, WebError> {
    check(&auth, "me.update", Some(auth.user_id))?;
    if body.name.trim().is_empty() || body.name.chars().count() > 128 {
        return Err(WebError::bad_request("bad name"));
    }
    let user = state
        .backend
        .update_me(auth.user_id, body.name.trim())
        .await?;
    Ok(with_hx(
        Json(json!(user)).into_response(),
        &headers,
        None,
        Some("saved"),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsernameChangeBody {
    pub current_password: String,
    pub username: String,
}

/// Change the login username. Validation (`validate_username`) and the
/// current-password guard both live in the backend, the single source shared
/// with the CLI; the handler only forwards and answers htmx. The username is
/// visible in the shell (eyebrow aside), so the UI reloads `/me` in full
/// (`HX-Redirect`) instead of the partial `refreshMe` used by TOTP.
pub async fn change_username<B: Backend>(
    State(state): State<AppState<B>>,
    Auth(auth): Auth,
    headers: HeaderMap,
    JsonOrForm(body): JsonOrForm<UsernameChangeBody>,
) -> Result<Response, WebError> {
    check(&auth, "me.update", Some(auth.user_id))?;
    let user = state
        .backend
        .change_username(auth.user_id, &body.current_password, &body.username)
        .await?;
    Ok(with_hx(
        Json(json!(user)).into_response(),
        &headers,
        Some("/me"),
        Some("saved"),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordChangeBody {
    pub current_password: String,
    pub new_password: String,
}

pub async fn change_password<B: Backend>(
    State(state): State<AppState<B>>,
    Auth(auth): Auth,
    headers: HeaderMap,
    JsonOrForm(body): JsonOrForm<PasswordChangeBody>,
) -> Result<Response, WebError> {
    check(&auth, "me.update", Some(auth.user_id))?;
    if body.new_password.chars().count() < 12 {
        return Err(WebError::bad_request(
            "password must be at least 12 characters",
        ));
    }
    state
        .backend
        .change_password(auth.user_id, &body.current_password, &body.new_password)
        .await?;
    Ok(with_hx(
        Json(json!({ "ok": true })).into_response(),
        &headers,
        None,
        Some("saved"),
    ))
}

#[derive(Debug, Deserialize)]
pub struct TotpBody {
    /// `start` | `confirm` | `remove`.
    pub action: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

pub async fn totp<B: Backend>(
    State(state): State<AppState<B>>,
    Auth(auth): Auth,
    jar: CookieJar,
    headers: HeaderMap,
    JsonOrForm(body): JsonOrForm<TotpBody>,
) -> Result<Response, WebError> {
    check(&auth, "me.update", Some(auth.user_id))?;
    match body.action.as_str() {
        "start" => {
            // I2: the backend enforces the current-password check when a
            // verified 2FA already exists; the handler only forwards it.
            let setup = state
                .backend
                .totp_setup_start(auth.user_id, body.password.as_deref())
                .await?;
            if crate::web::ctx::is_hx(&headers) {
                let lang = crate::web::handlers::ui::page_prefs(
                    &state,
                    &jar,
                    &headers,
                    crate::web::handlers::ui::chrome::PrefsQuery::NONE,
                )
                .lang;
                let t = |k: &str| state.locales.t(lang, k);
                let page = crate::web::handlers::ui::TotpStartPartial {
                    secret: setup.secret,
                    qr_svg: setup.qr_svg,
                    t_secret_k: t("me.totp_secret"),
                    t_code: t("me.totp_code"),
                    t_verify: t("me.totp_verify"),
                };
                return crate::web::handlers::ui::render_fragment(&page);
            }
            Ok(Json(json!(setup)).into_response())
        }
        "confirm" => {
            let code = body.code.unwrap_or_default();
            if crate::validate::validate_totp_code(&code).is_err() {
                return Err(WebError::bad_request("totp code must be 6 digits"));
            }
            state
                .backend
                .totp_setup_confirm(auth.user_id, &code)
                .await?;
            // Le formulaire de confirmation est en `hx-swap="none"` (le JSON
            // ne doit JAMAIS finir dans le DOM) : l'UI suit via le trigger
            // `refreshMe`, qui re-render `#me-page` (pastille + tag + formes).
            Ok(with_hx_trigger(
                Json(json!({ "ok": true })).into_response(),
                &headers,
                None,
                Some(json!({ "toast": "saved", "refreshMe": true })),
            ))
        }
        "remove" => {
            let pw = body.password.unwrap_or_default();
            state.backend.totp_remove(auth.user_id, &pw).await?;
            Ok(with_hx_trigger(
                Json(json!({ "ok": true })).into_response(),
                &headers,
                None,
                Some(json!({ "toast": "saved", "refreshMe": true })),
            ))
        }
        _ => Err(WebError::bad_request("unknown totp action")),
    }
}
