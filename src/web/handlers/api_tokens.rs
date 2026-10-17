#![forbid(unsafe_code)]

//! Jetons d'API longue durée (`/api/me/tokens`, `/api/admin/tokens`).
//!
//! - Auth requise (cookie ou Bearer). Les routes `/me` portent sur les
//!   jetons propres de l'appelant (`me.update`, scope own) ; un CLIENT qui
//!   vise l'id d'autrui reçoit le même 404 qu'un id inconnu
//!   (anti-énumération). Les routes `/admin` exigent `admin.any`.
//! - `POST` retourne le clair UNE SEULE FOIS (`{id,name,token,
//!   expiresAt,createdAt}`) ; les listes ne l'exposent jamais (ni le hash).
//! - Mutations DB-only : aucun effet WireGuard, donc pas de `apply_tunnel`
//!   (comme la génération OTL, l'autre mutation sans effet noyau).
//! - Appelants htmx : création -> corps ignoré (`hx-swap="none"`) +
//!   `HX-Trigger {"refreshMe", "showToken"}` (`app.js` affiche le clair UNE
//!   SEULE FOIS dans la modale globale, la liste se met à jour) ;
//!   suppression -> `HX-Trigger` `refreshMe` (`hx-swap="none"`).

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Json, Response},
};
use serde::Deserialize;
use serde_json::json;

use crate::web::{
    ctx::{AppState, Backend, JsonOrForm, WebError, is_hx, with_hx_trigger},
    guards::{Auth, check},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTokenBody {
    /// 1-64 caractères (validé côté backend, source unique).
    pub name: String,
    /// ISO-8601 optionnel ; absent/vide/`null` = permanent.
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// `GET /api/me/tokens` : jetons propres (sans hash, sans clair).
pub async fn list_mine<B: Backend>(
    State(state): State<AppState<B>>,
    Auth(auth): Auth,
) -> Result<Json<serde_json::Value>, WebError> {
    check(&auth, "me.update", Some(auth.user_id))?;
    let tokens = state.backend.list_api_tokens(auth.user_id).await?;
    Ok(Json(json!(tokens)))
}

/// `POST /api/me/tokens` : crée et retourne le clair UNE SEULE FOIS.
/// Corps JSON ou formulaire : `{name 1-64, expiresAt? ISO-8601|null}`.
pub async fn create_mine<B: Backend>(
    State(state): State<AppState<B>>,
    Auth(auth): Auth,
    headers: HeaderMap,
    JsonOrForm(body): JsonOrForm<CreateTokenBody>,
) -> Result<Response, WebError> {
    check(&auth, "me.update", Some(auth.user_id))?;
    let created = state
        .backend
        .create_api_token(auth.user_id, &body.name, body.expires_at.as_deref())
        .await?;
    if is_hx(&headers) {
        // Le corps est ignoré (`hx-swap="none"` côté formulaire) : le clair
        // (ASCII seul, jamais d'accent à encoder en tête HTTP) voyage dans le
        // trigger `showToken` qu'`app.js` affiche dans la modale globale ;
        // `refreshMe` met à jour la liste. Les appelants non-htmx gardent le
        // JSON ci-dessous, inchangé.
        return Ok(with_hx_trigger(
            Json(json!({ "ok": true })).into_response(),
            &headers,
            None,
            Some(json!({ "refreshMe": true, "showToken": created.token })),
        ));
    }
    Ok(Json(json!(created)).into_response())
}

/// `DELETE /api/me/tokens/{id}` : révoque un jeton propre.
/// Id inconnu OU d'autrui -> même 404 (anti-énumération).
pub async fn delete_mine<B: Backend>(
    State(state): State<AppState<B>>,
    Auth(auth): Auth,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Response, WebError> {
    check(&auth, "me.update", Some(auth.user_id))?;
    if !state
        .backend
        .delete_api_token(auth.user_id, false, id)
        .await?
    {
        return Err(WebError::not_found("token not found"));
    }
    Ok(with_hx_trigger(
        Json(json!({ "ok": true })).into_response(),
        &headers,
        None,
        Some(json!({ "toast": "saved", "refreshMe": true })),
    ))
}

/// `GET /api/admin/tokens` : tous les jetons (ADMIN-only).
pub async fn list_all<B: Backend>(
    State(state): State<AppState<B>>,
    Auth(auth): Auth,
) -> Result<Json<serde_json::Value>, WebError> {
    check(&auth, "admin.any", None)?;
    let tokens = state.backend.list_all_api_tokens().await?;
    Ok(Json(json!(tokens)))
}

/// `DELETE /api/admin/tokens/{id}` : révoque n'importe quel jeton (ADMIN-only).
pub async fn delete_any<B: Backend>(
    State(state): State<AppState<B>>,
    Auth(auth): Auth,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Response, WebError> {
    check(&auth, "admin.any", None)?;
    if !state
        .backend
        .delete_api_token(auth.user_id, true, id)
        .await?
    {
        return Err(WebError::not_found("token not found"));
    }
    Ok(with_hx_trigger(
        Json(json!({ "ok": true })).into_response(),
        &headers,
        None,
        Some(json!({ "toast": "saved" })),
    ))
}
