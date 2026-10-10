#![forbid(unsafe_code)]

//! Client CRUD + OTL + config/QR.
//!
//! Bodies accept JSON or urlencoded ([`PatchBody`]/[`JsonOrForm`]); the
//! free-form update patch is coerced (`""` -> `null` inherit, comma lists
//! -> arrays, checkbox -> bool). htmx callers get `HX-Redirect` /
//! `HX-Trigger {"toast"}` on success; enable/disable additionally fire
//! `refreshGrid` so the index grid re-renders without waiting a poll tick.
//!
//! Permissions: `clients.custom` gates filtered listing, `clients.view`
//! details, `clients.create` creation (ADMIN-only), `clients.update`
//! edits, `clients.delete` removal.
//!
//! Effect rule: every POST|DELETE here calls `apply_tunnel` (full
//! `Tunnel::apply`) **except** [`generate_otl`], the single mutation
//! without a kernel effect.

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::web::{
    ctx::{
        AppState, Backend, ClientView, JsonOrForm, PatchBody, Principal, WebError, coerce_patch,
        with_hx, with_hx_trigger,
    },
    guards::{Auth, check},
    handlers::ui::chrome::{LangQuery, page_prefs},
};

const CLIENT_LISTS: [&str; 8] = [
    "allowedIpsV4",
    "allowedIpsV6",
    "serverAllowedIpsV4",
    "serverAllowedIpsV6",
    "firewallIpsV4",
    "firewallIpsV6",
    "dnsV4",
    "dnsV6",
];
const CLIENT_BOOLS: [&str; 1] = ["enabled"];
const CLIENT_NUMS: [&str; 2] = ["mtu", "persistentKeepalive"];
const CLIENT_NULLABLES: [&str; 3] = ["expiresAt", "serverEndpoint", "preSharedKey"];

/// Load a client by id, mapping "missing" to the shared 404, then enforce
/// `permission` against its owner. Every id-scoped route starts with this.
///
/// Anti-enumeration: when the ownership check fails with 403 (a CLIENT probing
/// a client id it does not own), answer the **same 404** a missing id yields,
/// so a CLIENT cannot enumerate which ids exist. Genuine admin routes run their
/// own `check` and keep answering 403 for a non-admin. Any other error (e.g.
/// the 500 for an unknown permission) is propagated unchanged.
async fn load_client<B: Backend>(
    state: &AppState<B>,
    auth: &Principal,
    id: i64,
    permission: &str,
) -> Result<ClientView, WebError> {
    let client = state
        .backend
        .get_client(id)
        .await?
        .ok_or_else(|| WebError::not_found("client not found"))?;
    match check(auth, permission, Some(client.user_id)) {
        Ok(()) => Ok(client),
        Err(e) if e.status() == StatusCode::FORBIDDEN => {
            Err(WebError::not_found("client not found"))
        }
        Err(e) => Err(e),
    }
}

/// Common success shape for client mutations: JSON body plus, for htmx
/// callers, an optional `HX-Redirect` and the `"saved"` toast.
fn saved_hx(client: &ClientView, headers: &HeaderMap, redirect: Option<&str>) -> Response {
    with_hx(
        Json(json!(client)).into_response(),
        headers,
        redirect,
        Some("saved"),
    )
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub filter: Option<String>,
    /// `name` | `-name` | `created` | `-created`.
    #[serde(default)]
    pub sort: Option<String>,
}

pub async fn list<B: Backend>(
    State(state): State<AppState<B>>,
    Auth(auth): Auth,
    _headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, WebError> {
    // Listing with a filter is the `clients.custom` resource; plain listing
    // still requires an authenticated user (401 handled above) and CLIENTs
    // only ever see their own rows (backend filters by `userId`).
    let scope = if q.filter.is_some() || q.sort.is_some() {
        Some(auth.user_id)
    } else {
        None
    };
    check(&auth, "clients.custom", scope.or(Some(auth.user_id)))?;
    let mut clients = state.backend.list_clients().await?;
    super::filter_and_sort_clients(
        &mut clients,
        Some((auth.user_id, auth.is_admin())),
        q.filter.as_deref(),
        q.sort.as_deref(),
    );
    Ok(Json(json!(clients)))
}

#[derive(Debug, Deserialize)]
pub struct CreateBody {
    pub name: String,
}

pub async fn create<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Auth(auth): Auth,
    headers: HeaderMap,
    JsonOrForm(body): JsonOrForm<CreateBody>,
) -> Result<Response, WebError> {
    super::check_mutation_limit(&state, addr, &headers).await?;
    check(&auth, "clients.create", None)?;
    let name = body.name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(WebError::bad_request("bad client name"));
    }
    let client = state.backend.create_client(name).await?;
    state.backend.apply_tunnel().await?;
    Ok(saved_hx(&client, &headers, None))
}

pub async fn get<B: Backend>(
    State(state): State<AppState<B>>,
    Auth(auth): Auth,
    _headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, WebError> {
    let client = load_client(&state, &auth, id, "clients.view").await?;
    Ok(Json(json!(client)))
}

/// Keys a non-admin must never set through the client patch.
///
/// - `serverAllowedIps` injects extra `AllowedIPs` on the server-side peer: a
///   CLIENT could route or intercept arbitrary traffic (I4).
/// - `expiresAt` decides when the cron auto-disables the client: a CLIENT
///   could clear or push back its own expiry to bypass auto-disable (M3).
///
/// The raw patch (before coercion) is inspected, so an empty form value is
/// refused too. ADMIN is unrestricted.
const ADMIN_ONLY_KEYS: [&str; 3] = ["serverAllowedIpsV4", "serverAllowedIpsV6", "expiresAt"];

/// Refuse 403 a non-admin patch carrying an [`ADMIN_ONLY_KEYS`] field.
fn reject_admin_only_patch_keys(patch: &Value, auth: &Principal) -> Result<(), WebError> {
    if auth.is_admin() {
        return Ok(());
    }
    if let Value::Object(map) = patch {
        for key in ADMIN_ONLY_KEYS {
            if map.contains_key(key) {
                return Err(WebError::forbidden(format!("{key} is admin-only")));
            }
        }
    }
    Ok(())
}

pub async fn update<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Auth(auth): Auth,
    headers: HeaderMap,
    Path(id): Path<i64>,
    PatchBody(patch): PatchBody,
) -> Result<Response, WebError> {
    super::check_mutation_limit(&state, addr, &headers).await?;
    load_client(&state, &auth, id, "clients.update").await?;
    reject_admin_only_patch_keys(&patch, &auth)?;
    let patch = coerce_patch(
        patch,
        &CLIENT_LISTS,
        &CLIENT_BOOLS,
        &CLIENT_NUMS,
        &CLIENT_NULLABLES,
    );
    let client = state.backend.update_client(id, patch).await?;
    state.backend.apply_tunnel().await?;
    Ok(saved_hx(&client, &headers, None))
}

pub async fn delete<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Auth(auth): Auth,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Response, WebError> {
    super::check_mutation_limit(&state, addr, &headers).await?;
    load_client(&state, &auth, id, "clients.delete").await?;
    state.backend.delete_client(id).await?;
    state.backend.apply_tunnel().await?;
    Ok(with_hx(
        Json(json!({ "ok": true })).into_response(),
        &headers,
        Some("/"),
        Some("deleted"),
    ))
}

pub async fn enable<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Auth(auth): Auth,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Response, WebError> {
    set_enabled(state, auth, addr, headers, id, true).await
}

pub async fn disable<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Auth(auth): Auth,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Response, WebError> {
    set_enabled(state, auth, addr, headers, id, false).await
}

/// Action commune des deux routes enable/disable : rate-limit mutation,
/// permission `clients.update`, mutation, `Tunnel::apply`. L'activation d'un
/// client expire repond 422 depuis le backend. Les appelants htmx declenchent
/// en plus `refreshGrid` pour re-rendre la grille sans attendre un tick de poll.
async fn set_enabled<B: Backend>(
    state: AppState<B>,
    auth: Principal,
    addr: std::net::SocketAddr,
    headers: HeaderMap,
    id: i64,
    enabled: bool,
) -> Result<Response, WebError> {
    super::check_mutation_limit(&state, addr, &headers).await?;
    load_client(&state, &auth, id, "clients.update").await?;
    let client = if enabled {
        state.backend.enable_client(id).await?
    } else {
        state.backend.disable_client(id).await?
    };
    state.backend.apply_tunnel().await?;
    Ok(with_hx_trigger(
        Json(json!(client)).into_response(),
        &headers,
        None,
        Some(json!({ "toast": "saved", "refreshGrid": true })),
    ))
}

/// `POST /api/client/:id/psk` : genere une PSK pour ce client (override par
/// client) puis refait un `Tunnel::apply` complet.
pub async fn generate_psk<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Auth(auth): Auth,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Response, WebError> {
    set_psk(state, auth, addr, headers, id, true).await
}

/// `DELETE /api/client/:id/psk` : retire la PSK du client (override par
/// client) puis refait un `Tunnel::apply` complet.
pub async fn remove_psk<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Auth(auth): Auth,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Response, WebError> {
    set_psk(state, auth, addr, headers, id, false).await
}

/// Action commune des deux routes PSK : rate-limit mutation, permission
/// `clients.update`, mutation, `Tunnel::apply`. Les appelants htmx reviennent
/// sur la fiche (`HX-Redirect`) pour refleter le nouvel etat ; les clients API
/// recoivent le `ClientView` JSON.
async fn set_psk<B: Backend>(
    state: AppState<B>,
    auth: crate::web::ctx::Principal,
    addr: std::net::SocketAddr,
    headers: HeaderMap,
    id: i64,
    enabled: bool,
) -> Result<Response, WebError> {
    super::check_mutation_limit(&state, addr, &headers).await?;
    load_client(&state, &auth, id, "clients.update").await?;
    let client = state.backend.set_client_psk(id, enabled).await?;
    state.backend.apply_tunnel().await?;
    Ok(saved_hx(&client, &headers, Some(&format!("/clients/{id}"))))
}

/// `POST /api/client/:id/rotateKeys` : regenere la paire de cles du client
/// (privee + publique, la PSK eventuelle est conservee) puis refait un
/// `Tunnel::apply` complet. Les appelants htmx reviennent sur la fiche.
pub async fn rotate_keys<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Auth(auth): Auth,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Response, WebError> {
    super::check_mutation_limit(&state, addr, &headers).await?;
    load_client(&state, &auth, id, "clients.update").await?;
    let client = state.backend.rotate_client_keys(id).await?;
    state.backend.apply_tunnel().await?;
    Ok(saved_hx(&client, &headers, Some(&format!("/clients/{id}"))))
}

/// The ONLY client mutation without `Tunnel::apply`.
/// htmx callers receive the token via `HX-Trigger` (clipboard + countdown
/// are handled in `app.js`); the JSON body is unchanged for API clients.
pub async fn generate_otl<B: Backend>(
    State(state): State<AppState<B>>,
    Auth(auth): Auth,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(q): Query<LangQuery>,
) -> Result<Response, WebError> {
    use crate::web::ctx::with_hx_trigger;
    load_client(&state, &auth, id, "clients.update").await?;
    let otl = state.backend.generate_otl(id).await?;
    // Toast localisé (même priorité `?lang=` > cookie > `Accept-Language`
    // que les pages) : le token part de toute façon dans le presse-papiers
    // via `app.js`, le message ne fait que le confirmer.
    let prefs = page_prefs(&state, &jar, &headers, q.prefs());
    let copied = state.locales.t(prefs.lang, "toast.link_copied");
    let trigger = serde_json::json!({ "toast": copied, "otl": otl.token, "exp": otl.expires_at });
    let resp = Json(json!(otl)).into_response();
    Ok(with_hx_trigger(resp, &headers, None, Some(trigger)))
}

/// `GET /api/client/:id/configuration` downloads the `.conf` attachment.
/// Filenames are sanitized to <= 32 chars.
pub async fn configuration<B: Backend>(
    State(state): State<AppState<B>>,
    Auth(auth): Auth,
    _headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, WebError> {
    load_client(&state, &auth, id, "clients.view").await?;
    let (mut name, conf) = state.backend.client_conf(id).await?;
    super::sanitize_conf_filename(&mut name);
    Ok(super::conf_attachment(&name, conf))
}

/// `GET /api/client/:id/qrcode.svg` renders the QR server-side (SVG).
pub async fn qrcode<B: Backend>(
    State(state): State<AppState<B>>,
    Auth(auth): Auth,
    _headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, WebError> {
    load_client(&state, &auth, id, "clients.view").await?;
    let (_, conf) = state.backend.client_conf(id).await?;
    let svg = crate::web::qr::render_qr_svg(conf.as_bytes())
        .map_err(|e| WebError::internal(format!("qr: {e}")))?;
    Ok(([(axum::http::header::CONTENT_TYPE, "image/svg+xml")], svg))
}
