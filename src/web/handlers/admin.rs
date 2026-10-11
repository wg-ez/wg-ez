#![forbid(unsafe_code)]

//! Admin routes. All require `admin.any`.
//!
//! Free-form patches accept JSON or urlencoded ([`PatchBody`]) and are
//! coerced to typed JSON; htmx callers get `HX-Trigger {"toast"}`.
//!
//! - `GET|POST /api/admin/general|hooks|interface|userconfig`
//! - `POST /api/admin/interface/cidr` (reallocates everything)
//! - `POST /api/admin/interface/restart` (`down` + `up`, cuts tunnels)
//! - `GET /api/admin/ip-info` (15-min cached host candidates)
//!
//! Every POST applies the tunnel. It is a hot apply (`syncconf`) unless one
//! of the non-hot settings changed (MTU, Table, CIDR, hooks): then a full
//! `down`+`up` is used so the change is actually reflected. Enabling the
//! firewall without iptables answers 400 after a reprobe (backend
//! responsibility).

use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    response::{IntoResponse, Json, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::web::{
    ctx::{
        AppState, Backend, JsonOrForm, PatchBody, WebError, coerce_patch, with_hx, with_hx_trigger,
    },
    guards::{Auth, check},
};

fn admin(auth: &crate::web::ctx::Principal) -> Result<(), WebError> {
    check(auth, "admin.any", None)
}

/// Vrai si au moins une des clés a changé entre `before` et `after`.
/// Sert à déclencher un `wg-quick up` (down+up) plutôt qu'un apply à chaud
/// quand un réglage non répercutable par `wg syncconf` a bougé.
fn restart_needed(before: &Value, after: &Value, keys: &[&str]) -> bool {
    keys.iter().any(|k| before.get(*k) != after.get(*k))
}

macro_rules! pair {
    ($get_fn:ident, $set_fn:ident, $get_b:ident, $set_b:ident, $lists:expr, $bools:expr, $nums:expr, $restart_keys:expr) => {
        pub async fn $get_fn<B: Backend>(
            State(state): State<AppState<B>>,
            Auth(auth): Auth,
            _headers: HeaderMap,
        ) -> Result<Json<Value>, WebError> {
            admin(&auth)?;
            Ok(Json(state.backend.$get_b().await?))
        }

        pub async fn $set_fn<B: Backend>(
            State(state): State<AppState<B>>,
            ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
            Auth(auth): Auth,
            headers: HeaderMap,
            PatchBody { patch, is_json }: PatchBody,
        ) -> Result<Response, WebError> {
            super::check_mutation_limit(&state, addr, &headers).await?;
            admin(&auth)?;
            // `wg syncconf` répercute à chaud les pairs, ListenPort et le
            // firewall, mais PAS MTU/Table/Address/hooks : si l'un de ces
            // réglages a réellement changé, il faut un `down`+`up` (le tunnel
            // est brièvement coupé). Sinon on reste sur un apply à chaud.
            let before = state.backend.$get_b().await?;
            let patch = coerce_patch(patch, $lists, $bools, $nums, &[], is_json);
            let out = state.backend.$set_b(patch).await?;
            if restart_needed(&before, &out, $restart_keys) {
                state.backend.restart_interface().await?;
            } else {
                state.backend.apply_tunnel().await?;
            }
            Ok(with_hx(
                Json(out).into_response(),
                &headers,
                None,
                Some("saved"),
            ))
        }
    };
}

pair!(
    get_general,
    set_general,
    get_general,
    set_general,
    &[],
    &["metricsPrometheus", "metricsJson"],
    &["sessionTimeout"],
    &[]
);
pair!(
    get_hooks,
    set_hooks,
    get_hooks,
    set_hooks,
    &[],
    &[],
    &[],
    &["preUp", "postUp", "preDown", "postDown"]
);
pair!(
    get_interface,
    set_interface,
    get_interface,
    set_interface,
    &[],
    &["firewallEnabled"],
    &["port", "mtu"],
    &["mtu", "routingTable"]
);
pair!(
    get_userconfig,
    set_userconfig,
    get_userconfig,
    set_userconfig,
    &[
        "defaultDnsV4",
        "defaultDnsV6",
        "defaultAllowedIpsV4",
        "defaultAllowedIpsV6",
    ],
    &["defaultPreSharedKey"],
    &["port", "defaultMtu", "defaultKeepalive"],
    &[]
);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CidrBody {
    #[serde(default)]
    pub ipv4_cidr: Option<String>,
    #[serde(default)]
    pub ipv6_cidr: Option<String>,
}

pub async fn change_cidr<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Auth(auth): Auth,
    headers: HeaderMap,
    JsonOrForm(body): JsonOrForm<CidrBody>,
) -> Result<Response, WebError> {
    super::check_mutation_limit(&state, addr, &headers).await?;
    admin(&auth)?;
    // Un changement de CIDR change l'`Address` du serveur : non répercutable
    // à chaud, donc `down`+`up` si la valeur a réellement bougé.
    let before = state.backend.get_interface().await?;
    let out = state
        .backend
        .change_cidr(body.ipv4_cidr.as_deref(), body.ipv6_cidr.as_deref())
        .await?;
    if restart_needed(&before, &out, &["ipv4Cidr", "ipv6Cidr"]) {
        state.backend.restart_interface().await?;
    } else {
        state.backend.apply_tunnel().await?;
    }
    // Un changement de CIDR réécrit aussi les hooks (NAT) côté serveur. On
    // déclenche un rafraîchissement ciblé des seuls champs de hooks côté
    // client (`HX-Trigger` -> app.js) plutôt qu'un reload complet de page.
    Ok(with_hx_trigger(
        Json(out).into_response(),
        &headers,
        None,
        Some(json!({ "toast": "saved", "hooks": true })),
    ))
}

pub async fn restart<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Auth(auth): Auth,
    headers: HeaderMap,
) -> Result<Response, WebError> {
    super::check_mutation_limit(&state, addr, &headers).await?;
    admin(&auth)?;
    // Explicit admin button: `down` then `up`, cuts tunnels.
    state.backend.restart_interface().await?;
    Ok(with_hx(
        Json(json!({ "ok": true })).into_response(),
        &headers,
        None,
        Some("saved"),
    ))
}

pub async fn ip_info<B: Backend>(
    State(state): State<AppState<B>>,
    Auth(auth): Auth,
    _headers: HeaderMap,
) -> Result<Json<Value>, WebError> {
    admin(&auth)?;
    Ok(Json(state.backend.ip_info().await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_only_when_a_non_hot_key_changed() {
        let before = json!({ "mtu": 1420, "port": 51820, "routingTable": "auto" });

        // Rien ne bouge -> apply à chaud.
        assert!(!restart_needed(&before, &before, &["mtu", "routingTable"]));

        // Port modifié -> reste applicable à chaud.
        let port_only = json!({ "mtu": 1420, "port": 51821, "routingTable": "auto" });
        assert!(!restart_needed(
            &before,
            &port_only,
            &["mtu", "routingTable"]
        ));

        // MTU / Table modifiés -> `wg-quick up` requis.
        let mtu = json!({ "mtu": 1500, "port": 51820, "routingTable": "auto" });
        assert!(restart_needed(&before, &mtu, &["mtu", "routingTable"]));
        let table = json!({ "mtu": 1420, "port": 51820, "routingTable": "off" });
        assert!(restart_needed(&before, &table, &["mtu", "routingTable"]));
    }
}
