#![forbid(unsafe_code)]

//! Client CRUD for [`super::SqliteBackend`].
//!
//! `null` = inheritance is honored when rendering views; every mutation here
//! is followed by [`crate::web::ctx::Backend::apply_tunnel`] at the handler
//! level (OTL generation lives in `otl.rs` and is the only exception).

use rusqlite::Connection;
use serde_json::{Map, Value};

use super::SqliteBackend;
use super::common::{
    LiveCacheSlot, as_string_list, build_client_conf, cached_live_peers, clean_strings,
    client_view, db_err, generate_keypair, interface_row, now_iso, now_unix, number_value,
    parse_json_vec, reject_patch_keys, userconfig_row,
};
use crate::store::client::{Client, ClientUpdate, DEFAULT_API_USER_ID, NewClient};
use crate::web::ctx::{ClientView, GlobalDefaults, WebError};
use crate::wg::firewall;
use crate::wg::runner::SystemRunner;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Load a client row by id, or answer 404.
fn client_row(conn: &Connection, id: i64) -> Result<Client, WebError> {
    crate::store::client::get(conn, id)
        .map_err(db_err)?
        .ok_or_else(|| WebError::not_found("client not found"))
}

/// Build the view of an already-loaded client row: its `user_configs` row
/// (500 when the seed is missing) plus the shared best-effort live peer map
/// (`cache` dedupes the `wg dump` probes of one request).
fn client_view_for(
    conn: &Connection,
    client: &Client,
    iface_name: &str,
    cache: &LiveCacheSlot,
) -> Result<ClientView, WebError> {
    let cfg = userconfig_row(conn, &client.interface_id)?;
    let live = cached_live_peers(cache, iface_name);
    client_view(client, &cfg, &live, now_unix())
}

/// Load a client by id (404 when missing) and build its view.
fn client_view_by_id(
    conn: &Connection,
    id: i64,
    iface_name: &str,
    cache: &LiveCacheSlot,
) -> Result<ClientView, WebError> {
    let client = client_row(conn, id)?;
    client_view_for(conn, &client, iface_name, cache)
}

/// Shared mutation skeleton: load the client row by id (404 when missing),
/// let `build` turn that row into the [`ClientUpdate`] to apply, stamp the
/// write, then reload the view. Each caller only supplies its own patch
/// logic; the load/timestamp/update/reload sequence lives here once.
fn mutate_client(
    conn: &Connection,
    id: i64,
    iface_name: &str,
    cache: &LiveCacheSlot,
    build: impl FnOnce(&Client) -> Result<ClientUpdate, WebError>,
) -> Result<ClientView, WebError> {
    let client = client_row(conn, id)?;
    let patch = build(&client)?;
    let now = now_iso()?;
    crate::store::client::update(conn, id, &patch, &now).map_err(db_err)?;
    client_view_by_id(conn, id, iface_name, cache)
}

/// Collect the addresses already assigned on a client field, skipping rows
/// whose value is absent or unparsable.
fn used_addresses<T: std::str::FromStr>(
    clients: &[Client],
    field: impl Fn(&Client) -> Option<&str>,
) -> Vec<T> {
    clients
        .iter()
        .filter_map(field)
        .filter_map(|s| s.parse().ok())
        .collect()
}

/// Borne les adresses `ipv4Address`/`ipv6Address` fournies par le patch :
/// elles doivent tomber dans le CIDR de l'interface du client et ne pas viser
/// l'adresse réseau, l'adresse serveur (`start + 1`) ni le broadcast / la
/// dernière adresse v6 (cf. [`crate::ip::validate_pool_address`]).
///
/// `null`/vide (effacement de l'adresse) reste autorisé ; une famille
/// désactivée est laissée telle quelle : sa valeur reste en base mais n'est
/// jamais rendue, donc le comportement antérieur est préservé.
fn enforce_client_address_bounds(
    conn: &Connection,
    client: &Client,
    upd: &ClientUpdate,
    disable_v4: bool,
    disable_v6: bool,
) -> Result<(), WebError> {
    let v4 = if disable_v4 {
        None
    } else {
        upd.ipv4_address.as_ref().and_then(|v| v.as_deref())
    };
    let v6 = if disable_v6 {
        None
    } else {
        upd.ipv6_address.as_ref().and_then(|v| v.as_deref())
    };
    if v4.is_none() && v6.is_none() {
        return Ok(());
    }
    let iface = interface_row(conn, &client.interface_id)?;
    if let Some(raw) = v4 {
        let addr: std::net::IpAddr = raw
            .parse()
            .map_err(|_| WebError::bad_request("bad ipv4 address"))?;
        crate::ip::validate_pool_address(addr, &iface.ipv4_cidr)
            .map_err(|e| WebError::bad_request(format!("bad ipv4 address: {e}")))?;
    }
    if let Some(raw) = v6 {
        let addr: std::net::IpAddr = raw
            .parse()
            .map_err(|_| WebError::bad_request("bad ipv6 address"))?;
        crate::ip::validate_pool_address(addr, &iface.ipv6_cidr)
            .map_err(|e| WebError::bad_request(format!("bad ipv6 address: {e}")))?;
    }
    Ok(())
}

/// A patch that flips `enabled` to `true` on an expired client answers 422,
/// exactly like the dedicated `enable` route. Disabling stays always allowed.
///
/// The effective expiry accounts for an `expiresAt` set in the same patch:
/// `Some(None)` clears it to permanent, `Some(Some(_))` replaces it (only an
/// admin can, cf. `handlers/client.rs::reject_admin_only_patch_keys`), `None`
/// keeps the stored value. Without this check a CLIENT whose admin fixed an
/// expiry could resurrect the client with a direct `PATCH {enabled:true}`.
fn enforce_enable_not_expired(client: &Client, upd: &ClientUpdate) -> Result<(), WebError> {
    if upd.enabled != Some(true) {
        return Ok(());
    }
    let effective = match &upd.expires_at {
        Some(v) => v.as_deref(),
        None => client.expires_at.as_deref(),
    };
    if let Some(exp) = effective {
        let now = now_iso()?;
        if exp <= now.as_str() {
            return Err(WebError::unprocessable("client expired"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Patch parsing
// ---------------------------------------------------------------------------

/// `name`: absent -> `None`, otherwise trimmed to 1..=64 characters and
/// plain-string checked.
fn name_field(map: &Map<String, Value>) -> Result<Option<String>, WebError> {
    let Some(v) = map.get("name") else {
        return Ok(None);
    };
    let Value::String(name) = v else {
        return Err(WebError::bad_request("bad client name"));
    };
    let name = name.trim().to_string();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(WebError::bad_request("bad client name"));
    }
    crate::validate::check_plain_string(&name).map_err(|e| WebError::bad_request(e.to_string()))?;
    Ok(Some(name))
}

/// `null` -> `None` (inherit), a valid `<T>` string -> `Some(trimmed)`,
/// anything else -> 400 `bad`.
fn nullable_ip<T: std::str::FromStr>(v: &Value, bad: &str) -> Result<Option<String>, WebError> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) => {
            s.parse::<T>().map_err(|_| WebError::bad_request(bad))?;
            Ok(Some(s.trim().to_string()))
        }
        _ => Err(WebError::bad_request(bad)),
    }
}

/// `null` -> `None` (inherit), a string array -> validated then serialized as
/// the JSON column, anything else -> 400 `bad`.
fn nullable_string_list<F>(v: &Value, bad: &str, validate: F) -> Result<Option<String>, WebError>
where
    F: FnOnce(&[String]) -> Result<(), WebError>,
{
    match v {
        Value::Null => Ok(None),
        Value::Array(_) => {
            let items = as_string_list(v)?;
            validate(&items)?;
            Ok(Some(
                serde_json::to_string(&items).map_err(|e| WebError::internal(e.to_string()))?,
            ))
        }
        _ => Err(WebError::bad_request(bad)),
    }
}

/// `null` -> `None`, an integer fitting a validated `u32` -> `Some`, anything
/// else -> 400 `bad`.
fn nullable_number<F>(v: &Value, bad: &str, validate: F) -> Result<Option<i64>, WebError>
where
    F: FnOnce(u32) -> Result<(), crate::validate::ValidationError>,
{
    match v {
        Value::Null => Ok(None),
        _ => number_value(v, bad, validate).map(Some),
    }
}

/// `null`/blank -> `None`, a valid `host:port` -> `Some(trimmed)`, anything
/// else -> 400. Written verbatim as `Endpoint = ...` in the server `.conf`,
/// and an invalid endpoint makes `wg` reject the sync.
fn nullable_endpoint(v: &Value) -> Result<Option<String>, WebError> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) => {
            let s = s.trim();
            if s.is_empty() {
                return Ok(None);
            }
            crate::validate::validate_endpoint(s)
                .map_err(|e| WebError::bad_request(e.to_string()))?;
            Ok(Some(s.to_string()))
        }
        _ => Err(WebError::bad_request("bad serverEndpoint")),
    }
}

/// `null`/blank -> empty (clears the per-client PSK), anything else -> 400.
/// The API never carries the key itself: generation goes through
/// `POST /api/client/:id/psk`.
fn nullable_psk(v: &Value) -> Result<String, WebError> {
    match v {
        Value::Null => Ok(String::new()),
        Value::String(s) if s.trim().is_empty() => Ok(String::new()),
        _ => Err(WebError::bad_request("bad preSharedKey")),
    }
}

/// Parse an `update_client` patch into a [`ClientUpdate`], validating every
/// field exactly as before (`null` = clear/inherit). `pub(crate)` so the router
/// tests can drive the real validation (as the `set_general` mock reuses
/// `general_update`).
pub(crate) fn parse_client_update(patch: &Value) -> Result<ClientUpdate, WebError> {
    reject_patch_keys(patch)?;
    let empty = Map::new();
    let map = match patch {
        Value::Object(map) => map,
        Value::Null => &empty,
        _ => return Err(WebError::bad_request("patch must be an object")),
    };
    let mut upd = ClientUpdate::default();
    if let Some(name) = name_field(map)? {
        upd.name = Some(name);
    }
    if let Some(v) = map.get("ipv4Address") {
        upd.ipv4_address = Some(nullable_ip::<std::net::Ipv4Addr>(v, "bad ipv4 address")?);
    }
    if let Some(v) = map.get("ipv6Address") {
        upd.ipv6_address = Some(nullable_ip::<std::net::Ipv6Addr>(v, "bad ipv6 address")?);
    }
    for (key, slot) in [
        ("allowedIpsV4", &mut upd.allowed_ips_v4),
        ("allowedIpsV6", &mut upd.allowed_ips_v6),
    ] {
        if let Some(v) = map.get(key) {
            *slot = Some(nullable_string_list(v, &format!("bad {key}"), |items| {
                crate::validate::validate_allowed_ips(items)
                    .map_err(|e| WebError::bad_request(e.to_string()))
            })?);
        }
    }
    for (key, slot) in [
        ("serverAllowedIpsV4", &mut upd.server_allowed_ips_v4),
        ("serverAllowedIpsV6", &mut upd.server_allowed_ips_v6),
    ] {
        if let Some(v) = map.get(key) {
            *slot = Some(server_allowed_ips_value(v)?);
        }
    }
    for (key, slot) in [
        ("firewallIpsV4", &mut upd.firewall_ips_v4),
        ("firewallIpsV6", &mut upd.firewall_ips_v6),
    ] {
        if let Some(v) = map.get(key) {
            *slot = Some(nullable_string_list(v, &format!("bad {key}"), |items| {
                for entry in items {
                    crate::validate::check_plain_string(entry)
                        .map_err(|e| WebError::bad_request(e.to_string()))?;
                    // A port is required as soon as a proto is present
                    // (`IP:port[/tcp|/udp]`); `IP/proto` alone is invalid.
                    let rule = firewall::parse_entry(entry)
                        .map_err(|e| WebError::bad_request(e.to_string()))?;
                    // La destination part verbatim en `-d` iptables : exiger
                    // une IP/CIDR comme `allowedIps` (noms, `*`, prefixe
                    // invalide refusés), sinon une ligne empoisonnée fait
                    // avorter tout le `Tunnel::apply` avant le `DROP` final.
                    crate::validate::validate_ip_or_cidr(&rule.dest)
                        .map_err(|e| WebError::bad_request(e.to_string()))?;
                }
                Ok(())
            })?);
        }
    }
    for (key, slot, v6) in [
        ("dnsV4", &mut upd.dns_v4, false),
        ("dnsV6", &mut upd.dns_v6, true),
    ] {
        if let Some(v) = map.get(key) {
            *slot = Some(nullable_string_list(v, &format!("bad {key}"), |items| {
                // M4 : une entrée DNS doit être une IP nue de la famille du
                // champ ; `[]` reste accepté (efface le DNS du client).
                crate::validate::validate_dns_list(items, v6)
                    .map_err(|e| WebError::bad_request(e.to_string()))
            })?);
        }
    }
    if let Some(v) = map.get("mtu") {
        upd.mtu = Some(nullable_number(
            v,
            "bad mtu",
            crate::validate::validate_mtu,
        )?);
    }
    if let Some(v) = map.get("persistentKeepalive") {
        upd.persistent_keepalive = Some(nullable_number(
            v,
            "bad keepalive",
            crate::validate::validate_keepalive,
        )?);
    }
    if let Some(v) = map.get("serverEndpoint") {
        upd.server_endpoint = Some(nullable_endpoint(v)?);
    }
    if let Some(v) = map.get("preSharedKey") {
        upd.pre_shared_key = Some(nullable_psk(v)?);
    }
    if let Some(v) = map.get("expiresAt") {
        upd.expires_at = Some(parse_expires_at(v)?);
    }
    if let Some(v) = map.get("enabled") {
        let Value::Bool(b) = v else {
            return Err(WebError::bad_request("bad enabled"));
        };
        upd.enabled = Some(*b);
    }
    Ok(upd)
}

impl SqliteBackend {
    pub(crate) async fn list_clients_inner(&self) -> Result<Vec<ClientView>, WebError> {
        let iface_name = self.iface_name();
        let cache = self.live_cache.clone();
        self.with_db(move |conn| {
            let live = cached_live_peers(&cache, &iface_name);
            let now = now_unix();
            let mut out = Vec::new();
            for iface in crate::store::interface::list(&conn).map_err(db_err)? {
                let cfg = userconfig_row(&conn, &iface.name)?;
                for c in crate::store::client::list(&conn, &iface.name).map_err(db_err)? {
                    out.push(client_view(&c, &cfg, &live, now)?);
                }
            }
            Ok(out)
        })
        .await
    }

    pub(crate) async fn get_client_inner(&self, id: i64) -> Result<Option<ClientView>, WebError> {
        let iface_name = self.iface_name();
        let cache = self.live_cache.clone();
        self.with_db(move |conn| {
            let Some(client) = crate::store::client::get(&conn, id).map_err(db_err)? else {
                return Ok(None);
            };
            client_view_for(&conn, &client, &iface_name, &cache).map(Some)
        })
        .await
    }

    pub(crate) async fn create_client_inner(&self, name: &str) -> Result<ClientView, WebError> {
        let name = name.trim().to_string();
        if name.is_empty() || name.chars().count() > 64 {
            return Err(WebError::bad_request("bad client name"));
        }
        crate::validate::check_plain_string(&name)
            .map_err(|e| WebError::bad_request(e.to_string()))?;
        let iface_name = self.iface_name();
        let disable_v4 = self.config.disable_ipv4;
        let disable_v6 = self.config.disable_ipv6;
        let cache = self.live_cache.clone();
        self.with_db(move |conn| {
            let iface = interface_row(&conn, &iface_name)?;
            let cfg = userconfig_row(&conn, &iface.name)?;
            let existing = crate::store::client::list(&conn, &iface.name).map_err(db_err)?;
            let used_v4 = used_addresses(&existing, |c| c.ipv4_address.as_deref());
            let used_v6 = used_addresses(&existing, |c| c.ipv6_address.as_deref());
            let v4_cidr = if disable_v4 {
                None
            } else {
                Some(iface.ipv4_cidr.as_str())
            };
            let v6_cidr = if disable_v6 {
                None
            } else {
                Some(iface.ipv6_cidr.as_str())
            };
            let (v4, v6) = crate::ip::allocate_pair(v4_cidr, v6_cidr, &used_v4, &used_v6)
                .map_err(|e| WebError::bad_request(e.to_string()))?;
            let runner = SystemRunner;
            let (private_key, public_key, psk) = generate_keypair(&runner)?;
            // Reglage global : PSK generee pour chaque nouveau client sauf
            // si l'admin l'a desactivee (`defaultPreSharedKey`).
            let pre_shared_key = if cfg.default_pre_shared_key {
                psk
            } else {
                String::new()
            };
            let now = now_iso()?;
            let input = NewClient {
                ipv4_address: v4.map(|v| v.to_string()),
                ipv6_address: v6.map(|v| v.to_string()),
                ..NewClient::base(
                    DEFAULT_API_USER_ID,
                    iface.name.clone(),
                    name.clone(),
                    private_key,
                    public_key,
                    pre_shared_key,
                )
            };
            let id = crate::store::client::create(&conn, &input, &now).map_err(db_err)?;
            let client = crate::store::client::get(&conn, id)
                .map_err(db_err)?
                .ok_or_else(|| WebError::internal("client row missing"))?;
            client_view_for(&conn, &client, &iface_name, &cache)
        })
        .await
    }

    pub(crate) async fn update_client_inner(
        &self,
        id: i64,
        patch: Value,
    ) -> Result<ClientView, WebError> {
        let upd = parse_client_update(&patch)?;
        let iface_name = self.iface_name();
        let disable_v4 = self.config.disable_ipv4;
        let disable_v6 = self.config.disable_ipv6;
        let cache = self.live_cache.clone();
        self.with_db(move |conn| {
            mutate_client(&conn, id, &iface_name, &cache, |client| {
                enforce_client_address_bounds(&conn, client, &upd, disable_v4, disable_v6)?;
                enforce_enable_not_expired(client, &upd)?;
                Ok(upd.clone())
            })
        })
        .await
    }

    pub(crate) async fn delete_client_inner(&self, id: i64) -> Result<(), WebError> {
        self.with_db(move |conn| {
            if !crate::store::client::delete(&conn, id).map_err(db_err)? {
                return Err(WebError::not_found("client not found"));
            }
            Ok(())
        })
        .await
    }

    pub(crate) async fn enable_client_inner(&self, id: i64) -> Result<ClientView, WebError> {
        let iface_name = self.iface_name();
        let cache = self.live_cache.clone();
        self.with_db(move |conn| {
            mutate_client(&conn, id, &iface_name, &cache, |client| {
                if let Some(exp) = client.expires_at.as_deref() {
                    let now = now_iso()?;
                    if exp <= now.as_str() {
                        // Expired clients answer 422 until expiration is updated.
                        return Err(WebError::unprocessable("client expired"));
                    }
                }
                Ok(ClientUpdate {
                    enabled: Some(true),
                    ..Default::default()
                })
            })
        })
        .await
    }

    pub(crate) async fn disable_client_inner(&self, id: i64) -> Result<ClientView, WebError> {
        let iface_name = self.iface_name();
        let cache = self.live_cache.clone();
        self.with_db(move |conn| {
            mutate_client(&conn, id, &iface_name, &cache, |_| {
                Ok(ClientUpdate {
                    enabled: Some(false),
                    ..Default::default()
                })
            })
        })
        .await
    }

    /// `POST|DELETE /api/client/:id/psk` : `enabled = true` genere une
    /// nouvelle PSK, `false` l'efface (override par client). L'appelant
    /// relance ensuite `Tunnel::apply` (regle d'effet client).
    pub(crate) async fn set_client_psk_inner(
        &self,
        id: i64,
        enabled: bool,
    ) -> Result<ClientView, WebError> {
        let iface_name = self.iface_name();
        let cache = self.live_cache.clone();
        self.with_db(move |conn| {
            mutate_client(&conn, id, &iface_name, &cache, |_| {
                let psk = if enabled {
                    let runner = SystemRunner;
                    let (_priv, _pub, psk) = generate_keypair(&runner)?;
                    psk
                } else {
                    String::new()
                };
                Ok(ClientUpdate {
                    pre_shared_key: Some(psk),
                    ..Default::default()
                })
            })
        })
        .await
    }

    /// `POST /api/client/:id/rotateKeys` : nouvelle paire de cles (privee +
    /// publique) pour ce client, PSK inchangee. L'appelant relance ensuite
    /// `Tunnel::apply` (regle d'effet client).
    pub(crate) async fn rotate_client_keys_inner(&self, id: i64) -> Result<ClientView, WebError> {
        let iface_name = self.iface_name();
        let cache = self.live_cache.clone();
        self.with_db(move |conn| {
            mutate_client(&conn, id, &iface_name, &cache, |_| {
                let runner = SystemRunner;
                let (private_key, public_key, _psk) = generate_keypair(&runner)?;
                Ok(ClientUpdate {
                    private_key: Some(private_key),
                    public_key: Some(public_key),
                    ..Default::default()
                })
            })
        })
        .await
    }

    pub(crate) async fn client_conf_inner(&self, id: i64) -> Result<(String, String), WebError> {
        let disable_v4 = self.config.disable_ipv4;
        let disable_v6 = self.config.disable_ipv6;
        self.with_db(move |conn| {
            let client = client_row(&conn, id)?;
            build_client_conf(&conn, &client, disable_v4, disable_v6)
        })
        .await
    }

    pub(crate) async fn global_defaults_inner(&self) -> Result<GlobalDefaults, WebError> {
        let iface_name = self.iface_name();
        self.with_db(move |conn| {
            let cfg = userconfig_row(&conn, &iface_name)?;
            let fw = crate::store::interface::get(&conn, &iface_name)
                .map_err(db_err)?
                .is_some_and(|i| i.firewall_enabled);
            Ok(GlobalDefaults {
                default_dns_v4: parse_json_vec(&cfg.default_dns_v4),
                default_dns_v6: parse_json_vec(&cfg.default_dns_v6),
                default_allowed_ips_v4: parse_json_vec(&cfg.default_allowed_ips_v4),
                default_allowed_ips_v6: parse_json_vec(&cfg.default_allowed_ips_v6),
                firewall_enabled: fw,
            })
        })
        .await
    }
}

/// Normalise une valeur `expiresAt` : `null`/chaine vide -> `None`
/// (permanent), `JJ-MM-AAAA` humain ou RFC 3339 -> forme canonique
/// **UTC a la seconde** `YYYY-MM-DDTHH:MM:SSZ` (offset converti, fraction
/// supprimee). Le stockage canonique rend la comparaison lexicographique du
/// cron (`expiresAt <= now`) et de `enable` valide ; tout le reste = 400.
fn parse_expires_at(v: &Value) -> Result<Option<String>, WebError> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) => {
            let s = s.trim();
            if s.is_empty() {
                return Ok(None);
            }
            use time::format_description::well_known::Rfc3339 as R;
            if let Ok(dt) = time::OffsetDateTime::parse(s, &R) {
                return canonical_expires(dt).map(Some);
            }
            const HUMAN: &[time::format_description::FormatItem<'_>] =
                time::macros::format_description!("[day]-[month]-[year]");
            let d =
                time::Date::parse(s, HUMAN).map_err(|_| WebError::bad_request("bad expiresAt"))?;
            let midnight = d.with_time(time::Time::MIDNIGHT).assume_utc();
            canonical_expires(midnight).map(Some)
        }
        _ => Err(WebError::bad_request("bad expiresAt")),
    }
}

/// Re-emit a parsed expiry in the canonical UTC whole-second shape shared by
/// every date column ([`crate::db::format_iso8601`]).
fn canonical_expires(dt: time::OffsetDateTime) -> Result<String, WebError> {
    crate::db::format_iso8601(dt).map_err(|e| WebError::internal(format!("expiresAt: {e}")))
}

/// `serverAllowedIps` -> JSON column. `null` = heritage, c'est-a-dire aucune
/// IP ajoutee au peer ; la colonne est `NOT NULL`, on ecrit donc `[]`.
/// Les entrees sont copiees telles quelles dans les `AllowedIPs` du peer
/// par [`crate::wg::render`], on verifie donc que chacune est une IP nue ou
/// un CIDR avant de la stocker.
fn server_allowed_ips_value(v: &Value) -> Result<String, WebError> {
    match v {
        Value::Null => Ok("[]".to_string()),
        Value::Array(_) => {
            let items = clean_strings(&as_string_list(v)?)?;
            for entry in &items {
                crate::validate::validate_ip_or_cidr(entry)
                    .map_err(|e| WebError::bad_request(e.to_string()))?;
            }
            serde_json::to_string(&items).map_err(|e| WebError::internal(e.to_string()))
        }
        _ => Err(WebError::bad_request("bad serverAllowedIps")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::memdb;
    use serde_json::json;

    fn err_message(e: &WebError) -> String {
        e.to_string()
    }

    #[test]
    fn expires_at_accepts_human_date_and_rfc3339() {
        // Vide / null = permanent.
        assert_eq!(parse_expires_at(&Value::Null).expect("null"), None);
        assert_eq!(parse_expires_at(&json!("  ")).expect("blank"), None);
        // JJ-MM-AAAA -> canonique RFC 3339 (cron + affichage inchanges).
        assert_eq!(
            parse_expires_at(&json!("25-12-2031")).expect("human"),
            Some("2031-12-25T00:00:00Z".to_string())
        );
        // RFC 3339 deja canonique : inchange.
        assert_eq!(
            parse_expires_at(&json!("2031-12-25T00:00:00Z")).expect("rfc"),
            Some("2031-12-25T00:00:00Z".to_string())
        );
        // Tout le reste = 400 : ISO sans heure, US, texte libre.
        for bad in [
            "2031-12-25",
            "12/25/2031",
            "25/12/2031",
            "demain",
            "32-12-2031",
            "25-13-2031",
        ] {
            assert!(parse_expires_at(&json!(bad)).is_err(), "doit refuser {bad}");
        }
    }

    /// M3: whatever the accepted input shape (offset, fractional seconds),
    /// `expiresAt` is stored as UTC whole seconds so the lexicographic
    /// comparison with `db::now_iso8601` (cron + `enable`) stays exact.
    #[test]
    fn expires_at_is_canonicalised_to_utc_whole_seconds() {
        // Offset +14:00 -> previous day 23:30 UTC.
        assert_eq!(
            parse_expires_at(&json!("2031-12-25T13:30:00+14:00")).expect("offset"),
            Some("2031-12-24T23:30:00Z".to_string())
        );
        // Offset -05:00 -> +5 h UTC.
        assert_eq!(
            parse_expires_at(&json!("2031-12-25T00:00:00-05:00")).expect("negative offset"),
            Some("2031-12-25T05:00:00Z".to_string())
        );
        // Fractional seconds are dropped, never stored (`...:00.5Z` would sort
        // *before* `...:00Z`).
        assert_eq!(
            parse_expires_at(&json!("2031-12-25T13:30:00.123456Z")).expect("fraction"),
            Some("2031-12-25T13:30:00Z".to_string())
        );
        // A lower-case separator (`t`/`z`) still normalises to the same shape.
        assert_eq!(
            parse_expires_at(&json!("2031-12-25T13:30:00z")).expect("lowercase"),
            Some("2031-12-25T13:30:00Z".to_string())
        );
    }

    /// M3: a PATCH that turns `enabled` back on must be refused 422 while the
    /// client is expired (same rule as the dedicated `enable` route); turning
    /// it off is always allowed, and setting a fresh future expiry unlocks it.
    #[test]
    fn enable_patch_is_refused_when_expired() {
        let expired = Client {
            expires_at: Some("2000-01-01T00:00:00Z".to_string()),
            ..client_fixture()
        };
        let on = ClientUpdate {
            enabled: Some(true),
            ..Default::default()
        };
        assert_eq!(
            enforce_enable_not_expired(&expired, &on)
                .expect_err("expired + enable must 422")
                .status(),
            axum::http::StatusCode::UNPROCESSABLE_ENTITY
        );

        // `enabled:false` is never blocked.
        let off = ClientUpdate {
            enabled: Some(false),
            ..Default::default()
        };
        assert!(enforce_enable_not_expired(&expired, &off).is_ok());

        // Replacing the expiry with a future one in the same patch unlocks it.
        let renewed = ClientUpdate {
            enabled: Some(true),
            expires_at: Some(Some("2999-01-01T00:00:00Z".to_string())),
            ..Default::default()
        };
        assert!(enforce_enable_not_expired(&expired, &renewed).is_ok());

        // Clearing it to permanent also unlocks it.
        let permanent = ClientUpdate {
            enabled: Some(true),
            expires_at: Some(None),
            ..Default::default()
        };
        assert!(enforce_enable_not_expired(&expired, &permanent).is_ok());

        // A non-expired client enables normally.
        let future = Client {
            expires_at: Some("2999-01-01T00:00:00Z".to_string()),
            ..client_fixture()
        };
        assert!(enforce_enable_not_expired(&future, &on).is_ok());
    }

    /// In-memory `Client` fixture for the enable/expiry guard tests.
    fn client_fixture() -> Client {
        Client {
            id: 1,
            user_id: 1,
            interface_id: "wg0".to_string(),
            name: "c".to_string(),
            ipv4_address: Some("10.8.0.2".to_string()),
            ipv6_address: None,
            private_key: "k".to_string(),
            public_key: "pub".to_string(),
            pre_shared_key: String::new(),
            allowed_ips_v4: None,
            allowed_ips_v6: None,
            server_allowed_ips_v4: "[]".to_string(),
            server_allowed_ips_v6: "[]".to_string(),
            firewall_ips_v4: None,
            firewall_ips_v6: None,
            dns_v4: None,
            dns_v6: None,
            mtu: None,
            persistent_keepalive: None,
            server_endpoint: None,
            enabled: true,
            expires_at: None,
            created_at: "t".to_string(),
            updated_at: "t".to_string(),
        }
    }

    /// M3: the cron selects expired clients through a lexicographic SQL
    /// comparison; the canonical whole-second shape must make that exact.
    #[test]
    fn disable_expired_matches_canonical_timestamps() {
        let conn = memdb();
        seed_owner_client(&conn);
        crate::store::client::update(
            &conn,
            1,
            &ClientUpdate {
                expires_at: Some(Some("2000-01-01T00:00:00Z".to_string())),
                ..Default::default()
            },
            "t",
        )
        .expect("expire");
        let now = crate::db::now_iso8601().expect("now");
        assert_eq!(
            crate::store::client::disable_expired(&conn, &now).expect("cron"),
            1,
            "an expired canonical row must be selected"
        );
        // A future canonical row is left alone.
        crate::store::client::update(
            &conn,
            1,
            &ClientUpdate {
                expires_at: Some(Some("2999-01-01T00:00:00Z".to_string())),
                enabled: Some(true),
                ..Default::default()
            },
            "t",
        )
        .expect("renew");
        assert_eq!(
            crate::store::client::disable_expired(&conn, &now).expect("cron"),
            0
        );
    }

    #[test]
    fn server_allowed_ips_null_is_inheritance() {
        // Un champ de formulaire vide arrive en `null` apres `coerce_patch` :
        // il doit etre accepte (colonne NOT NULL -> liste vide), pas 400.
        assert_eq!(
            server_allowed_ips_value(&Value::Null).expect("null"),
            "[]".to_string()
        );
    }

    #[test]
    fn server_allowed_ips_accepts_bare_ip_and_cidr() {
        for value in [
            json!([]),
            json!(["1.2.3.4"]),
            json!(["10.0.0.0/8"]),
            json!(["fd00::1"]),
            json!(["fd00::/8", "0.0.0.0/0"]),
        ] {
            let out = server_allowed_ips_value(&value).expect("valid");
            let back: Value = serde_json::from_str(&out).expect("json column");
            assert_eq!(back, value);
        }
    }

    #[test]
    fn server_allowed_ips_rejects_invalid_entries() {
        // Chaine vide / blancs : rejete par `clean_strings`.
        assert_eq!(
            err_message(&server_allowed_ips_value(&json!([""])).expect_err("empty")),
            "list items must not be empty"
        );
        // Ce n'est ni une IP ni un CIDR : la config WireGuard serait invalide.
        for bad in [
            json!(["pas-une-ip"]),
            json!(["0.0.0.0/0:51820"]),
            json!(["example.com"]),
            json!(["10.0.0.0/8/8"]),
        ] {
            let e = server_allowed_ips_value(&bad).expect_err("invalid");
            assert_eq!(e.status(), axum::http::StatusCode::BAD_REQUEST, "{bad}");
        }
        // Type inattendu (ce que produit un champ de formulaire non vide
        // envoye par l'UI : une chaine, pas un tableau).
        assert_eq!(
            err_message(&server_allowed_ips_value(&json!("10.0.0.0/8")).expect_err("string")),
            "bad serverAllowedIps"
        );
        assert!(server_allowed_ips_value(&json!(42)).is_err());
    }

    // -----------------------------------------------------------------------
    // I4 : bornage des adresses client dans le pool de l'interface.
    // -----------------------------------------------------------------------

    /// Insere un user et un client `id = 1` sur l'interface seedee `wg0`
    /// (`10.8.0.0/24`, pool IPv6 `...:cafe:0/112`).
    fn seed_owner_client(conn: &Connection) {
        conn.execute(
            "INSERT INTO users (id, username, name, role) VALUES (1, 'u', 'U', 1)",
            [],
        )
        .expect("user");
        conn.execute(
            "INSERT INTO clients (id, userId, interfaceId, name, ipv4Address, ipv6Address, \
             privateKey, publicKey, createdAt, updatedAt) \
             VALUES (1, 1, 'wg0', 'c', '10.8.0.2', 'fdcc:ad94:bacf:61a4::cafe:2', \
             'k', 'pub', 't', 't')",
            [],
        )
        .expect("client");
    }

    fn bounds_err(
        upd: &ClientUpdate,
        disable_v4: bool,
        disable_v6: bool,
    ) -> axum::http::StatusCode {
        let conn = memdb();
        seed_owner_client(&conn);
        let client = client_row(&conn, 1).expect("client");
        enforce_client_address_bounds(&conn, &client, upd, disable_v4, disable_v6)
            .expect_err("doit etre refuse")
            .status()
    }

    #[test]
    fn address_bounds_reject_network_server_broadcast_and_out_of_cidr() {
        for bad in [
            "10.8.0.0",
            "10.8.0.1",
            "10.8.0.255",
            "10.9.0.2",
            "192.168.0.1",
        ] {
            let upd = parse_client_update(&json!({ "ipv4Address": bad })).expect("parse");
            assert_eq!(
                bounds_err(&upd, false, false),
                axum::http::StatusCode::BAD_REQUEST,
                "{bad}"
            );
        }
    }

    #[test]
    fn address_bounds_validate_ipv6_pool() {
        for bad in [
            "fdcc:ad94:bacf:61a4::cafe:0",
            "fdcc:ad94:bacf:61a4::cafe:1",
            "fdcc:ad94:bacf:61a4::cafe:ffff",
            "fd00::1",
        ] {
            let upd = parse_client_update(&json!({ "ipv6Address": bad })).expect("parse");
            assert_eq!(
                bounds_err(&upd, false, false),
                axum::http::StatusCode::BAD_REQUEST,
                "{bad}"
            );
        }
    }

    #[test]
    fn valid_in_pool_address_is_accepted_and_persisted() {
        let conn = memdb();
        seed_owner_client(&conn);
        let client = client_row(&conn, 1).expect("client");
        let upd = parse_client_update(&json!({ "ipv4Address": "10.8.0.42" })).expect("parse");
        enforce_client_address_bounds(&conn, &client, &upd, false, false).expect("dans le pool");
        crate::store::client::update(&conn, 1, &upd, "t2").expect("update");
        let after = client_row(&conn, 1).expect("reload");
        assert_eq!(after.ipv4_address.as_deref(), Some("10.8.0.42"));
    }

    #[test]
    fn null_address_clears_and_is_always_allowed() {
        let conn = memdb();
        seed_owner_client(&conn);
        let client = client_row(&conn, 1).expect("client");
        let upd = parse_client_update(&json!({ "ipv4Address": null })).expect("parse");
        assert!(enforce_client_address_bounds(&conn, &client, &upd, false, false).is_ok());
    }

    #[test]
    fn disabled_family_is_left_untouched() {
        // Hors pool mais famille desactivee : valeur stockee mais inutilisee,
        // on ne casse pas le comportement anterieur (accepte, non borne).
        let conn = memdb();
        seed_owner_client(&conn);
        let client = client_row(&conn, 1).expect("client");
        let upd = parse_client_update(&json!({ "ipv4Address": "192.168.0.1" })).expect("parse");
        assert!(enforce_client_address_bounds(&conn, &client, &upd, true, false).is_ok());
    }

    /// M4 : `dnsV4`/`dnsV6` n'acceptent que des IP nues de la bonne famille.
    #[test]
    fn client_dns_fields_require_bare_ip_of_family() {
        // Valide : la valeur est persistee telle quelle.
        let upd = parse_client_update(&json!({ "dnsV4": ["1.1.1.1"] })).expect("parse");
        assert_eq!(
            upd.dns_v4.as_ref().and_then(|v| v.as_deref()),
            Some(r#"["1.1.1.1"]"#),
            "valid v4 DNS is serialized"
        );
        assert!(
            parse_client_update(&json!({ "dnsV6": ["2606:4700:4700::1111"] })).is_ok(),
            "valid v6 DNS"
        );

        // Invalide cote v4 : nom, CIDR, port, famille v6, controle.
        for bad in [
            "not-an-ip",
            "dns.google",
            "1.2.3.4/24",
            "1.2.3.4:53",
            "::1",
            "a\u{0}b",
        ] {
            let e = parse_client_update(&json!({ "dnsV4": [bad] })).expect_err(bad);
            assert_eq!(e.status(), axum::http::StatusCode::BAD_REQUEST, "{bad}");
        }
        // Invalide cote v6 : une IP v4 (mauvaise famille) est refusee.
        let e = parse_client_update(&json!({ "dnsV6": ["1.1.1.1"] })).expect_err("v6 family");
        assert_eq!(e.status(), axum::http::StatusCode::BAD_REQUEST);
        // Entree vide refusee (une liste vide `[]` reste valide = efface).
        assert!(parse_client_update(&json!({ "dnsV4": [""] })).is_err());
        assert!(parse_client_update(&json!({ "dnsV4": [] })).is_ok());
    }
}
