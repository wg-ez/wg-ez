#![forbid(unsafe_code)]

//! Admin operations for [`super::SqliteBackend`]: general, hooks,
//! interface, userconfig, CIDR reallocation, interface restart and the
//! 15-min cached `ip-info`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::PoisonError;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use rusqlite::Connection;
use serde_json::{Map, Value, json};

use super::SqliteBackend;
use super::common::{
    as_string_list, db_err, general_row, hooks_row, interface_row, now_iso, number_value,
    reject_patch_keys, userconfig_row,
};
use crate::store::general::General;
use crate::web::ctx::WebError;
use crate::wg::firewall;
use crate::wg::runner::SystemRunner;

/// Lifetime of the `GET /api/admin/ip-info` host/port cache.
const IPINFO_TTL: Duration = Duration::from_secs(15 * 60);

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Map a poisoned cache mutex to a 500.
fn lock_err<T>(e: PoisonError<T>) -> WebError {
    WebError::internal(format!("lock: {e}"))
}

/// Consume a JSON patch into its object, rejecting prototype-pollution and
/// control-character keys. `null` is an empty patch; any other type is 400.
fn patch_object(patch: Value) -> Result<Map<String, Value>, WebError> {
    reject_patch_keys(&patch)?;
    match patch {
        Value::Object(map) => Ok(map),
        Value::Null => Ok(Map::new()),
        _ => Err(WebError::bad_request("patch must be an object")),
    }
}

/// Read `key` as an integer that must fit in a `u32` validated by `validate`.
/// Absent -> `None`; wrong type or out-of-`u32` -> `bad {key}`. The range
/// message is owned by `validate`.
fn number_field<F>(
    map: &Map<String, Value>,
    key: &str,
    validate: F,
) -> Result<Option<i64>, WebError>
where
    F: FnOnce(u32) -> Result<(), crate::validate::ValidationError>,
{
    let Some(value) = map.get(key) else {
        return Ok(None);
    };
    let bad = format!("bad {key}");
    number_value(value, &bad, validate).map(Some)
}

/// Read `key` as a boolean. Absent -> `None`; any other type -> `bad {key}`.
fn bool_field(map: &Map<String, Value>, key: &str) -> Result<Option<bool>, WebError> {
    match map.get(key) {
        None => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(WebError::bad_request(format!("bad {key}"))),
    }
}

/// Server hooks a `PATCH` may replace. `None` = leave the stored value alone.
#[derive(Default)]
struct HooksPatch {
    pre_up: Option<String>,
    post_up: Option<String>,
    pre_down: Option<String>,
    post_down: Option<String>,
}

/// Extract the four server hooks from a patch, sanitizing each present value.
fn hooks_patch(map: &Map<String, Value>) -> Result<HooksPatch, WebError> {
    fn field(map: &Map<String, Value>, key: &str) -> Result<Option<String>, WebError> {
        match map.get(key) {
            None => Ok(None),
            Some(Value::String(s)) => crate::validate::sanitize_hook(s)
                .map(Some)
                .map_err(|e| WebError::bad_request(e.to_string())),
            Some(_) => Err(WebError::bad_request(format!("bad {key}"))),
        }
    }
    Ok(HooksPatch {
        pre_up: field(map, "preUp")?,
        post_up: field(map, "postUp")?,
        pre_down: field(map, "preDown")?,
        post_down: field(map, "postDown")?,
    })
}

/// Décision de mise à jour du mot de passe des métriques à partir d'un patch.
enum PasswordPatch {
    /// Clé absente ou chaîne vide/blanche : on conserve le hash stocké (le
    /// champ password de l'UI n'est jamais pré-rempli).
    Keep,
    /// `null` JSON explicite : on efface le hash.
    Clear,
    /// Chaîne non vide : nouveau clair à hasher.
    Set(String),
}

/// Lit `metricsPassword` depuis un patch (I6) :
/// - clé absente ou chaîne **vide/blanche** -> [`PasswordPatch::Keep`] ;
/// - `null` JSON -> [`PasswordPatch::Clear`] ;
/// - chaîne non vide (≤ 1024 o) -> [`PasswordPatch::Set`] ;
/// - tout autre type -> 400.
fn password_patch(map: &Map<String, Value>) -> Result<PasswordPatch, WebError> {
    match map.get("metricsPassword") {
        None => Ok(PasswordPatch::Keep),
        Some(Value::Null) => Ok(PasswordPatch::Clear),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(PasswordPatch::Keep),
        Some(Value::String(s)) => {
            if s.len() > 1024 {
                return Err(WebError::bad_request("bad metricsPassword"));
            }
            Ok(PasswordPatch::Set(s.clone()))
        }
        Some(_) => Err(WebError::bad_request("bad metricsPassword")),
    }
}

/// Nouveaux réglages `general` calculés depuis la ligne courante et un patch.
/// Pure hors hashage (fourni par l'appelant), donc testable sans base : c'est
/// ici que vivent la règle « champ vide = inchangé » et la garde I6
/// « métriques activées => Bearer obligatoire ».
#[derive(Debug)]
pub(crate) struct GeneralUpdate {
    pub(crate) session_timeout: i64,
    pub(crate) metrics_prometheus: bool,
    pub(crate) metrics_json: bool,
    pub(crate) metrics_password: Option<String>,
}

/// Fusionne un patch `general` dans la ligne courante. La garde I6 s'exécute
/// **avant** toute écriture : un patch refusé ne persiste rien.
pub(crate) fn general_update<H>(
    cur: &General,
    map: &Map<String, Value>,
    hash: H,
) -> Result<GeneralUpdate, WebError>
where
    H: FnOnce(&str) -> Result<String, WebError>,
{
    let timeout = match map.get("sessionTimeout") {
        None => None,
        Some(Value::Number(n)) => {
            let t = n
                .as_i64()
                .ok_or_else(|| WebError::bad_request("bad sessionTimeout"))?;
            if !(1..=31_536_000).contains(&t) {
                return Err(WebError::bad_request("bad sessionTimeout"));
            }
            Some(t)
        }
        Some(_) => return Err(WebError::bad_request("bad sessionTimeout")),
    };
    let prom = bool_field(map, "metricsPrometheus")?;
    let js = bool_field(map, "metricsJson")?;
    let metrics_password = match password_patch(map)? {
        PasswordPatch::Keep => cur.metrics_password.clone(),
        PasswordPatch::Clear => None,
        PasswordPatch::Set(clear) => Some(hash(&clear)?),
    };
    let metrics_prometheus = prom.unwrap_or(cur.metrics_prometheus);
    let metrics_json = js.unwrap_or(cur.metrics_json);
    // I6 : impossible d'exposer les métriques sans Bearer. Vérifié AVANT
    // l'UPDATE pour qu'un patch refusé ne persiste rien (le patch et
    // l'écriture partagent la même connexion, dans le même closure).
    if (metrics_prometheus || metrics_json) && metrics_password.is_none() {
        return Err(WebError::bad_request("metricsPassword required"));
    }
    Ok(GeneralUpdate {
        session_timeout: timeout.unwrap_or(cur.session_timeout),
        metrics_prometheus,
        metrics_json,
        metrics_password,
    })
}

/// Bornes des pools v4/v6 d'une interface, prêtes pour la réaffectation.
struct PoolBounds {
    v4_base: u32,
    v4_bcast: u32,
    v6_base: u128,
    v6_last: u128,
    disable_v4: bool,
    disable_v6: bool,
}

impl PoolBounds {
    fn new(
        ipv4_cidr: &str,
        ipv6_cidr: &str,
        disable_v4: bool,
        disable_v6: bool,
    ) -> Result<Self, WebError> {
        let (v4_base, v4_bcast) = if disable_v4 {
            (0, 0)
        } else {
            let v4: ipnet::IpNet = ipv4_cidr
                .parse()
                .map_err(|_| WebError::internal("bad ipv4Cidr"))?;
            match v4 {
                ipnet::IpNet::V4(n) => (u32::from(n.network()), u32::from(n.broadcast())),
                ipnet::IpNet::V6(_) => return Err(WebError::internal("bad ipv4Cidr")),
            }
        };
        let (v6_base, v6_last) = if disable_v6 {
            (0, 0)
        } else {
            let v6: ipnet::IpNet = ipv6_cidr
                .parse()
                .map_err(|_| WebError::internal("bad ipv6Cidr"))?;
            match v6 {
                ipnet::IpNet::V6(n) => (u128::from(n.network()), crate::ip::last_v6(&n)),
                ipnet::IpNet::V4(_) => return Err(WebError::internal("bad ipv6Cidr")),
            }
        };
        Ok(Self {
            v4_base,
            v4_bcast,
            v6_base,
            v6_last,
            disable_v4,
            disable_v6,
        })
    }
}

/// Réaffecte toutes les adresses des clients d'une interface (serveur =
/// start+1, clients start+2 dans l'ordre des `id`). Les familles desactivees
/// sont **laissees intactes** : leurs adresses restent en base (inutilisees),
/// jamais effacees.
///
/// Deux phases obligatoires : on libère d'abord toutes les adresses (`NULL`)
/// puis on réaffecte. Sans ça, une réaffectation croisée vise une adresse
/// encore portée par un client pas encore traité et heurte les contraintes
/// `UNIQUE(ipv4Address)` / `UNIQUE(ipv6Address)`. Doit tourner dans la
/// transaction ouverte par l'appelant.
fn reallocate_clients(
    conn: &Connection,
    interface_id: &str,
    pool: &PoolBounds,
    now: &str,
) -> Result<(), WebError> {
    use crate::store::client::{self, ClientUpdate};

    let mut clients = client::list(conn, interface_id).map_err(db_err)?;
    clients.sort_by_key(|c| c.id);

    for c in &clients {
        let patch = ClientUpdate {
            ipv4_address: if pool.disable_v4 { None } else { Some(None) },
            ipv6_address: if pool.disable_v6 { None } else { Some(None) },
            ..Default::default()
        };
        client::update(conn, c.id, &patch, now).map_err(db_err)?;
    }

    for (i, c) in clients.iter().enumerate() {
        let step = i as u64;
        let v4addr = if pool.disable_v4 {
            None
        } else {
            let a = pool
                .v4_base
                .checked_add(2 + step as u32)
                .filter(|a| *a < pool.v4_bcast)
                .ok_or_else(|| WebError::bad_request("IP pool exhausted"))?;
            Some(Ipv4Addr::from(a).to_string())
        };
        let v6addr = if pool.disable_v6 {
            None
        } else {
            let a = pool
                .v6_base
                .checked_add(2 + step as u128)
                .filter(|a| *a < pool.v6_last)
                .ok_or_else(|| WebError::bad_request("IP pool exhausted"))?;
            Some(Ipv6Addr::from(a).to_string())
        };
        let patch = ClientUpdate {
            ipv4_address: v4addr.map(Some),
            ipv6_address: v6addr.map(Some),
            ..Default::default()
        };
        client::update(conn, c.id, &patch, now).map_err(db_err)?;
    }
    Ok(())
}

impl SqliteBackend {
    pub(crate) async fn get_general_inner(&self) -> Result<Value, WebError> {
        self.with_db(move |conn| Ok(Self::general_json(&general_row(&conn)?)))
            .await
    }

    pub(crate) async fn set_general_inner(&self, patch: Value) -> Result<Value, WebError> {
        let map = patch_object(patch)?;
        self.with_db(move |conn| {
            let cur = general_row(&conn)?;
            let upd = general_update(&cur, &map, |clear| {
                crate::auth::password::hash_password_blocking(clear).map_err(|e| match e {
                    // Seule une longueur insuffisante est imputable au client ;
                    // un échec Argon2 est interne et ne doit pas exposer le
                    // Display de la dépendance dans un 400 (M10).
                    crate::auth::password::PasswordError::TooShort => {
                        WebError::bad_request(e.to_string())
                    }
                    other => {
                        tracing::error!("metrics password hash failed: {other}");
                        WebError::internal("password hash error")
                    }
                })
            })?;
            crate::store::general::update(
                &conn,
                upd.session_timeout,
                upd.metrics_prometheus,
                upd.metrics_json,
                upd.metrics_password.as_deref(),
            )
            .map_err(db_err)?;
            Ok(Self::general_json(&general_row(&conn)?))
        })
        .await
    }

    pub(crate) async fn get_hooks_inner(&self) -> Result<Value, WebError> {
        let iface_name = self.iface_name();
        self.with_db(move |conn| Ok(Self::hooks_json(&hooks_row(&conn, &iface_name)?)))
            .await
    }

    pub(crate) async fn set_hooks_inner(&self, patch: Value) -> Result<Value, WebError> {
        let patch = hooks_patch(&patch_object(patch)?)?;
        let iface_name = self.iface_name();
        self.with_db(move |conn| {
            let mut hooks = hooks_row(&conn, &iface_name)?;
            if let Some(v) = patch.pre_up {
                hooks.pre_up = v;
            }
            if let Some(v) = patch.post_up {
                hooks.post_up = v;
            }
            if let Some(v) = patch.pre_down {
                hooks.pre_down = v;
            }
            if let Some(v) = patch.post_down {
                hooks.post_down = v;
            }
            crate::store::hooks::upsert(&conn, &hooks).map_err(db_err)?;
            Ok(Self::hooks_json(&hooks))
        })
        .await
    }

    pub(crate) async fn get_interface_inner(&self) -> Result<Value, WebError> {
        let iface_name = self.iface_name();
        self.with_db(move |conn| Ok(Self::interface_json(&interface_row(&conn, &iface_name)?)))
            .await
    }

    pub(crate) async fn set_interface_inner(&self, patch: Value) -> Result<Value, WebError> {
        let map = patch_object(patch)?;
        let device = match map.get("device") {
            None => None,
            Some(Value::String(s)) => {
                let device = s.trim().to_string();
                if !crate::validate::is_valid_interface_name(&device) {
                    return Err(WebError::bad_request("bad device"));
                }
                crate::validate::check_plain_string(&device)
                    .map_err(|e| WebError::bad_request(e.to_string()))?;
                Some(device)
            }
            Some(_) => return Err(WebError::bad_request("bad device")),
        };
        let port = number_field(&map, "port", crate::validate::validate_port)?;
        let mtu = number_field(&map, "mtu", crate::validate::validate_mtu)?;
        let table = match map.get("routingTable") {
            None => None,
            Some(Value::String(s)) => {
                crate::validate::validate_table(s.trim())
                    .map_err(|e| WebError::bad_request(e.to_string()))?;
                Some(s.trim().to_string())
            }
            Some(_) => return Err(WebError::bad_request("bad routingTable")),
        };
        let firewall_enabled = bool_field(&map, "firewallEnabled")?;
        let iface_name = self.iface_name();
        let disable_v6 = self.config.disable_ipv6;
        let flag = self.firewall_on.clone();
        self.with_db(move |conn| {
            let mut iface = interface_row(&conn, &iface_name)?;
            if let Some(d) = device {
                iface.device = d;
            }
            if let Some(p) = port {
                iface.port = p;
            }
            if let Some(m) = mtu {
                iface.mtu = m;
            }
            if let Some(t) = table {
                iface.routing_table = t;
            }
            if let Some(want) = firewall_enabled
                && want != iface.firewall_enabled
            {
                if want {
                    // Enabling the firewall without iptables answers 400
                    // after a reprobe.
                    firewall::probe_for_enable(&SystemRunner, disable_v6)
                        .map_err(|e| WebError::bad_request(e.to_string()))?;
                }
                iface.firewall_enabled = want;
            }
            crate::store::interface::upsert(&conn, &iface).map_err(db_err)?;
            flag.store(iface.firewall_enabled, Ordering::Relaxed);
            Ok(Self::interface_json(&iface))
        })
        .await
    }

    pub(crate) async fn get_userconfig_inner(&self) -> Result<Value, WebError> {
        let iface_name = self.iface_name();
        self.with_db(move |conn| Ok(Self::userconfig_json(&userconfig_row(&conn, &iface_name)?)))
            .await
    }

    pub(crate) async fn set_userconfig_inner(&self, patch: Value) -> Result<Value, WebError> {
        let map = patch_object(patch)?;
        let host = match map.get("host") {
            None => None,
            Some(Value::String(s)) => {
                let host = s.trim().to_string();
                crate::validate::validate_host(&host)
                    .map_err(|e| WebError::bad_request(e.to_string()))?;
                Some(host)
            }
            Some(_) => return Err(WebError::bad_request("bad host")),
        };
        let port = number_field(&map, "port", crate::validate::validate_port)?;
        let dns = |key: &str, v6: bool| -> Result<Option<Vec<String>>, WebError> {
            match map.get(key) {
                None => Ok(None),
                Some(v) => {
                    let Value::Array(_) = v else {
                        return Err(WebError::bad_request(format!("bad {key}")));
                    };
                    let items = as_string_list(v)?;
                    if items.is_empty() {
                        return Err(WebError::bad_request(format!("bad {key}")));
                    }
                    // M4 : un DNS doit être une adresse IP nue de la bonne
                    // famille (ni nom, ni CIDR, ni port).
                    crate::validate::validate_dns_list(&items, v6)
                        .map_err(|e| WebError::bad_request(e.to_string()))?;
                    Ok(Some(items))
                }
            }
        };
        let dns_v4 = dns("defaultDnsV4", false)?;
        let dns_v6 = dns("defaultDnsV6", true)?;
        let allowed = |key: &str| -> Result<Option<Vec<String>>, WebError> {
            match map.get(key) {
                None => Ok(None),
                Some(v) => {
                    let Value::Array(_) = v else {
                        return Err(WebError::bad_request(format!("bad {key}")));
                    };
                    let items = as_string_list(v)?;
                    crate::validate::validate_allowed_ips(&items)
                        .map_err(|e| WebError::bad_request(e.to_string()))?;
                    Ok(Some(items))
                }
            }
        };
        let allowed_v4 = allowed("defaultAllowedIpsV4")?;
        let allowed_v6 = allowed("defaultAllowedIpsV6")?;
        let mtu = number_field(&map, "defaultMtu", crate::validate::validate_mtu)?;
        let keepalive = number_field(
            &map,
            "defaultKeepalive",
            crate::validate::validate_keepalive,
        )?;
        let preshared = bool_field(&map, "defaultPreSharedKey")?;
        let iface_name = self.iface_name();
        self.with_db(move |conn| {
            let mut cfg = userconfig_row(&conn, &iface_name)?;
            if let Some(h) = host {
                cfg.host = h;
            }
            if let Some(p) = port {
                cfg.port = p;
            }
            if let Some(d) = dns_v4 {
                cfg.default_dns_v4 =
                    serde_json::to_string(&d).map_err(|e| WebError::internal(e.to_string()))?;
            }
            if let Some(d) = dns_v6 {
                cfg.default_dns_v6 =
                    serde_json::to_string(&d).map_err(|e| WebError::internal(e.to_string()))?;
            }
            if let Some(a) = allowed_v4 {
                cfg.default_allowed_ips_v4 =
                    serde_json::to_string(&a).map_err(|e| WebError::internal(e.to_string()))?;
            }
            if let Some(a) = allowed_v6 {
                cfg.default_allowed_ips_v6 =
                    serde_json::to_string(&a).map_err(|e| WebError::internal(e.to_string()))?;
            }
            if let Some(m) = mtu {
                cfg.default_mtu = m;
            }
            if let Some(k) = keepalive {
                cfg.default_keepalive = k;
            }
            if let Some(p) = preshared {
                cfg.default_pre_shared_key = p;
            }
            crate::store::userconfig::upsert(&conn, &cfg).map_err(db_err)?;
            Ok(Self::userconfig_json(&cfg))
        })
        .await
    }

    pub(crate) async fn change_cidr_inner(
        &self,
        ipv4_cidr: Option<&str>,
        ipv6_cidr: Option<&str>,
    ) -> Result<Value, WebError> {
        let disable_v4 = self.config.disable_ipv4;
        let disable_v6 = self.config.disable_ipv6;
        let v4 = ipv4_cidr
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let v6 = ipv6_cidr
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        // Une famille desactivee ne peut pas etre modifiee : ses valeurs
        // restent en base, inutilisees.
        if disable_v4 && v4.is_some() {
            return Err(WebError::bad_request("IPv4 is disabled"));
        }
        if disable_v6 && v6.is_some() {
            return Err(WebError::bad_request("IPv6 is disabled"));
        }
        if v4.is_none() && v6.is_none() {
            return Err(WebError::bad_request("nothing to change"));
        }
        if let Some(c) = &v4 {
            let net: ipnet::IpNet = c
                .parse()
                .map_err(|_| WebError::bad_request("bad ipv4Cidr"))?;
            if matches!(net, ipnet::IpNet::V6(_)) {
                return Err(WebError::bad_request("bad ipv4Cidr"));
            }
        }
        if let Some(c) = &v6 {
            let net: ipnet::IpNet = c
                .parse()
                .map_err(|_| WebError::bad_request("bad ipv6Cidr"))?;
            if matches!(net, ipnet::IpNet::V4(_)) {
                return Err(WebError::bad_request("bad ipv6Cidr"));
            }
        }
        let iface_name = self.iface_name();
        self.with_db(move |mut conn| {
            let tx = conn.transaction().map_err(db_err)?;
            let mut iface = interface_row(&tx, &iface_name)?;
            let old_v4 = iface.ipv4_cidr.clone();
            let old_v6 = iface.ipv6_cidr.clone();
            if let Some(c) = &v4 {
                iface.ipv4_cidr = c.clone();
            }
            if let Some(c) = &v6 {
                iface.ipv6_cidr = c.clone();
            }
            crate::store::interface::upsert(&tx, &iface).map_err(db_err)?;
            // Le CIDR vit aussi dans les hooks (ex. `-s 10.8.0.0/24` du
            // MASQUERADE) : le répercuter pour que le NAT suive l'interface.
            if old_v4 != iface.ipv4_cidr || old_v6 != iface.ipv6_cidr {
                crate::store::hooks::sync_cidr(
                    &tx,
                    &iface_name,
                    &old_v4,
                    &iface.ipv4_cidr,
                    &old_v6,
                    &iface.ipv6_cidr,
                )
                .map_err(db_err)?;
            }
            // Reallocate every client from the new pools (id order). Two-phase
            // inside the transaction: free (NULL) then assign, so a crossed
            // reassignment never collides with a client not yet processed.
            let now = now_iso()?;
            let pool = PoolBounds::new(&iface.ipv4_cidr, &iface.ipv6_cidr, disable_v4, disable_v6)?;
            reallocate_clients(&tx, &iface.name, &pool, &now)?;
            let iface = interface_row(&tx, &iface_name)?;
            let out = Self::interface_json(&iface);
            tx.commit().map_err(db_err)?;
            Ok(out)
        })
        .await
    }

    pub(crate) async fn restart_interface_inner(&self) -> Result<(), WebError> {
        let iface_name = self.iface_name();
        let disable_v4 = self.config.disable_ipv4;
        let disable_v6 = self.config.disable_ipv6;
        let tunnel = self.tunnel.clone();
        self.with_db(move |conn| {
            let snap = super::common::load_snapshot(&conn, &iface_name, disable_v4, disable_v6)?;
            // Explicit admin button: `down` then `up` (cuts tunnels).
            tunnel
                .restart(&snap)
                .map_err(|e| WebError::internal(format!("restart: {e}")))?;
            Ok(())
        })
        .await
    }

    pub(crate) async fn ip_info_inner(&self) -> Result<Value, WebError> {
        if let Some(cached) = self.ipinfo_cached()? {
            return Ok(cached);
        }
        let iface_name = self.iface_name();
        let value = self
            .with_db(move |conn| {
                let cfg = userconfig_row(&conn, &iface_name)?;
                let iface = interface_row(&conn, &iface_name)?;
                Ok::<Value, WebError>(json!({
                    "hosts": cfg.host,
                    "port": iface.port,
                }))
            })
            .await?;
        self.cache_ipinfo(&value)?;
        Ok(value)
    }

    /// Return the cached `ip-info` response while it is younger than
    /// [`IPINFO_TTL`].
    fn ipinfo_cached(&self) -> Result<Option<Value>, WebError> {
        let guard = self.ipinfo_cache.lock().map_err(lock_err)?;
        if let (Some(t), Some(v)) = (guard.0, guard.1.clone())
            && t.elapsed() < IPINFO_TTL
        {
            return Ok(Some(v));
        }
        Ok(None)
    }

    /// Store a fresh `ip-info` response with its timestamp.
    fn cache_ipinfo(&self, value: &Value) -> Result<(), WebError> {
        let mut guard = self.ipinfo_cache.lock().map_err(lock_err)?;
        *guard = (Some(Instant::now()), Some(value.clone()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::memdb;

    /// Deux clients dont les nouvelles adresses se croisent (ordre des `id`
    /// différent de l'ordre des adresses) : sans la phase `NULL` préalable,
    /// la réaffectation violerait `UNIQUE(ipv6Address)`.
    #[test]
    fn reallocate_survives_crossed_unique_addresses() {
        let conn = memdb();
        conn.execute(
            "INSERT INTO users (id, username, name, role) VALUES (1, 'u', 'U', 1)",
            [],
        )
        .expect("user");
        for (id, v4, v6) in [
            (1_i64, "10.8.0.2", "fdcc:ad94:bacf:61a4::cafe:2"),
            (12, "10.8.0.5", "fdcc:ad94:bacf:61a4::cafe:5"),
            (13, "10.8.0.3", "fdcc:ad94:bacf:61a4::cafe:3"),
        ] {
            conn.execute(
                "INSERT INTO clients (id, userId, interfaceId, name, ipv4Address, ipv6Address, \
                 privateKey, publicKey, createdAt, updatedAt) \
                 VALUES (?1, 1, 'wg0', ?2, ?3, ?4, 'k', ?5, 't', 't')",
                rusqlite::params![id, format!("c{id}"), v4, v6, format!("pub{id}")],
            )
            .expect("client");
        }

        let pool = PoolBounds::new(
            "10.20.0.0/24",
            "fdcc:ad94:bacf:61a4::cafe:0/112",
            false,
            false,
        )
        .expect("pool");
        reallocate_clients(&conn, "wg0", &pool, "t2").expect("reallocate");

        let mut stmt = conn
            .prepare("SELECT id, ipv4Address, ipv6Address FROM clients ORDER BY id")
            .expect("stmt");
        let rows: Vec<(i64, String, String)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .expect("query")
            .map(|r| r.expect("row"))
            .collect();
        assert_eq!(
            rows,
            vec![
                (
                    1,
                    "10.20.0.2".to_string(),
                    "fdcc:ad94:bacf:61a4::cafe:2".to_string()
                ),
                (
                    12,
                    "10.20.0.3".to_string(),
                    "fdcc:ad94:bacf:61a4::cafe:3".to_string()
                ),
                (
                    13,
                    "10.20.0.4".to_string(),
                    "fdcc:ad94:bacf:61a4::cafe:4".to_string()
                ),
            ]
        );
    }

    fn general_fixture(password: Option<&str>) -> General {
        General {
            id: 1,
            setup_step: 0,
            session_timeout: 3600,
            metrics_prometheus: false,
            metrics_json: false,
            metrics_password: password.map(str::to_string),
        }
    }

    fn patch(v: Value) -> Map<String, Value> {
        v.as_object().cloned().expect("patch object")
    }

    /// I6 : activer une métrique sans Bearer stocké est refusé (400), que le
    /// mot de passe soit déjà absent ou effacé par le patch.
    #[test]
    fn enabling_metrics_without_password_is_rejected() {
        let cur = general_fixture(None);
        let err = general_update(&cur, &patch(json!({ "metricsPrometheus": true })), |_| {
            Ok("unused".into())
        })
        .expect_err("must reject");
        assert_eq!(err.status(), axum::http::StatusCode::BAD_REQUEST);

        // Metrics off (or unchanged) stays allowed without a password.
        assert!(
            general_update(
                &cur,
                &patch(json!({ "metricsPrometheus": false, "metricsJson": false })),
                |_| Ok("unused".into()),
            )
            .is_ok()
        );
    }

    /// I6 : effacer le mot de passe alors que les métriques restent actives
    /// est refusé (sinon l'endpoint deviendrait public).
    #[test]
    fn clearing_password_while_metrics_enabled_is_rejected() {
        let mut cur = general_fixture(Some("stored-hash"));
        cur.metrics_json = true;
        let err = general_update(&cur, &patch(json!({ "metricsPassword": null })), |_| {
            Ok("unused".into())
        })
        .expect_err("must reject");
        assert_eq!(err.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    /// Le champ password de l'UI, vide, ne doit JAMAIS effacer le hash déjà
    /// stocké (on peut activer les métriques avec un mot de passe existant).
    #[test]
    fn empty_ui_password_field_keeps_the_stored_password() {
        let cur = general_fixture(Some("stored-hash"));
        let upd = general_update(
            &cur,
            &patch(json!({
                "metricsPassword": "",
                "metricsPrometheus": true,
                "metricsJson": true,
            })),
            |_| Ok("should-not-be-used".into()),
        )
        .expect("keep");
        assert_eq!(upd.metrics_password.as_deref(), Some("stored-hash"));
        assert!(upd.metrics_prometheus && upd.metrics_json);
    }

    /// `null` efface (métriques désactivées) et une chaîne non vide remplace
    /// le hash en hashant le clair.
    #[test]
    fn explicit_null_clears_and_new_password_replaces() {
        let cur = general_fixture(Some("stored-hash"));
        let cleared = general_update(
            &cur,
            &patch(json!({
                "metricsPassword": null,
                "metricsPrometheus": false,
                "metricsJson": false,
            })),
            |_| Ok("unused".into()),
        )
        .expect("clear");
        assert!(cleared.metrics_password.is_none());

        let replaced = general_update(
            &cur,
            &patch(json!({ "metricsPassword": "scrape-secret", "metricsJson": true })),
            |clear| Ok(format!("hash:{clear}")),
        )
        .expect("replace");
        assert_eq!(
            replaced.metrics_password.as_deref(),
            Some("hash:scrape-secret")
        );
    }

    /// Construit un backend SQLite réel sur une base temporaire (les tests
    /// unitaires `set_userconfig_inner` ont besoin d'une vraie DB).
    fn temp_backend(tag: &str) -> SqliteBackend {
        let dir = std::env::temp_dir();
        let db = dir.join(format!("wgez-m4-{}-{tag}.db", std::process::id()));
        let _ = std::fs::remove_file(&db);
        let config = crate::config::AppConfig {
            host: "0.0.0.0".to_string(),
            port: 51821,
            insecure: true,
            disable_ipv6: false,
            disable_ipv4: false,
            disable_password_auth: false,
            wg_interface: "wg0".to_string(),
            trusted_proxies: Vec::new(),
            db_path: db.display().to_string(),
            wg_conf_dir: dir.display().to_string(),
            init: None,
        };
        SqliteBackend::new(config).expect("backend")
    }

    /// M4 : `set_userconfig_inner` refuse un DNS qui n'est pas une IP nue de la
    /// bonne famille et accepte une IP valide.
    #[tokio::test]
    async fn userconfig_default_dns_must_be_bare_ip() {
        let backend = temp_backend("dns");
        let err = backend
            .set_userconfig_inner(json!({ "defaultDnsV4": ["not-an-ip"] }))
            .await
            .expect_err("invalid DNS must be rejected");
        assert_eq!(err.status(), axum::http::StatusCode::BAD_REQUEST);

        // Mauvaise famille : une IP v6 dans `defaultDnsV4`.
        let err = backend
            .set_userconfig_inner(json!({ "defaultDnsV4": ["2606:4700:4700::1111"] }))
            .await
            .expect_err("wrong family must be rejected");
        assert_eq!(err.status(), axum::http::StatusCode::BAD_REQUEST);

        // Valide : accepté et persisté.
        let out = backend
            .set_userconfig_inner(json!({ "defaultDnsV4": ["1.1.1.1"] }))
            .await
            .expect("valid DNS");
        assert_eq!(out["defaultDnsV4"], json!(["1.1.1.1"]));

        // Une IP v4 dans le champ v6 est refusée.
        let err = backend
            .set_userconfig_inner(json!({ "defaultDnsV6": ["1.1.1.1"] }))
            .await
            .expect_err("v4 in v6 field must be rejected");
        assert_eq!(err.status(), axum::http::StatusCode::BAD_REQUEST);
    }
}
