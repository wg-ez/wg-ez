#![forbid(unsafe_code)]

//! Shared helpers for [`super::SqliteBackend`]: error mapping, blocking
//! runner, view builders, client `.conf` rendering, snapshot loading,
//! key generation and patch validation.
//!
//! Everything here is `pub(crate)` (or re-exported `pub`) so the sibling
//! backend modules (`auth`, `clients`, `admin`, `metrics`, `setup`, `otl`)
//! share one implementation. No behavior lives here twice.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rusqlite::Connection;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;

use crate::tunnel::ApplySnapshot;
use crate::web::ctx::{ClientView, WebError};
use crate::wg::firewall::{self, FirewallClient, FirewallPlan};
use crate::wg::render::{self, ClientInterface, ClientPeer, PeerInput, ServerInterface};
use crate::wg::runner::{Runner, SystemRunner};
use crate::wg::status::{self, PeerStatus};

/// Map a SQLite error: uniqueness violations become 400 conflicts, everything
/// else a 500 so the detail stays server-side in the log.
///
/// Only `UNIQUE` / `PRIMARY KEY` duplicates are conflicts ([`crate::db::is_unique_violation`]);
/// `NOT NULL`, `CHECK`, `FOREIGN KEY` and the like remain genuine 500s.
///
/// The raw SQLite detail (`UNIQUE constraint failed: clients.ipv4Address`,
/// index names, ...) must **never** reach a < 500 response: it would disclose
/// the schema (M10). The client only ever sees `"conflict"`; the detail is
/// logged server-side and the body stays generic. The 500 branch keeps its
/// (masked) detail because [`crate::web::ctx::WebError`]'s renderer replaces
/// the body with `{"error":"internal error"}`.
pub(crate) fn db_err(e: rusqlite::Error) -> WebError {
    if crate::db::is_unique_violation(&e) {
        tracing::warn!("db conflict: {e}");
        WebError::bad_request("conflict")
    } else {
        tracing::error!("db error: {e}");
        WebError::internal(format!("db: {e}"))
    }
}

/// Load the singleton `general` row, or a 500 when the seed is missing.
pub(crate) fn general_row(conn: &Connection) -> Result<crate::store::general::General, WebError> {
    crate::store::general::get(conn)
        .map_err(db_err)?
        .ok_or_else(|| WebError::internal("general row missing"))
}

/// Load the `hooks` row of an interface, or a 500 when it is missing.
pub(crate) fn hooks_row(
    conn: &Connection,
    iface_name: &str,
) -> Result<crate::store::hooks::Hooks, WebError> {
    crate::store::hooks::get(conn, iface_name)
        .map_err(db_err)?
        .ok_or_else(|| WebError::internal("hooks row missing"))
}

/// Load the `interfaces` row, or a 500 when it is missing.
pub(crate) fn interface_row(
    conn: &Connection,
    iface_name: &str,
) -> Result<crate::store::interface::Interface, WebError> {
    crate::store::interface::get(conn, iface_name)
        .map_err(db_err)?
        .ok_or_else(|| WebError::internal("interface row missing"))
}

/// Load the `user_configs` row of an interface, or a 500 when it is missing.
pub(crate) fn userconfig_row(
    conn: &Connection,
    iface_name: &str,
) -> Result<crate::store::userconfig::UserConfig, WebError> {
    crate::store::userconfig::get(conn, iface_name)
        .map_err(db_err)?
        .ok_or_else(|| WebError::internal("user config row missing"))
}

/// Map a setup error to its HTTP status. Unsafe states (db, hash) are 500s;
/// validation/env problems are the caller's fault (400).
pub(crate) fn setup_err(e: crate::setup::SetupError) -> WebError {
    use crate::auth::password::PasswordError as P;
    use crate::setup::SetupError as E;
    let msg = e.to_string();
    match e {
        E::Db(_) => WebError::internal(msg),
        E::Password(P::TooShort) => WebError::bad_request(msg),
        E::Password(P::Hash(_)) => WebError::internal(msg),
        E::Validate(_) | E::Validation(_) | E::Env(_) | E::State(_) => WebError::bad_request(msg),
    }
}

/// Run blocking work (sqlite, argon2, `wg`) off the single-thread runtime.
pub(crate) async fn blocking<F, T>(f: F) -> Result<T, WebError>
where
    F: FnOnce() -> Result<T, WebError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| WebError::internal(format!("blocking task failed: {e}")))?
}

/// Open the DB with WAL + FK + migrations and a busy timeout so the 60 s
/// cron and the server never fail on a locked database.
pub(crate) fn open_path(db_path: &str) -> Result<Connection, WebError> {
    let conn =
        crate::db::open(Path::new(db_path)).map_err(|e| WebError::internal(format!("db: {e}")))?;
    conn.busy_timeout(Duration::from_secs(5))
        .map_err(|e| WebError::internal(format!("db: {e}")))?;
    Ok(conn)
}

/// Map a store `User` row onto the API view. `totp_enabled` is true only once
/// the secret has actually been verified.
pub(crate) fn user_view(u: &crate::store::user::User) -> crate::web::ctx::UserView {
    crate::web::ctx::UserView {
        id: u.id,
        username: u.username.clone(),
        name: u.name.clone(),
        role: u.role,
        totp_enabled: u.totp_key.is_some() && u.totp_verified,
        totp_verified: u.totp_verified,
    }
}

/// Parse a JSON string array, degrading to an empty list on any error. Used
/// for non-nullable columns whose malformed content must not fail a request.
pub(crate) fn parse_json_vec(raw: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(raw).unwrap_or_default()
}

/// Parse a nullable JSON string array column: `NULL` -> `None` (inherit),
/// anything else -> the parsed list. Malformed JSON is a 500 (data corrupt).
pub(crate) fn parse_json_opt(raw: Option<&str>) -> Result<Option<Vec<String>>, WebError> {
    raw.map(|s| serde_json::from_str(s).map_err(|e| WebError::internal(format!("db: {e}"))))
        .transpose()
}

/// Resolve a nullable JSON list column against its global default: `None`
/// means inherit, so the fallback is used (never an empty list).
pub(crate) fn resolve_json_list(raw: Option<&str>, fallback: &str) -> Vec<String> {
    parse_json_vec(raw.unwrap_or(fallback))
}

/// Server hooks are stored one line per row; a blank value means "no hook".
/// The renderer still expects a `Vec` because hooks are multi-line by contract.
fn hook_lines(raw: Option<&str>) -> Vec<String> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => vec![s.to_string()],
        None => Vec::new(),
    }
}

/// Convert a numeric column to `u16`, mapping an out-of-range value to a 500
/// tagged with the offending field.
fn checked_u16(value: i64, field: &str) -> Result<u16, WebError> {
    u16::try_from(value).map_err(|_| WebError::internal(format!("{field} out of range")))
}

/// Current wall-clock time in Unix seconds (`0` if the clock is pre-epoch).
///
/// Delegates to [`crate::db::now_unix_secs`], the canonical implementation.
pub(crate) fn now_unix() -> i64 {
    crate::db::now_unix_secs() as i64
}

/// Current wall-clock time in [`crate::db::now_iso8601`]'s RFC 3339 shape, or
/// a 500 when the clock cannot be formatted.
pub(crate) fn now_iso() -> Result<String, WebError> {
    crate::db::now_iso8601().map_err(|e| WebError::internal(format!("db: {e}")))
}

/// Format a Unix handshake timestamp as RFC 3339, or `None` when unset/out of
/// range (the UI treats it as "never").
pub(crate) fn handshake_iso(handshake_unix: i64) -> Option<String> {
    time::OffsetDateTime::from_unix_timestamp(handshake_unix)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

/// Best-effort live map (`wg show <iface> dump`) keyed by peer public key.
/// Any failure yields an empty map: live status must never fail a request.
pub(crate) fn live_map(runner: &SystemRunner, iface: &str) -> HashMap<String, PeerStatus> {
    let mut out = HashMap::new();
    let wg = crate::wg::runner::wg_executable();
    let args = vec!["show".to_string(), iface.to_string(), "dump".to_string()];
    let Ok(res) = runner.exec(&wg, &args, None) else {
        return out;
    };
    let Ok(text) = String::from_utf8(res.stdout) else {
        return out;
    };
    let Ok(peers) = status::parse_dump(&text) else {
        return out;
    };
    for p in peers {
        out.insert(p.public_key.clone(), p);
    }
    out
}

/// Short-lived slot holding the last `wg show <iface> dump` peer map.
///
/// A grid render runs `metrics_snapshot` (topbar) and `list_clients` (cards)
/// back-to-back, and the push watcher probes the same interface every tick.
/// Without a shared slot that is two to three independent `wg` processes a few
/// milliseconds apart — the visible CPU/RAM blip. The watcher publishes its
/// probe here and the render paths reuse it.
pub(crate) struct LiveCache {
    iface: String,
    at: Instant,
    map: HashMap<String, PeerStatus>,
}

/// Reuse window for [`LiveCache`]: larger than the few ms between the probes of
/// one request, smaller than every watcher cadence (5 s) so the watcher never
/// reads a stale entry and always probes fresh.
pub(crate) const LIVE_CACHE_TTL: Duration = Duration::from_secs(2);

/// Shared, mutable [`LiveCache`] slot owned by [`super::SqliteBackend`].
pub(crate) type LiveCacheSlot = Mutex<Option<LiveCache>>;

/// Probe `wg show <iface> dump` now, publish the map to `cache`, and return it.
///
/// Used by the watcher, which must observe the kernel at its own tick — it
/// never reads the cache, so a UI probe in between can never mask a change.
pub(crate) fn probe_live_peers(cache: &LiveCacheSlot, iface: &str) -> HashMap<String, PeerStatus> {
    let map = live_map(&SystemRunner, iface);
    let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(LiveCache {
        iface: iface.to_string(),
        at: Instant::now(),
        map: map.clone(),
    });
    map
}

/// Peer map from `cache` when fresh and for the same interface, else a fresh
/// probe that also refills it.
///
/// Used by the render paths: the watcher has just probed for the push that
/// triggered the render, so this is normally a cache hit and spawns no `wg`.
pub(crate) fn cached_live_peers(cache: &LiveCacheSlot, iface: &str) -> HashMap<String, PeerStatus> {
    {
        let guard = cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = guard.as_ref()
            && c.iface == iface
            && c.at.elapsed() < LIVE_CACHE_TTL
        {
            return c.map.clone();
        }
    }
    probe_live_peers(cache, iface)
}

/// Merge a probed peer state into `view` when the public key is present in
/// the live map; leave the zeroed view untouched otherwise.
pub(crate) fn apply_live(
    view: &mut ClientView,
    public_key: &str,
    live: &HashMap<String, PeerStatus>,
    now: i64,
) {
    if let Some(st) = live.get(public_key) {
        view.rx_bytes = st.transfer_rx;
        view.tx_bytes = st.transfer_tx;
        view.endpoint = st.endpoint.clone();
        view.latest_handshake_at = st.latest_handshake.and_then(handshake_iso);
        view.connected = status::is_connected(st.latest_handshake, now);
    }
}

/// Fingerprint of a live peer map plus a liveness hint, for the push watcher
/// (`StatusSignal`). The map is sorted first: `HashMap` iteration order is
/// not stable, and the fingerprint only needs to change when the *content*
/// changes. Two independent hashes are kept so the watcher can push a state
/// transition at once while coalescing byte-counter churn:
/// - `state`: peer set + endpoint + handshake + `connected`;
/// - `traffic`: rx/tx counters only.
///
/// `connected` is folded into `state` so a handshake ageing past the 2 min
/// window is observed even without new `wg` output.
///
/// Returns `(state, traffic, connected_count)`: the count is the number of
/// peers currently connected in the same probe, so the long-poll can render
/// the live topbar count without a fresh `wg show dump`.
pub(crate) fn live_fingerprint(live: &HashMap<String, PeerStatus>, now: i64) -> (u64, u64, u64) {
    let mut peers: Vec<(&String, &PeerStatus)> = live.iter().collect();
    peers.sort_unstable_by(|a, b| a.0.cmp(b.0));

    let mut state_h = DefaultHasher::new();
    let mut traffic_h = DefaultHasher::new();
    let mut connected_count = 0u64;
    for (key, peer) in peers {
        key.hash(&mut state_h);
        peer.endpoint.hash(&mut state_h);
        peer.latest_handshake.hash(&mut state_h);
        let connected = status::is_connected(peer.latest_handshake, now);
        connected_count += u64::from(connected);
        connected.hash(&mut state_h);

        key.hash(&mut traffic_h);
        peer.transfer_rx.hash(&mut traffic_h);
        peer.transfer_tx.hash(&mut traffic_h);
    }
    (state_h.finish(), traffic_h.finish(), connected_count)
}

/// Build the API view of a client row: resolve `null` inheritance against
/// `cfg` and merge the optional live peer status. Les deux familles sont
/// restituees telles quelles : l'UI grise celle qui est desactivee, mais la
/// valeur stockee n'est jamais perdue.
pub(crate) fn client_view(
    client: &crate::store::client::Client,
    cfg: &crate::store::userconfig::UserConfig,
    live: &HashMap<String, PeerStatus>,
    now: i64,
) -> Result<ClientView, WebError> {
    let mut view = ClientView {
        id: client.id,
        user_id: client.user_id,
        name: client.name.clone(),
        enabled: client.enabled,
        has_pre_shared_key: !client.pre_shared_key.trim().is_empty(),
        ipv4_address: client.ipv4_address.clone().unwrap_or_default(),
        ipv6_address: client.ipv6_address.clone(),
        allowed_ips_v4: parse_json_opt(client.allowed_ips_v4.as_deref())?,
        allowed_ips_v6: parse_json_opt(client.allowed_ips_v6.as_deref())?,
        // `serverAllowedIps` has no inherit semantics: blank -> `[]`.
        server_allowed_ips_v4: parse_json_vec(&client.server_allowed_ips_v4),
        server_allowed_ips_v6: parse_json_vec(&client.server_allowed_ips_v6),
        firewall_ips_v4: parse_json_opt(client.firewall_ips_v4.as_deref())?,
        firewall_ips_v6: parse_json_opt(client.firewall_ips_v6.as_deref())?,
        dns_v4: parse_json_opt(client.dns_v4.as_deref())?,
        dns_v6: parse_json_opt(client.dns_v6.as_deref())?,
        mtu: client.mtu.unwrap_or(cfg.default_mtu),
        persistent_keepalive: client.persistent_keepalive.unwrap_or(cfg.default_keepalive),
        server_endpoint: client.server_endpoint.clone(),
        expires_at: client.expires_at.clone(),
        created_at: client.created_at.clone(),
        endpoint: None,
        latest_handshake_at: None,
        rx_bytes: 0,
        tx_bytes: 0,
        connected: false,
    };
    apply_live(&mut view, &client.public_key, live, now);
    Ok(view)
}

/// Build the client `.conf` text + file name from DB rows.
pub(crate) fn build_client_conf(
    conn: &Connection,
    client: &crate::store::client::Client,
    disable_ipv4: bool,
    disable_ipv6: bool,
) -> Result<(String, String), WebError> {
    let iface = interface_row(conn, &client.interface_id)?;
    let cfg = userconfig_row(conn, &iface.name)?;
    let hide_v4 = disable_ipv4;
    let hide_v6 = disable_ipv6;
    if hide_v4 && hide_v6 {
        return Err(WebError::internal("no address family enabled"));
    }
    let v4 = if hide_v4 {
        None
    } else {
        client.ipv4_address.clone().filter(|s| !s.trim().is_empty())
    };
    let v6 = if hide_v6 {
        None
    } else {
        client.ipv6_address.clone().filter(|s| !s.trim().is_empty())
    };
    // DNS/AllowedIPs : uniquement la famille effectivement rendue, resolue
    // contre le defaut global de CETTE famille (heredite par famille).
    let mut dns = Vec::new();
    if !hide_v4 {
        dns.extend(resolve_json_list(
            client.dns_v4.as_deref(),
            &cfg.default_dns_v4,
        ));
    }
    if !hide_v6 {
        dns.extend(resolve_json_list(
            client.dns_v6.as_deref(),
            &cfg.default_dns_v6,
        ));
    }
    let mut allowed = Vec::new();
    if !hide_v4 {
        allowed.extend(resolve_json_list(
            client.allowed_ips_v4.as_deref(),
            &cfg.default_allowed_ips_v4,
        ));
    }
    if !hide_v6 {
        allowed.extend(resolve_json_list(
            client.allowed_ips_v6.as_deref(),
            &cfg.default_allowed_ips_v6,
        ));
    }
    let mtu = checked_u16(client.mtu.unwrap_or(cfg.default_mtu), "mtu")?;
    if !(1024..=9000).contains(&mtu) {
        return Err(WebError::internal("mtu out of range"));
    }
    let keepalive = checked_u16(
        client.persistent_keepalive.unwrap_or(cfg.default_keepalive),
        "keepalive",
    )?;
    let port = checked_u16(cfg.port, "port")?;
    if port == 0 {
        return Err(WebError::internal("port out of range"));
    }
    let endpoint = if cfg.host.trim().is_empty() {
        None
    } else {
        Some(
            render::format_endpoint(cfg.host.trim(), port)
                .map_err(|e| WebError::internal(e.to_string()))?,
        )
    };
    let psk = client.pre_shared_key.trim();
    let text = render::render_client(
        &ClientInterface {
            private_key: client.private_key.clone(),
            ipv4: v4,
            ipv6: v6,
            mtu,
            dns,
        },
        &ClientPeer {
            server_public_key: iface.public_key.clone(),
            preshared_key: if psk.is_empty() {
                None
            } else {
                Some(psk.to_string())
            },
            allowed_ips: allowed,
            keepalive,
            endpoint,
        },
    )
    .map_err(|e| WebError::internal(e.to_string()))?;
    Ok((format!("{}.conf", client.name), text))
}

/// Load a coherent [`ApplySnapshot`]: interface + enabled peers + firewall
/// plan. Used by `apply`, `restart` and the boot sequence in `main.rs`.
pub fn load_snapshot(
    conn: &Connection,
    iface_name: &str,
    disable_ipv4: bool,
    disable_ipv6: bool,
) -> Result<ApplySnapshot, WebError> {
    let iface = interface_row(conn, iface_name)?;
    let cfg = userconfig_row(conn, &iface.name)?;
    let hooks = hooks_row(conn, &iface.name)?;
    let clients = crate::store::client::list(conn, &iface.name).map_err(db_err)?;

    let address_v4 = if disable_ipv4 {
        None
    } else {
        let ip = crate::ip::server_address(&iface.ipv4_cidr)
            .map_err(|e| WebError::internal(e.to_string()))?;
        let prefix = crate::ip::prefix_len(&iface.ipv4_cidr)
            .map_err(|e| WebError::internal(e.to_string()))?;
        Some(format!("{ip}/{prefix}"))
    };
    let address_v6 = if disable_ipv6 {
        None
    } else {
        let ip = crate::ip::server_address(&iface.ipv6_cidr)
            .map_err(|e| WebError::internal(e.to_string()))?;
        let prefix = crate::ip::prefix_len(&iface.ipv6_cidr)
            .map_err(|e| WebError::internal(e.to_string()))?;
        Some(format!("{ip}/{prefix}"))
    };
    if address_v4.is_none() && address_v6.is_none() {
        return Err(WebError::internal("no address family enabled"));
    }
    let listen_port = checked_u16(iface.port, "port")?;
    if listen_port == 0 {
        return Err(WebError::internal("port out of range"));
    }
    let mtu = checked_u16(iface.mtu, "mtu")?;
    let server = ServerInterface {
        private_key: iface.private_key.clone(),
        address_v4,
        address_v6,
        listen_port,
        mtu,
        table: iface.routing_table.clone(),
        pre_up: hook_lines(Some(&hooks.pre_up)),
        post_up: hook_lines(Some(&hooks.post_up)),
        pre_down: hook_lines(Some(&hooks.pre_down)),
        post_down: hook_lines(Some(&hooks.post_down)),
    };

    let default_allowed_v4: Vec<String> = parse_json_vec(&cfg.default_allowed_ips_v4);
    let default_allowed_v6: Vec<String> = parse_json_vec(&cfg.default_allowed_ips_v6);
    let mut peers = Vec::new();
    let mut fw_clients = Vec::new();
    for c in clients.iter().filter(|c| c.enabled) {
        let v4 = if disable_ipv4 {
            None
        } else {
            c.ipv4_address.clone().filter(|s| !s.trim().is_empty())
        };
        let v6 = if disable_ipv6 {
            None
        } else {
            c.ipv6_address.clone().filter(|s| !s.trim().is_empty())
        };
        if v4.is_none() && v6.is_none() {
            return Err(WebError::internal("client has no tunnel address"));
        }
        // `serverAllowedIps` has no inherit semantics: blank -> `[]`.
        // Les routes supplementaires des deux familles sont concatenees.
        let mut server_allowed = parse_json_vec(&c.server_allowed_ips_v4);
        server_allowed.extend(parse_json_vec(&c.server_allowed_ips_v6));
        // Firewall rules: par famille, `firewallIps` non vide -> `allowedIps`
        // -> defaut global de la meme famille.
        let fw4: Option<Vec<String>> = parse_json_opt(c.firewall_ips_v4.as_deref())?;
        let ai4: Option<Vec<String>> = parse_json_opt(c.allowed_ips_v4.as_deref())?;
        let fw6: Option<Vec<String>> = parse_json_opt(c.firewall_ips_v6.as_deref())?;
        let ai6: Option<Vec<String>> = parse_json_opt(c.allowed_ips_v6.as_deref())?;
        let rules = if !disable_ipv4 {
            firewall::resolve_rules(fw4.as_deref(), ai4.as_deref(), &default_allowed_v4)
        } else {
            Vec::new()
        };
        let rules_v6 = if !disable_ipv6 {
            firewall::resolve_rules(fw6.as_deref(), ai6.as_deref(), &default_allowed_v6)
        } else {
            Vec::new()
        };
        let parsed = rules
            .iter()
            .chain(rules_v6.iter())
            .map(|entry| {
                firewall::parse_entry(entry).map_err(|e| WebError::internal(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        peers.push(PeerInput {
            public_key: c.public_key.clone(),
            preshared_key: {
                let psk = c.pre_shared_key.trim();
                if psk.is_empty() {
                    None
                } else {
                    Some(psk.to_string())
                }
            },
            ipv4: v4.clone(),
            ipv6: v6.clone(),
            server_allowed_ips: server_allowed,
            endpoint: c.server_endpoint.clone().filter(|s| !s.trim().is_empty()),
        });
        fw_clients.push(FirewallClient {
            id: c.id,
            name: c.name.clone(),
            ipv4: v4,
            ipv6: v6,
            rules: parsed,
        });
    }
    Ok(ApplySnapshot {
        iface: iface.name.clone(),
        server,
        peers,
        firewall: FirewallPlan {
            iface: iface.name.clone(),
            enabled: iface.firewall_enabled,
            disable_ipv4,
            disable_ipv6,
            clients: fw_clients,
        },
    })
}

/// Generate `(private_key, public_key, preshared_key)` via `wg`.
///
/// The public key is **always** the one derived by `wg pubkey` from the
/// private key: a random, unrelated public key would produce a peer that can
/// never complete a handshake (and an unclamped private key). When the `wg`
/// binary is unavailable we refuse to fabricate a keypair instead of
/// silently creating an unusable client.
pub fn generate_keypair(runner: &SystemRunner) -> Result<(String, String, String), WebError> {
    let exec_text = |program: &str, args: &[String], stdin: Option<&[u8]>| -> Option<String> {
        let out = runner.exec(program, args, stdin).ok()?;
        if !out.is_success() {
            return None;
        }
        let text = String::from_utf8(out.stdout).ok()?;
        let text = text.trim();
        (!text.is_empty()).then_some(text.to_string())
    };
    let wg = crate::wg::runner::wg_executable();
    let privkey = exec_text(&wg, &["genkey".to_string()], None).ok_or_else(|| {
        WebError::internal("wg genkey unavailable; refusing to fabricate a keypair")
    })?;
    let pubkey =
        exec_text(&wg, &["pubkey".to_string()], Some(privkey.as_bytes())).ok_or_else(|| {
            WebError::internal("wg pubkey unavailable; refusing a mismatched keypair")
        })?;
    let psk = exec_text(&wg, &["genpsk".to_string()], None)
        .ok_or_else(|| WebError::internal("wg genpsk unavailable"))?;
    Ok((privkey, pubkey, psk))
}

/// Boot/apply reconciliation of `interface.firewallEnabled`.
///
/// When the flag is set in DB but iptables is not available (see
/// [`firewall::check_at_boot`]), disable it in DB and warn. Returns `true`
/// when the flag was just disabled, so the boot sequence can add its own
/// stderr notice. Shared by the boot sequence (`main.rs`) and
/// [`super::SqliteBackend::apply_tunnel`].
pub fn reconcile_firewall_flag(
    conn: &Connection,
    iface_name: &str,
    disable_ipv6: bool,
) -> Result<bool, WebError> {
    let enabled = interface_row(conn, iface_name)?.firewall_enabled;
    if matches!(
        firewall::check_at_boot(&SystemRunner, enabled, disable_ipv6),
        firewall::BootFirewall::DisabledNoIptables
    ) {
        crate::store::interface::set_firewall_enabled(conn, iface_name, false).map_err(db_err)?;
        tracing::warn!("firewall disabled: iptables not available");
        Ok(true)
    } else {
        Ok(false)
    }
}

// ---------------------------------------------------------------------------
// Patch validation (client + admin)
// ---------------------------------------------------------------------------

/// Reject patch keys that could poison a prototype or carry control
/// characters, before any of them reaches a store call.
pub(crate) fn reject_patch_keys(patch: &Value) -> Result<(), WebError> {
    let Value::Object(map) = patch else {
        return Ok(());
    };
    for k in map.keys() {
        crate::validate::reject_proto_keys(k).map_err(|e| WebError::bad_request(e.to_string()))?;
        crate::validate::reject_control_chars(k)
            .map_err(|e| WebError::bad_request(e.to_string()))?;
    }
    Ok(())
}

/// Convert a `Value::Number` into an `i64` that must fit in a `u32` validated
/// by `validate`: a non-number, a non-integer or an out-of-`u32` value all map
/// to the caller's `bad` message, while `validate` owns the range message.
///
/// Callers wrap this with their own presence semantics: [`super::admin`]'s
/// `number_field` handles "key absent" and [`super::clients`]'s
/// `nullable_number` handles "`null` = inheritance".
pub(crate) fn number_value<F>(v: &Value, bad: &str, validate: F) -> Result<i64, WebError>
where
    F: FnOnce(u32) -> Result<(), crate::validate::ValidationError>,
{
    let Value::Number(n) = v else {
        return Err(WebError::bad_request(bad));
    };
    let raw = n.as_i64().ok_or_else(|| WebError::bad_request(bad))?;
    let unsigned = u32::try_from(raw).map_err(|_| WebError::bad_request(bad))?;
    validate(unsigned).map_err(|e| WebError::bad_request(e.to_string()))?;
    Ok(raw)
}

/// Parse a JSON array of strings, rejecting any non-string item.
pub(crate) fn as_string_list(v: &Value) -> Result<Vec<String>, WebError> {
    match v {
        Value::Array(items) => items
            .iter()
            .map(|it| match it {
                Value::String(s) => Ok(s.clone()),
                _ => Err(WebError::bad_request("list items must be strings")),
            })
            .collect(),
        _ => Err(WebError::bad_request("expected a string array")),
    }
}

/// Validate a list of user-supplied strings: no blank entries and no control
/// characters (delegated to [`crate::validate::check_plain_string`]).
pub(crate) fn clean_strings(items: &[String]) -> Result<Vec<String>, WebError> {
    for s in items {
        if s.trim().is_empty() {
            return Err(WebError::bad_request("list items must not be empty"));
        }
        crate::validate::check_plain_string(s).map_err(|e| WebError::bad_request(e.to_string()))?;
    }
    Ok(items.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(handshake: Option<i64>, rx: u64, tx: u64) -> PeerStatus {
        PeerStatus {
            public_key: "k".to_string(),
            endpoint: Some("198.51.100.1:1".to_string()),
            latest_handshake: handshake,
            transfer_rx: rx,
            transfer_tx: tx,
        }
    }

    #[test]
    fn fingerprint_is_order_independent_and_content_sensitive() {
        let now = 1_700_000_100;
        let mut a = HashMap::new();
        a.insert("k1".to_string(), peer(Some(1_700_000_000), 10, 20));
        a.insert("k2".to_string(), peer(None, 0, 0));

        // Same content, opposite insertion order -> same signal.
        let mut b = HashMap::new();
        b.insert("k2".to_string(), peer(None, 0, 0));
        b.insert("k1".to_string(), peer(Some(1_700_000_000), 10, 20));
        assert_eq!(live_fingerprint(&a, now), live_fingerprint(&b, now));

        // Moving traffic changes ONLY the traffic hash: the state hash (and
        // thus the connection status) must stay put.
        let mut c = a.clone();
        c.insert("k1".to_string(), peer(Some(1_700_000_000), 11, 20));
        let (state_a, traffic_a, count_a) = live_fingerprint(&a, now);
        let (state_c, traffic_c, _) = live_fingerprint(&c, now);
        assert_eq!(state_a, state_c, "counters must not affect the state hash");
        assert_ne!(traffic_a, traffic_c, "counter move must be visible");
        assert_eq!(count_a, 1, "one peer is connected in this probe");

        // The same handshake past the 2 min window is no longer counted and
        // changes the state hash (so the UI sees the stale transition).
        let (state_stale, _, count_stale) = live_fingerprint(&a, 1_700_000_000 + 601);
        assert_eq!(count_stale, 0, "stale handshake is not counted");
        assert_ne!(state_a, state_stale);
    }

    #[test]
    fn empty_live_map_is_neutral() {
        let empty = HashMap::new();
        let (state, traffic, count) = live_fingerprint(&empty, 1_700_000_000);
        assert_eq!(count, 0);
        assert_eq!(live_fingerprint(&empty, 1_700_000_999), (state, traffic, 0));
    }

    /// M10 : une violation d'unicité devient un 400 générique. Le message ne
    /// doit contenir ni « UNIQUE »/« constraint », ni le nom de la table ou de
    /// la colonne — le détail SQLite reste côté serveur (loggé).
    #[test]
    fn db_err_unique_is_generic_400() {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        conn.execute_batch(
            "CREATE TABLE clients (\
                 id INTEGER PRIMARY KEY, \
                 ipv4Address TEXT UNIQUE);",
        )
        .expect("schema");
        conn.execute("INSERT INTO clients (ipv4Address) VALUES ('10.8.0.2')", [])
            .expect("first insert");
        let raw = conn
            .execute("INSERT INTO clients (ipv4Address) VALUES ('10.8.0.2')", [])
            .expect_err("duplicate must violate UNIQUE");
        // Preuve que le brut contient bien le détail qu'on refuse de publier.
        assert!(raw.to_string().contains("UNIQUE"), "{raw}");

        let err = db_err(raw);
        assert_eq!(err.status(), axum::http::StatusCode::BAD_REQUEST);
        let msg = err.to_string();
        for needle in ["UNIQUE", "constraint", "clients", "ipv4Address", "sqlite"] {
            assert!(!msg.contains(needle), "fuite interne {needle:?} dans {msg}");
        }
        assert_eq!(msg, "conflict");
    }

    /// Le 500 (erreur non-unicité) reste inchangé : masqué à l'émission.
    #[test]
    fn db_err_non_unique_stays_internal() {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT NOT NULL)")
            .expect("schema");
        let raw = conn
            .execute("INSERT INTO t (v) VALUES (NULL)", [])
            .expect_err("NOT NULL must fail");
        let err = db_err(raw);
        assert_eq!(err.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }
}
