#![forbid(unsafe_code)]

//! Production backend: `SqliteBackend` implements [`crate::web::ctx::Backend`].
//!
//! Thin orchestrator over the `backend/*` submodules, one per concern:
//! `common` (shared helpers: error mapping, `spawn_blocking` runner, view
//! builders, client `.conf` rendering, [`load_snapshot`], [`generate_keypair`],
//! patch validation), `auth` (password / session / "me" / TOTP), `clients`
//! (CRUD), `otl` (one-time links), `api_tokens` (long-lived Bearer tokens),
//! `admin` (general / hooks / interface /
//! userconfig / CIDR / restart / ip-info), `metrics` (snapshots + Bearer
//! check), `setup` (setup steps + meta queries).
//!
//! Rules honored here:
//! - every blocking call (sqlite, argon2, `wg`) runs inside
//!   `tokio::task::spawn_blocking` (single-thread `current_thread` runtime);
//! - every fallible method returns `Result`; no `unwrap`/`expect`, no
//!   `unsafe`;
//! - `null` = inheritance (`allowedIps`/`dns` fall back to the global
//!   default, `firewallIps` falls back to `allowedIps` then the global
//!   default); `None` is never confused with `[]`;
//! - every client/admin POST|DELETE caller runs the full `Tunnel::apply`
//!   afterwards (the handlers do that via [`Backend::apply_tunnel`]); OTL
//!   generation is the only mutation without a kernel effect;
//! - session cookies store a 256-bit token; only its SHA-256 hex (as hashed
//!   by [`crate::web::guards::hash_token`]) is persisted.

mod admin;
mod api_tokens;
mod auth;
mod clients;
mod common;
mod metrics;
mod otl;
mod setup;

/// Re-export the pure `general` merge so tests can exercise the real I6 guard
/// (`metricsPassword required`, empty field keeps the stored hash) without a
/// database.
#[cfg(test)]
pub(crate) use admin::general_update;
/// Exposée aux tests routeur : la validation réelle d'un patch client (M4).
#[cfg(test)]
pub(crate) use clients::parse_client_update;
/// Re-export crate-visible : la traduction réelle d'une erreur SQLite (M10),
/// partagée par le backend et les tests routeur.
pub(crate) use common::db_err;

pub use common::{generate_keypair, load_snapshot, reconcile_firewall_flag};
// Crate-visible re-export so the offline CLI shares the exact same client
// `.conf` resolution as the server (`/cnf/*`, OTL, QR).
pub(crate) use common::build_client_conf;

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Instant;

use rusqlite::Connection;
use serde_json::{Value, json};

use crate::config::AppConfig;
use crate::tunnel::Tunnel;
use crate::web::ctx::{
    ApiTokenCreated, ApiTokenView, Backend, ClientView, GlobalDefaults, LoginOutcome,
    MetricsSnapshot, OtlOutcome, OtlView, StatusSignal, TotpSetup, UserView, WebError,
};
use crate::wg::runner::SystemRunner;

use common::{
    LiveCacheSlot, blocking, interface_row, live_fingerprint, now_unix, open_path, parse_json_vec,
    probe_live_peers,
};

// ---------------------------------------------------------------------------
// Forwarding macro
// ---------------------------------------------------------------------------

/// Generates the `impl Backend for SqliteBackend` async forwarders of the form
/// `async fn $name(..) -> $ret { self.$inner(..).await }`.
///
/// Only the pure one-line delegations to a `*_inner` method live here. The
/// synchronous getters (`app_version`, `insecure`,
/// `ipv4_enabled`, `ipv6_enabled`) and the two async methods that carry real
/// logic (`apply_tunnel`, `status_signal`) stay handwritten in the impl below.
macro_rules! forward_async {
    ($(fn $name:ident($($arg:ident : $ty:ty),* $(,)?) -> $ret:ty => $inner:ident;)*) => {
        $(
            async fn $name(&self $(, $arg: $ty)*) -> $ret {
                self.$inner($($arg),*).await
            }
        )*
    };
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// Production [`Backend`]: SQLite + argon2 + `wg`, all blocking work inside
/// `spawn_blocking`.
pub struct SqliteBackend {
    db_path: String,
    config: AppConfig,
    tunnel: Arc<Tunnel<SystemRunner>>,
    /// Cached `interface.firewallEnabled` (the trait getter is sync).
    firewall_on: Arc<AtomicBool>,
    /// 15-min cache for `GET /api/admin/ip-info` host candidates.
    ipinfo_cache: Arc<Mutex<(Option<Instant>, Option<Value>)>>,
    /// Short-lived shared `wg dump` cache (see [`common::LiveCache`]): the
    /// watcher publishes its probe, the render paths reuse it instead of
    /// spawning `wg` two more times moments later.
    live_cache: Arc<LiveCacheSlot>,
}

impl SqliteBackend {
    pub fn new(config: AppConfig) -> Result<Self, WebError> {
        let tunnel = Arc::new(Tunnel::new(SystemRunner).with_conf_dir(config.wg_conf_dir.clone()));
        let backend = Self {
            db_path: config.db_path.clone(),
            config,
            tunnel,
            firewall_on: Arc::new(AtomicBool::new(false)),
            ipinfo_cache: Arc::new(Mutex::new((None, None))),
            live_cache: Arc::new(LiveCacheSlot::default()),
        };
        backend.refresh_firewall_flag()?;
        Ok(backend)
    }

    fn open_db(&self) -> Result<Connection, WebError> {
        open_path(&self.db_path)
    }

    /// Open the DB and run `f` on it inside `spawn_blocking`.
    pub(crate) async fn with_db<T, F>(&self, f: F) -> Result<T, WebError>
    where
        F: FnOnce(Connection) -> Result<T, WebError> + Send + 'static,
        T: Send + 'static,
    {
        let db_path = self.db_path.clone();
        blocking(move || {
            let conn = open_path(&db_path)?;
            f(conn)
        })
        .await
    }

    fn iface_name(&self) -> String {
        self.config.wg_interface.clone()
    }

    fn refresh_firewall_flag(&self) -> Result<(), WebError> {
        let conn = self.open_db()?;
        let on = crate::store::interface::get(&conn, &self.config.wg_interface)
            .map_err(db_err)?
            .is_some_and(|i| i.firewall_enabled);
        self.firewall_on.store(on, Ordering::Relaxed);
        Ok(())
    }

    fn general_json(g: &crate::store::general::General) -> Value {
        json!({
            "sessionTimeout": g.session_timeout,
            "metricsPrometheus": g.metrics_prometheus,
            "metricsJson": g.metrics_json,
            // I6: never the hash, only whether a Bearer is configured.
            "metricsPasswordSet": g.metrics_password.is_some(),
        })
    }

    fn interface_json(i: &crate::store::interface::Interface) -> Value {
        json!({
            "name": i.name,
            "device": i.device,
            "port": i.port,
            "publicKey": i.public_key,
            "ipv4Cidr": i.ipv4_cidr,
            "ipv6Cidr": i.ipv6_cidr,
            "mtu": i.mtu,
            "routingTable": i.routing_table,
            "firewallEnabled": i.firewall_enabled,
        })
    }

    fn hooks_json(h: &crate::store::hooks::Hooks) -> Value {
        json!({
            "preUp": h.pre_up,
            "postUp": h.post_up,
            "preDown": h.pre_down,
            "postDown": h.post_down,
        })
    }

    fn userconfig_json(c: &crate::store::userconfig::UserConfig) -> Value {
        json!({
            "host": c.host,
            "port": c.port,
            "defaultDnsV4": parse_json_vec(&c.default_dns_v4),
            "defaultDnsV6": parse_json_vec(&c.default_dns_v6),
            "defaultAllowedIpsV4": parse_json_vec(&c.default_allowed_ips_v4),
            "defaultAllowedIpsV6": parse_json_vec(&c.default_allowed_ips_v6),
            "defaultMtu": c.default_mtu,
            "defaultKeepalive": c.default_keepalive,
            "defaultPreSharedKey": c.default_pre_shared_key,
        })
    }
}

impl Backend for SqliteBackend {
    fn app_version(&self) -> String {
        crate::VERSION.to_string()
    }

    fn insecure(&self) -> bool {
        self.config.insecure
    }

    forward_async! {
        // -- meta ----------------------------------------------------------
        fn setup_step() -> Result<i64, WebError> => setup_step_inner;

        // -- auth/session --------------------------------------------------
        fn password_auth_allowed() -> Result<bool, WebError> => password_auth_allowed_inner;
        fn login_password(username: &str, password: &str) -> Result<LoginOutcome, WebError> => login_password_inner;
        fn get_user(user_id: i64) -> Result<UserView, WebError> => get_user_inner;
        fn verify_totp(user_id: i64, code: &str) -> Result<bool, WebError> => verify_totp_inner;
        fn create_session(user_id: i64) -> Result<String, WebError> => create_session_inner;
        fn lookup_session(token_hash_hex: &str) -> Result<Option<UserView>, WebError> => lookup_session_inner;
        fn destroy_session(token_hash_hex: &str) -> Result<(), WebError> => destroy_session_inner;

        // -- me ------------------------------------------------------------
        fn update_me(user_id: i64, name: &str) -> Result<UserView, WebError> => update_me_inner;
        fn change_username(user_id: i64, current: &str, username: &str) -> Result<UserView, WebError> => change_username_inner;
        fn change_password(user_id: i64, current: &str, next: &str) -> Result<(), WebError> => change_password_inner;
        fn totp_setup_start(user_id: i64, password: &str) -> Result<TotpSetup, WebError> => totp_setup_start_inner;
        fn totp_setup_confirm(user_id: i64, code: &str, password: &str) -> Result<(), WebError> => totp_setup_confirm_inner;
        fn totp_remove(user_id: i64, password: &str) -> Result<(), WebError> => totp_remove_inner;

        // -- clients -------------------------------------------------------
        fn list_clients() -> Result<Vec<ClientView>, WebError> => list_clients_inner;
        fn get_client(id: i64) -> Result<Option<ClientView>, WebError> => get_client_inner;
        fn create_client(name: &str) -> Result<ClientView, WebError> => create_client_inner;
        fn update_client(id: i64, patch: Value) -> Result<ClientView, WebError> => update_client_inner;
        fn delete_client(id: i64) -> Result<(), WebError> => delete_client_inner;
        fn enable_client(id: i64) -> Result<ClientView, WebError> => enable_client_inner;
        fn disable_client(id: i64) -> Result<ClientView, WebError> => disable_client_inner;
        fn set_client_psk(id: i64, enabled: bool) -> Result<ClientView, WebError> => set_client_psk_inner;
        fn rotate_client_keys(id: i64) -> Result<ClientView, WebError> => rotate_client_keys_inner;
        fn generate_otl(id: i64) -> Result<OtlView, WebError> => generate_otl_inner;
        fn client_conf(id: i64) -> Result<(String, String), WebError> => client_conf_inner;
        fn global_defaults() -> Result<GlobalDefaults, WebError> => global_defaults_inner;

        // -- one-time links (public download) ------------------------------
        fn consume_otl(token: &str) -> Result<OtlOutcome, WebError> => consume_otl_inner;

        // -- api tokens (long-lived Bearer credentials, DB-only) -----------
        fn create_api_token(user_id: i64, name: &str, expires_at: Option<&str>) -> Result<ApiTokenCreated, WebError> => create_api_token_inner;
        fn list_api_tokens(user_id: i64) -> Result<Vec<ApiTokenView>, WebError> => list_api_tokens_inner;
        fn list_all_api_tokens() -> Result<Vec<ApiTokenView>, WebError> => list_all_api_tokens_inner;
        fn delete_api_token(caller_id: i64, is_admin: bool, id: i64) -> Result<bool, WebError> => delete_api_token_inner;
        fn auth_api_token(token_hash_hex: &str) -> Result<Option<UserView>, WebError> => auth_api_token_inner;

        // -- admin ---------------------------------------------------------
        fn get_general() -> Result<Value, WebError> => get_general_inner;
        fn set_general(patch: Value) -> Result<Value, WebError> => set_general_inner;
        fn get_hooks() -> Result<Value, WebError> => get_hooks_inner;
        fn set_hooks(patch: Value) -> Result<Value, WebError> => set_hooks_inner;
        fn get_interface() -> Result<Value, WebError> => get_interface_inner;
        fn set_interface(patch: Value) -> Result<Value, WebError> => set_interface_inner;
        fn get_userconfig() -> Result<Value, WebError> => get_userconfig_inner;
        fn set_userconfig(patch: Value) -> Result<Value, WebError> => set_userconfig_inner;
        fn change_cidr(ipv4_cidr: Option<&str>, ipv6_cidr: Option<&str>) -> Result<Value, WebError> => change_cidr_inner;
        fn restart_interface() -> Result<(), WebError> => restart_interface_inner;
        fn ip_info() -> Result<Value, WebError> => ip_info_inner;

        // -- metrics -------------------------------------------------------
        fn metrics_enabled() -> Result<(bool, bool), WebError> => metrics_enabled_inner;
        fn metrics_check(password: Option<&str>) -> Result<bool, WebError> => metrics_check_inner;
        fn metrics_snapshot() -> Result<MetricsSnapshot, WebError> => metrics_snapshot_inner;

        // -- setup ---------------------------------------------------------
        fn setup_create_admin(username: &str, password: &str) -> Result<i64, WebError> => setup_create_admin_inner;
        fn setup_set_host(host: &str, port: u16) -> Result<(), WebError> => setup_set_host_inner;
        fn setup_suggest() -> Result<Value, WebError> => setup_suggest_inner;
    }

    fn ipv4_enabled(&self) -> bool {
        self.config.ipv4_enabled()
    }

    fn ipv6_enabled(&self) -> bool {
        self.config.ipv6_enabled()
    }

    async fn apply_tunnel(&self) -> Result<(), WebError> {
        let flag = self.firewall_on.clone();
        let iface_name = self.iface_name();
        let disable_v4 = self.config.disable_ipv4;
        let disable_v6 = self.config.disable_ipv6;
        let tunnel = self.tunnel.clone();
        self.with_db(move |conn| {
            reconcile_firewall_flag(&conn, &iface_name, disable_v6)?;
            let snap = load_snapshot(&conn, &iface_name, disable_v4, disable_v6)?;
            tunnel
                .apply(&snap)
                .map_err(|e| WebError::internal(format!("tunnel apply: {e}")))?;
            let on = interface_row(&conn, &iface_name)?.firewall_enabled;
            flag.store(on, Ordering::Relaxed);
            Ok(())
        })
        .await
    }

    async fn status_signal(&self) -> Result<StatusSignal, WebError> {
        // Live-only probe: no SQLite open, one `wg show ... dump` per tick
        // run off the single-thread runtime. The probe is always FRESH (it
        // never reads the shared cache) and publishes the map so the grid
        // render that this push triggers reuses it instead of spawning `wg`
        // twice more. Failures yield the neutral signal (`live_map` already
        // swallows them) so the watcher never propagates an error nor a
        // spurious change.
        let iface_name = self.iface_name();
        let cache = self.live_cache.clone();
        blocking(move || {
            let live = probe_live_peers(&cache, &iface_name);
            let (state, traffic, connected) = live_fingerprint(&live, now_unix());
            Ok(StatusSignal {
                state,
                traffic,
                connected,
            })
        })
        .await
    }
}
