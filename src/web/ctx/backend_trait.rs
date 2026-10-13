#![forbid(unsafe_code)]

//! Backend trait (implemented once by the backend agents in `main.rs`).

use std::future::Future;

use serde_json::Value;

use super::errors::WebError;
use super::views::{
    ClientView, GlobalDefaults, LoginOutcome, MetricsSnapshot, OtlOutcome, OtlView, TotpSetup,
    UserView,
};

/// Live-status signal consumed by the push watcher
/// ([`crate::web::watcher::StatusWatcher`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatusSignal {
    /// Hash of connection-relevant state: peer set, observed endpoint,
    /// latest handshake and the `connected` flag. A change here is pushed
    /// immediately (connect/disconnect/endpoint/handshake refresh).
    pub state: u64,
    /// Hash of the traffic counters only. A change here is coalesced by the
    /// watcher (bounded refresh cadence), never pushed per packet.
    pub traffic: u64,
    /// Number of connected peers in the same probe. Carried alongside the
    /// hashes so the long-poll can push the live topbar count without a
    /// second `wg` probe (cf. `GET /api/status/stream`).
    pub connected: u64,
}

/// All fallible web operations. Every method returns `Result`; no
/// `unwrap`/`expect` on user-touched paths. Implementations must run
/// blocking work (argon2, sqlite, `wg`) via `spawn_blocking`.
/// Native `async fn` in trait + static dispatch: no `async-trait` dep.
pub trait Backend: Send + Sync + 'static {
    // -- meta -------------------------------------------------------------
    fn app_version(&self) -> String;
    /// `INSECURE` env: true => plain HTTP banner + non-secure cookies.
    fn insecure(&self) -> bool;
    /// Setup step; `0` = finished.
    fn setup_step(&self) -> impl Future<Output = Result<i64, WebError>> + Send;

    // -- auth/session ------------------------------------------------------
    fn password_auth_allowed(&self) -> impl Future<Output = Result<bool, WebError>> + Send;
    /// Returns the user + whether TOTP is required. Must verify a dummy
    /// Argon2 hash when the user is unknown (timing protection). On a
    /// non-2FA success the session is minted here; the cookie is always a
    /// browser-session cookie (no `Max-Age`, cleared on browser close).
    fn login_password(
        &self,
        username: &str,
        password: &str,
    ) -> impl Future<Output = Result<LoginOutcome, WebError>> + Send;
    fn get_user(&self, user_id: i64) -> impl Future<Output = Result<UserView, WebError>> + Send;
    fn verify_totp(
        &self,
        user_id: i64,
        code: &str,
    ) -> impl Future<Output = Result<bool, WebError>> + Send;
    /// Create a session, return the clear 256-bit token (hashed in DB).
    /// The cookie is always a browser-session cookie (no `Max-Age`).
    fn create_session(&self, user_id: i64)
    -> impl Future<Output = Result<String, WebError>> + Send;
    fn lookup_session(
        &self,
        token_hash_hex: &str,
    ) -> impl Future<Output = Result<Option<UserView>, WebError>> + Send;
    fn destroy_session(
        &self,
        token_hash_hex: &str,
    ) -> impl Future<Output = Result<(), WebError>> + Send;
    /// Basic auth `user:pass`; when TOTP is active the guard still refuses
    /// upstream, with the same 401 as a wrong password (no oracle).
    fn login_basic(
        &self,
        username: &str,
        password: &str,
    ) -> impl Future<Output = Result<Option<UserView>, WebError>> + Send;

    // -- me -----------------------------------------------------------------
    fn update_me(
        &self,
        user_id: i64,
        name: &str,
    ) -> impl Future<Output = Result<UserView, WebError>> + Send;
    /// Change the caller's login username. Requires the current password
    /// (same guard as the password/2FA changes), validates through
    /// [`crate::validate::validate_username`], and relies on the `UNIQUE`
    /// index for the duplicate check (mapped to a generic 400, no leak).
    fn change_username(
        &self,
        user_id: i64,
        current: &str,
        username: &str,
    ) -> impl Future<Output = Result<UserView, WebError>> + Send;
    fn change_password(
        &self,
        user_id: i64,
        current: &str,
        next: &str,
    ) -> impl Future<Output = Result<(), WebError>> + Send;
    /// Start (or restart) TOTP enrollment. `password` MUST always be the
    /// current password (step-up proof, exactly like the password/username
    /// changes and the 2FA removal): a stolen session cookie alone can never
    /// enroll an attacker-known 2FA that would survive session expiry and
    /// password rotation.
    fn totp_setup_start(
        &self,
        user_id: i64,
        password: &str,
    ) -> impl Future<Output = Result<TotpSetup, WebError>> + Send;
    /// Confirm TOTP enrollment. Needs the 6-digit `code` AND the current
    /// `password` (same step-up proof as `start`).
    fn totp_setup_confirm(
        &self,
        user_id: i64,
        code: &str,
        password: &str,
    ) -> impl Future<Output = Result<(), WebError>> + Send;
    fn totp_remove(
        &self,
        user_id: i64,
        password: &str,
    ) -> impl Future<Output = Result<(), WebError>> + Send;

    // -- clients --------------------------------------------------------------
    fn list_clients(&self) -> impl Future<Output = Result<Vec<ClientView>, WebError>> + Send;
    fn get_client(
        &self,
        id: i64,
    ) -> impl Future<Output = Result<Option<ClientView>, WebError>> + Send;
    /// Creates keys + PSK, allocates first-free IPv4/IPv6. Attached to
    /// `userId = 1` (TODO inherited from v15).
    fn create_client(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<ClientView, WebError>> + Send;
    fn update_client(
        &self,
        id: i64,
        patch: Value,
    ) -> impl Future<Output = Result<ClientView, WebError>> + Send;
    fn delete_client(&self, id: i64) -> impl Future<Output = Result<(), WebError>> + Send;
    /// 422 when the client is expired.
    fn enable_client(&self, id: i64) -> impl Future<Output = Result<ClientView, WebError>> + Send;
    fn disable_client(&self, id: i64) -> impl Future<Output = Result<ClientView, WebError>> + Send;
    /// Per-client PSK override: `true` generates a fresh pre-shared key,
    /// `false` removes it. Callers must run `apply_tunnel` afterwards.
    fn set_client_psk(
        &self,
        id: i64,
        enabled: bool,
    ) -> impl Future<Output = Result<ClientView, WebError>> + Send;
    /// Regenerates the client keypair (private + public); the per-client PSK
    /// is kept. Callers must run `apply_tunnel` afterwards.
    fn rotate_client_keys(
        &self,
        id: i64,
    ) -> impl Future<Output = Result<ClientView, WebError>> + Send;
    /// The ONLY client mutation that must NOT call `apply_tunnel`.
    fn generate_otl(&self, id: i64) -> impl Future<Output = Result<OtlView, WebError>> + Send;
    /// (file name, conf text).
    fn client_conf(
        &self,
        id: i64,
    ) -> impl Future<Output = Result<(String, String), WebError>> + Send;
    fn global_defaults(&self) -> impl Future<Output = Result<GlobalDefaults, WebError>> + Send;
    /// Whether the IPv4 family is enabled (`IP_MODE`, auto-detected at boot).
    fn ipv4_enabled(&self) -> bool;
    /// Whether the IPv6 family is enabled.
    fn ipv6_enabled(&self) -> bool;

    // -- one-time links (public download) --------------------------------------
    fn consume_otl(&self, token: &str)
    -> impl Future<Output = Result<OtlOutcome, WebError>> + Send;

    // -- admin ------------------------------------------------------------------
    fn get_general(&self) -> impl Future<Output = Result<Value, WebError>> + Send;
    fn set_general(&self, patch: Value) -> impl Future<Output = Result<Value, WebError>> + Send;
    fn get_hooks(&self) -> impl Future<Output = Result<Value, WebError>> + Send;
    fn set_hooks(&self, patch: Value) -> impl Future<Output = Result<Value, WebError>> + Send;
    fn get_interface(&self) -> impl Future<Output = Result<Value, WebError>> + Send;
    fn set_interface(&self, patch: Value) -> impl Future<Output = Result<Value, WebError>> + Send;
    fn get_userconfig(&self) -> impl Future<Output = Result<Value, WebError>> + Send;
    fn set_userconfig(&self, patch: Value) -> impl Future<Output = Result<Value, WebError>> + Send;
    fn change_cidr(
        &self,
        ipv4_cidr: Option<&str>,
        ipv6_cidr: Option<&str>,
    ) -> impl Future<Output = Result<Value, WebError>> + Send;
    /// Explicit admin restart: `down` + `up` (cuts tunnels).
    fn restart_interface(&self) -> impl Future<Output = Result<(), WebError>> + Send;
    fn ip_info(&self) -> impl Future<Output = Result<Value, WebError>> + Send;

    // -- metrics ------------------------------------------------------------------
    fn metrics_enabled(&self) -> impl Future<Output = Result<(bool, bool), WebError>> + Send;
    fn metrics_check(
        &self,
        password: Option<&str>,
    ) -> impl Future<Output = Result<bool, WebError>> + Send;
    fn metrics_snapshot(&self) -> impl Future<Output = Result<MetricsSnapshot, WebError>> + Send;

    // -- setup ----------------------------------------------------------------------
    /// Atomically create the first ADMIN and advance to step 3. Returns the
    /// new user id so the handler can mint a session cookie. Must reject
    /// (never create a CLIENT) when setup already advanced or a user exists.
    fn setup_create_admin(
        &self,
        username: &str,
        password: &str,
    ) -> impl Future<Output = Result<i64, WebError>> + Send;
    fn setup_set_host(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = Result<(), WebError>> + Send;
    fn setup_suggest(&self) -> impl Future<Output = Result<Value, WebError>> + Send;

    // -- kernel ------------------------------------------------------------------------
    /// Full `Tunnel::apply`: render -> write 0600 -> `syncconf` -> firewall.
    /// Called after every client/admin POST|DELETE except OTL generation.
    /// Never `wg-quick up` here (cuts tunnels).
    fn apply_tunnel(&self) -> impl Future<Output = Result<(), WebError>> + Send;

    // -- live status (push watcher) ------------------------------------------------------
    /// Cheap `wg show <iface> dump` fingerprint for the long-poll watcher.
    /// Best-effort: implementations must never fail a request because of it
    /// (return [`StatusSignal::default`] on any error).
    fn status_signal(&self) -> impl Future<Output = Result<StatusSignal, WebError>> + Send;
}
