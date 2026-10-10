#![forbid(unsafe_code)]

//! View DTOs (owned by the web layer; backend maps its store rows onto these).

use serde::{Deserialize, Serialize};

/// Authenticated principal resolved by [`crate::web::guards::authenticate`].
#[derive(Debug, Clone)]
pub struct Principal {
    pub user_id: i64,
    pub username: String,
    /// 1 = ADMIN, 2 = CLIENT.
    pub role: i64,
    pub totp_verified: bool,
}

impl Principal {
    pub fn is_admin(&self) -> bool {
        self.role == 1
    }
}

/// Client row as rendered by UI + API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientView {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub enabled: bool,
    /// `true` quand le pair possede une pre-shared key (le materiel de la
    /// cle n'est jamais expose par l'API).
    #[serde(default)]
    pub has_pre_shared_key: bool,
    pub ipv4_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_address: Option<String>,
    /// `None` = inherit global default v4 (never `[]` for inherit).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_ips_v4: Option<Vec<String>>,
    /// `None` = inherit global default v6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_ips_v6: Option<Vec<String>>,
    #[serde(default)]
    pub server_allowed_ips_v4: Vec<String>,
    #[serde(default)]
    pub server_allowed_ips_v6: Vec<String>,
    /// `None` = inherit `allowedIpsV4` then global default v4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firewall_ips_v4: Option<Vec<String>>,
    /// `None` = inherit `allowedIpsV6` then global default v6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firewall_ips_v6: Option<Vec<String>>,
    /// `None` = inherit global default DNS v4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_v4: Option<Vec<String>>,
    /// `None` = inherit global default DNS v6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_v6: Option<Vec<String>>,
    pub mtu: i64,
    pub persistent_keepalive: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Creation timestamp (RFC 3339). Used to sort the grid by creation date
    /// (never by `updatedAt`, so edits don't reorder the list). UI-only:
    /// `skip` keeps the public API shape unchanged.
    #[serde(skip)]
    pub created_at: String,
    // Live status merged from `wg show dump` (nulls when unknown).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_handshake_at: Option<String>,
    #[serde(default)]
    pub rx_bytes: u64,
    #[serde(default)]
    pub tx_bytes: u64,
    #[serde(default)]
    pub connected: bool,
}

/// Metrics snapshot; formatting (text + JSON) lives in `metrics_dto.rs`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct MetricsSnapshot {
    pub interface: String,
    pub configured_peers: u64,
    pub enabled_peers: u64,
    pub connected_peers: u64,
    pub peers: Vec<PeerMetric>,
}

/// Per-peer counters for metrics. Labels mirror v15 exactly
/// (`interface,enabled,ipv4Address,ipv6Address,name` + `endpoint`).
#[derive(Debug, Clone, Default, Serialize)]
pub struct PeerMetric {
    pub name: String,
    pub enabled: bool,
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Seconds since last handshake, `None` when never (renders `0` in
    /// Prometheus text, like v15, and `null` in JSON).
    pub latest_handshake_seconds: Option<u64>,
    /// Observed endpoint, `None` for `(none)` (row omitted in text).
    pub endpoint: Option<String>,
    pub public_key: String,
}

/// Outcome of `POST /api/auth/password`.
#[derive(Debug, Clone)]
pub enum LoginOutcome {
    Ok { user: UserView, token: String },
    TotpRequired { user_id: i64, username: String },
}

/// Authenticated user profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserView {
    pub id: i64,
    pub username: String,
    pub name: String,
    /// 1 = ADMIN, 2 = CLIENT.
    pub role: i64,
    pub totp_enabled: bool,
    pub totp_verified: bool,
}

/// New TOTP secret offer (20 random bytes, base32).
#[derive(Debug, Clone, Serialize)]
pub struct TotpSetup {
    pub secret: String,
    pub otpauth_url: String,
    pub qr_svg: String,
}

/// Created/renewed one-time link.
#[derive(Debug, Clone, Serialize)]
pub struct OtlView {
    pub token: String,
    pub expires_at: String,
    pub url: String,
}

/// Outcome of `GET /cnf/:token`.
#[derive(Debug, Clone)]
pub enum OtlOutcome {
    Ok { file_name: String, conf: String },
    Unknown,
    Expired,
}

/// Global defaults for inheritance display, per address family.
#[derive(Debug, Clone, Default, Serialize)]
pub struct GlobalDefaults {
    pub default_dns_v4: Vec<String>,
    pub default_dns_v6: Vec<String>,
    pub default_allowed_ips_v4: Vec<String>,
    pub default_allowed_ips_v6: Vec<String>,
    pub firewall_enabled: bool,
}

/// One `key / value` row of the `.kv` primitive (demo `.specs`), rendered
/// by the `kv()` macro of `templates/partials/ui.html`. Everything is
/// precomputed: no text is assembled in a template.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Kv {
    pub k: String,
    pub v: String,
}
