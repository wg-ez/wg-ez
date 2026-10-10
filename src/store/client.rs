//! CRUD SQL des clients WireGuard.
//!
//! - `userId` des clients crees par l'API : [`DEFAULT_API_USER_ID`] = 1
//!   (tous rattaches au premier utilisateur).
//! - Les listes a double famille sont eclatees v4/v6 : `allowedIpsV4`/`V6` et
//!   `dnsV4`/`V6` a `NULL` = heritage du defaut global de la meme famille ;
//!   `firewallIpsV4`/`V6` a `NULL` = heritage de `allowedIpsV4`/`V6` puis du
//!   defaut global v4/v6.
//! - `serverAllowedIpsV4`/`V6` NOT NULL, defaut `'[]'` ; `expiresAt` NULL =
//!   permanent.

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::db::{bool_int, int_bool};

/// Proprietaire des clients crees via l'API.
pub const DEFAULT_API_USER_ID: i64 = 1;

/// Ligne `clients`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub id: i64,
    pub user_id: i64,
    pub interface_id: String,
    pub name: String,
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
    pub private_key: String,
    pub public_key: String,
    pub pre_shared_key: String,
    /// JSON array ou `None` = heritage du defaut global v4.
    pub allowed_ips_v4: Option<String>,
    /// JSON array ou `None` = heritage du defaut global v6.
    pub allowed_ips_v6: Option<String>,
    /// JSON array, NOT NULL (famille IPv4).
    pub server_allowed_ips_v4: String,
    /// JSON array, NOT NULL (famille IPv6).
    pub server_allowed_ips_v6: String,
    /// JSON array ou `None` = heritage de `allowedIpsV4` puis du defaut v4.
    pub firewall_ips_v4: Option<String>,
    /// JSON array ou `None` = heritage de `allowedIpsV6` puis du defaut v6.
    pub firewall_ips_v6: Option<String>,
    /// JSON array ou `None` = heritage du DNS global v4.
    pub dns_v4: Option<String>,
    /// JSON array ou `None` = heritage du DNS global v6.
    pub dns_v6: Option<String>,
    pub mtu: Option<i64>,
    pub persistent_keepalive: Option<i64>,
    pub server_endpoint: Option<String>,
    pub enabled: bool,
    /// ISO-8601 ou `None` = permanent.
    pub expires_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Donnees de creation (cles et IP deja allouees par l'appelant).
#[derive(Debug, Clone)]
pub struct NewClient {
    pub user_id: i64,
    pub interface_id: String,
    pub name: String,
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
    pub private_key: String,
    pub public_key: String,
    pub pre_shared_key: String,
    pub allowed_ips_v4: Option<String>,
    pub allowed_ips_v6: Option<String>,
    pub server_allowed_ips_v4: String,
    pub server_allowed_ips_v6: String,
    pub firewall_ips_v4: Option<String>,
    pub firewall_ips_v6: Option<String>,
    pub dns_v4: Option<String>,
    pub dns_v6: Option<String>,
    pub mtu: Option<i64>,
    pub persistent_keepalive: Option<i64>,
    pub server_endpoint: Option<String>,
    pub enabled: bool,
    pub expires_at: Option<String>,
}

impl NewClient {
    /// Client « de base » : listes d'heritage a `None`, `serverAllowedIps`
    /// vides, hooks/endpoint/expiry absents, `enabled = true`. L'appelant
    /// renseigne les adresses, la config et les eventuels overrides par
    /// struct update (`..NewClient::base(..)`).
    pub fn base(
        user_id: i64,
        interface_id: String,
        name: String,
        private_key: String,
        public_key: String,
        pre_shared_key: String,
    ) -> Self {
        Self {
            user_id,
            interface_id,
            name,
            ipv4_address: None,
            ipv6_address: None,
            private_key,
            public_key,
            pre_shared_key,
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
        }
    }
}

/// Patch partiel : `None` = champ inchange ; `Some(None)` = remise a NULL
/// (heritage) sur les colonnes nullables.
#[derive(Debug, Clone, Default)]
pub struct ClientUpdate {
    pub name: Option<String>,
    pub ipv4_address: Option<Option<String>>,
    pub ipv6_address: Option<Option<String>>,
    /// Rotation de paire de cles (`rotateKeys`) : remplace la cle privee.
    pub private_key: Option<String>,
    /// Rotation de paire de cles (`rotateKeys`) : remplace la cle publique.
    pub public_key: Option<String>,
    /// `Some("")` efface la PSK ; `Some(psk)` la remplace.
    pub pre_shared_key: Option<String>,
    pub allowed_ips_v4: Option<Option<String>>,
    pub allowed_ips_v6: Option<Option<String>>,
    pub server_allowed_ips_v4: Option<String>,
    pub server_allowed_ips_v6: Option<String>,
    pub firewall_ips_v4: Option<Option<String>>,
    pub firewall_ips_v6: Option<Option<String>>,
    pub dns_v4: Option<Option<String>>,
    pub dns_v6: Option<Option<String>>,
    pub mtu: Option<Option<i64>>,
    pub persistent_keepalive: Option<Option<i64>>,
    pub server_endpoint: Option<Option<String>>,
    pub enabled: Option<bool>,
    pub expires_at: Option<Option<String>>,
}

const COLUMNS: &str = "id, userId, interfaceId, name, ipv4Address, ipv6Address, privateKey, \
    publicKey, preSharedKey, allowedIpsV4, allowedIpsV6, serverAllowedIpsV4, \
    serverAllowedIpsV6, firewallIpsV4, firewallIpsV6, dnsV4, dnsV6, mtu, \
    persistentKeepalive, serverEndpoint, enabled, \
    expiresAt, createdAt, updatedAt";

fn map(row: &rusqlite::Row<'_>) -> Result<Client, rusqlite::Error> {
    Ok(Client {
        id: row.get("id")?,
        user_id: row.get("userId")?,
        interface_id: row.get("interfaceId")?,
        name: row.get("name")?,
        ipv4_address: row.get("ipv4Address")?,
        ipv6_address: row.get("ipv6Address")?,
        private_key: row.get("privateKey")?,
        public_key: row.get("publicKey")?,
        pre_shared_key: row.get("preSharedKey")?,
        allowed_ips_v4: row.get("allowedIpsV4")?,
        allowed_ips_v6: row.get("allowedIpsV6")?,
        server_allowed_ips_v4: row.get("serverAllowedIpsV4")?,
        server_allowed_ips_v6: row.get("serverAllowedIpsV6")?,
        firewall_ips_v4: row.get("firewallIpsV4")?,
        firewall_ips_v6: row.get("firewallIpsV6")?,
        dns_v4: row.get("dnsV4")?,
        dns_v6: row.get("dnsV6")?,
        mtu: row.get("mtu")?,
        persistent_keepalive: row.get("persistentKeepalive")?,
        server_endpoint: row.get("serverEndpoint")?,
        enabled: int_bool(row.get::<_, i64>("enabled")?),
        expires_at: row.get("expiresAt")?,
        created_at: row.get("createdAt")?,
        updated_at: row.get("updatedAt")?,
    })
}

/// Liste les clients d'une interface, tries par nom (supporte `?filter`/`sort` en couche web).
pub fn list(conn: &Connection, interface_id: &str) -> Result<Vec<Client>, rusqlite::Error> {
    let sql = format!("SELECT {COLUMNS} FROM clients WHERE interfaceId = ?1 ORDER BY name");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([interface_id], map)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Detail d'un client (+ endpoint live calcule en couche web).
pub fn get(conn: &Connection, id: i64) -> Result<Option<Client>, rusqlite::Error> {
    let sql = format!("SELECT {COLUMNS} FROM clients WHERE id = ?1");
    conn.query_row(&sql, [id], map).optional()
}

/// Insertion ; retourne l'id auto-incremente.
///
/// ```rust
/// # fn main() -> Result<(), wgez::db::DbError> {
/// let conn = rusqlite::Connection::open_in_memory()?;
/// conn.execute_batch("PRAGMA foreign_keys=ON;")?;
/// wgez::db::run_migrations(&conn)?;
/// wgez::store::user::create(&conn, "admin", None, "Admin")?;
/// let input = wgez::store::client::NewClient {
///     ipv4_address: Some("10.8.0.2".to_string()),
///     mtu: Some(1420),
///     persistent_keepalive: Some(0),
///     ..wgez::store::client::NewClient::base(
///         wgez::store::client::DEFAULT_API_USER_ID,
///         "wg0".to_string(),
///         "phone".to_string(),
///         "priv".to_string(),
///         "pub".to_string(),
///         String::new(),
///     )
/// };
/// let now = "2026-01-01T00:00:00Z";
/// let id = wgez::store::client::create(&conn, &input, now)?;
/// let fetched = wgez::store::client::get(&conn, id)?;
/// assert!(fetched.is_some_and(|c| c.name == "phone" && c.enabled));
/// # Ok(())
/// # }
/// ```
pub fn create(conn: &Connection, input: &NewClient, now: &str) -> Result<i64, rusqlite::Error> {
    conn.execute(
        "INSERT INTO clients (userId, interfaceId, name, ipv4Address, ipv6Address, \
         privateKey, publicKey, preSharedKey, allowedIpsV4, allowedIpsV6, \
         serverAllowedIpsV4, serverAllowedIpsV6, firewallIpsV4, firewallIpsV6, \
         dnsV4, dnsV6, mtu, persistentKeepalive, serverEndpoint, \
         enabled, expiresAt, createdAt, updatedAt) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, \
         ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)",
        rusqlite::params![
            input.user_id,
            input.interface_id,
            input.name,
            input.ipv4_address,
            input.ipv6_address,
            input.private_key,
            input.public_key,
            input.pre_shared_key,
            input.allowed_ips_v4,
            input.allowed_ips_v6,
            input.server_allowed_ips_v4,
            input.server_allowed_ips_v6,
            input.firewall_ips_v4,
            input.firewall_ips_v6,
            input.dns_v4,
            input.dns_v6,
            input.mtu,
            input.persistent_keepalive,
            input.server_endpoint,
            bool_int(input.enabled),
            input.expires_at,
            now,
            now,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Mise a jour partielle + `updatedAt` ; retourne vrai si une ligne a ete touchee.
/// Seuls des noms de colonnes fixes sont assembles ; toutes les valeurs sont parametrees.
pub fn update(
    conn: &Connection,
    id: i64,
    patch: &ClientUpdate,
    now: &str,
) -> Result<bool, rusqlite::Error> {
    let mut sets: Vec<&str> = Vec::new();
    let mut values: Vec<&dyn rusqlite::ToSql> = Vec::new();

    if let Some(v) = &patch.name {
        sets.push("name = ?");
        values.push(v);
    }
    if let Some(v) = &patch.ipv4_address {
        sets.push("ipv4Address = ?");
        values.push(v);
    }
    if let Some(v) = &patch.ipv6_address {
        sets.push("ipv6Address = ?");
        values.push(v);
    }
    if let Some(v) = &patch.private_key {
        sets.push("privateKey = ?");
        values.push(v);
    }
    if let Some(v) = &patch.public_key {
        sets.push("publicKey = ?");
        values.push(v);
    }
    if let Some(v) = &patch.pre_shared_key {
        sets.push("preSharedKey = ?");
        values.push(v);
    }
    if let Some(v) = &patch.allowed_ips_v4 {
        sets.push("allowedIpsV4 = ?");
        values.push(v);
    }
    if let Some(v) = &patch.allowed_ips_v6 {
        sets.push("allowedIpsV6 = ?");
        values.push(v);
    }
    if let Some(v) = &patch.server_allowed_ips_v4 {
        sets.push("serverAllowedIpsV4 = ?");
        values.push(v);
    }
    if let Some(v) = &patch.server_allowed_ips_v6 {
        sets.push("serverAllowedIpsV6 = ?");
        values.push(v);
    }
    if let Some(v) = &patch.firewall_ips_v4 {
        sets.push("firewallIpsV4 = ?");
        values.push(v);
    }
    if let Some(v) = &patch.firewall_ips_v6 {
        sets.push("firewallIpsV6 = ?");
        values.push(v);
    }
    if let Some(v) = &patch.dns_v4 {
        sets.push("dnsV4 = ?");
        values.push(v);
    }
    if let Some(v) = &patch.dns_v6 {
        sets.push("dnsV6 = ?");
        values.push(v);
    }
    if let Some(v) = &patch.mtu {
        sets.push("mtu = ?");
        values.push(v);
    }
    if let Some(v) = &patch.persistent_keepalive {
        sets.push("persistentKeepalive = ?");
        values.push(v);
    }
    if let Some(v) = &patch.server_endpoint {
        sets.push("serverEndpoint = ?");
        values.push(v);
    }
    if let Some(v) = &patch.expires_at {
        sets.push("expiresAt = ?");
        values.push(v);
    }
    let enabled_int: i64;
    if let Some(v) = &patch.enabled {
        enabled_int = bool_int(*v);
        sets.push("enabled = ?");
        values.push(&enabled_int);
    }
    sets.push("updatedAt = ?");
    values.push(&now);
    values.push(&id);

    let sql = format!("UPDATE clients SET {} WHERE id = ?", sets.join(", "));
    let n = conn.execute(&sql, values.as_slice())?;
    Ok(n > 0)
}

/// Suppression (l'OTL lie part en CASCADE).
pub fn delete(conn: &Connection, id: i64) -> Result<bool, rusqlite::Error> {
    let n = conn.execute("DELETE FROM clients WHERE id = ?1", [id])?;
    Ok(n > 0)
}

/// Desactive les clients dont `expiresAt` est depasse ; retourne leur nombre.
/// (L'appelant declenche ensuite un `Tunnel::apply` complet si > 0.)
pub fn disable_expired(conn: &Connection, now: &str) -> Result<usize, rusqlite::Error> {
    let n = conn.execute(
        "UPDATE clients SET enabled = 0, updatedAt = ?1 \
         WHERE enabled = 1 AND expiresAt IS NOT NULL AND expiresAt <= ?1",
        [now],
    )?;
    Ok(n)
}
