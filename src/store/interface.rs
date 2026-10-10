//! CRUD SQL de l'interface WireGuard en DB.
//!
//! - `name` = cle primaire, defaut `wg0` (seed). Pas de colonne `enabled`
//!   en V1, aucun champ AWG.
//! - `routingTable` : `auto`, `off` ou un numero (valide en couche web).
//! - `firewallEnabled` : opt-in du firewall par client.

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::db::{bool_int, int_bool};

/// Ligne `interfaces`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    pub device: String,
    pub port: i64,
    pub private_key: String,
    pub public_key: String,
    pub ipv4_cidr: String,
    pub ipv6_cidr: String,
    pub mtu: i64,
    pub routing_table: String,
    pub firewall_enabled: bool,
}

fn map(row: &rusqlite::Row<'_>) -> Result<Interface, rusqlite::Error> {
    Ok(Interface {
        name: row.get("name")?,
        device: row.get("device")?,
        port: row.get("port")?,
        private_key: row.get("privateKey")?,
        public_key: row.get("publicKey")?,
        ipv4_cidr: row.get("ipv4Cidr")?,
        ipv6_cidr: row.get("ipv6Cidr")?,
        mtu: row.get("mtu")?,
        routing_table: row.get("routingTable")?,
        firewall_enabled: int_bool(row.get::<_, i64>("firewallEnabled")?),
    })
}

pub fn get(conn: &Connection, name: &str) -> Result<Option<Interface>, rusqlite::Error> {
    conn.query_row(
        "SELECT name, device, port, privateKey, publicKey, ipv4Cidr, ipv6Cidr, mtu, \
         routingTable, firewallEnabled FROM interfaces WHERE name = ?1",
        [name],
        map,
    )
    .optional()
}

pub fn list(conn: &Connection) -> Result<Vec<Interface>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT name, device, port, privateKey, publicKey, ipv4Cidr, ipv6Cidr, mtu, \
         routingTable, firewallEnabled FROM interfaces ORDER BY name",
    )?;
    let rows = stmt.query_map([], map)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Insertion ou remplacement complet (lignes `hooks`/`user_configs` liees via CASCADE).
pub fn upsert(conn: &Connection, iface: &Interface) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO interfaces (name, device, port, privateKey, publicKey, ipv4Cidr, \
         ipv6Cidr, mtu, routingTable, firewallEnabled) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
         ON CONFLICT(name) DO UPDATE SET device = excluded.device, port = excluded.port, \
         privateKey = excluded.privateKey, publicKey = excluded.publicKey, \
         ipv4Cidr = excluded.ipv4Cidr, ipv6Cidr = excluded.ipv6Cidr, mtu = excluded.mtu, \
         routingTable = excluded.routingTable, firewallEnabled = excluded.firewallEnabled",
        rusqlite::params![
            iface.name,
            iface.device,
            iface.port,
            iface.private_key,
            iface.public_key,
            iface.ipv4_cidr,
            iface.ipv6_cidr,
            iface.mtu,
            iface.routing_table,
            bool_int(iface.firewall_enabled),
        ],
    )?;
    Ok(())
}

/// Bascule du flag firewall (boot sans iptables -> desactive en DB + warn, couche tunnel).
pub fn set_firewall_enabled(
    conn: &Connection,
    name: &str,
    enabled: bool,
) -> Result<bool, rusqlite::Error> {
    let n = conn.execute(
        "UPDATE interfaces SET firewallEnabled = ?1 WHERE name = ?2",
        rusqlite::params![bool_int(enabled), name],
    )?;
    Ok(n > 0)
}

/// Renomme l'interface (`name` = cle primaire). Les lignes `hooks`,
/// `user_configs` et `clients` suivent via `ON UPDATE CASCADE` : aucun
/// clonage, aucune donnee perdue. Retourne vrai si une ligne a ete touchee.
pub fn rename(conn: &Connection, from: &str, to: &str) -> Result<bool, rusqlite::Error> {
    let n = conn.execute(
        "UPDATE interfaces SET name = ?1 WHERE name = ?2",
        rusqlite::params![to, from],
    )?;
    Ok(n > 0)
}

pub fn delete(conn: &Connection, name: &str) -> Result<bool, rusqlite::Error> {
    let n = conn.execute("DELETE FROM interfaces WHERE name = ?1", [name])?;
    Ok(n > 0)
}
