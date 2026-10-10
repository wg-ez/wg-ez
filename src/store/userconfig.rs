//! CRUD SQL des defauts globaux par interface (`user_configs`).
//!
//! - `id` = nom d'interface, CASCADE.
//! - DNS et AllowedIPs sont eclates v4/v6 (`defaultDnsV4`/`defaultDnsV6`,
//!   `defaultAllowedIpsV4`/`defaultAllowedIpsV6`) : desactiver une famille ne
//!   touche jamais les valeurs de l'autre.
//! - `defaultMtu` 1420, `defaultKeepalive` 0.
//! - `defaultPreSharedKey` : genere une PSK pour chaque nouveau client
//!   (actif par defaut, desactivable par client).
//! - `host`/`port` = host et port publics annonces aux clients.

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::db::{bool_int, int_bool};

/// Ligne `user_configs` (`id` = nom d'interface).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    pub id: String,
    pub default_mtu: i64,
    pub default_keepalive: i64,
    /// JSON array (famille IPv4).
    pub default_dns_v4: String,
    /// JSON array (famille IPv6).
    pub default_dns_v6: String,
    /// JSON array (famille IPv4).
    pub default_allowed_ips_v4: String,
    /// JSON array (famille IPv6).
    pub default_allowed_ips_v6: String,
    /// Genere une PSK a la creation d'un client.
    pub default_pre_shared_key: bool,
    pub host: String,
    pub port: i64,
}

fn map(row: &rusqlite::Row<'_>) -> Result<UserConfig, rusqlite::Error> {
    Ok(UserConfig {
        id: row.get("id")?,
        default_mtu: row.get("defaultMtu")?,
        default_keepalive: row.get("defaultKeepalive")?,
        default_dns_v4: row.get("defaultDnsV4")?,
        default_dns_v6: row.get("defaultDnsV6")?,
        default_allowed_ips_v4: row.get("defaultAllowedIpsV4")?,
        default_allowed_ips_v6: row.get("defaultAllowedIpsV6")?,
        default_pre_shared_key: int_bool(row.get::<_, i64>("defaultPreSharedKey")?),
        host: row.get("host")?,
        port: row.get("port")?,
    })
}

pub fn get(conn: &Connection, id: &str) -> Result<Option<UserConfig>, rusqlite::Error> {
    conn.query_row(
        "SELECT id, defaultMtu, defaultKeepalive, defaultDnsV4, defaultDnsV6, \
         defaultAllowedIpsV4, defaultAllowedIpsV6, defaultPreSharedKey, host, port \
         FROM user_configs WHERE id = ?1",
        [id],
        map,
    )
    .optional()
}

pub fn upsert(conn: &Connection, cfg: &UserConfig) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO user_configs (id, defaultMtu, defaultKeepalive, defaultDnsV4, \
         defaultDnsV6, defaultAllowedIpsV4, defaultAllowedIpsV6, defaultPreSharedKey, \
         host, port) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
         ON CONFLICT(id) DO UPDATE SET defaultMtu = excluded.defaultMtu, \
         defaultKeepalive = excluded.defaultKeepalive, defaultDnsV4 = excluded.defaultDnsV4, \
         defaultDnsV6 = excluded.defaultDnsV6, \
         defaultAllowedIpsV4 = excluded.defaultAllowedIpsV4, \
         defaultAllowedIpsV6 = excluded.defaultAllowedIpsV6, \
         defaultPreSharedKey = excluded.defaultPreSharedKey, host = excluded.host, \
         port = excluded.port",
        rusqlite::params![
            cfg.id,
            cfg.default_mtu,
            cfg.default_keepalive,
            cfg.default_dns_v4,
            cfg.default_dns_v6,
            cfg.default_allowed_ips_v4,
            cfg.default_allowed_ips_v6,
            bool_int(cfg.default_pre_shared_key),
            cfg.host,
            cfg.port,
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::memdb;

    #[test]
    fn default_preshared_key_is_seeded_on_and_round_trips() {
        let conn = memdb();
        let cfg = get(&conn, "wg0").expect("get").expect("seed");
        assert!(
            cfg.default_pre_shared_key,
            "seed must enable PSK by default"
        );
        let mut off = cfg.clone();
        off.default_pre_shared_key = false;
        upsert(&conn, &off).expect("upsert");
        let back = get(&conn, "wg0").expect("get").expect("row");
        assert!(!back.default_pre_shared_key);
    }

    #[test]
    fn families_are_stored_separately() {
        let conn = memdb();
        let mut cfg = get(&conn, "wg0").expect("get").expect("seed");
        assert_eq!(
            serde_json::from_str::<Vec<String>>(&cfg.default_dns_v4).expect("v4"),
            vec!["1.1.1.1"]
        );
        assert_eq!(
            serde_json::from_str::<Vec<String>>(&cfg.default_dns_v6).expect("v6"),
            vec!["2606:4700:4700::1111"]
        );
        cfg.default_dns_v4 = r#"["9.9.9.9"]"#.to_string();
        upsert(&conn, &cfg).expect("upsert");
        let back = get(&conn, "wg0").expect("get").expect("row");
        assert_eq!(back.default_dns_v4, r#"["9.9.9.9"]"#);
        // La famille v6 n'a pas bouge.
        assert_eq!(back.default_dns_v6, cfg.default_dns_v6);
    }
}
