#![forbid(unsafe_code)]

//! Seed the canonical `wg0` rows onto a custom `WG_INTERFACE`.
//!
//! The migration `002_seed.sql` is the single source of truth for the default
//! `wg0` interface/hooks/user-config rows. The configured interface is obtained
//! by renaming the seeded `wg0` row: the foreign keys of `hooks`,
//! `user_configs` and `clients` are declared `ON UPDATE CASCADE`, so the whole
//! graph follows the primary-key rename and no row (in particular no client)
//! is lost.

use super::SetupError;

/// Ensure the interface/hooks/user-config rows exist for `name`.
///
/// Idempotent: a no-op when the interface row is already present. For a new
/// name the seeded `wg0` row is renamed in place; `hooks`, `user_configs` and
/// `clients` follow via `ON UPDATE CASCADE`.
pub fn ensure_interface_rows(conn: &rusqlite::Connection, name: &str) -> Result<(), SetupError> {
    if crate::store::interface::get(conn, name)?.is_some() {
        return Ok(());
    }
    // Never silently re-hardcode: the canonical seed must exist.
    if crate::store::interface::get(conn, "wg0")?.is_some() {
        crate::store::interface::rename(conn, "wg0", name)?;
        Ok(())
    } else {
        Err(SetupError::State(
            "seed interface wg0 is missing".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{client, hooks, interface, user, userconfig};
    use crate::test_support::memdb;

    fn assert_interface_clone(seed: &interface::Interface, got: &interface::Interface) {
        assert_eq!(got.device, seed.device);
        assert_eq!(got.port, seed.port);
        assert_eq!(got.private_key, seed.private_key);
        assert_eq!(got.public_key, seed.public_key);
        assert_eq!(got.ipv4_cidr, seed.ipv4_cidr);
        assert_eq!(got.ipv6_cidr, seed.ipv6_cidr);
        assert_eq!(got.mtu, seed.mtu);
        assert_eq!(got.routing_table, seed.routing_table);
        assert_eq!(got.firewall_enabled, seed.firewall_enabled);
    }

    #[test]
    fn custom_interface_renames_seed_rows() {
        let conn = memdb();
        let seed_iface = interface::get(&conn, "wg0")
            .expect("get")
            .expect("seed iface");
        let seed_hooks = hooks::get(&conn, "wg0").expect("get").expect("seed hooks");
        let seed_cfg = userconfig::get(&conn, "wg0")
            .expect("get")
            .expect("seed cfg");

        ensure_interface_rows(&conn, "wg1").expect("ensure");

        let got_iface = interface::get(&conn, "wg1")
            .expect("get")
            .expect("wg1 iface");
        assert_eq!(got_iface.name, "wg1");
        assert_interface_clone(&seed_iface, &got_iface);
        assert!(got_iface.private_key.is_empty());
        assert!(got_iface.public_key.is_empty());

        let got_hooks = hooks::get(&conn, "wg1").expect("get").expect("wg1 hooks");
        assert_eq!(got_hooks.id, "wg1");
        assert_eq!(got_hooks.pre_up, seed_hooks.pre_up);
        assert_eq!(got_hooks.post_up, seed_hooks.post_up);
        assert_eq!(got_hooks.pre_down, seed_hooks.pre_down);
        assert_eq!(got_hooks.post_down, seed_hooks.post_down);

        let got_cfg = userconfig::get(&conn, "wg1")
            .expect("get")
            .expect("wg1 cfg");
        assert_eq!(got_cfg.id, "wg1");
        assert_eq!(got_cfg.default_mtu, seed_cfg.default_mtu);
        assert_eq!(got_cfg.default_keepalive, seed_cfg.default_keepalive);
        assert_eq!(got_cfg.default_dns_v4, seed_cfg.default_dns_v4);
        assert_eq!(got_cfg.default_dns_v6, seed_cfg.default_dns_v6);
        assert_eq!(
            got_cfg.default_allowed_ips_v4,
            seed_cfg.default_allowed_ips_v4
        );
        assert_eq!(
            got_cfg.default_allowed_ips_v6,
            seed_cfg.default_allowed_ips_v6
        );
        assert_eq!(
            got_cfg.default_pre_shared_key,
            seed_cfg.default_pre_shared_key
        );
        assert_eq!(got_cfg.host, seed_cfg.host);
        assert_eq!(got_cfg.port, seed_cfg.port);

        // `interfaces.port` is UNIQUE (one interface per instance): the seeded
        // `wg0` row is renamed in place, never kept alongside the custom name.
        assert!(
            interface::get(&conn, "wg0").expect("get wg0").is_none(),
            "wg0 must be renamed to the custom interface"
        );
    }

    #[test]
    fn ensure_is_idempotent() {
        let conn = memdb();
        ensure_interface_rows(&conn, "wg1").expect("first");
        let first_iface = interface::get(&conn, "wg1").expect("get").expect("iface");
        let first_hooks = hooks::get(&conn, "wg1").expect("get").expect("hooks");
        let first_cfg = userconfig::get(&conn, "wg1").expect("get").expect("cfg");

        ensure_interface_rows(&conn, "wg1").expect("second");

        let again_iface = interface::get(&conn, "wg1").expect("get").expect("iface");
        let again_hooks = hooks::get(&conn, "wg1").expect("get").expect("hooks");
        let again_cfg = userconfig::get(&conn, "wg1").expect("get").expect("cfg");
        assert_interface_clone(&first_iface, &again_iface);
        assert_eq!(again_iface.name, "wg1");
        assert_eq!(again_hooks.post_up, first_hooks.post_up);
        assert_eq!(again_hooks.post_down, first_hooks.post_down);
        assert_eq!(again_cfg.default_dns_v4, first_cfg.default_dns_v4);
        assert_eq!(again_cfg.port, first_cfg.port);
    }

    #[test]
    fn wg0_is_a_noop() {
        let conn = memdb();
        let before = interface::get(&conn, "wg0").expect("get").expect("seed");
        ensure_interface_rows(&conn, "wg0").expect("ensure wg0");
        let after = interface::get(&conn, "wg0").expect("get").expect("seed");
        assert_interface_clone(&before, &after);
        assert_eq!(after.name, "wg0");
        assert_eq!(after.private_key, before.private_key);
        assert_eq!(after.public_key, before.public_key);
    }

    #[test]
    fn renaming_interface_cascades_to_clients() {
        let conn = memdb();
        user::create(&conn, "admin", Some("hash"), "Administrator").expect("admin");
        let now = "2026-01-01T00:00:00Z";
        let input = client::NewClient {
            ipv4_address: Some("10.8.0.2".to_string()),
            ipv6_address: Some("fdcc::2".to_string()),
            mtu: Some(1420),
            persistent_keepalive: Some(25),
            ..client::NewClient::base(
                1,
                "wg0".to_string(),
                "phone".to_string(),
                "cpriv".to_string(),
                "cpub".to_string(),
                "psk".to_string(),
            )
        };
        let id = client::create(&conn, &input, now).expect("client");
        let before = client::get(&conn, id).expect("get").expect("client row");
        assert_eq!(before.interface_id, "wg0");

        ensure_interface_rows(&conn, "wg1").expect("ensure");

        // The FK `ON UPDATE CASCADE` rewrote `interfaceId`; the row is intact.
        let after = client::get(&conn, id)
            .expect("get")
            .expect("client row must survive the rename");
        assert_eq!(after.interface_id, "wg1");
        assert_eq!(after.name, "phone");
        assert_eq!(after.public_key, "cpub");
        assert_eq!(client::list(&conn, "wg1").expect("list").len(), 1);
        assert!(client::list(&conn, "wg0").expect("list").is_empty());
    }
}
