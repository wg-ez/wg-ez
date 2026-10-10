#![forbid(unsafe_code)]

//! Metrics operations for [`super::SqliteBackend`].
//!
//! The Bearer password is checked FIRST (401 while set); the per-endpoint
//! flag (400 when off) is enforced by the caller.
//!
//! **Fail-closed (I6):** a missing `metricsPassword` never grants access. An
//! endpoint that is somehow enabled without a stored hash therefore answers
//! 401 instead of leaking every peer's name, addresses, public key and real
//! public endpoint.

use super::SqliteBackend;
use super::common::{cached_live_peers, db_err, general_row, now_unix};
use crate::web::ctx::{MetricsSnapshot, PeerMetric, WebError};
use crate::wg::status;

/// Pure Bearer decision, **fail-closed**: no stored hash -> refuse; a stored
/// hash requires the matching clear token. `verify_password_blocking` already
/// answers `Ok(false)` on mismatch, and an unparsable hash is treated as a
/// refusal (never a panic). Kept pure so the fail-closed rule is unit-tested
/// without a database.
pub(crate) fn metrics_check_decision(stored: Option<&str>, password: Option<&str>) -> bool {
    match stored {
        None => false,
        Some(hash) => password.is_some_and(|clear| {
            crate::auth::password::verify_password_blocking(hash, clear).unwrap_or(false)
        }),
    }
}

impl SqliteBackend {
    pub(crate) async fn metrics_enabled_inner(&self) -> Result<(bool, bool), WebError> {
        self.with_db(move |conn| {
            let g = general_row(&conn)?;
            Ok((g.metrics_prometheus, g.metrics_json))
        })
        .await
    }

    pub(crate) async fn metrics_check_inner(
        &self,
        password: Option<&str>,
    ) -> Result<bool, WebError> {
        let password = password.map(str::to_string);
        self.with_db(move |conn| {
            let g = general_row(&conn)?;
            // Bearer checked FIRST (401 while set), then the per-endpoint
            // flag (400 when off, handled by the caller). Fail-closed: no
            // stored hash refuses.
            Ok(metrics_check_decision(
                g.metrics_password.as_deref(),
                password.as_deref(),
            ))
        })
        .await
    }

    pub(crate) async fn metrics_snapshot_inner(&self) -> Result<MetricsSnapshot, WebError> {
        let iface_name = self.iface_name();
        let cache = self.live_cache.clone();
        self.with_db(move |conn| {
            let live = cached_live_peers(&cache, &iface_name);
            let now = now_unix();
            let mut peers = Vec::new();
            let mut configured = 0u64;
            let mut enabled = 0u64;
            let mut connected = 0u64;
            for iface in crate::store::interface::list(&conn).map_err(db_err)? {
                for c in crate::store::client::list(&conn, &iface.name).map_err(db_err)? {
                    configured += 1;
                    if c.enabled {
                        enabled += 1;
                    }
                    let st = live.get(&c.public_key);
                    let hs_age = st.and_then(|s| s.latest_handshake).and_then(|hs| {
                        now.checked_sub(hs)
                            .filter(|age| *age >= 0)
                            .map(|age| age as u64)
                    });
                    if status::is_connected(st.and_then(|s| s.latest_handshake), now) {
                        connected += 1;
                    }
                    peers.push(PeerMetric {
                        name: c.name.clone(),
                        enabled: c.enabled,
                        ipv4_address: c.ipv4_address.clone(),
                        ipv6_address: c.ipv6_address.clone(),
                        rx_bytes: st.map(|s| s.transfer_rx).unwrap_or(0),
                        tx_bytes: st.map(|s| s.transfer_tx).unwrap_or(0),
                        latest_handshake_seconds: hs_age,
                        endpoint: st.and_then(|s| s.endpoint.clone()),
                        public_key: c.public_key.clone(),
                    });
                }
            }
            Ok(MetricsSnapshot {
                interface: iface_name.clone(),
                configured_peers: configured,
                enabled_peers: enabled,
                connected_peers: connected,
                peers,
            })
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I6, defense in depth: with no stored hash the decision is a refusal,
    /// even when no Bearer is supplied.
    #[test]
    fn metrics_check_is_fail_closed_without_stored_password() {
        assert!(!metrics_check_decision(None, None));
        assert!(!metrics_check_decision(None, Some("anything")));
    }

    /// A stored hash only accepts the matching clear Bearer.
    #[test]
    fn metrics_check_requires_the_matching_bearer() {
        let hash = crate::auth::password::hash_password_blocking("scrape-secret")
            .expect("hash metrics password");
        assert!(!metrics_check_decision(Some(&hash), None));
        assert!(!metrics_check_decision(Some(&hash), Some("wrong")));
        assert!(metrics_check_decision(Some(&hash), Some("scrape-secret")));
    }
}
