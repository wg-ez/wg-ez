#![forbid(unsafe_code)]

//! Metrics DTOs: handwritten Prometheus text + JSON, byte-compatible in
//! shape with upstream v15 (verified against v15
//! `server/routes/metrics/*.get.ts` + `server/utils/prometheus.ts`).
//!
//! - Labels: `interface,enabled,ipv4Address,ipv6Address,name` (+ `endpoint`
//!   for `peer_endpoint_info`, row omitted when no endpoint observed).
//! - `latest_handshake_seconds` is seconds-since-handshake, `0` when never
//!   (v15 wart, kept for parity); "connected" means handshake < 2 min.
//! - JSON uses v15 keys (`wireguard_*_peers` + `clients[]`); no Prometheus
//!   crate (binary size). `time` features needed: `std`, `formatting`.

use serde::Serialize;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use super::ctx::{MetricsSnapshot, PeerMetric};

/// JSON envelope for `GET /metrics/json` (v15 keys).
#[derive(Debug, Clone, Serialize)]
pub struct MetricsJson {
    pub wireguard_configured_peers: u64,
    pub wireguard_enabled_peers: u64,
    pub wireguard_connected_peers: u64,
    pub clients: Vec<PeerMetricJson>,
}

/// Per-client JSON row (v15 keys).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerMetricJson {
    pub name: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_address: Option<String>,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_handshake_at: Option<String>,
    pub transfer_rx: u64,
    pub transfer_tx: u64,
}

impl From<&PeerMetric> for PeerMetricJson {
    fn from(p: &PeerMetric) -> Self {
        Self {
            name: p.name.clone(),
            enabled: p.enabled,
            ipv4_address: p.ipv4_address.clone(),
            ipv6_address: p.ipv6_address.clone(),
            public_key: p.public_key.clone(),
            endpoint: p.endpoint.clone(),
            latest_handshake_at: p.latest_handshake_seconds.and_then(handshake_iso),
            transfer_rx: p.rx_bytes,
            transfer_tx: p.tx_bytes,
        }
    }
}

/// `seconds-ago` -> RFC-3339 timestamp (v15 serializes `Date`s as ISO).
fn handshake_iso(secs_ago: u64) -> Option<String> {
    (OffsetDateTime::now_utc() - Duration::seconds(secs_ago.min(1 << 40) as i64))
        .format(&Rfc3339)
        .ok()
}

impl From<&MetricsSnapshot> for MetricsJson {
    fn from(s: &MetricsSnapshot) -> Self {
        Self {
            wireguard_configured_peers: s.configured_peers,
            wireguard_enabled_peers: s.enabled_peers,
            wireguard_connected_peers: s.connected_peers,
            clients: s.peers.iter().map(PeerMetricJson::from).collect(),
        }
    }
}

/// Prometheus label escaping, v15 order: `\` -> `\\`, newline -> `\n`,
/// `"` -> `\"`.
pub fn esc_label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

fn opt(s: Option<&String>) -> &str {
    s.map(String::as_str).unwrap_or("")
}

/// `name="value"` label set, v15 insertion order.
fn peer_labels(iface: &str, p: &PeerMetric) -> String {
    format!(
        "interface=\"{}\",enabled=\"{}\",ipv4Address=\"{}\",ipv6Address=\"{}\",name=\"{}\"",
        esc_label(iface),
        p.enabled,
        esc_label(opt(p.ipv4_address.as_ref())),
        esc_label(opt(p.ipv6_address.as_ref())),
        esc_label(&p.name),
    )
}

/// Render the Prometheus text exposition format (v15 HELP/TYPE lines).
pub fn render_prometheus(snap: &MetricsSnapshot) -> String {
    let mut out = String::with_capacity(1024 + snap.peers.len() * 256);
    let iface = esc_label(&snap.interface);
    out.push_str("# HELP wireguard_configured_peers\n");
    out.push_str("# TYPE wireguard_configured_peers gauge\n");
    out.push_str(&format!(
        "wireguard_configured_peers{{interface=\"{iface}\"}} {}\n",
        snap.configured_peers
    ));
    out.push('\n');
    out.push_str("# HELP wireguard_enabled_peers\n");
    out.push_str("# TYPE wireguard_enabled_peers gauge\n");
    out.push_str(&format!(
        "wireguard_enabled_peers{{interface=\"{iface}\"}} {}\n",
        snap.enabled_peers
    ));
    out.push('\n');
    out.push_str("# HELP wireguard_connected_peers\n");
    out.push_str("# TYPE wireguard_connected_peers gauge\n");
    out.push_str(&format!(
        "wireguard_connected_peers{{interface=\"{iface}\"}} {}\n",
        snap.connected_peers
    ));
    out.push('\n');
    out.push_str("# HELP wireguard_sent_bytes Bytes sent to the peer\n");
    out.push_str("# TYPE wireguard_sent_bytes counter\n");
    for p in &snap.peers {
        out.push_str(&format!(
            "wireguard_sent_bytes{{{}}} {}\n",
            peer_labels(&snap.interface, p),
            p.tx_bytes
        ));
    }
    out.push('\n');
    out.push_str("# HELP wireguard_received_bytes Bytes received from the peer\n");
    out.push_str("# TYPE wireguard_received_bytes counter\n");
    for p in &snap.peers {
        out.push_str(&format!(
            "wireguard_received_bytes{{{}}} {}\n",
            peer_labels(&snap.interface, p),
            p.rx_bytes
        ));
    }
    out.push('\n');
    out.push_str(
        "# HELP wireguard_latest_handshake_seconds UNIX timestamp seconds of the last handshake\n",
    );
    out.push_str("# TYPE wireguard_latest_handshake_seconds gauge\n");
    for p in &snap.peers {
        out.push_str(&format!(
            "wireguard_latest_handshake_seconds{{{}}} {}\n",
            peer_labels(&snap.interface, p),
            p.latest_handshake_seconds.unwrap_or(0)
        ));
    }
    out.push('\n');
    out.push_str(
        "# HELP wireguard_peer_endpoint_info Current endpoint (IP:port) of a connected peer\n",
    );
    out.push_str("# TYPE wireguard_peer_endpoint_info gauge\n");
    for p in &snap.peers {
        if let Some(ep) = p.endpoint.as_deref() {
            out.push_str(&format!(
                "wireguard_peer_endpoint_info{{{0},endpoint=\"{1}\"}} 1\n",
                peer_labels(&snap.interface, p),
                esc_label(ep)
            ));
        }
    }
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::ctx::{MetricsSnapshot, PeerMetric};

    fn snap() -> MetricsSnapshot {
        MetricsSnapshot {
            interface: "wg0".into(),
            configured_peers: 2,
            enabled_peers: 1,
            connected_peers: 1,
            peers: vec![
                PeerMetric {
                    name: "al\"ice".into(),
                    enabled: true,
                    ipv4_address: Some("10.8.0.2".into()),
                    ipv6_address: None,
                    rx_bytes: 10,
                    tx_bytes: 20,
                    latest_handshake_seconds: Some(42),
                    endpoint: Some("1.2.3.4:51820".into()),
                    public_key: "k".into(),
                },
                PeerMetric {
                    name: "bob".into(),
                    enabled: false,
                    ipv4_address: Some("10.8.0.3".into()),
                    ipv6_address: None,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    latest_handshake_seconds: None,
                    endpoint: None,
                    public_key: "k2".into(),
                },
            ],
        }
    }

    #[test]
    fn text_format_matches_v15_shape() {
        let t = render_prometheus(&snap());
        for want in [
            "wireguard_configured_peers{interface=\"wg0\"} 2",
            "wireguard_enabled_peers{interface=\"wg0\"} 1",
            "wireguard_connected_peers{interface=\"wg0\"} 1",
            "wireguard_sent_bytes{interface=\"wg0\",enabled=\"true\",ipv4Address=\"10.8.0.2\",ipv6Address=\"\",name=\"al\\\"ice\"} 20",
            "wireguard_received_bytes{interface=\"wg0\",enabled=\"true\",ipv4Address=\"10.8.0.2\",ipv6Address=\"\",name=\"al\\\"ice\"} 10",
            // never-seen handshake renders 0 (v15 wart).
            "wireguard_latest_handshake_seconds{interface=\"wg0\",enabled=\"false\",ipv4Address=\"10.8.0.3\",ipv6Address=\"\",name=\"bob\"} 0",
            "wireguard_peer_endpoint_info{interface=\"wg0\",enabled=\"true\",ipv4Address=\"10.8.0.2\",ipv6Address=\"\",name=\"al\\\"ice\",endpoint=\"1.2.3.4:51820\"} 1",
        ] {
            assert!(t.contains(want), "missing: {want}\n{t}");
        }
        // bob has no endpoint: exactly one endpoint_info row.
        assert_eq!(t.matches("wireguard_peer_endpoint_info{").count(), 1);
    }

    #[test]
    fn json_uses_v15_keys() {
        let s = snap();
        let j = MetricsJson::from(&s);
        assert_eq!(j.wireguard_connected_peers, 1);
        assert_eq!(j.clients.len(), 2);
        assert_eq!(j.clients[0].transfer_tx, 20);
        assert_eq!(j.clients[1].latest_handshake_at, None);
        assert!(j.clients[0].latest_handshake_at.is_some());
        let v = serde_json::to_value(&j).expect("json");
        assert_eq!(v["wireguard_configured_peers"], 2);
        assert_eq!(v["clients"][0]["publicKey"], "k");
    }
}
