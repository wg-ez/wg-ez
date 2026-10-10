//! Statut temps réel parsé depuis `wg show <iface> dump` (TSV).
//!
//! - endpoint `(none)` → `None` ;
//! - handshake `0` → `None` (jamais vu) ;
//! - connecté = handshake de moins de 2 minutes ;
//! - compteurs Rx/Tx en octets cumulés.

use std::fmt;

/// Un handshake est frais s'il date de moins de 2 minutes.
pub const CONNECTED_HANDSHAKE_MAX_SECS: i64 = 2 * 60;

/// Statut d'un pair tel que rapporté par `wg dump`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerStatus {
    /// Clé publique du pair.
    pub public_key: String,
    /// Endpoint observé (`None` si `(none)`).
    pub endpoint: Option<String>,
    /// Dernier handshake en secondes Unix (`None` si `0`).
    pub latest_handshake: Option<i64>,
    /// Octets reçus cumulés.
    pub transfer_rx: u64,
    /// Octets émis cumulés.
    pub transfer_tx: u64,
}

/// Vrai si `handshake` (secondes Unix) a moins de 2 minutes à `now_unix`.
/// Un handshake futur ou absent n'est jamais connecté.
pub fn is_connected(handshake: Option<i64>, now_unix: i64) -> bool {
    match handshake {
        Some(hs) => hs <= now_unix && now_unix - hs < CONNECTED_HANDSHAKE_MAX_SECS,
        None => false,
    }
}

/// Erreur de parsing du dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusError {
    /// Ligne de pair malformée (compteurs ou handshake illisibles).
    BadLine { line_no: usize, reason: String },
}

impl fmt::Display for StatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLine { line_no, reason } => {
                write!(f, "bad wg dump peer line {line_no}: {reason}")
            }
        }
    }
}

impl std::error::Error for StatusError {}

/// Parse la sortie complète de `wg show <iface> dump`.
///
/// La première ligne (4 champs : clé privée, clé publique, port, fwmark)
/// décrit l'interface et est ignorée ; chaque ligne à 8 champs décrit un
/// pair. Les lignes vides sont ignorées.
pub fn parse_dump(text: &str) -> Result<Vec<PeerStatus>, StatusError> {
    let mut peers = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let line = line.trim_end();
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() == 4 {
            // Ligne d'interface : ignorée.
            continue;
        }
        if fields.len() != 8 {
            return Err(StatusError::BadLine {
                line_no: idx + 1,
                reason: format!("expected 8 tab-separated fields, got {}", fields.len()),
            });
        }
        peers.push(parse_peer_line(idx + 1, &fields)?);
    }
    Ok(peers)
}

fn parse_peer_line(line_no: usize, f: &[&str]) -> Result<PeerStatus, StatusError> {
    let bad = |reason: &str| StatusError::BadLine {
        line_no,
        reason: reason.to_string(),
    };

    let public_key = f[0].trim();
    if public_key.is_empty() {
        return Err(bad("empty public key"));
    }
    let endpoint = match f[2].trim() {
        "" | "(none)" => None,
        ep => Some(ep.to_string()),
    };
    let latest_handshake = match f[4].trim().parse::<i64>() {
        Ok(0) => None,
        Ok(hs) if hs > 0 => Some(hs),
        _ => return Err(bad("bad latest handshake timestamp")),
    };
    let transfer_rx = f[5]
        .trim()
        .parse::<u64>()
        .map_err(|_| bad("bad transfer-rx counter"))?;
    let transfer_tx = f[6]
        .trim()
        .parse::<u64>()
        .map_err(|_| bad("bad transfer-tx counter"))?;

    Ok(PeerStatus {
        public_key: public_key.to_string(),
        endpoint,
        latest_handshake,
        transfer_rx,
        transfer_tx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "SERVERPRIV\tSERVERPUB\t51820\toff\n\
        CLIENTPUB1\tPSK\t192.0.2.10:51280\t10.8.0.2/32\t1700000000\t1234\t5678\t25\n\
        CLIENTPUB2\t(none)\t(none)\t10.8.0.3/32\t0\t0\t0\toff\n";

    #[test]
    fn parses_interface_and_peers() {
        let peers = parse_dump(SAMPLE).expect("parse");
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].public_key, "CLIENTPUB1");
        assert_eq!(peers[0].endpoint.as_deref(), Some("192.0.2.10:51280"));
        assert_eq!(peers[0].latest_handshake, Some(1_700_000_000));
        assert_eq!((peers[0].transfer_rx, peers[0].transfer_tx), (1234, 5678));
        // `(none)` -> None, `0` -> None.
        assert_eq!(peers[1].endpoint, None);
        assert_eq!(peers[1].latest_handshake, None);
    }

    #[test]
    fn connected_means_handshake_under_two_minutes() {
        assert!(is_connected(Some(1_700_000_000), 1_700_000_000 + 119));
        assert!(!is_connected(Some(1_700_000_000), 1_700_000_000 + 120));
        assert!(!is_connected(None, 1_700_000_000));
        // Handshake futur : pas connecté.
        assert!(!is_connected(Some(1_700_000_100), 1_700_000_000));
    }

    #[test]
    fn bad_counters_rejected() {
        let bad = "PRIV\tPUB\t51820\toff\nPUB\tPSK\tep\tips\tnot-a-number\trx\ttx\t25\n";
        assert!(parse_dump(bad).is_err());
    }

    #[test]
    fn empty_dump_yields_no_peers() {
        assert_eq!(parse_dump("").expect("empty"), vec![]);
    }
}
