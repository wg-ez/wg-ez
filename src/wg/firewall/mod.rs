//! Firewall par client, imposé côté serveur dans iptables.
//!
//! - Opt-in via `interface.firewallEnabled` (désactivé par défaut).
//! - Une chaîne par interface : `WG_CLIENTS_<iface>`, créée avec
//!   `-N ... || true`, vidée (`-F`) avant chaque repeuplement, rattachée à
//!   saut unique (`-D ... || true` puis `-I FORWARD 1 -i <iface>`),
//!   terminée par un `DROP` final.
//! - Reconstructions coalescées via [`Coalescer`].
//! - Priorité des sources : `firewallIps` non vide → `allowedIps` du client
//!   → `defaultAllowedIps` global.
//! - Un port est exigé dès qu'un proto est présent (`IP:port[/tcp|/udp]`,
//!   `CIDR:port`, `[v6]:port`) ; `IP/proto` seul est invalide.
//! - Destination IPv6 → `ip6tables` avec l'`ipv6Address` du client comme
//!   source ; ignorée si `IP_MODE=ipv4`.
//! - Chaque règle porte un commentaire `client <id>: <nom>` (sanitisé,
//!   tronqué à 256 octets).
//! - Boot avec firewall actif mais sans iptables : le flag est désactivé en
//!   DB par l'appelant ([`check_at_boot`] signale le cas) + warn.
//! - Disponibilité iptables sondée une fois puis mise en cache mémoire.

mod apply;
mod parse;
mod plan;
mod probe;

pub use apply::{Coalescer, apply_cmds, rebuild_coalesced};
pub use parse::{ParsedRule, Proto, parse_entry};
pub use plan::{
    FirewallClient, FirewallCmd, FirewallPlan, plan_rebuild, plan_remove, resolve_rules,
    rule_comment, sanitize_comment_name,
};
pub use probe::{
    BootFirewall, check_at_boot, clear_probe_cache, probe_available, probe_for_enable,
};

use std::fmt;

use super::runner::RunnerError;

/// Erreur firewall (parsing ou exécution).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallError {
    /// Entrée de règle invalide.
    InvalidEntry(String),
    /// Échec d'une commande iptables.
    Runner(RunnerError),
    /// Mutex empoisonné (ne devrait pas arriver avec `panic = "abort"`).
    Lock(String),
}

impl fmt::Display for FirewallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEntry(msg) => write!(f, "invalid firewall entry: {msg}"),
            Self::Runner(e) => write!(f, "firewall command failed: {e}"),
            Self::Lock(msg) => write!(f, "firewall lock poisoned: {msg}"),
        }
    }
}

impl std::error::Error for FirewallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runner(e) => Some(e),
            _ => None,
        }
    }
}

impl From<RunnerError> for FirewallError {
    fn from(e: RunnerError) -> Self {
        Self::Runner(e)
    }
}

/// Nom de la chaîne dédiée à une interface.
pub fn chain_name(iface: &str) -> String {
    format!("WG_CLIENTS_{iface}")
}

#[cfg(test)]
mod tests {
    use super::super::runner::{CommandOutput, MockRunner};
    use super::*;

    #[test]
    fn parses_all_documented_formats() {
        let ip = parse_entry("10.10.0.5").expect("ip");
        assert_eq!(ip.dest, "10.10.0.5");
        assert_eq!((ip.port, ip.proto), (None, None));
        assert!(!ip.is_v6);

        let cidr = parse_entry("10.10.0.0/24").expect("cidr");
        assert_eq!(cidr.dest, "10.10.0.0/24");

        let with_port = parse_entry("10.10.0.5:80").expect("port");
        assert_eq!((with_port.port, with_port.proto), (Some(80), None));

        let tcp = parse_entry("10.10.0.5:80/tcp").expect("tcp");
        assert_eq!((tcp.port, tcp.proto), (Some(80), Some(Proto::Tcp)));

        let udp = parse_entry("10.10.0.0/24:443/udp").expect("udp");
        assert_eq!((udp.port, udp.proto), (Some(443), Some(Proto::Udp)));

        let v6 = parse_entry("[::1]:443/tcp").expect("v6");
        assert!(v6.is_v6);
        assert_eq!(v6.dest, "::1");
        assert_eq!((v6.port, v6.proto), (Some(443), Some(Proto::Tcp)));
    }

    #[test]
    fn proto_without_port_is_invalid() {
        assert!(parse_entry("10.10.0.5/tcp").is_err());
        assert!(parse_entry("10.10.0.0/24/udp").is_err());
        assert!(parse_entry("[::1]/tcp").is_err());
    }

    #[test]
    fn bare_ipv6_needs_brackets_for_port() {
        // IPv6 nu : tout est destination, jamais de port.
        let bare = parse_entry("::/0").expect("bare v6");
        assert!(bare.is_v6);
        assert_eq!(bare.port, None);
    }

    #[test]
    fn bad_ports_rejected() {
        assert!(parse_entry("10.0.0.1:0").is_err());
        assert!(parse_entry("10.0.0.1:65536").is_err());
        assert!(parse_entry("10.0.0.1:http").is_err());
    }

    #[test]
    fn priority_firewall_then_allowed_then_default() {
        let def = vec!["0.0.0.0/0".to_string()];
        assert_eq!(
            resolve_rules(
                Some(&["10.0.0.1".to_string()]),
                Some(&["10.0.0.2".to_string()]),
                &def
            ),
            vec!["10.0.0.1".to_string()]
        );
        // firewallIps vide -> allowedIps.
        assert_eq!(
            resolve_rules(Some(&[]), Some(&["10.0.0.2".to_string()]), &def),
            vec!["10.0.0.2".to_string()]
        );
        // null, null -> défaut global.
        assert_eq!(resolve_rules(None, None, &def), def);
    }

    #[test]
    fn comment_sanitized_and_capped() {
        assert_eq!(rule_comment(7, "alice"), "client 7: alice");
        assert_eq!(rule_comment(1, "a;b\nc"), "client 1: a_b_c");
        let long = "x".repeat(300);
        let comment = rule_comment(1, &long);
        assert!(comment.len() <= "client 1: ".len() + 256);
    }

    #[test]
    fn rebuild_plan_shape() {
        let plan = FirewallPlan {
            iface: "wg0".to_string(),
            enabled: true,
            disable_ipv4: false,
            disable_ipv6: false,
            clients: vec![FirewallClient {
                id: 3,
                name: "bob".to_string(),
                ipv4: Some("10.8.0.3".to_string()),
                ipv6: Some("fdcc::3".to_string()),
                rules: vec![parse_entry("10.10.0.5:80/tcp").expect("rule")],
            }],
        };
        let cmds = plan_rebuild(&plan).expect("plan");
        let rendered: Vec<String> = cmds
            .iter()
            .map(|c| format!("{} {}", c.program, c.args.join(" ")))
            .collect();
        assert!(rendered.iter().any(|c| c == "iptables -N WG_CLIENTS_wg0"));
        // Flush avant repeuplement : sinon le DROP du rebuild precedent
        // masque toutes les nouvelles regles.
        assert!(rendered.iter().any(|c| c == "iptables -F WG_CLIENTS_wg0"));
        assert!(
            rendered
                .iter()
                .any(|c| c == "iptables -D FORWARD -i wg0 -j WG_CLIENTS_wg0")
        );
        assert!(
            rendered
                .iter()
                .any(|c| c == "iptables -I FORWARD 1 -i wg0 -j WG_CLIENTS_wg0")
        );
        // Le flush doit precéder la premiere regle `-A` de la chaine.
        let flush = rendered
            .iter()
            .position(|c| c == "iptables -F WG_CLIENTS_wg0")
            .expect("flush");
        let first_a = rendered
            .iter()
            .position(|c| c.starts_with("iptables -A WG_CLIENTS_wg0"))
            .expect("rule");
        assert!(flush < first_a);
        assert!(rendered.iter().any(|c| c.contains("-A WG_CLIENTS_wg0")
            && c.contains("-s 10.8.0.3")
            && c.contains("-d 10.10.0.5")
            && c.contains("-p tcp")
            && c.contains("--dport 80")
            && c.contains("client 3: bob")));
        assert!(
            rendered
                .iter()
                .any(|c| c == "iptables -A WG_CLIENTS_wg0 -j DROP")
        );
        assert!(
            rendered
                .iter()
                .any(|c| c == "ip6tables -A WG_CLIENTS_wg0 -j DROP")
        );
    }

    #[test]
    fn rebuild_skips_v6_when_disabled() {
        let plan = FirewallPlan {
            iface: "wg0".to_string(),
            enabled: true,
            disable_ipv4: false,
            disable_ipv6: true,
            clients: vec![FirewallClient {
                id: 1,
                name: "v6".to_string(),
                ipv4: Some("10.8.0.2".to_string()),
                ipv6: Some("fdcc::2".to_string()),
                rules: vec![parse_entry("[::1]:443/tcp").expect("rule")],
            }],
        };
        let cmds = plan_rebuild(&plan).expect("plan");
        assert!(!cmds.iter().any(|c| c.program == "ip6tables"));
        // La règle v6 est ignorée : pas de règle ACCEPT restante.
        assert!(!cmds.iter().any(|c| c.args.contains(&"ACCEPT".to_string())));
    }

    #[test]
    fn rebuild_skips_v4_when_disabled() {
        let plan = FirewallPlan {
            iface: "wg0".to_string(),
            enabled: true,
            disable_ipv4: true,
            disable_ipv6: false,
            clients: vec![FirewallClient {
                id: 1,
                name: "v4".to_string(),
                ipv4: Some("10.8.0.2".to_string()),
                ipv6: Some("fdcc::2".to_string()),
                rules: vec![parse_entry("10.10.0.5:80/tcp").expect("rule")],
            }],
        };
        let cmds = plan_rebuild(&plan).expect("plan");
        assert!(!cmds.iter().any(|c| c.program == "iptables"));
        // La règle v4 est ignorée : pas de règle ACCEPT restante.
        assert!(!cmds.iter().any(|c| c.args.contains(&"ACCEPT".to_string())));
        assert!(cmds.iter().any(|c| c.program == "ip6tables"));
    }

    #[test]
    fn coalescer_runs_single_rebuild() {
        let mock = MockRunner::new();
        let guard = Coalescer::new();
        let plan = FirewallPlan {
            iface: "wg0".to_string(),
            enabled: true,
            disable_ipv4: false,
            disable_ipv6: true,
            clients: vec![],
        };
        rebuild_coalesced(&mock, &guard, &plan).expect("rebuild");
        assert!(!guard.is_in_progress());
        assert!(!mock.calls().is_empty());
    }

    #[test]
    fn probe_cache_and_boot_check() {
        clear_probe_cache();
        let mock = MockRunner::new();
        mock.respond_program("iptables", CommandOutput::stdout_text("iptables v1.8\n"));
        mock.respond_program("ip6tables", CommandOutput::stdout_text("ip6tables v1.8\n"));
        assert!(probe_available(&mock, true));
        let before = mock.call_count();
        // Second appel : cache, aucune nouvelle commande.
        assert!(probe_available(&mock, true));
        assert_eq!(mock.call_count(), before);

        assert_eq!(check_at_boot(&mock, false, false), BootFirewall::Ok);

        clear_probe_cache();
        let missing = MockRunner::new();
        missing.set_default_fail(true);
        assert_eq!(
            check_at_boot(&missing, true, false),
            BootFirewall::DisabledNoIptables
        );
        clear_probe_cache();
    }
}
