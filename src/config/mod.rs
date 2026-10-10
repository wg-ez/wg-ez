//! Lecture + validation des variables d'environnement, une fois au boot.
//!
//! La config est validee par [`AppConfig::load`] (ou [`AppConfig::load_from`)
//! puis figee (`Clone`, aucun interieur mutable) : les handlers et la CLI
//! partagent ensuite la meme valeur sans la relire.
//!
//! Regles implementees :
//! - `PORT` requis, 1..=65535.
//! - `HOST` vaut `0.0.0.0` par defaut.
//! - `WG_INTERFACE` : 1..=15 caracteres dans `[a-zA-Z0-9_=+.-]`.
//! - `PASSWORD` / `PASSWORD_HASH` (v14) refusent le boot avec un pointeur vers
//!   le guide de migration v14 -> v15.
//! - `TRUSTED_PROXIES` : CSV d'IP et de CIDR, vide par defaut ; toute valeur
//!   invalide refuse le boot. Seuls ces proxys autorisent `X-Forwarded-For`.
//!   `X-Forwarded-Host` n'est jamais honore (pas de routage par hote) et
//!   `X-Forwarded-Proto` non plus (le protocole reel est dicte uniquement par
//!   `INSECURE`).
//! - `INIT_ENABLED` exige le groupe 1 (`INIT_USERNAME`, `INIT_PASSWORD` de 12+
//!   caracteres, `INIT_HOST`, `INIT_PORT`) plus les groupes optionnels
//!   DNS / CIDR / AllowedIPs.
//! - `EXPERIMENTAL_AWG`, `OVERRIDE_AUTO_AWG` et `OAUTH_*` sont ignorees (AWG et
//!   OAuth exclus de la V1) : leur presence ne fait ni boot ni erreur.

mod init;
mod parse;
mod types;

pub use parse::{parse_trusted_proxies, validate_interface};
pub use types::{AppConfig, ConfigError, InitConfig};

use std::collections::HashMap;

use init::load_init;
use parse::{check_string, parse_bool_default, parse_port, raw};

/// Interface selection mode (`IP_MODE`).
///
/// - `auto` : chaque famille suit sa detection (conteneur sans IPv6 global
///   -> IPv4 seul ; sans route IPv4 -> IPv6 seul ; ni l'un ni l'autre ->
///   double pile par prudence pour ne jamais demarrer sans famille) ;
/// - `ipv4` : IPv4 seul ; `ipv6` : IPv6 seul ; `both` : les deux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpMode {
    Auto,
    Ipv4,
    Ipv6,
    Both,
}

impl IpMode {
    /// `(disable_ipv4, disable_ipv6)`.
    pub fn flags(self, ipv4_available: bool, ipv6_available: bool) -> (bool, bool) {
        match self {
            IpMode::Auto => match (ipv4_available, ipv6_available) {
                (true, true) | (false, false) => (false, false),
                (true, false) => (false, true),
                (false, true) => (true, false),
            },
            IpMode::Ipv4 => (false, true),
            IpMode::Ipv6 => (true, false),
            IpMode::Both => (false, false),
        }
    }
}

/// Detection de la disponibilite IPv4 du conteneur au demarrage.
///
/// En `auto`, symetrique d'IPv6 : on exige une route IPv4 (`/proc/net/route`)
/// sur une interface autre que `lo` et autre que l'interface WireGuard
/// elle-meme (sinon la route `10.8.0.0/24` d'une precedente `.conf`
/// auto-entretiendrait la detection). Un conteneur IPv6-only (aucune route
/// IPv4 hors `lo`) donne donc `false`. Hors Linux (`/proc` absent) on retombe
/// sur un bind `0.0.0.0:0`.
pub fn detect_ipv4_available() -> bool {
    let exclude = std::env::var("WG_INTERFACE").unwrap_or_else(|_| "wg0".to_string());
    detect_ipv4_available_except(&exclude)
}

/// Variante testable de [`detect_ipv4_available`] (interface exclue explicite).
pub fn detect_ipv4_available_except(exclude_iface: &str) -> bool {
    match std::fs::read_to_string("/proc/net/route") {
        Ok(content) => has_usable_ipv4_route(&content, exclude_iface),
        Err(_) => std::net::UdpSocket::bind("0.0.0.0:0").is_ok(),
    }
}

/// Vrai si `/proc/net/route` expose une route IPv4 utilisable.
///
/// Format noyau : en-tete `Iface Destination Gateway Flags ...`, une ligne par
/// route (`Destination`/`Flags` en hex). On ignore `lo`, l'interface exclue et
/// les routes non `RTF_UP` (bit `0x1` des flags).
fn has_usable_ipv4_route(content: &str, exclude_iface: &str) -> bool {
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(dev), Some(_dst), Some(_gw), Some(flags)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if dev == "Iface" || dev == "lo" || dev == exclude_iface {
            continue;
        }
        if u32::from_str_radix(flags, 16).is_ok_and(|f| f & 0x1 == 0) {
            continue;
        }
        if interface_up(dev).unwrap_or(true) {
            return true;
        }
    }
    false
}

/// Detection de la disponibilite IPv6 du conteneur au demarrage.
///
/// `IP_MODE` permet de forcer ; en `auto` cette fonction decide. Le seul
/// drapeau noyau (`.../disable_ipv6 == 0`) ne suffit pas : il est a `0` sur
/// presque tous les hotes Docker meme quand le conteneur n'a aucun reseau
/// IPv6 attache (cas remonte : conteneur sur `bridge` IPv4 seul, IPv6 present
/// dans `.conf` alors qu'attendu en IPv4 seul). On exige donc une adresse
/// IPv6 globale (scope `00` dans `/proc/net/if_inet6`) sur une interface
/// autre que `lo` et autre que l'interface WireGuard elle-meme (sinon une
/// precedente `.conf` avec ULA `fd00:...` auto-entretiendrait la detection).
/// Les loopback (`::1`, scope `10`) et link-local (`fe80::/10`, scope `20`)
/// ne comptent pas. Hors Linux (`/proc` absent) on retombe sur un bind
/// `[::]:0`.
pub fn detect_ipv6_available() -> bool {
    let exclude = std::env::var("WG_INTERFACE").unwrap_or_else(|_| "wg0".to_string());
    detect_ipv6_available_except(&exclude)
}

/// Variante testable de [`detect_ipv6_available`] (interface exclue explicite).
pub fn detect_ipv6_available_except(exclude_iface: &str) -> bool {
    if std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
        .is_ok_and(|v| v.trim() == "1")
    {
        return false;
    }
    match std::fs::read_to_string("/proc/net/if_inet6") {
        Ok(content) => has_global_ipv6(&content, exclude_iface),
        Err(_) => std::net::UdpSocket::bind("[::]:0").is_ok(),
    }
}

/// Vrai si le contenu de `/proc/net/if_inet6` expose une adresse globale.
///
/// Format noyau par ligne : `<addr32hex> <ifindex> <prefixlen> <scope> <flags> <dev>`
/// (`scope` en hex : `00` global, `10` hote/loopback, `20` lien). On ignore les
/// adresses `tentative` (DAD en cours, bit `0x40` des flags) et les interfaces
/// `lo` / exclue.
fn has_global_ipv6(content: &str, exclude_iface: &str) -> bool {
    content.lines().any(|line| {
        let mut parts = line.split_whitespace();
        let (Some(addr), Some(_idx), Some(_plen), Some(scope), Some(flags), Some(dev)) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return false;
        };
        if !scope.eq_ignore_ascii_case("00") {
            return false;
        }
        if addr.eq_ignore_ascii_case("00000000000000000000000000000001") {
            return false;
        }
        if dev == "lo" || dev == exclude_iface {
            return false;
        }
        if u8::from_str_radix(flags, 16).is_ok_and(|f| f & 0x40 != 0) {
            return false;
        }
        interface_up(dev).unwrap_or(true)
    })
}

/// Best-effort : `false` si `/sys/class/net/<dev>/operstate` vaut `down` ou
/// `dormant`. `None` (fichier illisible, non-Linux) = on ne filtre pas.
fn interface_up(dev: &str) -> Option<bool> {
    let state = std::fs::read_to_string(format!("/sys/class/net/{dev}/operstate")).ok()?;
    let s = state.trim().to_ascii_lowercase();
    if s == "down" || s == "dormant" {
        Some(false)
    } else {
        Some(true)
    }
}

/// Resout `IP_MODE` en drapeaux de famille.
///
/// `IP_MODE` est l'unique levier : `auto` (defaut, detection IPv4 + IPv6),
/// `ipv4`, `ipv6` ou `both`. Toute autre valeur refuse le boot.
pub fn resolve_ip_mode(
    env: &HashMap<String, String>,
    ipv4_available: bool,
    ipv6_available: bool,
) -> Result<(bool, bool), ConfigError> {
    let mode = match raw(env, "IP_MODE") {
        None => IpMode::Auto,
        Some(mode) => match mode.to_ascii_lowercase().as_str() {
            "auto" => IpMode::Auto,
            "ipv4" | "4" | "v4" => IpMode::Ipv4,
            "ipv6" | "6" | "v6" => IpMode::Ipv6,
            "both" | "dual" => IpMode::Both,
            _ => {
                return Err(ConfigError::Invalid(
                    "IP_MODE",
                    "must be auto, ipv4, ipv6 or both".to_string(),
                ));
            }
        },
    };
    Ok(mode.flags(ipv4_available, ipv6_available))
}

const MIGRATION_POINTER: &str = "v14 PASSWORD/PASSWORD_HASH were removed in v15; follow the v14 -> v15 migration guide \
     and create the admin via the setup assistant or INIT_* instead";

impl AppConfig {
    /// Vrai quand la famille IPv4 est active.
    pub fn ipv4_enabled(&self) -> bool {
        !self.disable_ipv4
    }

    /// Vrai quand la famille IPv6 est active.
    pub fn ipv6_enabled(&self) -> bool {
        !self.disable_ipv6
    }

    /// Lit et valide l'environnement du process, une fois au boot.
    pub fn load() -> Result<Self, ConfigError> {
        let env: HashMap<String, String> = std::env::vars().collect();
        Self::load_from(&env)
    }

    /// Variante pure (tests) : valide une map au lieu du process.
    pub fn load_from(env: &HashMap<String, String>) -> Result<Self, ConfigError> {
        // `EXPERIMENTAL_AWG`, `OVERRIDE_AUTO_AWG`, `OAUTH_*` : ignorees (V1).
        // `X-Forwarded-Proto` : jamais honore, donc jamais lu ici.

        if env.get("PASSWORD").is_some_and(|v| !v.trim().is_empty()) {
            return Err(ConfigError::Legacy(
                "PASSWORD",
                MIGRATION_POINTER.to_string(),
            ));
        }
        if env
            .get("PASSWORD_HASH")
            .is_some_and(|v| !v.trim().is_empty())
        {
            return Err(ConfigError::Legacy(
                "PASSWORD_HASH",
                MIGRATION_POINTER.to_string(),
            ));
        }

        let port_raw = match raw(env, "PORT") {
            Some(v) => v,
            None => return Err(ConfigError::Missing("PORT")),
        };
        let port = parse_port("PORT", &port_raw)?;

        let host = match raw(env, "HOST") {
            Some(v) => v,
            None => "0.0.0.0".to_string(),
        };
        check_string("HOST", &host)?;

        let wg_interface = match raw(env, "WG_INTERFACE") {
            Some(v) => v,
            None => "wg0".to_string(),
        };
        validate_interface(&wg_interface)?;

        let trusted_proxies = match raw(env, "TRUSTED_PROXIES") {
            Some(v) => parse_trusted_proxies(&v)?,
            None => Vec::new(),
        };

        let init_enabled = parse_bool_default(env, "INIT_ENABLED", false)?;
        let init = if init_enabled {
            Some(load_init(env)?)
        } else {
            None
        };

        let db_path = match raw(env, "DB_PATH") {
            Some(v) => v,
            None => "/etc/wireguard/wg-ez.db".to_string(),
        };
        let wg_conf_dir = match raw(env, "WG_CONF_DIR") {
            Some(v) => v,
            None => "/etc/wireguard".to_string(),
        };

        let (disable_ipv4, disable_ipv6) = resolve_ip_mode(
            env,
            detect_ipv4_available_except(&wg_interface),
            detect_ipv6_available_except(&wg_interface),
        )?;

        Ok(Self {
            host,
            port,
            insecure: parse_bool_default(env, "INSECURE", false)?,
            disable_ipv6,
            disable_ipv4,
            disable_password_auth: parse_bool_default(env, "DISABLE_PASSWORD_AUTH", false)?,
            wg_interface,
            trusted_proxies,
            db_path,
            wg_conf_dir,
            init,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        let mut m = HashMap::new();
        for (k, v) in pairs {
            m.insert((*k).to_string(), (*v).to_string());
        }
        m
    }

    #[test]
    fn port_is_required() {
        assert!(matches!(
            AppConfig::load_from(&env(&[])),
            Err(ConfigError::Missing("PORT"))
        ));
    }

    #[test]
    fn port_range_checked() -> Result<(), ConfigError> {
        AppConfig::load_from(&env(&[("PORT", "51821")]))?;
        assert!(matches!(
            AppConfig::load_from(&env(&[("PORT", "0")])),
            Err(ConfigError::Invalid("PORT", _))
        ));
        assert!(matches!(
            AppConfig::load_from(&env(&[("PORT", "99999")])),
            Err(ConfigError::Invalid("PORT", _))
        ));
        assert!(matches!(
            AppConfig::load_from(&env(&[("PORT", "abc")])),
            Err(ConfigError::Invalid("PORT", _))
        ));
        Ok(())
    }

    #[test]
    fn legacy_password_refuses_boot() {
        assert!(matches!(
            AppConfig::load_from(&env(&[("PORT", "51821"), ("PASSWORD", "secret")])),
            Err(ConfigError::Legacy("PASSWORD", _))
        ));
        assert!(matches!(
            AppConfig::load_from(&env(&[("PORT", "51821"), ("PASSWORD_HASH", "hash")])),
            Err(ConfigError::Legacy("PASSWORD_HASH", _))
        ));
    }

    #[test]
    fn interface_charset_and_length() -> Result<(), ConfigError> {
        let cfg = AppConfig::load_from(&env(&[("PORT", "51821")]))?;
        assert_eq!(cfg.wg_interface, "wg0");
        AppConfig::load_from(&env(&[("PORT", "51821"), ("WG_INTERFACE", "a-b_c=d+e.f")]))?;
        assert!(matches!(
            AppConfig::load_from(&env(&[
                ("PORT", "51821"),
                ("WG_INTERFACE", "0123456789abcdef")
            ])),
            Err(ConfigError::Invalid("WG_INTERFACE", _))
        ));
        assert!(matches!(
            AppConfig::load_from(&env(&[("PORT", "51821"), ("WG_INTERFACE", "wg0!")])),
            Err(ConfigError::Invalid("WG_INTERFACE", _))
        ));
        Ok(())
    }

    #[test]
    fn trusted_proxies_csv() -> Result<(), ConfigError> {
        let cfg = AppConfig::load_from(&env(&[("PORT", "51821")]))?;
        assert!(cfg.trusted_proxies.is_empty());
        let cfg = AppConfig::load_from(&env(&[
            ("PORT", "51821"),
            ("TRUSTED_PROXIES", "10.0.0.1, 192.168.0.0/16, ::1"),
        ]))?;
        assert_eq!(cfg.trusted_proxies.len(), 3);
        assert!(matches!(
            AppConfig::load_from(&env(&[("PORT", "51821"), ("TRUSTED_PROXIES", "nope")])),
            Err(ConfigError::Invalid("TRUSTED_PROXIES", _))
        ));
        Ok(())
    }

    #[test]
    fn awg_and_oauth_envs_ignored() -> Result<(), ConfigError> {
        AppConfig::load_from(&env(&[
            ("PORT", "51821"),
            ("EXPERIMENTAL_AWG", "1"),
            ("OVERRIDE_AUTO_AWG", "1"),
            ("OAUTH_GOOGLE_ID", "x"),
        ]))?;
        Ok(())
    }

    #[test]
    fn init_requires_group_one() {
        assert!(matches!(
            AppConfig::load_from(&env(&[("PORT", "51821"), ("INIT_ENABLED", "1")])),
            Err(ConfigError::InitIncomplete(_))
        ));
        assert!(matches!(
            AppConfig::load_from(&env(&[
                ("PORT", "51821"),
                ("INIT_ENABLED", "true"),
                ("INIT_USERNAME", "admin"),
                ("INIT_PASSWORD", "short"),
                ("INIT_HOST", "vpn.example.com"),
                ("INIT_PORT", "51820"),
            ])),
            Err(ConfigError::Invalid("INIT_PASSWORD", _))
        ));
    }

    #[test]
    fn init_happy_path() -> Result<(), ConfigError> {
        let cfg = AppConfig::load_from(&env(&[
            ("PORT", "51821"),
            ("INIT_ENABLED", "true"),
            ("INIT_USERNAME", "admin"),
            ("INIT_PASSWORD", "twelve-chars!!"),
            ("INIT_HOST", "vpn.example.com"),
            ("INIT_PORT", "51820"),
        ]))?;
        let init = cfg
            .init
            .filter(|i| i.username == "admin" && i.port == 51820);
        assert!(init.is_some());
        Ok(())
    }

    /// `INIT_DNS` n'accepte que des IP nues (v4 ou v6), jamais un nom ou
    /// un CIDR ; c'est le chemin de boot réel (`config::init`).
    #[test]
    fn init_dns_requires_bare_ip() {
        let with_dns = |dns: &str| {
            env(&[
                ("PORT", "51821"),
                ("INIT_ENABLED", "true"),
                ("INIT_USERNAME", "admin"),
                ("INIT_PASSWORD", "twelve-chars!!"),
                ("INIT_HOST", "vpn.example.com"),
                ("INIT_PORT", "51820"),
                ("INIT_DNS", dns),
            ])
        };
        assert!(matches!(
            AppConfig::load_from(&with_dns("dns.google")),
            Err(ConfigError::Invalid("INIT_DNS", _))
        ));
        assert!(matches!(
            AppConfig::load_from(&with_dns("1.1.1.1/24")),
            Err(ConfigError::Invalid("INIT_DNS", _))
        ));
        assert!(AppConfig::load_from(&with_dns("1.1.1.1,2606:4700:4700::1111")).is_ok());
    }

    #[test]
    fn host_and_bool_defaults() -> Result<(), ConfigError> {
        let cfg = AppConfig::load_from(&env(&[("PORT", "51821"), ("IP_MODE", "both")]))?;
        assert_eq!(cfg.host, "0.0.0.0");
        assert!(!cfg.insecure);
        assert!(!cfg.disable_ipv6);
        assert!(!cfg.disable_ipv4);
        assert!(!cfg.disable_password_auth);
        assert!(cfg.init.is_none());
        Ok(())
    }

    #[test]
    fn ip_mode_resolution() -> Result<(), ConfigError> {
        // Explicite : ne depend jamais de la detection.
        assert_eq!(
            resolve_ip_mode(&env(&[("IP_MODE", "ipv4")]), true, true)?,
            (false, true)
        );
        assert_eq!(
            resolve_ip_mode(&env(&[("IP_MODE", "ipv6")]), true, true)?,
            (true, false)
        );
        assert_eq!(
            resolve_ip_mode(&env(&[("IP_MODE", "both")]), false, false)?,
            (false, false)
        );
        // auto : matrice symetrique ; ni l'un ni l'autre -> double pile (fail-open).
        assert_eq!(resolve_ip_mode(&env(&[]), true, true)?, (false, false));
        assert_eq!(resolve_ip_mode(&env(&[]), true, false)?, (false, true));
        assert_eq!(resolve_ip_mode(&env(&[]), false, true)?, (true, false));
        assert_eq!(resolve_ip_mode(&env(&[]), false, false)?, (false, false));
        assert_eq!(
            resolve_ip_mode(&env(&[("IP_MODE", "auto")]), true, false)?,
            (false, true)
        );
        assert_eq!(
            resolve_ip_mode(&env(&[("IP_MODE", "auto")]), false, true)?,
            (true, false)
        );
        // Valeurs alternatives et casse.
        assert_eq!(
            resolve_ip_mode(&env(&[("IP_MODE", "IPv4")]), true, true)?,
            (false, true)
        );
        assert_eq!(
            resolve_ip_mode(&env(&[("IP_MODE", "dual")]), true, true)?,
            (false, false)
        );
        assert!(resolve_ip_mode(&env(&[("IP_MODE", "nope")]), true, true).is_err());
        Ok(())
    }

    #[test]
    fn ip_mode_env_in_config() -> Result<(), ConfigError> {
        let cfg = AppConfig::load_from(&env(&[("PORT", "51821"), ("IP_MODE", "ipv6")]))?;
        assert!(cfg.disable_ipv4);
        assert!(!cfg.disable_ipv6);
        assert!(!cfg.ipv4_enabled());
        assert!(cfg.ipv6_enabled());
        Ok(())
    }

    /// La detection `auto` exige une adresse globale : loopback + link-local
    /// seuls (conteneur sur bridge IPv4, cas remonte) = pas d'IPv6.
    #[test]
    fn has_global_ipv6_ignores_loopback_and_linklocal() {
        let v4_only = "00000000000000000000000000000001 01 80 10 80 lo\n\
             fe800000000000000242acfffe140002 02 40 20 80 eth0\n";
        assert!(!super::has_global_ipv6(v4_only, "wg0"));
        // Ligne malformee = ignoree, jamais de panique.
        assert!(!super::has_global_ipv6("nonsense\n", "wg0"));
        assert!(!super::has_global_ipv6("", "wg0"));
    }

    /// Une globale sur `eth0` compte ; sur `wg0` (ULA d'une precedente conf)
    /// ou en `tentative` (DAD), non.
    #[test]
    fn has_global_ipv6_counts_only_usable_global() {
        let with_global = "00000000000000000000000000000001 01 80 10 80 lo\n\
             20010db8000000000000000000000001 02 80 00 80 eth0\n";
        assert!(super::has_global_ipv6(with_global, "wg0"));
        let wg_only = "fd00deadbeefcafe0000000000000001 0a 80 00 80 wg0\n";
        assert!(!super::has_global_ipv6(wg_only, "wg0"));
        let tentative = "20010db8000000000000000000000002 02 80 00 40 eth0\n";
        assert!(!super::has_global_ipv6(tentative, "wg0"));
    }

    /// Routes IPv4 : `eth0` compte, `lo` / `wg0` / route `DOWN` seuls non.
    #[test]
    fn has_usable_ipv4_route_ignores_lo_wg_and_down() {
        let h =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n";
        let lo = "lo\t00000000\t0100007F\t0003\t0\t0\t0\t00000000\t0\t0\t0\n";
        assert!(!super::has_usable_ipv4_route(&format!("{h}{lo}"), "wg0"));
        let eth_def = "eth0\t00000000\t010014AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n";
        let eth_net = "eth0\t0014AC\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        assert!(!super::has_usable_ipv4_route(h, "wg0"));
        assert!(super::has_usable_ipv4_route(
            &format!("{h}{eth_def}{eth_net}"),
            "wg0"
        ));
        let wg = "wg0\t0008080A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        assert!(!super::has_usable_ipv4_route(&format!("{h}{wg}"), "wg0"));
        let down = "eth0\t00000000\t010014AC\t0000\t0\t0\t0\t00000000\t0\t0\t0\n";
        assert!(!super::has_usable_ipv4_route(&format!("{h}{down}"), "wg0"));
        assert!(!super::has_usable_ipv4_route("", "wg0"));
    }
}
