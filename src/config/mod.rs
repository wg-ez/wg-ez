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
/// - `auto` : IPv4 toujours actif, IPv6 depend de la detection noyau ;
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
    pub fn flags(self, ipv6_available: bool) -> (bool, bool) {
        match self {
            IpMode::Auto => (false, !ipv6_available),
            IpMode::Ipv4 => (false, true),
            IpMode::Ipv6 => (true, false),
            IpMode::Both => (false, false),
        }
    }
}

/// Detection de la disponibilite IPv6 du conteneur/noyau au demarrage.
///
/// `IP_MODE` permet de forcer ; en `auto` cette fonction decide. On lit
/// d'abord le drapeau noyau (`/proc/net` peut etre absent hors Linux), puis
/// on retombe sur un bind `[::]:0` : un noyau avec IPv6 desactive refuse la
/// socket, ce qui est exactement « pas d'IPv6 pour WireGuard ».
pub fn detect_ipv6_available() -> bool {
    if let Ok(v) = std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6") {
        return v.trim() == "0";
    }
    std::net::UdpSocket::bind("[::]:0").is_ok()
}

/// Resout `IP_MODE` en drapeaux de famille.
///
/// `IP_MODE` est l'unique levier : `auto` (defaut, detection IPv6),
/// `ipv4`, `ipv6` ou `both`. Toute autre valeur refuse le boot.
pub fn resolve_ip_mode(
    env: &HashMap<String, String>,
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
    Ok(mode.flags(ipv6_available))
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

        let (disable_ipv4, disable_ipv6) = resolve_ip_mode(env, detect_ipv6_available())?;

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
            resolve_ip_mode(&env(&[("IP_MODE", "ipv4")]), true)?,
            (false, true)
        );
        assert_eq!(
            resolve_ip_mode(&env(&[("IP_MODE", "ipv6")]), true)?,
            (true, false)
        );
        assert_eq!(
            resolve_ip_mode(&env(&[("IP_MODE", "both")]), false)?,
            (false, false)
        );
        // auto : IPv6 present -> dual, absent -> IPv4 seul.
        assert_eq!(resolve_ip_mode(&env(&[]), true)?, (false, false));
        assert_eq!(resolve_ip_mode(&env(&[]), false)?, (false, true));
        assert_eq!(
            resolve_ip_mode(&env(&[("IP_MODE", "auto")]), false)?,
            (false, true)
        );
        // Valeurs alternatives et casse.
        assert_eq!(
            resolve_ip_mode(&env(&[("IP_MODE", "IPv4")]), true)?,
            (false, true)
        );
        assert_eq!(
            resolve_ip_mode(&env(&[("IP_MODE", "dual")]), true)?,
            (false, false)
        );
        assert!(resolve_ip_mode(&env(&[("IP_MODE", "nope")]), true).is_err());
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
}
