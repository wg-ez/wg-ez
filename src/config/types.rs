//! Types figes de la configuration (`PORT`, `HOST`, `INIT_*`, ...).
//!
//! Voir [`crate::config`] pour les regles implementees.

use ipnet::IpNet;
use thiserror::Error;

/// Erreur de validation de la configuration (refus de boot).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    /// Variable obligatoire absente.
    #[error("missing required env {0}")]
    Missing(&'static str),
    /// Variable presente mais invalide.
    #[error("invalid env {0}: {1}")]
    Invalid(&'static str, String),
    /// Variable legacy v14 : le boot est refuse avec un pointeur migration.
    #[error("legacy env {0} is set: {1}")]
    Legacy(&'static str, String),
    /// Setup non-interactif incomplet : champ manquant.
    #[error("INIT_ENABLED requires {0}")]
    InitIncomplete(&'static str),
}

/// Parametres du setup non-interactif (`INIT_ENABLED=true`).
#[derive(Clone, PartialEq, Eq)]
pub struct InitConfig {
    /// Login du compte admin a creer.
    pub username: String,
    /// Mot de passe admin (12+ caracteres, verifie au boot).
    pub password: String,
    /// Host public annonce aux clients.
    pub host: String,
    /// Port public annonce aux clients.
    pub port: u16,
    /// DNS par defaut (`INIT_DNS`, CSV).
    pub dns: Vec<String>,
    /// Pool IPv4 (`INIT_IPV4_CIDR`).
    pub ipv4_cidr: IpNet,
    /// Pool IPv6 (`INIT_IPV6_CIDR`, vide = desactive).
    pub ipv6_cidr: Option<IpNet>,
    /// AllowedIPs par defaut (`INIT_ALLOWED_IPS`, CSV, jamais vide).
    pub allowed_ips: Vec<String>,
}

/// Debug manuel : `password` est un secret en clair, jamais expose, meme si un
/// `{:?}` (log, panic, message d'erreur) atteint cette struct. Les autres
/// champs restent lisibles pour le diagnostic.
impl std::fmt::Debug for InitConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitConfig")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("dns", &self.dns)
            .field("ipv4_cidr", &self.ipv4_cidr)
            .field("ipv6_cidr", &self.ipv6_cidr)
            .field("allowed_ips", &self.allowed_ips)
            .finish()
    }
}

/// Configuration applicative fige au boot.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Adresse d'ecoute (`HOST`, defaut `0.0.0.0`).
    pub host: String,
    /// Port d'ecoute (`PORT`, requis).
    pub port: u16,
    /// `INSECURE=true` autorise cookies non-`secure` et HTTP (defaut false).
    pub insecure: bool,
    /// `IP_MODE=ipv4` : retire adresses et regles IPv6.
    pub disable_ipv6: bool,
    /// `IP_MODE=ipv6` : retire adresses et regles IPv4.
    pub disable_ipv4: bool,
    /// `DISABLE_PASSWORD_AUTH=true` interdit tout login par mot de passe.
    pub disable_password_auth: bool,
    /// Nom d'interface WireGuard (`WG_INTERFACE`, defaut `wg0`).
    pub wg_interface: String,
    /// Proxys autorises a fournir `X-Forwarded-For` (seule en-tete honoree).
    pub trusted_proxies: Vec<IpNet>,
    /// Chemin SQLite (`DB_PATH`, defaut `/etc/wireguard/wg-ez.db`).
    pub db_path: String,
    /// Dossier des `.conf` (`WG_CONF_DIR`, defaut `/etc/wireguard`).
    pub wg_conf_dir: String,
    /// Setup non-interactif (`INIT_ENABLED`), `None` = assistant web.
    pub init: Option<InitConfig>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_init() -> InitConfig {
        InitConfig {
            username: "admin".to_string(),
            password: "super-secret-pass".to_string(),
            host: "vpn.example.org".to_string(),
            port: 51820,
            dns: vec!["1.1.1.1".to_string()],
            ipv4_cidr: "10.8.0.0/24".parse().expect("v4 cidr"),
            ipv6_cidr: Some("fdcc:ad94:bacf:61a4::cafe:0/112".parse().expect("v6 cidr")),
            allowed_ips: vec!["0.0.0.0/0".to_string()],
        }
    }

    #[test]
    fn init_config_debug_redacts_password() {
        let debug = format!("{:?}", sample_init());
        assert!(
            debug.contains("<redacted>"),
            "secret field is redacted: {debug}"
        );
        assert!(
            !debug.contains("super-secret-pass"),
            "password must never leak through Debug: {debug}"
        );
        // Les champs non sensibles restent lisibles pour le diagnostic.
        assert!(debug.contains("admin"));
        assert!(debug.contains("vpn.example.org"));
    }

    /// `AppConfig` derive `Debug` et embarque `Option<InitConfig>` : l'impl
    /// manuelle doit le garder Debug-able sans divulguer le mot de passe.
    #[test]
    fn app_config_debug_keeps_init_redacted() {
        let app = AppConfig {
            host: "0.0.0.0".to_string(),
            port: 51821,
            insecure: false,
            disable_ipv6: false,
            disable_ipv4: false,
            disable_password_auth: false,
            wg_interface: "wg0".to_string(),
            trusted_proxies: vec![],
            db_path: "/etc/wireguard/wg-ez.db".to_string(),
            wg_conf_dir: "/etc/wireguard".to_string(),
            init: Some(sample_init()),
        };
        let debug = format!("{app:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("super-secret-pass"));
    }
}
