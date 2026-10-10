//! Setup non-interactif (`INIT_ENABLED=true`, groupe 1 + groupes optionnels).

use std::collections::HashMap;

use super::parse::{parse_cidr, parse_csv_list, parse_port, raw};
use super::types::{ConfigError, InitConfig};

pub(crate) fn load_init(env: &HashMap<String, String>) -> Result<InitConfig, ConfigError> {
    let username = match raw(env, "INIT_USERNAME") {
        Some(v) => v,
        None => return Err(ConfigError::InitIncomplete("INIT_USERNAME")),
    };
    crate::validate::validate_username(&username)
        .map_err(|e| ConfigError::Invalid("INIT_USERNAME", e.to_string()))?;

    let password = match raw(env, "INIT_PASSWORD") {
        Some(v) => v,
        None => return Err(ConfigError::InitIncomplete("INIT_PASSWORD")),
    };
    crate::validate::validate_password(&password)
        .map_err(|e| ConfigError::Invalid("INIT_PASSWORD", e.to_string()))?;

    let host = match raw(env, "INIT_HOST") {
        Some(v) => v,
        None => return Err(ConfigError::InitIncomplete("INIT_HOST")),
    };
    crate::validate::validate_host(&host)
        .map_err(|e| ConfigError::Invalid("INIT_HOST", e.to_string()))?;

    let port_raw = match raw(env, "INIT_PORT") {
        Some(v) => v,
        None => return Err(ConfigError::InitIncomplete("INIT_PORT")),
    };
    let port = parse_port("INIT_PORT", &port_raw)?;

    // Groupes optionnels avec defauts V1.
    let dns = match raw(env, "INIT_DNS") {
        Some(v) => {
            let list = parse_csv_list("INIT_DNS", &v)?;
            // Chaque entree est une IP nue (v4 ou v6), jamais un
            // nom/CIDR/port ; la repartition par famille se fait a l'apply.
            crate::validate::validate_dns_list_any(&list)
                .map_err(|e| ConfigError::Invalid("INIT_DNS", e.to_string()))?;
            list
        }
        None => vec!["1.1.1.1".to_string(), "2606:4700:4700::1111".to_string()],
    };
    let ipv4_cidr = match raw(env, "INIT_IPV4_CIDR") {
        Some(v) => {
            let net = parse_cidr("INIT_IPV4_CIDR", &v)?;
            if matches!(net, ipnet::IpNet::V6(_)) {
                return Err(ConfigError::Invalid(
                    "INIT_IPV4_CIDR",
                    "wrong address family".to_string(),
                ));
            }
            net
        }
        None => parse_cidr("INIT_IPV4_CIDR", "10.8.0.0/24")?,
    };
    // `raw()` filtre les chaînes vides : une clé présente mais vide
    // désactive explicitement l'IPv6 (contrairement à une clé absente qui
    // donne le défaut seed).
    let ipv6_cidr = match env.get("INIT_IPV6_CIDR") {
        None => Some(parse_cidr(
            "INIT_IPV6_CIDR",
            "fd00:dead:beef:cafe:babe:face:feed:0/112",
        )?),
        Some(v) if v.trim().is_empty() => None,
        Some(v) => {
            let net = parse_cidr("INIT_IPV6_CIDR", v.trim())?;
            if matches!(net, ipnet::IpNet::V4(_)) {
                return Err(ConfigError::Invalid(
                    "INIT_IPV6_CIDR",
                    "wrong address family".to_string(),
                ));
            }
            Some(net)
        }
    };
    let allowed_ips = match raw(env, "INIT_ALLOWED_IPS") {
        Some(v) => {
            let list = parse_csv_list("INIT_ALLOWED_IPS", &v)?;
            crate::validate::validate_allowed_ips(&list)
                .map_err(|e| ConfigError::Invalid("INIT_ALLOWED_IPS", e.to_string()))?;
            list
        }
        None => vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
    };

    Ok(InitConfig {
        username,
        password,
        host,
        port,
        dns,
        ipv4_cidr,
        ipv6_cidr,
        allowed_ips,
    })
}
