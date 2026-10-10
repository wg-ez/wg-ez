//! Parsers scalaires (`PORT`, booleens, CSV, CIDR, `WG_INTERFACE`, ...).
//!
//! Chaque fonction retourne un `Result` ; aucune panique sur chemin
//! utilisateur (`panic = "abort"` en release).

use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;

use super::types::ConfigError;
use crate::validate::{IFACE_MAX_LEN, is_valid_interface_name};

pub(crate) fn raw(env: &HashMap<String, String>, key: &str) -> Option<String> {
    env.get(key)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Refuse caracteres de controle et motifs de pollution prototype.
///
/// Source de verite unique : [`crate::validate::check_plain_string`] (rejette
/// `__proto__` en sous-chaine, `constructor`/`prototype` en cle exacte, les
/// controles C0/C1, `U+007F` et les separateurs `U+2028`/`U+2029`).
pub(crate) fn check_string(key: &'static str, value: &str) -> Result<(), ConfigError> {
    crate::validate::check_plain_string(value).map_err(|e| ConfigError::Invalid(key, e.to_string()))
}

pub(crate) fn parse_port(key: &'static str, value: &str) -> Result<u16, ConfigError> {
    match value.parse::<u16>() {
        Ok(p) if p >= 1 => Ok(p),
        _ => Err(ConfigError::Invalid(
            key,
            "port must be in 1..=65535".to_string(),
        )),
    }
}

pub(crate) fn parse_bool(key: &'static str, value: &str) -> Result<bool, ConfigError> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(ConfigError::Invalid(
            key,
            "boolean must be 0/1/true/false".to_string(),
        )),
    }
}

pub(crate) fn parse_bool_default(
    env: &HashMap<String, String>,
    key: &'static str,
    default: bool,
) -> Result<bool, ConfigError> {
    match raw(env, key) {
        None => Ok(default),
        Some(v) => parse_bool(key, &v),
    }
}

/// `WG_INTERFACE` : 1..=15 caracteres dans `[a-zA-Z0-9_=+.-]`.
///
/// Regle partagee avec le tunnel : [`crate::validate::is_valid_interface_name`]
/// (charset + longueur) et [`crate::validate::IFACE_MAX_LEN`]. La longueur est
/// testee en amont uniquement pour conserver le message d'erreur specifique.
pub fn validate_interface(value: &str) -> Result<(), ConfigError> {
    const KEY: &str = "WG_INTERFACE";
    if value.is_empty() || value.len() > IFACE_MAX_LEN {
        return Err(ConfigError::Invalid(
            KEY,
            "interface must be 1..=15 chars".to_string(),
        ));
    }
    if !is_valid_interface_name(value) {
        return Err(ConfigError::Invalid(
            KEY,
            "interface must match [a-zA-Z0-9_=+.-]".to_string(),
        ));
    }
    Ok(())
}

/// `TRUSTED_PROXIES` : CSV d'IP et de CIDR ; invalide = refus de boot.
pub fn parse_trusted_proxies(value: &str) -> Result<Vec<IpNet>, ConfigError> {
    const KEY: &str = "TRUSTED_PROXIES";
    let mut out = Vec::new();
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(out);
    }
    for part in trimmed.split(',') {
        let item = part.trim();
        if item.is_empty() {
            continue;
        }
        // Accepte une IP nue (promue en /32 ou /128) ou un CIDR.
        let net = match item.parse::<IpNet>() {
            Ok(n) => n,
            Err(_) => match item.parse::<IpAddr>() {
                Ok(IpAddr::V4(a)) => match ipnet::Ipv4Net::new(a, 32) {
                    Ok(n) => IpNet::V4(n),
                    Err(e) => return Err(ConfigError::Invalid(KEY, e.to_string())),
                },
                Ok(IpAddr::V6(a)) => match ipnet::Ipv6Net::new(a, 128) {
                    Ok(n) => IpNet::V6(n),
                    Err(e) => return Err(ConfigError::Invalid(KEY, e.to_string())),
                },
                Err(_) => {
                    return Err(ConfigError::Invalid(
                        KEY,
                        format!("'{item}' is neither an IP nor a CIDR"),
                    ));
                }
            },
        };
        out.push(net);
    }
    Ok(out)
}

pub(crate) fn parse_csv_list(key: &'static str, value: &str) -> Result<Vec<String>, ConfigError> {
    let mut out = Vec::new();
    for part in value.split(',') {
        let item = part.trim();
        if item.is_empty() {
            continue;
        }
        check_string(key, item)?;
        out.push(item.to_string());
    }
    if out.is_empty() {
        return Err(ConfigError::Invalid(
            key,
            "list must not be empty".to_string(),
        ));
    }
    Ok(out)
}

pub(crate) fn parse_cidr(key: &'static str, value: &str) -> Result<IpNet, ConfigError> {
    match value.parse::<IpNet>() {
        Ok(n) => Ok(n),
        Err(_) => Err(ConfigError::Invalid(
            key,
            format!("'{value}' is not a CIDR"),
        )),
    }
}
