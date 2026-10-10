#![forbid(unsafe_code)]

//! Non-interactive setup (`INIT_*`).

use super::SetupError;
use crate::validate;

/// Raw `INIT_*` env values.
#[derive(Debug, Clone, Default)]
pub struct InitEnv {
    pub enabled: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub host: Option<String>,
    pub port: Option<i64>,
    pub dns: Option<Vec<String>>,
    pub ipv4_cidr: Option<String>,
    pub ipv6_cidr: Option<String>,
    pub allowed_ips: Option<Vec<String>>,
}

/// Validated non-interactive setup. Group 1 (username/password/host/port)
/// is mandatory to skip setup; DNS / CIDR / AllowedIPs groups are optional
/// but all-or-nothing within their group.
#[derive(Debug, Clone)]
pub struct ValidatedInit {
    pub username: String,
    pub password: String,
    pub host: String,
    pub port: i64,
    pub dns: Option<Vec<String>>,
    pub ipv4_cidr: Option<String>,
    pub ipv6_cidr: Option<String>,
    pub allowed_ips: Option<Vec<String>>,
}

fn split_csv(raw: &str) -> Vec<String> {
    raw.split(',').map(|s| s.trim().to_string()).collect()
}

/// Read `INIT_*` from the process environment.
pub fn init_env_from_process() -> Result<InitEnv, SetupError> {
    let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let port = match get("INIT_PORT") {
        Some(raw) => Some(
            raw.parse::<i64>()
                .map_err(|_| SetupError::Env("INIT_PORT is not a number".to_string()))?,
        ),
        None => None,
    };
    Ok(InitEnv {
        enabled: matches!(
            std::env::var("INIT_ENABLED")
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
                .as_str(),
            "1" | "true" | "yes" | "on"
        ),
        username: get("INIT_USERNAME"),
        password: get("INIT_PASSWORD"),
        host: get("INIT_HOST"),
        port,
        dns: get("INIT_DNS").map(|v| split_csv(&v)),
        ipv4_cidr: get("INIT_IPV4_CIDR"),
        ipv6_cidr: get("INIT_IPV6_CIDR"),
        allowed_ips: get("INIT_ALLOWED_IPS").map(|v| split_csv(&v)),
    })
}

fn validate_cidr(value: &str, field: &str, v6: bool) -> Result<(), SetupError> {
    let net: ipnet::IpNet = value
        .trim()
        .parse()
        .map_err(|_| SetupError::Validation(format!("{field} must be CIDR (addr/prefix)")))?;
    if matches!(net, ipnet::IpNet::V6(_)) != v6 {
        return Err(SetupError::Validation(format!(
            "{field} has the wrong address family"
        )));
    }
    Ok(())
}

/// Validate group semantics (`None` when `INIT_ENABLED != true`).
pub fn validate_init_env(env: &InitEnv) -> Result<Option<ValidatedInit>, SetupError> {
    if !env.enabled {
        return Ok(None);
    }
    // Group 3 (CIDR) is all-or-nothing.
    if env.ipv4_cidr.is_some() != env.ipv6_cidr.is_some() {
        return Err(SetupError::Env(
            "INIT_IPV4_CIDR and INIT_IPV6_CIDR must be set together".to_string(),
        ));
    }
    if let Some(c) = &env.ipv4_cidr {
        validate_cidr(c, "INIT_IPV4_CIDR", false)?;
    }
    if let Some(c) = &env.ipv6_cidr {
        validate_cidr(c, "INIT_IPV6_CIDR", true)?;
    }
    if let Some(dns) = &env.dns {
        // M4 : chaque entrée `INIT_DNS` est une IP nue (v4 ou v6), jamais un
        // nom/CIDR/port. La répartition par famille se fait à l'application.
        validate::validate_dns_list_any(dns).map_err(SetupError::Validate)?;
    }
    if let Some(list) = &env.allowed_ips {
        validate::validate_allowed_ips(list).map_err(SetupError::Validate)?;
    }
    // Group 1: all four or setup cannot be skipped.
    let (username, password, host, port) = match (&env.username, &env.password, &env.host, env.port)
    {
        (Some(u), Some(p), Some(h), Some(pt)) => (u.clone(), p.clone(), h.clone(), pt),
        _ => {
            let mut missing = vec![];
            if env.username.is_none() {
                missing.push("INIT_USERNAME");
            }
            if env.password.is_none() {
                missing.push("INIT_PASSWORD");
            }
            if env.host.is_none() {
                missing.push("INIT_HOST");
            }
            if env.port.is_none() {
                missing.push("INIT_PORT");
            }
            return Err(SetupError::Env(format!(
                "to skip setup, set all of group 1 (missing: {})",
                missing.join(", ")
            )));
        }
    };
    validate::validate_username(username.trim()).map_err(SetupError::Validate)?;
    // 12+ enforced here.
    validate::validate_password(&password).map_err(SetupError::Validate)?;
    let (host, port) = super::validate_host_port(&host, port)?;
    Ok(Some(ValidatedInit {
        username: username.trim().to_string(),
        password,
        host,
        port,
        dns: env.dns.clone(),
        ipv4_cidr: env.ipv4_cidr.clone(),
        ipv6_cidr: env.ipv6_cidr.clone(),
        allowed_ips: env.allowed_ips.clone(),
    }))
}

/// Repartit des entrees (IP ou CIDR) entre familles IPv4 et IPv6.
fn split_by_family(entries: &[String]) -> (Vec<String>, Vec<String>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for e in entries {
        let is_v6 = e
            .parse::<std::net::IpAddr>()
            .map(|a| a.is_ipv6())
            .or_else(|_| {
                e.parse::<ipnet::IpNet>()
                    .map(|n| matches!(n, ipnet::IpNet::V6(_)))
            });
        if is_v6.unwrap_or(false) {
            v6.push(e.clone());
        } else {
            v4.push(e.clone());
        }
    }
    (v4, v6)
}

/// Charge la ligne `user_configs` de l'interface, ou erreur d'etat si absente.
fn userconfig_row(
    conn: &rusqlite::Connection,
    interface_name: &str,
) -> Result<crate::store::userconfig::UserConfig, SetupError> {
    crate::store::userconfig::get(conn, interface_name)?
        .ok_or_else(|| SetupError::State("user config for this interface is missing".to_string()))
}

/// Eclate une liste en familles, serialise chaque famille en JSON et ecrit le
/// resultat via les accesseurs `set` (DNS ou AllowedIPs), puis `upsert`.
fn apply_family_list<F>(
    conn: &rusqlite::Connection,
    interface_name: &str,
    entries: &[String],
    set: F,
) -> Result<(), SetupError>
where
    F: FnOnce(&mut crate::store::userconfig::UserConfig, String, String),
{
    let mut cfg = userconfig_row(conn, interface_name)?;
    let (v4, v6) = split_by_family(entries);
    // La sérialisation d'une liste de chaînes ne peut pas échouer ; si elle
    // échouait, son texte brut ne doit pas sortir dans un 400 (M10).
    let v4 = serde_json::to_string(&v4).map_err(|e| {
        tracing::error!("userconfig list encode failed: {e}");
        SetupError::Validation("cannot encode list".to_string())
    })?;
    let v6 = serde_json::to_string(&v6).map_err(|e| {
        tracing::error!("userconfig list encode failed: {e}");
        SetupError::Validation("cannot encode list".to_string())
    })?;
    set(&mut cfg, v4, v6);
    crate::store::userconfig::upsert(conn, &cfg)?;
    Ok(())
}

/// Outcome of [`apply_initial_setup`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialSetupOutcome {
    /// `true` when setup was already done (nothing applied).
    pub skipped: bool,
    pub admin_id: Option<i64>,
}

/// Apply a validated non-interactive setup at boot (order: CIDR -> DNS ->
/// AllowedIPs -> group 1 user/host/port). No-ops when setup is already done.
pub fn apply_initial_setup(
    conn: &rusqlite::Connection,
    init: &ValidatedInit,
    interface_name: &str,
) -> Result<InitialSetupOutcome, SetupError> {
    if crate::store::general::is_setup_done(conn)? {
        return Ok(InitialSetupOutcome {
            skipped: true,
            admin_id: None,
        });
    }
    if let (Some(v4), Some(v6)) = (&init.ipv4_cidr, &init.ipv6_cidr) {
        let mut iface = crate::store::interface::get(conn, interface_name)?
            .ok_or_else(|| SetupError::State("interface row missing".to_string()))?;
        let old_v4 = iface.ipv4_cidr.clone();
        let old_v6 = iface.ipv6_cidr.clone();
        iface.ipv4_cidr = v4.clone();
        iface.ipv6_cidr = v6.clone();
        crate::store::interface::upsert(conn, &iface)?;
        // Le seed des hooks référence 10.8.0.0/24 : répercuter le CIDR initial
        // pour que le NAT suive l'interface dès le premier boot.
        crate::store::hooks::sync_cidr(conn, interface_name, &old_v4, v4, &old_v6, v6)?;
    }
    if let Some(dns) = &init.dns {
        apply_family_list(conn, interface_name, dns, |cfg, v4, v6| {
            cfg.default_dns_v4 = v4;
            cfg.default_dns_v6 = v6;
        })?;
    }
    if let Some(list) = &init.allowed_ips {
        apply_family_list(conn, interface_name, list, |cfg, v4, v6| {
            cfg.default_allowed_ips_v4 = v4;
            cfg.default_allowed_ips_v6 = v6;
        })?;
    }
    let admin_id = super::admin::create_admin(conn, &init.username, &init.password)?;
    let mut cfg = userconfig_row(conn, interface_name)?;
    cfg.host = init.host.clone();
    cfg.port = init.port;
    crate::store::userconfig::upsert(conn, &cfg)?;
    crate::store::general::complete_setup(conn)?;
    Ok(InitialSetupOutcome {
        skipped: false,
        admin_id: Some(admin_id),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::memdb;

    #[test]
    fn init_groups_validated() {
        let base = InitEnv {
            enabled: true,
            username: Some("admin".into()),
            password: Some("long-enough-12".into()),
            host: Some("vpn.example.com".into()),
            port: Some(51820),
            ..Default::default()
        };
        assert!(validate_init_env(&base).expect("ok").is_some());
        let mut bad = base.clone();
        bad.password = Some("short".into());
        assert!(validate_init_env(&bad).is_err());
        let mut partial = base.clone();
        partial.ipv4_cidr = Some("10.9.0.0/24".into());
        assert!(validate_init_env(&partial).is_err());
        partial.ipv6_cidr = Some("fd00::/64".into());
        let v = validate_init_env(&partial).expect("ok").expect("some");
        assert_eq!(v.ipv4_cidr.as_deref(), Some("10.9.0.0/24"));
        let mut g1 = base.clone();
        g1.host = None;
        assert!(validate_init_env(&g1).is_err());
        assert!(
            validate_init_env(&InitEnv::default())
                .expect("ok")
                .is_none()
        );
    }

    #[test]
    fn init_dns_must_be_bare_ip() {
        let base = InitEnv {
            enabled: true,
            username: Some("admin".into()),
            password: Some("long-enough-12".into()),
            host: Some("vpn.example.com".into()),
            port: Some(51820),
            ..Default::default()
        };
        // Un nom : refusé (M4).
        let mut bad = base.clone();
        bad.dns = Some(vec!["dns.google".into()]);
        assert!(validate_init_env(&bad).is_err());
        // Un CIDR : refusé (ce n'est pas une adresse d'écoute).
        let mut cidr = base.clone();
        cidr.dns = Some(vec!["1.1.1.1/24".into()]);
        assert!(validate_init_env(&cidr).is_err());
        // Multi-famille d'IP nues : accepté, réparti v4/v6 à l'apply.
        let mut mixed = base;
        mixed.dns = Some(vec!["1.1.1.1".into(), "2606:4700:4700::1111".into()]);
        assert!(validate_init_env(&mixed).expect("ok").is_some());
    }

    #[test]
    fn initial_setup_applies_once_then_skips() {
        let conn = memdb();
        let init = validate_init_env(&InitEnv {
            enabled: true,
            username: Some("admin".into()),
            password: Some("long-enough-12".into()),
            host: Some("vpn.example.com".into()),
            port: Some(51820),
            dns: Some(vec!["9.9.9.9".into()]),
            ipv4_cidr: Some("10.9.0.0/24".into()),
            ipv6_cidr: Some("fd00::/64".into()),
            allowed_ips: Some(vec!["0.0.0.0/0".into()]),
        })
        .expect("valid")
        .expect("some");
        let out = apply_initial_setup(&conn, &init, "wg0").expect("apply");
        assert!(!out.skipped);
        assert_eq!(out.admin_id, Some(1));
        assert!(crate::store::general::is_setup_done(&conn).expect("done"));
        // Le CIDR initial est aussi répercuté dans les hooks (sinon le NAT
        // resterait sur le sous-réseau seed 10.8.0.0/24).
        let iface = crate::store::interface::get(&conn, "wg0")
            .expect("iface q")
            .expect("iface");
        assert_eq!(iface.ipv4_cidr, "10.9.0.0/24");
        let hooks = crate::store::hooks::get(&conn, "wg0")
            .expect("hooks q")
            .expect("hooks");
        assert!(hooks.post_up.contains("10.9.0.0/24"));
        assert!(!hooks.post_up.contains("10.8.0.0/24"));
        assert!(hooks.post_down.contains("10.9.0.0/24"));
        assert!(!hooks.post_down.contains("10.8.0.0/24"));
        // Le CIDR IPv6 est repercute de la meme facon dans le NAT66.
        assert!(hooks.post_up.contains("fd00::/64"));
        assert!(
            !hooks
                .post_up
                .contains("fd00:dead:beef:cafe:babe:face:feed:0/112")
        );
        assert!(hooks.post_down.contains("fd00::/64"));
        assert!(
            !hooks
                .post_down
                .contains("fd00:dead:beef:cafe:babe:face:feed:0/112")
        );
        let out2 = apply_initial_setup(&conn, &init, "wg0").expect("re-apply");
        assert!(out2.skipped);
    }
}
