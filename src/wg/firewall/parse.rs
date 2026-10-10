//! Parsing des entrées `firewallIps` / `allowedIps`.
//!
//! Formats acceptés : `IP`, `CIDR`, `IP:port`, `IP:port/tcp|udp`,
//! `CIDR:port[/tcp|/udp]`, `[IPv6]:port[/tcp|/udp]`. Un proto sans port
//! (`IP/proto`) est invalide. Un IPv6 nu avec port exige des crochets.

use super::FirewallError;

/// Protocole de transport d'une règle firewall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub(crate) fn as_arg(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Une entrée `firewallIps` / `allowedIps` parsée et normalisée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRule {
    /// Destination sans crochets (`10.10.0.5`, `10.10.0.0/24`, `::/0`...).
    pub dest: String,
    /// Port exigé dès qu'un proto est présent.
    pub port: Option<u16>,
    /// Protocole (`None` = TCP et UDP).
    pub proto: Option<Proto>,
    /// Vrai si la destination est IPv6 (règle `ip6tables`).
    pub is_v6: bool,
}

/// Parse une entrée firewall selon les formats acceptés ; un proto sans port
/// (`IP/proto`) est invalide.
pub fn parse_entry(entry: &str) -> Result<ParsedRule, FirewallError> {
    let entry = entry.trim();
    if entry.is_empty() {
        return Err(FirewallError::InvalidEntry("empty entry".to_string()));
    }
    if entry.len() > 512 {
        return Err(FirewallError::InvalidEntry(format!(
            "entry too long: `{entry}`"
        )));
    }

    // Suffixe /proto éventuel (insensible à la casse, normalisé en minuscules).
    let (head, proto) = match entry.rsplit_once('/') {
        Some((h, p)) if p.eq_ignore_ascii_case("tcp") || p.eq_ignore_ascii_case("udp") => {
            if h.is_empty() {
                return Err(FirewallError::InvalidEntry(format!(
                    "missing destination in `{entry}`"
                )));
            }
            let proto = if p.eq_ignore_ascii_case("tcp") {
                Proto::Tcp
            } else {
                Proto::Udp
            };
            (h, Some(proto))
        }
        Some((_, _)) if entry.contains("://") => {
            return Err(FirewallError::InvalidEntry(format!(
                "URLs are not allowed: `{entry}`"
            )));
        }
        _ => (entry, None),
    };

    // Forme [IPv6] ou [IPv6]:port.
    if head.starts_with('[') {
        let close = head.find(']').ok_or_else(|| {
            FirewallError::InvalidEntry(format!("unbalanced brackets in `{entry}`"))
        })?;
        let inner = &head[1..close];
        if inner.trim().is_empty() {
            return Err(FirewallError::InvalidEntry(format!(
                "empty IPv6 address in `{entry}`"
            )));
        }
        let rest = &head[close + 1..];
        let port = if rest.is_empty() {
            None
        } else if let Some(digits) = rest.strip_prefix(':') {
            Some(parse_port(digits, entry)?)
        } else {
            return Err(FirewallError::InvalidEntry(format!(
                "bad suffix after `]` in `{entry}`"
            )));
        };
        if proto.is_some() && port.is_none() {
            return Err(FirewallError::InvalidEntry(format!(
                "proto without port is invalid: `{entry}`"
            )));
        }
        validate_dest_chars(inner, entry)?;
        return Ok(ParsedRule {
            dest: inner.to_string(),
            port,
            proto,
            is_v6: true,
        });
    }

    // Un point signale une destination v4 (pointée ou CIDR) : tout ':'
    // impose alors un port numérique. Un '/' seul ne suffit pas (`::/0`).
    let looks_v4 = head.contains('.');
    let (host, port) = match head.rsplit_once(':') {
        None => (head, None),
        Some((h, tail)) => {
            if looks_v4 {
                // v4 / CIDR : tout ':' impose un port numérique.
                if h.is_empty() || tail.is_empty() || !tail.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(FirewallError::InvalidEntry(format!(
                        "bad port in `{entry}` (must be 1-65535)"
                    )));
                }
                (h, Some(parse_port(tail, entry)?))
            } else if !h.is_empty()
                && !tail.is_empty()
                && tail.bytes().all(|b| b.is_ascii_digit())
                && !h.contains(':')
            {
                (h, Some(parse_port(tail, entry)?))
            } else {
                // IPv6 nu (avec ou sans port entre crochets traité plus haut).
                (head, None)
            }
        }
    };
    if proto.is_some() && port.is_none() {
        return Err(FirewallError::InvalidEntry(format!(
            "proto without port is invalid: `{entry}`"
        )));
    }
    validate_dest_chars(host, entry)?;
    Ok(ParsedRule {
        dest: host.to_string(),
        port,
        proto,
        is_v6: host.contains(':'),
    })
}

fn parse_port(digits: &str, entry: &str) -> Result<u16, FirewallError> {
    match digits.parse::<u32>() {
        Ok(p) if (1..=65535).contains(&p) => Ok(p as u16),
        _ => Err(FirewallError::InvalidEntry(format!(
            "bad port in `{entry}` (must be 1-65535)"
        ))),
    }
}

fn validate_dest_chars(host: &str, entry: &str) -> Result<(), FirewallError> {
    if host.is_empty() {
        return Err(FirewallError::InvalidEntry(format!(
            "empty destination in `{entry}`"
        )));
    }
    let ok = host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'/' | b'-' | b'_' | b'*'));
    if !ok {
        return Err(FirewallError::InvalidEntry(format!(
            "bad characters in destination of `{entry}`"
        )));
    }
    Ok(())
}
