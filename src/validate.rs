#![forbid(unsafe_code)]

//! Input validation and CSP header.
//!
//! Rules:
//! - every free string rejects `__proto__` (substring, it hides inside
//!   paths like `a[__proto__]`), exact `constructor` / `prototype` keys,
//!   and control characters `\x00-\x1F` / `\x7F` (protects the generated
//!   `.conf` file);
//! - hooks go through [`sanitize_hook`] (`removeNewlines` + same rejects);
//! - port 1-65535, MTU 1024-9000, keepalive 0-65535, `allowedIps` never
//!   empty, routing table `auto` | `off` | number, TOTP exactly 6 digits,
//!   password 12+ characters, `serverAllowedIps` entries a bare IP or a CIDR,
//!   DNS entries a bare IPv4/IPv6 address of the right family.
//!
//! Trusted-proxy client-IP resolution lives in the web layer
//! (`crate::web::ctx::AppState::client_ip`).

/// Minimum password length. Single source of truth:
/// [`crate::auth::password::MIN_PASSWORD_LEN`].
pub use crate::auth::password::MIN_PASSWORD_LEN;
/// Minimum username length.
pub const MIN_USERNAME_LEN: usize = 2;
/// Maximum username length in bytes. Mirrors the login handler's accepted
/// bound (`web/handlers/auth.rs`): a longer name would be stored yet never
/// usable to log in, so every write path (setup, CLI, self-service) rejects
/// it here instead of locking the account out.
pub const MAX_USERNAME_LEN: usize = 256;
/// Maximum interface-name length (`WG_INTERFACE`). Single source of truth
/// shared by the config parser and the tunnel layer.
pub const IFACE_MAX_LEN: usize = 15;
/// CSP value: first-party only, zero inline. Single source of truth shared
/// with the response middleware (`router/middleware.rs`).
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; \
     style-src 'self'; img-src 'self' data:; \
     object-src 'none'; base-uri 'self'; frame-ancestors 'none'; \
     form-action 'self'; connect-src 'self'; font-src 'self'";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("forbidden prototype-pollution key")]
    PrototypePollution,
    #[error("control character rejected")]
    ControlChar,
    #[error("value is empty")]
    Empty,
    #[error("value is too long")]
    TooLong,
    #[error("username needs at least 2 characters")]
    UsernameTooShort,
    #[error("password must contain at least 12 characters")]
    PasswordTooShort,
    #[error("port must be within 1-65535")]
    InvalidPort,
    #[error("mtu must be within 1024-9000")]
    InvalidMtu,
    #[error("keepalive must be within 0-65535")]
    InvalidKeepalive,
    #[error("allowedIps must not be empty")]
    EmptyAllowedIps,
    #[error("routing table must be auto, off or a number")]
    InvalidTable,
    #[error("value must be a bare IP or a CIDR")]
    InvalidIpOrCidr,
    #[error("dns must be a bare IP address (no name, CIDR or port)")]
    InvalidDns,
    #[error("host must be 1-253 chars (bare IP or DNS name)")]
    InvalidHost,
    #[error("endpoint must be host:port (IPv6 in brackets)")]
    InvalidEndpoint,
    #[error("totp code must be exactly 6 digits")]
    InvalidTotp,
}

/// Reject `__proto__` (anywhere), and exact `constructor` / `prototype`.
pub fn reject_proto_keys(value: &str) -> Result<(), ValidationError> {
    if value.contains("__proto__") {
        return Err(ValidationError::PrototypePollution);
    }
    let lowered = value.trim().to_ascii_lowercase();
    if lowered == "constructor" || lowered == "prototype" {
        return Err(ValidationError::PrototypePollution);
    }
    Ok(())
}

/// Reject ASCII control characters, the Unicode C1 controls (`U+0080`-`U+009F`,
/// e.g. NEL) and the line/paragraph separators (`U+2028`/`U+2029`): none may
/// reach a log line, a `.conf` field or an HTTP header unchecked.
pub fn reject_control_chars(value: &str) -> Result<(), ValidationError> {
    if value
        .chars()
        .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}'))
    {
        return Err(ValidationError::ControlChar);
    }
    Ok(())
}

/// Standard check for every free-form string.
pub fn check_plain_string(value: &str) -> Result<(), ValidationError> {
    reject_proto_keys(value)?;
    reject_control_chars(value)?;
    Ok(())
}

/// Strip CR/LF to break hook injection across lines.
pub fn remove_newlines(value: &str) -> String {
    value.replace(['\r', '\n'], "")
}

/// Sanitize a hook script: break line injection, then enforce the string
/// rules on what remains (other control characters are still rejected).
pub fn sanitize_hook(hook: &str) -> Result<String, ValidationError> {
    let flat = remove_newlines(hook);
    check_plain_string(&flat)?;
    Ok(flat)
}

/// A WireGuard interface name: 1..=`IFACE_MAX_LEN` bytes among
/// `[a-zA-Z0-9_=+.-]`. Single source of truth for the charset (it is also an
/// anti path-traversal guard: no `/`, no space, no `..`).
pub fn is_valid_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= IFACE_MAX_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'=' | b'_' | b'+' | b'.' | b'-'))
}

/// Username: plain-string rules + at least 2 characters and at most
/// [`MAX_USERNAME_LEN`] bytes (the login handler's accepted bound).
pub fn validate_username(username: &str) -> Result<(), ValidationError> {
    check_plain_string(username)?;
    if username.chars().count() < MIN_USERNAME_LEN {
        return Err(ValidationError::UsernameTooShort);
    }
    if username.len() > MAX_USERNAME_LEN {
        return Err(ValidationError::TooLong);
    }
    Ok(())
}

/// Password: at least 12 characters. Single source of truth:
/// [`crate::auth::password::validate_password_policy`].
pub fn validate_password(password: &str) -> Result<(), ValidationError> {
    crate::auth::password::validate_password_policy(password)
        .map_err(|_| ValidationError::PasswordTooShort)
}

/// Port 1-65535.
pub fn validate_port(port: u32) -> Result<(), ValidationError> {
    if (1..=65_535).contains(&port) {
        Ok(())
    } else {
        Err(ValidationError::InvalidPort)
    }
}

/// MTU 1024-9000.
pub fn validate_mtu(mtu: u32) -> Result<(), ValidationError> {
    if (1024..=9000).contains(&mtu) {
        Ok(())
    } else {
        Err(ValidationError::InvalidMtu)
    }
}

/// Persistent keepalive 0-65535 (`0` = disabled).
pub fn validate_keepalive(keepalive: u32) -> Result<(), ValidationError> {
    if keepalive <= 65_535 {
        Ok(())
    } else {
        Err(ValidationError::InvalidKeepalive)
    }
}

/// True when `value` parses either as a bare IP address or as a CIDR network;
/// WireGuard's `AllowedIPs` accepts both forms, so both validators share it.
fn is_ip_or_cidr(value: &str) -> bool {
    value.parse::<ipnet::IpNet>().is_ok() || value.parse::<std::net::IpAddr>().is_ok()
}

/// `allowedIps` must never be empty (`null` = inherit, handled upstream);
/// every entry must be a real IP or CIDR. These entries land verbatim in the
/// rendered `.conf` (`AllowedIPs`) and, when the firewall is on, in
/// `iptables -d`; an unparsable value would otherwise poison the whole
/// `Tunnel::apply`.
pub fn validate_allowed_ips(ips: &[String]) -> Result<(), ValidationError> {
    if ips.is_empty() {
        return Err(ValidationError::EmptyAllowedIps);
    }
    for ip in ips {
        let trimmed = ip.trim();
        if trimmed.is_empty() {
            return Err(ValidationError::EmptyAllowedIps);
        }
        check_plain_string(trimmed)?;
        if !is_ip_or_cidr(trimmed) {
            return Err(ValidationError::InvalidIpOrCidr);
        }
    }
    Ok(())
}

/// A DNS resolver is an **address**, not a route: WireGuard's `DNS =` line
/// takes bare `IPv4`/`IPv6` values, so a name (`dns.google`), a CIDR
/// (`1.2.3.4/24`) or an `addr:port` pair must all be rejected. Those values
/// land verbatim in every client `.conf`, so an unparsable entry would poison
/// the rendered config.
fn is_dns_addr(value: &str, v6: bool) -> bool {
    if v6 {
        value.parse::<std::net::Ipv6Addr>().is_ok()
    } else {
        value.parse::<std::net::Ipv4Addr>().is_ok()
    }
}

/// Validate a **family-scoped** DNS list (`dnsV4`/`dnsV6`,
/// `defaultDnsV4`/`defaultDnsV6`): every entry must be a bare IP of that
/// family. An empty list stays valid (it clears the field / means "no DNS");
/// callers that forbid `[]` keep their own emptiness check.
pub fn validate_dns_list(items: &[String], v6: bool) -> Result<(), ValidationError> {
    for item in items {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            return Err(ValidationError::Empty);
        }
        check_plain_string(trimmed)?;
        if !is_dns_addr(trimmed, v6) {
            return Err(ValidationError::InvalidDns);
        }
    }
    Ok(())
}

/// Validate a **mixed-family** DNS list (`INIT_DNS`): every entry must be a
/// bare IPv4 or IPv6 address. The family split into `defaultDnsV4`/`V6` is
/// performed at apply time ([`crate::setup::init`]), and a disabled family
/// keeps its values in DB unused — so no `IP_MODE` cross-check is needed here.
pub fn validate_dns_list_any(items: &[String]) -> Result<(), ValidationError> {
    for item in items {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            return Err(ValidationError::Empty);
        }
        check_plain_string(trimmed)?;
        if trimmed.parse::<std::net::IpAddr>().is_err() {
            return Err(ValidationError::InvalidDns);
        }
    }
    Ok(())
}

/// Split a `host:port` / `[IPv6]:port` endpoint into its two halves without
/// validating either; `None` when the shape is wrong (`[::1]51820`, no colon,
/// ...). IPv6 hosts must be bracketed, so the closing `]` bounds the host and
/// the colon that follows introduces the port.
fn split_host_port(value: &str) -> Option<(&str, &str)> {
    if let Some(rest) = value.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        let port = rest[close + 1..].strip_prefix(':')?;
        Some((host, port))
    } else {
        value.rsplit_once(':')
    }
}

/// A `serverEndpoint`: `host:port` or `[IPv6]:port`. The host may be a bare
/// IP or a DNS name; no scheme, no path, no space. Validated before storage
/// because the value is written verbatim as `Endpoint = ...` in the server
/// `.conf` (an invalid endpoint makes `wg` reject the whole sync).
pub fn validate_endpoint(value: &str) -> Result<(), ValidationError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ValidationError::Empty);
    }
    check_plain_string(value)?;
    let (host, port) = split_host_port(value).ok_or(ValidationError::InvalidEndpoint)?;
    if host.trim().is_empty() {
        return Err(ValidationError::InvalidEndpoint);
    }
    let port: u32 = port
        .trim()
        .parse()
        .map_err(|_| ValidationError::InvalidEndpoint)?;
    validate_port(port)?;
    // Host charset: an IP or a DNS name. Reject `/`, `:`, spaces and any
    // WireGuard/iptables metacharacter that could break the `.conf` line.
    let ok = host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'_'));
    if !ok {
        return Err(ValidationError::InvalidEndpoint);
    }
    Ok(())
}

/// A single `serverAllowedIps` entry: WireGuard accepts both a bare address
/// (`1.2.3.4`, `fd00::1`) and a CIDR (`10.0.0.0/8`), so both are accepted;
/// anything else (a hostname, a port, a bare `/8`...) is rejected since the
/// value lands verbatim in the peer `AllowedIPs` of the rendered `.conf`.
pub fn validate_ip_or_cidr(value: &str) -> Result<(), ValidationError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ValidationError::Empty);
    }
    check_plain_string(trimmed)?;
    if is_ip_or_cidr(trimmed) {
        Ok(())
    } else {
        Err(ValidationError::InvalidIpOrCidr)
    }
}

/// Routing table: `auto`, `off` or a numeric id.
pub fn validate_table(table: &str) -> Result<(), ValidationError> {
    if table == "auto" || table == "off" {
        return Ok(());
    }
    if !table.is_empty()
        && table.bytes().all(|b| b.is_ascii_digit())
        && table.parse::<u32>().is_ok()
    {
        return Ok(());
    }
    Err(ValidationError::InvalidTable)
}

/// TOTP code: exactly 6 ASCII digits. Single source of truth:
/// [`crate::auth::totp::validate_code_format`].
pub fn validate_totp_code(code: &str) -> Result<(), ValidationError> {
    crate::auth::totp::validate_code_format(code).map_err(|_| ValidationError::InvalidTotp)
}

/// A public host (bare IP or DNS name, no port, no scheme, no path): the
/// `host` stored for `Endpoint` rendering and the `INIT_HOST` boot value.
/// Rejects prototype-pollution keys and control characters via
/// [`check_plain_string`], enforces 1..=253 chars and a safe charset
/// (`[A-Za-z0-9._-]` plus `:`/`[`/`]` for bare IPv6 literals). A value that
/// parses as an [`std::net::IpAddr`] is accepted as-is; otherwise DNS labels
/// must be non-empty and not start/end with `-`.
pub fn validate_host(value: &str) -> Result<(), ValidationError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 253 {
        return Err(ValidationError::InvalidHost);
    }
    check_plain_string(value)?;
    if value.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    if value.contains(':') {
        // `:` hors IP nue = `host:port` ou mélange : refusé (le port a son
        // propre champ). Seul un littéral v6 entre crochets reste accepté.
        if let Some(inner) = value
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            && inner.parse::<std::net::Ipv6Addr>().is_ok()
        {
            return Ok(());
        }
        return Err(ValidationError::InvalidHost);
    }
    // Optional brackets around a bare IPv6 literal (`[::1]`).
    // À ce stade plus de `:` possible (traité ci-dessus) : charset DNS strict.
    let inner = value
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(value);
    if inner.is_empty()
        || !inner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err(ValidationError::InvalidHost);
    }
    if value.contains('/') || value.contains('@') || value.contains(' ') {
        return Err(ValidationError::InvalidHost);
    }
    for label in inner.split('.') {
        if label.is_empty() || label.starts_with('-') || label.ends_with('-') {
            return Err(ValidationError::InvalidHost);
        }
    }
    Ok(())
}

/// OTL / pending-2FA token shape: 22 base64url chars (128 bits, no padding).
/// Used as a fast reject before the DB lookup; unknown values still map to
/// the same 404/401 as before.
pub fn is_valid_token_shape(value: &str) -> bool {
    value.len() == 22
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `Content-Security-Policy` header pair for responses.
pub fn csp_header() -> (&'static str, &'static str) {
    ("content-security-policy", CONTENT_SECURITY_POLICY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto_keys_rejected() {
        assert_eq!(
            reject_proto_keys("__proto__"),
            Err(ValidationError::PrototypePollution)
        );
        assert_eq!(
            reject_proto_keys("a[__proto__]"),
            Err(ValidationError::PrototypePollution)
        );
        assert_eq!(
            reject_proto_keys("constructor"),
            Err(ValidationError::PrototypePollution)
        );
        assert_eq!(
            reject_proto_keys("  Prototype "),
            Err(ValidationError::PrototypePollution)
        );
        assert!(reject_proto_keys("plain-name").is_ok());
    }

    #[test]
    fn control_chars_rejected() {
        assert_eq!(
            reject_control_chars("a\x00b"),
            Err(ValidationError::ControlChar)
        );
        assert_eq!(
            reject_control_chars("a\nb"),
            Err(ValidationError::ControlChar)
        );
        assert_eq!(
            reject_control_chars("a\x7fb"),
            Err(ValidationError::ControlChar)
        );
        assert!(reject_control_chars("café-été_9").is_ok());
    }

    #[test]
    fn hooks_lose_newlines_but_keep_other_rules() -> Result<(), String> {
        assert_eq!(remove_newlines("a\nb\r\nc\rd"), "abcd".to_string());
        assert_eq!(
            sanitize_hook("echo hi\nreboot").map_err(|e| e.to_string())?,
            "echo hireboot".to_string()
        );
        assert!(sanitize_hook("evil __proto__").is_err());
        assert!(sanitize_hook("evil\x00x").is_err());
        Ok(())
    }

    #[test]
    fn numeric_bounds() {
        assert!(validate_port(0).is_err());
        assert!(validate_port(1).is_ok());
        assert!(validate_port(65_535).is_ok());
        assert!(validate_port(65_536).is_err());
        assert!(validate_mtu(1023).is_err());
        assert!(validate_mtu(1420).is_ok());
        assert!(validate_mtu(9001).is_err());
        assert!(validate_keepalive(0).is_ok());
        assert!(validate_keepalive(65_536).is_err());
        assert!(validate_table("auto").is_ok());
        assert!(validate_table("off").is_ok());
        assert!(validate_table("100").is_ok());
        assert!(validate_table("main").is_err());
        assert!(validate_table("").is_err());
        assert!(validate_allowed_ips(&[]).is_err());
        assert!(validate_allowed_ips(&["0.0.0.0/0".to_string()]).is_ok());
        assert!(validate_password("short").is_err());
        assert!(validate_password("twelve-chars").is_ok());
        assert!(validate_totp_code("12345").is_err());
        assert!(validate_totp_code("12345a").is_err());
        assert!(validate_totp_code("123456").is_ok());
    }

    #[test]
    fn usernames_validated() {
        assert!(validate_username("ab").is_ok());
        assert_eq!(
            validate_username("a"),
            Err(ValidationError::UsernameTooShort)
        );
        assert_eq!(
            validate_username(""),
            Err(ValidationError::UsernameTooShort)
        );
        assert_eq!(
            validate_username("__proto__"),
            Err(ValidationError::PrototypePollution)
        );
        assert_eq!(
            validate_username("a\x00b"),
            Err(ValidationError::ControlChar)
        );
        // Au-dela de la borne du login (256 octets), le nom serait stocke mais
        // jamais utilisable : refus a l'ecriture pour ne pas verrouiller le compte.
        assert!(validate_username(&"a".repeat(MAX_USERNAME_LEN)).is_ok());
        assert_eq!(
            validate_username(&"a".repeat(MAX_USERNAME_LEN + 1)),
            Err(ValidationError::TooLong)
        );
    }

    #[test]
    fn bare_ip_or_cidr_accepted() {
        assert!(validate_ip_or_cidr("1.2.3.4").is_ok());
        assert!(validate_ip_or_cidr("fd00::1").is_ok());
        assert!(validate_ip_or_cidr("10.0.0.0/8").is_ok());
        assert!(validate_ip_or_cidr("fd00::/8").is_ok());
        assert!(validate_ip_or_cidr(" 0.0.0.0/0 ").is_ok());
        assert_eq!(validate_ip_or_cidr(""), Err(ValidationError::Empty));
        assert_eq!(
            validate_ip_or_cidr("pas-une-ip"),
            Err(ValidationError::InvalidIpOrCidr)
        );
        // Un port n'appartient pas aux AllowedIPs WireGuard.
        assert_eq!(
            validate_ip_or_cidr("0.0.0.0/0:51820"),
            Err(ValidationError::InvalidIpOrCidr)
        );
        assert_eq!(
            validate_ip_or_cidr("1.2.3.4\na"),
            Err(ValidationError::ControlChar)
        );
        assert_eq!(
            validate_ip_or_cidr("__proto__"),
            Err(ValidationError::PrototypePollution)
        );
    }

    #[test]
    fn control_chars_cover_c1_and_separators() {
        for bad in ["a\u{0085}b", "a\u{2028}b", "a\u{2029}b"] {
            assert_eq!(
                reject_control_chars(bad),
                Err(ValidationError::ControlChar),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn allowed_ips_must_be_ip_or_cidr() {
        assert!(validate_allowed_ips(&["0.0.0.0/0".to_string()]).is_ok());
        assert!(validate_allowed_ips(&["1.2.3.4".to_string()]).is_ok());
        assert!(validate_allowed_ips(&["fd00::/8".to_string()]).is_ok());
        assert_eq!(
            validate_allowed_ips(&["nonsense".to_string()]),
            Err(ValidationError::InvalidIpOrCidr)
        );
        assert_eq!(
            validate_allowed_ips(&["0.0.0.0/0".to_string(), "x".to_string()]),
            Err(ValidationError::InvalidIpOrCidr)
        );
    }

    /// M4 : un DNS est une adresse d'écoute nue, jamais un nom, un CIDR ou un
    /// `addr:port` (ces valeurs atterrissent telles quelles dans `DNS =` du
    /// `.conf` client).
    #[test]
    fn dns_entries_must_be_bare_ip_of_the_right_family() {
        // Famille IPv4.
        assert!(validate_dns_list(&["1.1.1.1".to_string()], false).is_ok());
        for bad in ["dns.google", "1.2.3.4/24", "1.2.3.4:53", "::1"] {
            assert_eq!(
                validate_dns_list(&[bad.to_string()], false),
                Err(ValidationError::InvalidDns),
                "{bad}"
            );
        }
        // Un caractère de contrôle est refusé avant même le parsing IP.
        assert_eq!(
            validate_dns_list(&["a\x00b".to_string()], false),
            Err(ValidationError::ControlChar)
        );
        assert_eq!(
            validate_dns_list(&[String::new()], false),
            Err(ValidationError::Empty)
        );

        // Famille IPv6.
        assert!(validate_dns_list(&["2606:4700:4700::1111".to_string()], true).is_ok());
        for bad in ["1.1.1.1", "dns.google", "2606:4700:4700::1111/64"] {
            assert!(
                validate_dns_list(&[bad.to_string()], true).is_err(),
                "{bad}"
            );
        }

        // Liste vide : valide (efface la valeur), la garde de non-vacuité
        // reste chez les appelants qui l'imposent.
        assert!(validate_dns_list(&[], false).is_ok());
        assert!(validate_dns_list(&[], true).is_ok());
    }

    /// `INIT_DNS` est multi-famille : chaque entrée reste une IP nue.
    #[test]
    fn init_dns_entries_must_be_any_bare_ip() {
        assert!(
            validate_dns_list_any(&["1.1.1.1".to_string(), "2606:4700:4700::1111".to_string()])
                .is_ok()
        );
        for bad in ["dns.google", "1.2.3.4/24", "1.2.3.4:53", "::1/128"] {
            assert!(validate_dns_list_any(&[bad.to_string()]).is_err(), "{bad}");
        }
        assert_eq!(
            validate_dns_list_any(&[String::new()]),
            Err(ValidationError::Empty)
        );
    }

    #[test]
    fn endpoint_shape_enforced() {
        assert!(validate_endpoint("vpn.example.com:51820").is_ok());
        assert!(validate_endpoint("1.2.3.4:51820").is_ok());
        assert!(validate_endpoint("[2001:db8::1]:51820").is_ok());
        assert_eq!(validate_endpoint(""), Err(ValidationError::Empty));
        assert_eq!(
            validate_endpoint("  "),
            Err(ValidationError::Empty),
            "blank endpoint is empty"
        );
        for bad in [
            "vpn.example.com",
            "vpn.example.com:0",
            "vpn.example.com:70000",
            "vpn.example.com:abc",
            ":51820",
            "http://vpn.example.com:51820",
            "1.2.3.4:51820/evil",
        ] {
            assert!(validate_endpoint(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn host_shape_enforced() {
        assert!(validate_host("vpn.example.com").is_ok());
        assert!(validate_host("1.2.3.4").is_ok());
        assert!(validate_host("::1").is_ok());
        for bad in [
            "",
            "http://vpn.example.com",
            "vpn.example.com:51820",
            "a/b",
            "a@b.com",
            "__proto__",
            "a\nb",
        ] {
            assert!(validate_host(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn token_shape_is_22_base64url() {
        assert!(is_valid_token_shape("AAAAAAAAAAAAAAAAAAAAAA"));
        assert!(!is_valid_token_shape("short"));
        assert!(!is_valid_token_shape("AAAAAAAAAAAAAAAAAAAAAA!"));
    }

    #[test]
    fn csp_has_no_inline() {
        let (_, value) = csp_header();
        assert!(value.contains("script-src 'self'"));
        assert!(!value.contains("unsafe-inline"));
    }
}
