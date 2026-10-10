//! Rendu des fichiers de configuration WireGuard.
//!
//! - [`render`] : fichier `wg-quick` complet (écrit sur disque en `0600`).
//! - [`render_syncconf`] : contenu accepté par `wg syncconf` à chaud.
//! - [`render_client`] : fichier `.conf` téléchargeable par un client.
//!
//! Les deux rendus serveur dérivent d'un [`assemble`] commun et chaque pair
//! passe par un [`push_peer`] unique. La version `syncconf` omet `Address`,
//! `MTU`, `Table`, `DNS`, `SaveConfig` et tous les hooks `Pre/Post` : `wg`
//! rejette tout le bloc sinon et le hot-apply devient silencieusement
//! inopérant (voir le test `syncconf_omits_hot_apply_forbidden_fields`).
//!
//! Aucun champ `SaveConfig` n'est jamais rendu.

use std::fmt::{self, Write as _};

/// Erreur de rendu (validation métier avant écriture).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    /// Valeur métier invalide (port, MTU, table, nom d'interface...).
    Invalid(String),
}

impl RenderError {
    /// Construit une erreur de validation à partir d'un message.
    fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}

impl fmt::Display for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(msg) => write!(f, "invalid wireguard config: {msg}"),
        }
    }
}

impl std::error::Error for RenderError {}

/// Section `[Interface]` du serveur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInterface {
    /// Clé privée du serveur.
    pub private_key: String,
    /// Adresse IPv4 + préfixe (`start+1`, ex. `10.8.0.1/24`), absente si
    /// `IP_MODE=ipv6`.
    pub address_v4: Option<String>,
    /// Adresse IPv6 + préfixe, absente si `IP_MODE=ipv4`.
    pub address_v6: Option<String>,
    /// Port UDP d'écoute (1–65535).
    pub listen_port: u16,
    /// MTU (1024–9000, défaut 1420).
    pub mtu: u16,
    /// Table de routage : `auto`, `off` ou un numéro.
    pub table: String,
    /// Hooks de montée / descente (lignes multiples autorisées).
    pub pre_up: Vec<String>,
    pub post_up: Vec<String>,
    pub pre_down: Vec<String>,
    pub post_down: Vec<String>,
}

/// Un bloc `[Peer]` côté serveur (un client activé).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInput {
    /// Clé publique du client.
    pub public_key: String,
    /// Pre-shared key du client.
    pub preshared_key: Option<String>,
    /// IPv4 du client (rendue en `/32`), absente si `IP_MODE=ipv6`.
    pub ipv4: Option<String>,
    /// IPv6 du client (rendue en `/128`), absente si `IP_MODE=ipv4`.
    pub ipv6: Option<String>,
    /// `serverAllowedIps` du client (ajoutées aux `/32` + `/128`).
    pub server_allowed_ips: Vec<String>,
    /// Endpoint fixe optionnel.
    pub endpoint: Option<String>,
}

/// Section `[Interface]` d'un client (fichier téléchargeable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientInterface {
    /// Clé privée du client.
    pub private_key: String,
    /// IPv4 du client (rendue en `/32`), absente si `IP_MODE=ipv6`.
    pub ipv4: Option<String>,
    /// IPv6 du client (rendue en `/128`), absente si `IP_MODE=ipv4`.
    pub ipv6: Option<String>,
    /// MTU copiée des défauts à la création.
    pub mtu: u16,
    /// DNS (omis quand vide ; hérite du défaut global si `None` résolu vide).
    pub dns: Vec<String>,
}

/// Section `[Peer]` d'un client (pointe vers le serveur).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientPeer {
    /// Clé publique du serveur.
    pub server_public_key: String,
    /// Pre-shared key du client.
    pub preshared_key: Option<String>,
    /// AllowedIPs (client ou défaut global).
    pub allowed_ips: Vec<String>,
    /// Keepalive persistant (0 = désactivé).
    pub keepalive: u16,
    /// Endpoint `host:port` (IPv6 entre crochets).
    pub endpoint: Option<String>,
}

/// Fichier `wg-quick` complet du serveur.
pub fn render(server: &ServerInterface, peers: &[PeerInput]) -> Result<String, RenderError> {
    validate_server_and_peers(server, peers)?;
    Ok(assemble(server, peers, false))
}

/// Contenu accepté par `wg syncconf` (sans `Address`, `MTU`, `Table`, `DNS`,
/// `SaveConfig` ni hooks `Pre/Post`).
pub fn render_syncconf(
    server: &ServerInterface,
    peers: &[PeerInput],
) -> Result<String, RenderError> {
    validate_server_and_peers(server, peers)?;
    Ok(assemble(server, peers, true))
}

/// Fichier `.conf` téléchargeable d'un client (QR, OTL, `/cnf/:token`).
pub fn render_client(iface: &ClientInterface, peer: &ClientPeer) -> Result<String, RenderError> {
    validate_mtu(iface.mtu)?;
    require_non_blank(&iface.private_key, "client private key is empty")?;
    require_non_blank(&peer.server_public_key, "server public key is empty")?;
    let mut addresses = Vec::new();
    if let Some(v4) = non_blank(iface.ipv4.as_deref()) {
        addresses.push(format!("{v4}/32"));
    }
    if let Some(v6) = non_blank(iface.ipv6.as_deref()) {
        addresses.push(format!("{v6}/128"));
    }
    if addresses.is_empty() {
        return Err(RenderError::invalid("client has no tunnel address"));
    }

    let mut out = String::from("[Interface]\n");
    push_directive(&mut out, "PrivateKey", iface.private_key.trim());
    push_directive(&mut out, "Address", addresses.join(", "));
    push_directive(&mut out, "MTU", iface.mtu);
    if !iface.dns.is_empty() {
        push_directive(&mut out, "DNS", iface.dns.join(", "));
    }

    out.push_str("\n[Peer]\n");
    push_directive(&mut out, "PublicKey", peer.server_public_key.trim());
    push_optional_directive(
        &mut out,
        "PresharedKey",
        non_blank(peer.preshared_key.as_deref()),
    );
    if !peer.allowed_ips.is_empty() {
        push_directive(&mut out, "AllowedIPs", peer.allowed_ips.join(", "));
    }
    push_optional_directive(&mut out, "Endpoint", non_blank(peer.endpoint.as_deref()));
    push_directive(&mut out, "PersistentKeepalive", peer.keepalive);
    Ok(out)
}

/// Met en forme un endpoint `host:port`, avec crochets pour un hôte IPv6 nu.
pub fn format_endpoint(host: &str, port: u16) -> Result<String, RenderError> {
    if port == 0 {
        return Err(RenderError::invalid("endpoint port is out of range"));
    }
    let host = host.trim();
    if host.is_empty() {
        return Err(RenderError::invalid("endpoint host is empty"));
    }
    if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        Ok(format!("[{host}]:{port}"))
    } else {
        Ok(format!("{host}:{port}"))
    }
}

/// Assemble le rendu serveur ; `syncconf` active le mode hot-apply restreint.
fn assemble(server: &ServerInterface, peers: &[PeerInput], syncconf: bool) -> String {
    let mut out = String::from("[Interface]\n");
    push_directive(&mut out, "PrivateKey", server.private_key.trim());
    if !syncconf {
        let mut addresses = Vec::new();
        if let Some(v4) = non_blank(server.address_v4.as_deref()) {
            addresses.push(v4.to_string());
        }
        if let Some(v6) = non_blank(server.address_v6.as_deref()) {
            addresses.push(v6.to_string());
        }
        push_directive(&mut out, "Address", addresses.join(", "));
        push_directive(&mut out, "MTU", server.mtu);
        push_directive(&mut out, "Table", server.table.trim());
    }
    push_directive(&mut out, "ListenPort", server.listen_port);
    if !syncconf {
        push_hooks(
            &mut out,
            &server.pre_up,
            &server.post_up,
            &server.pre_down,
            &server.post_down,
        );
    }
    for peer in peers {
        push_peer(&mut out, peer);
    }
    out
}

/// Écrit un bloc `[Peer]` serveur (commun à `render` et `render_syncconf`).
fn push_peer(out: &mut String, peer: &PeerInput) {
    out.push_str("\n[Peer]\n");
    push_directive(out, "PublicKey", peer.public_key.trim());
    push_optional_directive(
        out,
        "PresharedKey",
        non_blank(peer.preshared_key.as_deref()),
    );
    let mut allowed = Vec::new();
    if let Some(v4) = non_blank(peer.ipv4.as_deref()) {
        allowed.push(format!("{v4}/32"));
    }
    if let Some(v6) = non_blank(peer.ipv6.as_deref()) {
        allowed.push(format!("{v6}/128"));
    }
    allowed.extend(
        peer.server_allowed_ips
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(str::to_string),
    );
    push_directive(out, "AllowedIPs", allowed.join(", "));
    push_optional_directive(out, "Endpoint", non_blank(peer.endpoint.as_deref()));
}

/// Écrit une directive `clé = valeur` suivie d'un saut de ligne.
///
/// Point unique de neutralisation : la valeur est d'abord formatée en
/// `String`, puis tous ses caractères de contrôle (`\x00`–`\x1F` et `\x7F`,
/// via [`flatten_newlines`]) sont remplacés par un espace **avant** le
/// `writeln!`. Aucune valeur issue de la DB (clés, `AllowedIPs`, `Endpoint`,
/// `DNS`, `Table`…) ne peut donc injecter une directive supplémentaire ou
/// casser une ligne, même si la validation HTTP/CLI était contournée.
///
/// L'écriture dans un `String` (via `fmt::Write`) est infaillible : le
/// `Result` ne peut être qu'un `Ok` et est donc ignoré sans risque.
fn push_directive(out: &mut String, key: &str, value: impl fmt::Display) {
    let value = flatten_newlines(&value.to_string());
    let _ = writeln!(out, "{key} = {value}");
}

/// Écrit une directive seulement si `value` est présente.
fn push_optional_directive(out: &mut String, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        push_directive(out, key, value);
    }
}

/// Rend les quatre familles de hooks, dans l'ordre attendu par `wg-quick`.
fn push_hooks(
    out: &mut String,
    pre_up: &[String],
    post_up: &[String],
    pre_down: &[String],
    post_down: &[String],
) {
    push_hook_lines(out, "PreUp", pre_up);
    push_hook_lines(out, "PostUp", post_up);
    push_hook_lines(out, "PreDown", pre_down);
    push_hook_lines(out, "PostDown", post_down);
}

/// Rend les hooks après [`flatten_newlines`], en ignorant les lignes vides.
fn push_hook_lines(out: &mut String, key: &str, hooks: &[String]) {
    for hook in hooks {
        let clean = flatten_newlines(hook);
        let clean = clean.trim();
        if !clean.is_empty() {
            push_directive(out, key, clean);
        }
    }
}

/// Nettoie une valeur optionnelle : `None` si absente ou blanche.
fn non_blank(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|s| !s.is_empty())
}

/// Neutralise la classe de contrôle (`\x00`–`\x1F` et `\x7F`) en remplaçant
/// chaque caractère par un espace.
///
/// Utilisé pour les hooks (multi-lignes) et, de façon centralisée, par
/// [`push_directive`] : aucune directive ne peut ainsi contenir de saut de
/// ligne ou d'autre caractère de contrôle, quel que soit son origine.
///
/// On *remplace* (et non supprime) pour garder la parole séparée ; à ne pas
/// confondre avec [`crate::validate::remove_newlines`], qui *supprime*
/// `\r`/`\n` au moment de la validation.
fn flatten_newlines(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Valide l'interface et chaque pair avant tout rendu serveur.
fn validate_server_and_peers(
    server: &ServerInterface,
    peers: &[PeerInput],
) -> Result<(), RenderError> {
    validate_server(server)?;
    for peer in peers {
        validate_peer(peer)?;
    }
    Ok(())
}

fn validate_server(server: &ServerInterface) -> Result<(), RenderError> {
    require_non_blank(&server.private_key, "server private key is empty")?;
    if non_blank(server.address_v4.as_deref()).is_none()
        && non_blank(server.address_v6.as_deref()).is_none()
    {
        return Err(RenderError::invalid("server has no tunnel address"));
    }
    if server.listen_port == 0 {
        return Err(RenderError::invalid("listen port must be 1-65535"));
    }
    validate_mtu(server.mtu)?;
    validate_table(&server.table)
}

fn validate_peer(peer: &PeerInput) -> Result<(), RenderError> {
    require_non_blank(&peer.public_key, "peer public key is empty")?;
    if non_blank(peer.ipv4.as_deref()).is_none() && non_blank(peer.ipv6.as_deref()).is_none() {
        return Err(RenderError::invalid("peer has no tunnel address"));
    }
    Ok(())
}

/// Vérifie qu'une valeur n'est pas vide une fois les espaces retirés.
fn require_non_blank(value: &str, message: &str) -> Result<(), RenderError> {
    if value.trim().is_empty() {
        Err(RenderError::invalid(message))
    } else {
        Ok(())
    }
}

fn validate_mtu(mtu: u16) -> Result<(), RenderError> {
    if (1024..=9000).contains(&mtu) {
        Ok(())
    } else {
        Err(RenderError::invalid(format!("mtu {mtu} must be 1024-9000")))
    }
}

/// `table` accepte `auto`, `off` ou un nombre, via
/// [`crate::validate::validate_table`].
fn validate_table(table: &str) -> Result<(), RenderError> {
    let table = table.trim();
    crate::validate::validate_table(table).map_err(|_| {
        RenderError::invalid(format!(
            "routing table `{table}` must be auto, off or a number"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_server() -> ServerInterface {
        ServerInterface {
            private_key: "SERVER_PRIV".to_string(),
            address_v4: Some("10.8.0.1/24".to_string()),
            address_v6: Some("fdcc:ad94:bacf:61a4::cafe:1/112".to_string()),
            listen_port: 51820,
            mtu: 1420,
            table: "auto".to_string(),
            pre_up: vec!["iptables -A FORWARD -i wg0 -j ACCEPT".to_string()],
            post_up: vec![],
            pre_down: vec![],
            post_down: vec!["iptables -D FORWARD -i wg0 -j ACCEPT".to_string()],
        }
    }

    fn sample_peer() -> PeerInput {
        PeerInput {
            public_key: "CLIENT_PUB".to_string(),
            preshared_key: Some("PSK".to_string()),
            ipv4: Some("10.8.0.2".to_string()),
            ipv6: Some("fdcc:ad94:bacf:61a4::cafe:2".to_string()),
            server_allowed_ips: vec!["0.0.0.0/0".to_string()],
            endpoint: None,
        }
    }

    #[test]
    fn full_render_contains_everything() {
        let conf = render(&sample_server(), &[sample_peer()]).expect("render");
        assert!(conf.contains("Address = 10.8.0.1/24, fdcc:ad94:bacf:61a4::cafe:1/112"));
        assert!(conf.contains("MTU = 1420"));
        assert!(conf.contains("Table = auto"));
        assert!(conf.contains("ListenPort = 51820"));
        assert!(conf.contains("PreUp = iptables"));
        assert!(conf.contains("PostDown = iptables"));
        assert!(
            conf.contains("AllowedIPs = 10.8.0.2/32, fdcc:ad94:bacf:61a4::cafe:2/128, 0.0.0.0/0")
        );
        assert!(conf.contains("PresharedKey = PSK"));
        assert!(!conf.contains("SaveConfig"));
    }

    /// Garde-fou critique : inverser les deux rendus rend le hot-apply
    /// silencieusement inopérant (`wg` rejette tout le bloc `syncconf`).
    #[test]
    fn syncconf_omits_hot_apply_forbidden_fields() {
        let conf = render_syncconf(&sample_server(), &[sample_peer()]).expect("syncconf");
        for forbidden in [
            "Address",
            "MTU",
            "Table",
            "DNS",
            "SaveConfig",
            "PreUp",
            "PostUp",
            "PreDown",
            "PostDown",
        ] {
            for line in conf.lines() {
                let key = line.split('=').next().unwrap_or("").trim();
                assert_ne!(
                    key, forbidden,
                    "syncconf must never contain `{forbidden}` (line: `{line}`)"
                );
            }
        }
        // Le fond reste applicable : clés + peers présents.
        assert!(conf.contains("PrivateKey = SERVER_PRIV"));
        assert!(conf.contains("ListenPort = 51820"));
        assert!(conf.contains("PublicKey = CLIENT_PUB"));
        assert!(conf.contains("AllowedIPs = 10.8.0.2/32"));
    }

    #[test]
    fn client_render_omits_dns_when_empty() {
        let iface = ClientInterface {
            private_key: "C_PRIV".to_string(),
            ipv4: Some("10.8.0.2".to_string()),
            ipv6: None,
            mtu: 1420,
            dns: vec![],
        };
        let peer = ClientPeer {
            server_public_key: "S_PUB".to_string(),
            preshared_key: None,
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            keepalive: 25,
            endpoint: Some("vpn.example.com:51820".to_string()),
        };
        let conf = render_client(&iface, &peer).expect("client render");
        assert!(conf.contains("Address = 10.8.0.2/32\n"));
        assert!(!conf.lines().any(|l| l.starts_with("DNS")));
        assert!(conf.contains("PersistentKeepalive = 25"));
    }

    #[test]
    fn v6_only_client_renders_only_ipv6() {
        let iface = ClientInterface {
            private_key: "C_PRIV".to_string(),
            ipv4: None,
            ipv6: Some("fdcc::2".to_string()),
            mtu: 1420,
            dns: vec!["2606:4700:4700::1111".to_string()],
        };
        let peer = ClientPeer {
            server_public_key: "S_PUB".to_string(),
            preshared_key: None,
            allowed_ips: vec!["::/0".to_string()],
            keepalive: 25,
            endpoint: None,
        };
        let conf = render_client(&iface, &peer).expect("v6-only render");
        assert!(conf.contains("Address = fdcc::2/128\n"));
        assert!(!conf.contains("/32"));
        // Aucune adresse du tout -> refus explicite.
        let empty = ClientInterface {
            ipv4: None,
            ipv6: None,
            ..iface
        };
        assert!(render_client(&empty, &peer).is_err());
    }

    #[test]
    fn v6_only_server_and_peer_render() {
        let mut server = sample_server();
        server.address_v4 = None;
        let mut peer = sample_peer();
        peer.ipv4 = None;
        let conf = render(&server, &[peer]).expect("v6-only server");
        assert!(conf.contains("Address = fdcc:ad94:bacf:61a4::cafe:1/112"));
        assert!(!conf.contains("10.8.0.1"));
        assert!(!conf.contains("10.8.0.2/32"));
        assert!(conf.contains("AllowedIPs = fdcc:ad94:bacf:61a4::cafe:2/128, 0.0.0.0/0"));
    }

    #[test]
    fn hooks_lose_newlines() {
        assert_eq!(flatten_newlines("a\nb\rc\n"), "a b c ");
        let mut out = String::new();
        push_hook_lines(&mut out, "PreUp", &["one\nINJECTED=x two".to_string()]);
        assert_eq!(out, "PreUp = one INJECTED=x two\n");
    }

    /// Garde-fou défense-en-profondeur : la neutralisation est centralisée dans
    /// [`push_directive`], donc toute valeur (même issue d'une écriture DB hors
    /// API) reste sur une seule ligne.
    #[test]
    fn directive_never_injects_newline() {
        let mut out = String::new();
        push_directive(&mut out, "PrivateKey", "PK\nAllowedIPs = 0.0.0.0/0");
        assert_eq!(out, "PrivateKey = PK AllowedIPs = 0.0.0.0/0\n");
        assert_eq!(out.lines().count(), 1);
        assert!(!out.lines().any(|l| l.starts_with("AllowedIPs")));

        let mut out = String::new();
        push_directive(&mut out, "PrivateKey", "PK\r\nAllowedIPs = 0.0.0.0/0");
        assert_eq!(out.lines().count(), 1);

        let mut out = String::new();
        push_directive(&mut out, "PrivateKey", "PK\rAllowedIPs = 0.0.0.0/0");
        assert_eq!(out.lines().count(), 1);
    }

    #[test]
    fn server_private_key_newline_cannot_inject_directive() {
        let mut server = sample_server();
        server.private_key = "SERVER_PRIV\nAllowedIPs = 0.0.0.0/0".to_string();
        let conf = render(&server, &[]).expect("render");
        assert!(conf.contains("PrivateKey = SERVER_PRIV AllowedIPs = 0.0.0.0/0\n"));
        assert!(!conf.lines().any(|l| l.starts_with("AllowedIPs")));
    }

    #[test]
    fn peer_public_key_newline_cannot_inject_directive() {
        let mut peer = sample_peer();
        peer.public_key = "CLIENT_PUB\nEndpoint = evil.example:1".to_string();
        let conf = render(&sample_server(), &[peer]).expect("render");
        assert!(conf.contains("PublicKey = CLIENT_PUB Endpoint = evil.example:1\n"));
        assert!(!conf.lines().any(|l| l.starts_with("Endpoint")));
    }

    /// Neutralise toute la classe de contrôle C0 (`\x00`–`\x1F`) et `\x7F`.
    #[test]
    fn directive_flattens_control_characters() {
        assert_eq!(flatten_newlines("a\x00b\x7fc"), "a b c");
        let mut out = String::new();
        push_directive(&mut out, "PrivateKey", "a\x00b\x7fc\td");
        assert_eq!(out, "PrivateKey = a b c d\n");
    }

    #[test]
    fn endpoint_brackets_bare_ipv6() {
        assert_eq!(
            format_endpoint("vpn.example.com", 51820).expect("ep"),
            "vpn.example.com:51820"
        );
        assert_eq!(
            format_endpoint("2001:db8::1", 51820).expect("ep"),
            "[2001:db8::1]:51820"
        );
        assert_eq!(
            format_endpoint("[2001:db8::1]", 51820).expect("ep"),
            "[2001:db8::1]:51820"
        );
        assert!(format_endpoint("", 51820).is_err());
        assert!(format_endpoint("host", 0).is_err());
    }

    #[test]
    fn invalid_mtu_table_port_rejected() {
        let mut server = sample_server();
        server.mtu = 900;
        assert!(render(&server, &[]).is_err());
        let mut server = sample_server();
        server.table = "main-table!".to_string();
        assert!(render(&server, &[]).is_err());
        let mut server = sample_server();
        server.table = "100".to_string();
        assert!(render(&server, &[]).is_ok());
        let mut server = sample_server();
        server.listen_port = 0;
        assert!(render(&server, &[]).is_err());
    }
}
