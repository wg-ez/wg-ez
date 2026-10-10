//! Plan de rebuild iptables (pur, testable sans privilège).
//!
//! - Une chaîne par interface `WG_CLIENTS_<iface>`, création idempotente
//!   (`-N ... || true`), flush (`-F`) systématique avant repeuplement,
//!   rattachement à saut unique (`-D ... || true` puis `-I FORWARD 1`),
//!   `DROP` final, nettoyage de l'ancienne chaîne partagée `WG_CLIENTS`.
//! - Priorité des sources : `firewallIps` non vide → `allowedIps` du client
//!   → `defaultAllowedIps` global.
//! - Destination IPv6 → `ip6tables` avec l'`ipv6Address` du client ;
//!   ignorée si `IP_MODE=ipv4` ou sans adresse v6 ; symétrique v4.
//! - Chaque règle porte un commentaire `client <id>: <nom>` (sanitisé,
//!   tronqué à 256 octets).

use super::FirewallError;
use super::chain_name;
use super::parse::ParsedRule;

/// Un client pris en compte par le rebuild (déjà filtré : activé).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallClient {
    pub id: i64,
    pub name: String,
    /// IPv4 du client (absente si `IP_MODE=ipv6` ou pas d'adresse v4).
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    /// Entrées déjà résolues (via [`resolve_rules`]) puis parsées.
    pub rules: Vec<ParsedRule>,
}

/// Plan de rebuild pour une interface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FirewallPlan {
    pub iface: String,
    pub enabled: bool,
    pub disable_ipv4: bool,
    pub disable_ipv6: bool,
    pub clients: Vec<FirewallClient>,
}

/// Une commande iptables à exécuter ; `ignore_failure` modélise `|| true`
/// et les sondes `-C` (échec attendu quand la règle manque).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallCmd {
    pub program: String,
    pub args: Vec<String>,
    pub ignore_failure: bool,
}

impl FirewallCmd {
    fn new(program: &str, args: &[&str], ignore_failure: bool) -> Self {
        Self {
            program: program.to_string(),
            args: args.iter().map(|s| (*s).to_string()).collect(),
            ignore_failure,
        }
    }
}

/// Résout les règles effectives d'un client (priorité : `firewallIps` non
/// vide → `allowedIps` → défaut global). `None` = héritage.
pub fn resolve_rules(
    firewall_ips: Option<&[String]>,
    allowed_ips: Option<&[String]>,
    default_allowed: &[String],
) -> Vec<String> {
    if let Some(ips) = firewall_ips
        && !ips.is_empty()
    {
        return ips.to_vec();
    }
    if let Some(ips) = allowed_ips
        && !ips.is_empty()
    {
        return ips.to_vec();
    }
    default_allowed.to_vec()
}

/// Sanitise un nom de client pour le commentaire iptables : caractères
/// simples uniquement, tronqué à 256 octets (sans couper un caractère).
pub fn sanitize_comment_name(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        let keep = c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.' | '@');
        out.push(if keep { c } else { '_' });
    }
    // Troncature à 256 octets sur une frontière de caractère.
    while out.len() > 256 {
        out.pop();
    }
    out
}

/// Commentaire iptables d'une règle : `client <id>: <nom>`.
pub fn rule_comment(client_id: i64, name: &str) -> String {
    format!("client {client_id}: {}", sanitize_comment_name(name).trim())
}

/// Construit la séquence complète de rebuild (pure, testable) :
/// création idempotente, rattachement idempotent, règles par client,
/// `DROP` final, nettoyage de l'ancienne chaîne partagée `WG_CLIENTS`.
pub fn plan_rebuild(plan: &FirewallPlan) -> Result<Vec<FirewallCmd>, FirewallError> {
    let chain = chain_name(&plan.iface);
    let mut cmds = Vec::new();
    let v4 = !plan.disable_ipv4;
    let v6 = !plan.disable_ipv6;
    // (programme, famille active) ; l'ordre iptables-avant-ip6tables est
    // préservé à chaque étape.
    let families = [("iptables", v4), ("ip6tables", v6)];

    // 1. Création idempotente puis flush de la chaîne (toutes familles
    //    actives d'abord). -F : vider avant de repeupler. Sans ce flush, les
    //    ACCEPT et le DROP des rebuilds precedents restent en place et le
    //    premier DROP rend toutes les nouvelles regles inatteignables : le
    //    filtrage reste fige sur l'etat du tout premier rebuild.
    for (prog, _) in families.iter().copied().filter(|(_, active)| *active) {
        cmds.push(FirewallCmd::new(prog, &["-N", &chain], true));
        cmds.push(FirewallCmd::new(prog, &["-F", &chain], true));
    }
    // 2. Saut unique : -D ... || true puis -I FORWARD 1 (par famille active).
    for (prog, _) in families.iter().copied().filter(|(_, active)| *active) {
        cmds.push(FirewallCmd::new(
            prog,
            &["-D", "FORWARD", "-i", &plan.iface, "-j", &chain],
            true,
        ));
        cmds.push(FirewallCmd::new(
            prog,
            &["-I", "FORWARD", "1", "-i", &plan.iface, "-j", &chain],
            true,
        ));
    }
    // 3. Règles par client (client puis règle), programme + source selon la
    //    famille de la règle.
    for client in &plan.clients {
        let comment = rule_comment(client.id, &client.name);
        for rule in &client.rules {
            let (prog, active, src) = if rule.is_v6 {
                ("ip6tables", v6, client.ipv6.as_deref())
            } else {
                ("iptables", v4, client.ipv4.as_deref())
            };
            if !active {
                continue;
            }
            let Some(src) = src.map(str::trim).filter(|s| !s.is_empty()) else {
                continue;
            };
            cmds.push(accept_cmd(prog, &chain, src, rule, &comment));
        }
    }
    // 4. DROP final par famille active.
    for (prog, _) in families.iter().copied().filter(|(_, active)| *active) {
        cmds.push(FirewallCmd::new(prog, &["-A", &chain, "-j", "DROP"], false));
    }
    // 5. Nettoyage de l'ancienne chaîne partagée `WG_CLIENTS`.
    for (prog, _) in families.iter().copied().filter(|(_, active)| *active) {
        cleanup_legacy_chain(prog, &mut cmds);
    }
    Ok(cmds)
}

/// Nettoyage idempotent (`ignore_failure`) de l'ancienne chaîne partagée
/// `WG_CLIENTS`.
fn cleanup_legacy_chain(prog: &str, cmds: &mut Vec<FirewallCmd>) {
    for args in [
        &["-D", "FORWARD", "-j", "WG_CLIENTS"][..],
        &["-F", "WG_CLIENTS"][..],
        &["-X", "WG_CLIENTS"][..],
    ] {
        cmds.push(FirewallCmd::new(prog, args, true));
    }
}

fn accept_cmd(
    program: &str,
    chain: &str,
    src: &str,
    rule: &ParsedRule,
    comment: &str,
) -> FirewallCmd {
    let mut args = vec![
        "-A".to_string(),
        chain.to_string(),
        "-s".to_string(),
        src.to_string(),
        "-d".to_string(),
        rule.dest.clone(),
    ];
    if let Some(proto) = rule.proto {
        args.push("-p".to_string());
        args.push(proto.as_arg().to_string());
    }
    if let Some(port) = rule.port {
        // Sans proto explicite, la règle sans `-p` couvre TCP et UDP.
        args.push("--dport".to_string());
        args.push(port.to_string());
    }
    args.push("-m".to_string());
    args.push("comment".to_string());
    args.push("--comment".to_string());
    args.push(comment.to_string());
    args.push("-j".to_string());
    args.push("ACCEPT".to_string());
    FirewallCmd {
        program: program.to_string(),
        args,
        ignore_failure: false,
    }
}

/// Séquence de suppression d'une chaîne (down / firewall désactivé).
pub fn plan_remove(iface: &str, disable_ipv4: bool, disable_ipv6: bool) -> Vec<FirewallCmd> {
    let chain = chain_name(iface);
    let mut cmds = Vec::new();
    let families = [("iptables", !disable_ipv4), ("ip6tables", !disable_ipv6)];
    for (prog, _) in families.iter().copied().filter(|(_, active)| *active) {
        cmds.push(FirewallCmd::new(
            prog,
            &["-D", "FORWARD", "-i", iface, "-j", &chain],
            true,
        ));
        cmds.push(FirewallCmd::new(prog, &["-F", &chain], true));
        cmds.push(FirewallCmd::new(prog, &["-X", &chain], true));
        cleanup_legacy_chain(prog, &mut cmds);
    }
    cmds
}
