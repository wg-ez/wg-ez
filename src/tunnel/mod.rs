//! Seul module autorisé à toucher le noyau, via [`Tunnel::apply`].
//!
//! Séquence `apply` après chaque mutation de config (hors génération OTL) :
//! 1. [`render()`](super::wg::render::render) du fichier `wg-quick` complet ;
//! 2. écriture de `/etc/wireguard/<iface>.conf` en mode `0600` ;
//! 3. `wg syncconf` à chaud (jamais `wg-quick up`, qui coupe les tunnels) ;
//! 4. rebuild firewall par client.
//!
//! `down` + `up` n'ont lieu que sur le bouton admin Restart explicite
//! ([`Tunnel::restart`]) et au boot ([`Tunnel::boot`]) / à l'arrêt
//! ([`Tunnel::shutdown`]).

use std::fmt;
use std::path::{Path, PathBuf};

use super::wg::firewall::{self, Coalescer, FirewallPlan};
use super::wg::render::{self, PeerInput, RenderError, ServerInterface};
use super::wg::runner::{Runner, RunnerError, wg_executable};
use crate::validate::{IFACE_MAX_LEN, is_valid_interface_name};

/// Dossier contenant les `.conf` (`/etc/wireguard` en production).
pub const DEFAULT_CONF_DIR: &str = "/etc/wireguard";

/// Binaire `wg-quick` (montage / démontage d'interface).
const WG_QUICK: &str = "wg-quick";

/// Shell servant à `wg syncconf` (substitution de processus `<(...)`).
const BASH: &str = "bash";

/// Erreur d'application tunnel.
#[derive(Debug)]
pub enum TunnelError {
    /// Interface ou paramètre invalide.
    Invalid(String),
    /// Rendu impossible.
    Render(RenderError),
    /// Commande système en échec.
    Runner(RunnerError),
    /// Écriture du `.conf` impossible.
    Io(std::io::Error),
    /// Rebuild firewall en échec.
    Firewall(firewall::FirewallError),
}

impl fmt::Display for TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(msg) => write!(f, "invalid tunnel request: {msg}"),
            Self::Render(e) => write!(f, "cannot render config: {e}"),
            Self::Runner(e) => write!(f, "wireguard command failed: {e}"),
            Self::Io(e) => write!(f, "cannot write config file: {e}"),
            Self::Firewall(e) => write!(f, "firewall rebuild failed: {e}"),
        }
    }
}

impl std::error::Error for TunnelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Render(e) => Some(e),
            Self::Runner(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Firewall(e) => Some(e),
            Self::Invalid(_) => None,
        }
    }
}

impl From<RenderError> for TunnelError {
    fn from(e: RenderError) -> Self {
        Self::Render(e)
    }
}

impl From<RunnerError> for TunnelError {
    fn from(e: RunnerError) -> Self {
        Self::Runner(e)
    }
}

impl From<firewall::FirewallError> for TunnelError {
    fn from(e: firewall::FirewallError) -> Self {
        Self::Firewall(e)
    }
}

/// Photo cohérente à appliquer : interface + pairs activés + plan firewall.
#[derive(Debug, Clone)]
pub struct ApplySnapshot {
    /// Nom d'interface (`≤15` chars, `[a-zA-Z0-9_=+.-]`).
    pub iface: String,
    /// Section `[Interface]` du serveur.
    pub server: ServerInterface,
    /// Un [`PeerInput`] par client activé.
    pub peers: Vec<PeerInput>,
    /// Plan firewall (avec `enabled = false` quand opt-out).
    pub firewall: FirewallPlan,
}

/// Pilote noyau. Le seul chemin d'écriture vers `wg` / `iptables`.
#[derive(Debug)]
pub struct Tunnel<R: Runner> {
    runner: R,
    conf_dir: PathBuf,
    coalescer: Coalescer,
}

impl<R: Runner> Tunnel<R> {
    /// Nouveau tunnel ; `conf_dir` vaut `/etc/wireguard` par défaut.
    pub fn new(runner: R) -> Self {
        Self {
            runner,
            conf_dir: PathBuf::from(DEFAULT_CONF_DIR),
            coalescer: Coalescer::new(),
        }
    }

    /// Redirige le dossier des `.conf` (tests, CLI).
    pub fn with_conf_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.conf_dir = dir.into();
        self
    }

    /// Accès au runner (introspection, statut `wg dump`).
    pub fn runner(&self) -> &R {
        &self.runner
    }

    /// Chemin du `.conf` d'une interface **déjà validée**.
    fn conf_file(&self, iface: &str) -> PathBuf {
        self.conf_dir.join(format!("{iface}.conf"))
    }

    /// Rend le `wg-quick` complet puis l'écrit en `0600`.
    ///
    /// `snap.iface` doit avoir été validé par l'appelant.
    fn write_rendered_conf(&self, snap: &ApplySnapshot) -> Result<(), TunnelError> {
        let content = render::render(&snap.server, &snap.peers)?;
        write_conf_0600(&self.conf_file(&snap.iface), content.as_bytes()).map_err(TunnelError::Io)
    }

    /// `wg-quick down <iface>` best-effort : un tunnel absent n'est pas une
    /// erreur, seul l'arrêt compte.
    fn wg_quick_down(&self, iface: &str) {
        let _ = self.runner.exec_str(WG_QUICK, &["down", iface]);
    }

    /// `wg-quick up <iface>` : l'échec remonte à l'appelant.
    fn wg_quick_up(&self, iface: &str) -> Result<(), TunnelError> {
        self.runner.exec_str(WG_QUICK, &["up", iface])?;
        Ok(())
    }

    /// `Tunnel::apply` complet : render → écriture `0600` → `syncconf`
    /// à chaud → rebuild firewall. Jamais de `wg-quick up` ici.
    pub fn apply(&self, snap: &ApplySnapshot) -> Result<(), TunnelError> {
        validate_iface(&snap.iface)?;
        self.write_rendered_conf(snap)?;
        let hot = render::render_syncconf(&snap.server, &snap.peers)?;
        self.syncconf(&snap.iface, &hot)?;
        self.rebuild_firewall(&snap.firewall)
    }

    /// Séquence de boot : écriture `0600`, `wg-quick down` (échec ignoré),
    /// `wg-quick up` (applique déjà tout, donc sans `syncconf`), firewall.
    pub fn boot(&self, snap: &ApplySnapshot) -> Result<(), TunnelError> {
        validate_iface(&snap.iface)?;
        self.write_rendered_conf(snap)?;
        self.wg_quick_down(&snap.iface);
        self.wg_quick_up(&snap.iface)?;
        self.rebuild_firewall(&snap.firewall)
    }

    /// `down` puis `up` (coupe les tunnels), puis rebuild firewall.
    ///
    /// Ordre imposé : `down` -> écriture du `.conf` -> `up`.
    /// - le `down` doit lire le `.conf` **encore sur disque** (la config
    ///   réellement appliquée) pour exécuter les `PostDown` qui défont les
    ///   règles posées par l'ancien `PostUp`. Écrire d'abord ferait tourner
    ///   les **nouveaux** `PostDown` et laisserait fuiter les anciennes règles,
    ///   surtout si les nouvelles n'ont rien à voir avec les anciennes ;
    /// - le `up` relit ensuite le fichier réécrit, donc MTU/Table/Address et
    ///   les nouveaux hooks sont bien appliqués.
    ///
    /// Utilisé par le bouton admin Restart et par un changement de réglage
    /// d'interface que `wg syncconf` ne sait pas répercuter.
    pub fn restart(&self, snap: &ApplySnapshot) -> Result<(), TunnelError> {
        validate_iface(&snap.iface)?;
        // 1. Démonter la config en place avec ses propres hooks.
        self.wg_quick_down(&snap.iface);
        // 2. Réécrire le conf (nouveaux réglages/hooks) puis remonter dessus.
        self.write_rendered_conf(snap)?;
        self.wg_quick_up(&snap.iface)?;
        self.rebuild_firewall(&snap.firewall)
    }

    /// Arrêt propre : `wg-quick down` + nettoyage des chaînes (échecs ignorés).
    pub fn shutdown(&self, iface: &str, disable_ipv4: bool, disable_ipv6: bool) {
        if validate_iface(iface).is_err() {
            return;
        }
        self.wg_quick_down(iface);
        let cmds = firewall::plan_remove(iface, disable_ipv4, disable_ipv6);
        let _ = firewall::apply_cmds(&self.runner, &cmds);
    }

    /// Applique à chaud via `syncconf`.
    ///
    /// Forme exacte : `wg syncconf <iface> <(wg-quick strip <conf>)` sous
    /// `bash`, avec fallback sans shell (`syncconf_content` écrit dans un
    /// fichier tmp puis `wg syncconf <iface> <tmp>`).
    pub fn syncconf(&self, iface: &str, syncconf_content: &str) -> Result<(), TunnelError> {
        validate_iface(iface)?;
        let wg = wg_executable();
        let conf = self.conf_file(iface);
        let conf_str = conf.to_string_lossy().to_string();

        // Forme avec substitution bash.
        let script = format!(
            "exec {} syncconf {} <({} strip {})",
            shell_word(&wg),
            shell_word(iface),
            WG_QUICK,
            shell_word(&conf_str)
        );
        match self.runner.exec(BASH, &["-c".to_string(), script], None) {
            Ok(_) => Ok(()),
            Err(_) => self.syncconf_with_content(iface, syncconf_content),
        }
    }

    /// `syncconf` à partir d'un contenu déjà rendu (fallback sans shell).
    pub fn syncconf_with_content(
        &self,
        iface: &str,
        syncconf_content: &str,
    ) -> Result<(), TunnelError> {
        validate_iface(iface)?;
        let wg = wg_executable();
        let tmp = self.conf_dir.join(format!("{iface}.syncconf.tmp"));
        write_conf_0600(&tmp, syncconf_content.as_bytes()).map_err(TunnelError::Io)?;
        let res = self.runner.exec(
            &wg,
            &[
                "syncconf".to_string(),
                iface.to_string(),
                tmp.to_string_lossy().to_string(),
            ],
            None,
        );
        let _ = std::fs::remove_file(&tmp);
        res?;
        Ok(())
    }

    fn rebuild_firewall(&self, plan: &FirewallPlan) -> Result<(), TunnelError> {
        if plan.enabled {
            firewall::rebuild_coalesced(&self.runner, &self.coalescer, plan)?;
        } else {
            // Firewall coupé : ne jamais laisser une chaîne avec DROP final.
            let cmds = firewall::plan_remove(&plan.iface, plan.disable_ipv4, plan.disable_ipv6);
            firewall::apply_cmds(&self.runner, &cmds)?;
        }
        Ok(())
    }
}

/// Nom d'interface : `≤15` chars parmi `[a-zA-Z0-9_=+.-]` (anti-traversal).
///
/// Regle partagee avec la config : [`crate::validate::is_valid_interface_name`]
/// (charset + longueur) et [`crate::validate::IFACE_MAX_LEN`]. La longueur est
/// testee en amont uniquement pour conserver le message d'erreur specifique.
pub fn validate_iface(iface: &str) -> Result<(), TunnelError> {
    if iface.is_empty() || iface.len() > IFACE_MAX_LEN {
        return Err(TunnelError::Invalid(format!(
            "interface name `{iface}` must be 1-{IFACE_MAX_LEN} chars"
        )));
    }
    if !is_valid_interface_name(iface) {
        return Err(TunnelError::Invalid(format!(
            "interface name `{iface}` uses forbidden characters"
        )));
    }
    Ok(())
}

/// Écriture en mode `0600` (création restreinte + chmod de rattrapage si le
/// fichier préexiste avec des permissions plus larges).
///
/// L'ouverture passe `O_NOFOLLOW` : un lien symbolique planté à l'emplacement
/// du `.conf` (ou du tmp `syncconf`) fait échouer l'ouverture plutôt que
/// d'écrire à travers vers une cible arbitraire. Le chmod de rattrapage
/// s'applique au **descripteur effectivement ouvert** (`File::set_permissions`)
/// et non à un chemin re-résolu : il ne peut donc jamais atteindre une cible
/// de symlink, même en cas de course.
pub fn write_conf_0600(path: &Path, content: &[u8]) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        let mut opts = std::fs::OpenOptions::new();
        opts.write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            // `custom_flags` est safe ; seule la constante `O_NOFOLLOW` est
            // nécessaire (déjà compilée via `libc`).
            .custom_flags(libc::O_NOFOLLOW);

        let mut file = opts.open(path).map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "refusing to write config through symlink at {}",
                        path.display()
                    ),
                )
            } else {
                e
            }
        })?;
        file.write_all(content)?;
        file.flush()?;

        let mut perms = file.metadata()?.permissions();
        perms.set_mode(0o600);
        file.set_permissions(perms)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, content)
    }
}

fn shell_word(value: &str) -> String {
    let is_bare = !value.is_empty()
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/' | b'+' | b'=' | b':')
        });
    if is_bare {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::super::wg::firewall::FirewallPlan;
    use super::super::wg::render::{PeerInput, ServerInterface};
    use super::super::wg::runner::MockRunner;
    use super::*;

    fn sample_snapshot() -> ApplySnapshot {
        ApplySnapshot {
            iface: "wg0".to_string(),
            server: ServerInterface {
                private_key: "SERVER_PRIV".to_string(),
                address_v4: Some("10.8.0.1/24".to_string()),
                address_v6: None,
                listen_port: 51820,
                mtu: 1420,
                table: "auto".to_string(),
                pre_up: vec![],
                post_up: vec![],
                pre_down: vec![],
                post_down: vec![],
            },
            peers: vec![PeerInput {
                public_key: "CLIENT_PUB".to_string(),
                preshared_key: None,
                ipv4: Some("10.8.0.2".to_string()),
                ipv6: None,
                server_allowed_ips: vec![],
                endpoint: None,
            }],
            firewall: FirewallPlan {
                iface: "wg0".to_string(),
                enabled: false,
                disable_ipv4: false,
                disable_ipv6: true,
                clients: vec![],
            },
        }
    }

    /// Tunnel de test isolé dans un dossier temporaire dédié.
    fn test_tunnel(name: &str) -> (PathBuf, Tunnel<MockRunner>) {
        let dir = std::env::temp_dir().join(name);
        let _ = std::fs::create_dir_all(&dir);
        let tunnel = Tunnel::new(MockRunner::new()).with_conf_dir(dir.clone());
        (dir, tunnel)
    }

    /// Nombre d'appels `wg-quick <action>` enregistrés.
    fn count_wg_quick(tunnel: &Tunnel<MockRunner>, action: &str) -> usize {
        tunnel
            .runner()
            .calls()
            .iter()
            .filter(|c| c.program == WG_QUICK && c.args.iter().any(|a| a == action))
            .count()
    }

    /// Index du premier appel `wg-quick <action>`.
    fn wg_quick_index(tunnel: &Tunnel<MockRunner>, action: &str) -> usize {
        tunnel
            .runner()
            .calls()
            .iter()
            .position(|c| c.program == WG_QUICK && c.args.iter().any(|a| a == action))
            .expect("wg-quick call")
    }

    #[cfg(unix)]
    fn assert_conf_mode(path: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "config file must be 0600");
    }

    #[test]
    fn apply_writes_conf_syncs_and_never_brings_up() {
        // Le fallback sans shell est forcé en faisant échouer `bash`.
        // Ici bash réussit (mock) : on vérifie la forme exacte.
        let (dir, tunnel) = test_tunnel("wgez-tunnel-apply");
        tunnel.apply(&sample_snapshot()).expect("apply");

        let conf = std::fs::read_to_string(dir.join("wg0.conf")).expect("conf written");
        assert!(conf.contains("PrivateKey = SERVER_PRIV"));
        assert!(conf.contains("Address = 10.8.0.1/24"));
        #[cfg(unix)]
        assert_conf_mode(&dir.join("wg0.conf"));

        let calls = tunnel.runner().calls();
        let programs: Vec<&str> = calls.iter().map(|c| c.program.as_str()).collect();
        // syncconf via bash, jamais wg-quick up à chaud.
        assert!(programs.contains(&BASH));
        assert_eq!(count_wg_quick(&tunnel, "up"), 0);
        // Firewall désactivé -> nettoyage, pas de rebuild.
        assert!(calls.iter().any(|c| c.program == "iptables"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn syncconf_with_content_uses_tmp_file() {
        let (dir, tunnel) = test_tunnel("wgez-tunnel-sync");
        tunnel
            .syncconf_with_content("wg0", "[Interface]\nListenPort = 51820\n")
            .expect("syncconf");

        let calls = tunnel.runner().calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "wg");
        assert_eq!(calls[0].args[0], "syncconf");
        assert_eq!(calls[0].args[1], "wg0");
        // Le tmp est nettoyé.
        assert!(!dir.join("wg0.syncconf.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn boot_does_down_then_up_without_syncconf() {
        let (dir, tunnel) = test_tunnel("wgez-tunnel-boot");
        tunnel.boot(&sample_snapshot()).expect("boot");

        assert_eq!(count_wg_quick(&tunnel, "down"), 1);
        assert_eq!(count_wg_quick(&tunnel, "up"), 1);
        assert!(!tunnel.runner().calls().iter().any(|c| c.program == BASH));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restart_rewrites_conf_and_does_down_up() {
        let (dir, tunnel) = test_tunnel("wgez-tunnel-restart");
        tunnel.restart(&sample_snapshot()).expect("restart");

        // `wg-quick up` relit le conf : il doit porter le dernier rendu.
        let conf = std::fs::read_to_string(dir.join("wg0.conf")).expect("conf written");
        assert!(conf.contains("MTU = 1420"));
        assert!(conf.contains("PrivateKey = SERVER_PRIV"));
        #[cfg(unix)]
        assert_conf_mode(&dir.join("wg0.conf"));

        assert_eq!(count_wg_quick(&tunnel, "down"), 1);
        assert_eq!(count_wg_quick(&tunnel, "up"), 1);
        // Le `down` doit précéder le `up` (et la réécriture) : il lit l'ancien
        // conf pour défaire les anciennes règles avant d'appliquer les neuves.
        assert!(wg_quick_index(&tunnel, "down") < wg_quick_index(&tunnel, "up"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn syncconf_falls_back_without_shell() {
        use super::super::wg::runner::CommandOutput;
        let (dir, tunnel) = test_tunnel("wgez-tunnel-fallback");
        tunnel.runner().respond_program(
            BASH,
            CommandOutput {
                code: 127,
                stdout: Vec::new(),
                stderr: b"bash not found".to_vec(),
            },
        );
        tunnel
            .syncconf("wg0", "[Interface]\nListenPort = 51820\n")
            .expect("fallback syncconf");

        let calls = tunnel.runner().calls();
        assert_eq!(calls[0].program, BASH);
        assert_eq!(calls[1].program, "wg");
        assert_eq!(calls[1].args[0], "syncconf");
        assert!(!dir.join("wg0.syncconf.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn iface_names_rejected() {
        assert!(validate_iface("wg0").is_ok());
        assert!(validate_iface("").is_err());
        assert!(validate_iface("0123456789abcdef").is_err());
        assert!(validate_iface("../evil").is_err());
        assert!(validate_iface("wg 0").is_err());
    }

    /// Un fichier régulier neuf est bien créé en `0600`.
    #[cfg(unix)]
    #[test]
    fn write_conf_creates_regular_file_0600() {
        let dir = std::env::temp_dir().join("wgez-conf-0600");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("wg0.conf");

        write_conf_0600(&path, b"PrivateKey = SECRET\n").expect("write regular file");
        assert_eq!(
            std::fs::read(&path).expect("read"),
            b"PrivateKey = SECRET\n"
        );
        assert_conf_mode(&path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Un lien symbolique planté à l'emplacement du `.conf` fait échouer
    /// l'écriture (`O_NOFOLLOW`) et la cible victime reste **inchangée** : on
    /// n'écrit jamais à travers.
    #[cfg(unix)]
    #[test]
    fn write_conf_refuses_symlink_and_preserves_target() {
        use std::os::unix::fs::symlink;

        let dir = std::env::temp_dir().join("wgez-conf-symlink");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let victim = dir.join("victim.conf");
        std::fs::write(&victim, b"ORIGINAL").expect("victim");
        let link = dir.join("wg0.conf");
        symlink(&victim, &link).expect("symlink");

        let err = write_conf_0600(&link, b"PWNED")
            .expect_err("writing through a symlink must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

        // La cible n'a pas été ouverte/écrite.
        assert_eq!(std::fs::read(&victim).expect("read victim"), b"ORIGINAL");
        // Le lien symbolique n'a pas été remplacé par un fichier régulier.
        assert!(
            std::fs::symlink_metadata(&link)
                .expect("lstat")
                .file_type()
                .is_symlink()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
