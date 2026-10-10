//! Sondes de disponibilité iptables et contrôle au boot.
//!
//! Probe `iptables --version` (+ `ip6tables --version` si IPv6 actif).
//! La sortie du probe n'est jamais exposée (versions cachées).
//! Toute erreur d'exécution vaut indisponible. Résultat mis en cache
//! mémoire ([`super::clear_probe_cache`] force un nouveau probe).

use std::sync::{Mutex, OnceLock};

use crate::wg::runner::Runner;

use super::FirewallError;

/// Disponibilité iptables, résultat mis en cache mémoire.
pub fn probe_available<R: Runner>(runner: &R, want_ipv6: bool) -> bool {
    if let Some(cached) = probe_cache_get() {
        return cached;
    }
    let available = probe_once(runner, want_ipv6);
    probe_cache_set(available);
    available
}

fn probe_once<R: Runner>(runner: &R, want_ipv6: bool) -> bool {
    let v4 = runner
        .exec("iptables", &["--version".to_string()], None)
        .map(|o| o.is_success())
        .unwrap_or(false);
    if !v4 {
        return false;
    }
    if want_ipv6 {
        return runner
            .exec("ip6tables", &["--version".to_string()], None)
            .map(|o| o.is_success())
            .unwrap_or(false);
    }
    true
}

static PROBE_CACHE: OnceLock<Mutex<Option<bool>>> = OnceLock::new();

fn probe_cache_get() -> Option<bool> {
    PROBE_CACHE
        .get()
        .and_then(|m| m.lock().map(|v| *v).unwrap_or(None))
}

fn probe_cache_set(value: bool) {
    let cell = PROBE_CACHE.get_or_init(|| Mutex::new(None));
    if let Ok(mut v) = cell.lock() {
        *v = Some(value);
    }
}

/// Force un nouveau probe au prochain appel (tests).
pub fn clear_probe_cache() {
    if let Some(cell) = PROBE_CACHE.get()
        && let Ok(mut v) = cell.lock()
    {
        *v = None;
    }
}

/// Résultat du contrôle firewall au boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootFirewall {
    /// Firewall utilisable (ou déjà désactivé en config).
    Ok,
    /// Firewall actif en config mais iptables absent : l'appelant doit
    /// désactiver le flag en DB et logger un warning explicite.
    DisabledNoIptables,
}

/// Contrôle boot : si le firewall est actif mais qu'iptables manque,
/// signale `DisabledNoIptables` pour désactivation en DB + warn.
pub fn check_at_boot<R: Runner>(
    runner: &R,
    firewall_enabled: bool,
    disable_ipv6: bool,
) -> BootFirewall {
    if !firewall_enabled {
        return BootFirewall::Ok;
    }
    if probe_available(runner, !disable_ipv6) {
        BootFirewall::Ok
    } else {
        BootFirewall::DisabledNoIptables
    }
}

/// Une activation admin doit reprober iptables avant d'accepter.
pub fn probe_for_enable<R: Runner>(runner: &R, disable_ipv6: bool) -> Result<(), FirewallError> {
    clear_probe_cache();
    if probe_available(runner, !disable_ipv6) {
        Ok(())
    } else {
        Err(FirewallError::InvalidEntry(
            "iptables is not available, cannot enable firewall".to_string(),
        ))
    }
}
