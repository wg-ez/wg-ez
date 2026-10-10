//! Exécution des plans iptables avec coalescence des rebuilds.
//!
//! Une seule reconstruction est mise en file pendant qu'une autre est en
//! cours (`rebuildInProgress` / `rebuildQueued`).

use std::sync::Mutex;

use crate::wg::runner::Runner;

use super::FirewallError;
use super::plan::{FirewallCmd, FirewallPlan, plan_rebuild};

/// Exécute une séquence ; les commandes `ignore_failure` n'échouent jamais.
pub fn apply_cmds<R: Runner>(runner: &R, cmds: &[FirewallCmd]) -> Result<(), FirewallError> {
    for cmd in cmds {
        match runner.exec(&cmd.program, &cmd.args, None) {
            Ok(_) => {}
            Err(_) if cmd.ignore_failure => {}
            Err(e) => return Err(FirewallError::Runner(e)),
        }
    }
    Ok(())
}

/// État de coalescence des rebuilds (au plus une reconstruction en file).
#[derive(Debug, Default)]
pub struct Coalescer {
    state: Mutex<CoalesceState>,
}

#[derive(Debug, Default)]
struct CoalesceState {
    in_progress: bool,
    queued: bool,
}

impl Coalescer {
    /// Nouveau coalesceur au repos.
    pub fn new() -> Self {
        Self::default()
    }

    /// Vrai si une reconstruction est en cours (introspection tests).
    pub fn is_in_progress(&self) -> bool {
        self.state.lock().map(|s| s.in_progress).unwrap_or(false)
    }
}

/// Rebuild coalescé : si un rebuild est en cours, la demande est mise en
/// file (une seule) et exécutée juste après ; l'appelant ne bloque pas
/// en double.
pub fn rebuild_coalesced<R: Runner>(
    runner: &R,
    guard: &Coalescer,
    plan: &FirewallPlan,
) -> Result<(), FirewallError> {
    {
        let mut state = guard
            .state
            .lock()
            .map_err(|e| FirewallError::Lock(e.to_string()))?;
        if state.in_progress {
            state.queued = true;
            return Ok(());
        }
        state.in_progress = true;
    }

    loop {
        // Pas de `?` ici : `in_progress` doit retomber même en erreur.
        let res = plan_rebuild(plan).and_then(|cmds| apply_cmds(runner, &cmds));
        let mut state = guard
            .state
            .lock()
            .map_err(|e| FirewallError::Lock(e.to_string()))?;
        if state.queued {
            state.queued = false;
            drop(state);
            // Converge vers l'état le plus frais en rejouant une fois.
            let _ = res;
            continue;
        }
        state.in_progress = false;
        break res;
    }
}
