//! Cœur WireGuard : exécution système, rendu de config, statut et firewall.
//!
//! Seul [`crate::tunnel`] est autorisé à invoquer ces primitives vers le noyau.

pub mod firewall;
pub mod render;
pub mod runner;
pub mod status;
