#![forbid(unsafe_code)]

//! `wgez` : logique partagee entre le serveur (`wg-ez serve`) et la CLI
//! de secours (`wg-ez cli ...`).
//!
//! La config est lue et validee une fois au boot puis figee ; toute fonction
//! faillible retourne un `Result` explicite (le profil release utilise
//! `panic = "abort"`, donc aucune panique sur chemin utilisateur).

pub mod auth;
pub mod cli;
pub mod config;
pub mod cron;
pub mod db;
pub mod ip;
pub mod otl;
pub mod setup;
pub mod store;
#[cfg(test)]
pub(crate) mod test_support;
pub mod tunnel;
pub mod validate;
pub mod web;
pub mod wg;

/// Assets statiques pre-gzippes par `build.rs` (fichiers `static/` > 1024 o).
///
/// Le manifeste `$OUT_DIR/static_precompressed.rs` est genere a la compilation
/// avec des `include_bytes!` vers les `.gz`, pour servir le gzip pre-calcule.
pub mod static_assets {
    include!(concat!(env!("OUT_DIR"), "/static_precompressed.rs"));
}

/// Version du binaire (suit la version du paquet).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
