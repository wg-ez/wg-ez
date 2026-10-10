#![forbid(unsafe_code)]

//! Initial setup: admin creation, non-interactive `INIT_*` boot setup, and
//! setup-gating helpers for the web layer.
//!
//! Setup is valid only while `setupStep != 0`: step 1 allows `2`, step 3
//! allows `3`. `INIT_PASSWORD` must be 12+ chars.
//!
//! This module owns the setup *flow*; persistence goes through the sibling
//! stores (`store::{user,general,interface,userconfig,client}`), validation
//! through [`crate::validate`], hashing through [`crate::auth::password`].
//! The `Backend` implementation (serve) calls these helpers inside
//! `spawn_blocking`.

pub mod admin;
pub mod bootstrap;
pub mod gating;
pub mod host;
pub mod init;

pub use admin::{complete_step2, create_admin, set_setup_step};
pub use bootstrap::ensure_interface_rows;
pub use gating::{RequestedSetupStep, check_setup_step, setup_page_redirect};
pub use host::save_host_port;
pub use init::{
    InitEnv, InitialSetupOutcome, ValidatedInit, apply_initial_setup, init_env_from_process,
    validate_init_env,
};

use thiserror::Error;

use crate::auth::password::PasswordError;
use crate::validate::ValidationError;

#[derive(Debug, Error)]
pub enum SetupError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("{0}")]
    Validate(#[from] ValidationError),
    #[error("{0}")]
    Password(#[from] PasswordError),
    #[error("setup state error: {0}")]
    State(String),
    #[error("invalid value: {0}")]
    Validation(String),
    #[error("environment error: {0}")]
    Env(String),
}

/// Valide et normalise un host public (1-253, plain-string) + un port (1-65535).
///
/// Comportement partagé entre le setup non-interactif (`INIT_*`,
/// [`init::validate_init_env`]) et l'étape 3 du setup ([`host::save_host_port`]) :
/// trim → plain-string → longueur → port. Mêmes validations et mêmes messages
/// dans les deux chemins.
pub(crate) fn validate_host_port(host: &str, port: i64) -> Result<(String, i64), SetupError> {
    let trimmed = host.trim().to_string();
    crate::validate::validate_host(&trimmed).map_err(SetupError::Validate)?;
    let port_u32: u32 = port
        .try_into()
        .map_err(|_| SetupError::Validation("port must be 1-65535".to_string()))?;
    crate::validate::validate_port(port_u32).map_err(SetupError::Validate)?;
    Ok((trimmed, port))
}

/// Setup is finished when `setup_step == 0`.
pub const SETUP_DONE: i64 = 0;
/// Display name given to setup-created admins.
pub const ADMIN_DISPLAY_NAME: &str = "Administrator";
