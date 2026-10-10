//! CRUD SQL des reglages globaux (`general`, ligne unique `id = 1`).
//!
//! - `setupStep` 0 = setup termine ; le seed demarre a 1.
//! - `sessionTimeout` 3600 s d'expiration serveur des sessions.
//! - `metricsPrometheus` / `metricsJson` activent les endpoints ;
//!   `metricsPassword` (hash argon2 optionnel) exige un Bearer.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::db::{bool_int, int_bool};

/// Ligne `general` (toujours `id = 1`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct General {
    pub id: i64,
    pub setup_step: i64,
    pub session_timeout: i64,
    pub metrics_prometheus: bool,
    pub metrics_json: bool,
    /// Hash argon2 optionnel ou `None` = pas de Bearer exige.
    pub metrics_password: Option<String>,
}

fn map(row: &rusqlite::Row<'_>) -> Result<General, rusqlite::Error> {
    Ok(General {
        id: row.get("id")?,
        setup_step: row.get("setupStep")?,
        session_timeout: row.get("sessionTimeout")?,
        metrics_prometheus: int_bool(row.get::<_, i64>("metricsPrometheus")?),
        metrics_json: int_bool(row.get::<_, i64>("metricsJson")?),
        metrics_password: row.get("metricsPassword")?,
    })
}

pub fn get(conn: &Connection) -> Result<Option<General>, rusqlite::Error> {
    use rusqlite::OptionalExtension;
    conn.query_row(
        "SELECT id, setupStep, sessionTimeout, metricsPrometheus, metricsJson, metricsPassword \
         FROM general WHERE id = 1",
        [],
        map,
    )
    .optional()
}

/// Vrai quand le setup est termine (`setupStep = 0`).
pub fn is_setup_done(conn: &Connection) -> Result<bool, rusqlite::Error> {
    match get(conn)? {
        Some(g) => Ok(g.setup_step == 0),
        None => Ok(false),
    }
}

/// Met a jour les reglages (hors fin de setup, voir `complete_setup`).
pub fn update(
    conn: &Connection,
    session_timeout: i64,
    metrics_prometheus: bool,
    metrics_json: bool,
    metrics_password: Option<&str>,
) -> Result<bool, rusqlite::Error> {
    let n = conn.execute(
        "UPDATE general SET sessionTimeout = ?1, metricsPrometheus = ?2, metricsJson = ?3, \
         metricsPassword = ?4 WHERE id = 1",
        rusqlite::params![
            session_timeout,
            bool_int(metrics_prometheus),
            bool_int(metrics_json),
            metrics_password,
        ],
    )?;
    Ok(n > 0)
}

/// Termine le setup (`setupStep` -> 0).
pub fn complete_setup(conn: &Connection) -> Result<bool, rusqlite::Error> {
    let n = conn.execute("UPDATE general SET setupStep = 0 WHERE id = 1", [])?;
    Ok(n > 0)
}
