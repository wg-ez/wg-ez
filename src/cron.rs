#![forbid(unsafe_code)]

//! Cron de maintenance toutes les 60 s : auto-desactivation des clients expires
//! (l'appelant lance un `Tunnel::apply` complet si necessaire) + purge des OTL
//! expires + auto-desactivation des jetons d'API expires (ces deux derniers ne
//! touchent jamais WireGuard).
//!
//! Le tick reutilise [`crate::store::client::disable_expired`],
//! [`crate::store::otl::delete_expired`] et
//! [`crate::store::api_token::disable_expired`] (comparaison lexicographique
//! sur la forme TEXT canonique de `db::now_iso8601`). Une erreur de tick est
//! loguee, jamais fatale.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::task::JoinHandle;

/// Periode du cron : 60 s.
pub const CRON_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Error)]
pub enum CronError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("cron error: {0}")]
    Boot(String),
}

/// Resultat d'un tick.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CronOutcome {
    /// Clients desactives par ce tick (chacun declenche un `Tunnel::apply`).
    pub disabled: usize,
    /// Lignes OTL purgees par ce tick (sans effet WireGuard).
    pub purged_otl: usize,
    /// Jetons d'API expires desactives par ce tick (sans effet WireGuard).
    pub disabled_tokens: usize,
}

impl CronOutcome {
    /// Vrai quand `serve` doit lancer exactement un `Tunnel::apply` complet.
    /// Seuls les clients désactivés coupent des tunnels : OTL et jetons d'API
    /// sont DB-only.
    pub fn needs_apply(&self) -> bool {
        self.disabled > 0
    }
}

/// Un tick complet sur une connexion ouverte : desactive les clients expires,
/// purge les OTL expires, desactive les jetons d'API expires. L'appelant
/// decide du `Tunnel::apply` selon le resultat.
pub fn run_once(conn: &rusqlite::Connection) -> Result<CronOutcome, CronError> {
    let now = crate::db::now_iso8601().map_err(|e| CronError::Boot(e.to_string()))?;
    let disabled = crate::store::client::disable_expired(conn, &now)?;
    if disabled > 0 {
        tracing::debug!("cron: disabled {disabled} expired client(s)");
    }
    let purged_otl = crate::store::otl::delete_expired(conn, &now)?;
    if purged_otl > 0 {
        tracing::debug!("cron: purged {purged_otl} expired one-time link(s)");
    }
    let disabled_tokens = crate::store::api_token::disable_expired(conn, &now)?;
    if disabled_tokens > 0 {
        tracing::debug!("cron: disabled {disabled_tokens} expired API token(s)");
    }
    Ok(CronOutcome {
        disabled,
        purged_otl,
        disabled_tokens,
    })
}

/// Lance la boucle de 60 s. Tourne une fois au boot, puis toutes les 60 s.
/// Chaque tick ouvre la DB (`db::open`) et execute le travail SQLite dans
/// `spawn_blocking` (runtime `current_thread`). `on_tick` est appele apres
/// chaque tick reussi pour que `serve` lance un `Tunnel::apply` si
/// [`CronOutcome::needs_apply`]. Retourne le handle de tache a abort a l'arret.
pub fn spawn_cron(
    db_path: PathBuf,
    on_tick: Arc<dyn Fn(CronOutcome) + Send + Sync + 'static>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CRON_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let path = db_path.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                let conn = crate::db::open(&path).map_err(|e| CronError::Boot(e.to_string()))?;
                run_once(&conn)
            })
            .await;
            match outcome {
                Err(join) => tracing::warn!("cron: tick task failed: {join}"),
                Ok(Err(e)) => tracing::warn!("cron: running cron job failed: {e}"),
                Ok(Ok(out)) => (on_tick)(out),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memdb() -> rusqlite::Connection {
        let conn = crate::test_support::memdb();
        conn.execute(
            "INSERT INTO users (username, password, name, role, totpVerified, enabled)
             VALUES ('admin', 'x', 'Administrator', 1, 0, 1)",
            [],
        )
        .expect("admin");
        conn.execute(
            "INSERT INTO clients (userId, interfaceId, name, ipv4Address, ipv6Address,
              privateKey, publicKey, preSharedKey, serverAllowedIpsV4, serverAllowedIpsV6,
              enabled, expiresAt, createdAt, updatedAt) VALUES
             (1, 'wg0', 'perm', '10.8.0.2', 'fdcc::2', 'a', 'b-perm', 'c', '[]', '[]', 1, NULL, 't', 't'),
             (1, 'wg0', 'old', '10.8.0.3', 'fdcc::3', 'a', 'b-old', 'c', '[]', '[]', 1, '2000-01-01T00:00:00Z', 't', 't'),
             (1, 'wg0', 'future', '10.8.0.4', 'fdcc::4', 'a', 'b-future', 'c', '[]', '[]', 1, '2999-01-01T00:00:00Z', 't', 't'),
             (1, 'wg0', 'off', '10.8.0.5', 'fdcc::5', 'a', 'b-off', 'c', '[]', '[]', 0, '2000-01-01T00:00:00Z', 't', 't')",
            [],
        )
        .expect("clients");
        conn.execute(
            "INSERT INTO one_time_links (id, token, expiresAt) VALUES
             (2, 'tok-old', '2000-01-01T00:00:00Z'),
             (3, 'tok-new', '2999-01-01T00:00:00Z')",
            [],
        )
        .expect("otl");
        conn.execute(
            "INSERT INTO api_tokens (userId, name, tokenHash, expiresAt, lastUsedAt, createdAt, enabled) VALUES
             (1, 'old-token', 'hash-old', '2000-01-01T00:00:00Z', NULL, '2024-01-01T00:00:00Z', 1),
             (1, 'new-token', 'hash-new', '2999-01-01T00:00:00Z', NULL, '2024-01-01T00:00:00Z', 1),
             (1, 'perm-token', 'hash-perm', NULL, NULL, '2024-01-01T00:00:00Z', 1)",
            [],
        )
        .expect("api tokens");
        conn
    }

    fn enabled(conn: &rusqlite::Connection, name: &str) -> i64 {
        conn.query_row("SELECT enabled FROM clients WHERE name = ?1", [name], |r| {
            r.get(0)
        })
        .expect("row")
    }

    #[test]
    fn tick_disables_only_expired_enabled_and_purges_otl() {
        let conn = memdb();
        let out = run_once(&conn).expect("tick");
        assert_eq!(
            out,
            CronOutcome {
                disabled: 1,
                purged_otl: 1,
                disabled_tokens: 1,
            }
        );
        assert!(out.needs_apply());
        assert_eq!(enabled(&conn, "perm"), 1, "permanent untouched");
        assert_eq!(enabled(&conn, "old"), 0, "expired disabled");
        assert_eq!(enabled(&conn, "future"), 1, "future untouched");
        assert_eq!(enabled(&conn, "off"), 0, "already off untouched");
        // Jetons d'API : seul l'expiré encore actif est désactivé, sans
        // `Tunnel::apply` supplémentaire (le `needs_apply` vient des clients).
        let token_state = |name: &str| -> i64 {
            conn.query_row(
                "SELECT enabled FROM api_tokens WHERE name = ?1",
                [name],
                |r| r.get(0),
            )
            .expect("row")
        };
        assert_eq!(token_state("old-token"), 0, "expired token disabled");
        assert_eq!(token_state("new-token"), 1, "future token untouched");
        assert_eq!(token_state("perm-token"), 1, "permanent token untouched");
    }

    #[test]
    fn quiet_tick_needs_no_apply() {
        let conn = memdb();
        run_once(&conn).expect("first tick");
        let out = run_once(&conn).expect("second tick");
        assert_eq!(out, CronOutcome::default());
        assert!(!out.needs_apply());
    }
}
