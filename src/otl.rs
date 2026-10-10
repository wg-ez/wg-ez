#![forbid(unsafe_code)]

//! One-time-link logic (token generation, expiry math, download flow).
//!
//! Thin logic layer over the [`crate::store::otl`] persistence CRUD (single
//! row per client via `INSERT ... ON CONFLICT DO UPDATE`, table
//! `one_time_links`).
//!
//! Semantics (upstream v15 `OneTimeLinkService`, CRC32 replaced):
//! - token: 128 bits aléatoires, base64url sans padding (22 chars). Jamais
//!   de CRC32 (at most 1000 outputs on `rand 0-999` upstream).
//! - at-rest: seul le SHA-256 hex du token est stocké (`one_time_links.token`,
//!   colonne `TEXT UNIQUE`) ; comme pour les sessions, le token clair n'est
//!   jamais persisté. La possession du token clair reste le secret.
//! - lifetime: 5 min after generation; renewal rotates the token (v15 kept
//!   the old token and only extended the expiry — rotating is strictly
//!   safer and still "crée ou renouvelle").
//! - download (`GET /cnf/:token`): unknown -> 404 + seclog
//!   `type=one-time-link` (handlers layer); expired -> 410; valid ->
//!   expiry shortened to at most now + 10 s (anti-double-requête, mirrors
//!   v15 `erase()`) **only while the row is still at its initial 5 min TTL**.
//!   Once the grace window has been applied, later polling must not push it
//!   again, otherwise a link could be kept alive forever (I3). The 60 s cron
//!   then purges the row (no `Tunnel::apply`).
//! - `POST /api/client/:id/generateOneTimeLink` is the only mutation
//!   without `Tunnel::apply`.
//!
//! The download path compares expiry instants by parsing the stored TEXT.
//! The cron purge keeps using a lexicographic `expiresAt <= now` in SQL:
//! every row is written by [`crate::db::now_iso8601`] with the same canonical
//! UTC whole-second `...Z` RFC 3339 shape, so lexicographic order matches
//! time order for those rows.

use rusqlite::Connection;
use thiserror::Error;

/// Lifetime of a fresh link: 5 minutes.
pub const OTL_TTL_SECS: i64 = 5 * 60;
/// Anti-double-request grace applied on download: +10 s.
pub const OTL_GRACE_SECS: i64 = 10;
/// 128-bit tokens.
pub const TOKEN_BYTES: usize = 16;

#[derive(Debug, Error)]
pub enum OtlError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("time error: {0}")]
    Time(String),
}

/// Download-flow outcome for `GET /cnf/:token` (handlers map to HTTP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumeError {
    /// Unknown token -> 404 + `Security failure type=one-time-link`.
    Unknown,
    /// Past expiry -> 410 Gone.
    Expired,
}

impl std::fmt::Display for ConsumeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown one-time link"),
            Self::Expired => write!(f, "one-time link expired"),
        }
    }
}

impl std::error::Error for ConsumeError {}

/// Freshly generated (or renewed) link.
#[derive(Clone)]
pub struct GeneratedLink {
    pub client_id: i64,
    pub token: String,
    pub expires_at: String,
}

/// Debug manuel : `token` est le secret porteur du lien, jamais expose, meme si
/// un `{:?}` (log, panic, message d'erreur) atteint cette struct. Les autres
/// champs restent lisibles pour le diagnostic.
impl std::fmt::Debug for GeneratedLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedLink")
            .field("client_id", &self.client_id)
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// 128-bit random token, base64url without padding (22 chars). No CRC32.
///
/// Also reused for the opaque in-memory pending-2FA id (`web::handlers::auth`),
/// which is an identifier only, never the secret.
pub fn generate_token() -> String {
    let bytes: [u8; TOKEN_BYTES] = rand::random();
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

/// `now + secs` formatted like [`crate::db::now_iso8601`].
pub fn expiry_after_secs(secs: i64) -> Result<String, OtlError> {
    let at = time::OffsetDateTime::now_utc()
        .checked_add(time::Duration::seconds(secs))
        .ok_or_else(|| OtlError::Time("time overflow".to_string()))?;
    crate::db::format_iso8601(at).map_err(|e| OtlError::Time(e.to_string()))
}

/// Parse an RFC 3339 UTC timestamp as written by [`crate::db::format_iso8601`].
fn parse_iso8601(s: &str) -> Result<time::OffsetDateTime, OtlError> {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::parse(s, &Rfc3339).map_err(|e| OtlError::Time(e.to_string()))
}

/// `base + secs`, formatted like [`crate::db::format_iso8601`]. Used by tests
/// to derive explicit, increasing `now` values from a generated link.
#[cfg(test)]
fn add_secs_iso8601(base: &str, secs: i64) -> Result<String, OtlError> {
    let at = parse_iso8601(base)?
        .checked_add(time::Duration::seconds(secs))
        .ok_or_else(|| OtlError::Time("time overflow".to_string()))?;
    crate::db::format_iso8601(at).map_err(|e| OtlError::Time(e.to_string()))
}

/// Create or renew the link of a client (single row, token rotated, expiry
/// now + 5 min). Retries once on the ~2^-128 token collision.
pub fn generate_for_client(conn: &Connection, client_id: i64) -> Result<GeneratedLink, OtlError> {
    for _ in 0..2 {
        let token = generate_token();
        let expires_at = expiry_after_secs(OTL_TTL_SECS)?;
        match crate::store::otl::upsert(conn, client_id, &token, &expires_at) {
            Ok(()) => {
                return Ok(GeneratedLink {
                    client_id,
                    token,
                    expires_at,
                });
            }
            Err(e) if crate::db::is_unique_violation(&e) => continue,
            Err(e) => return Err(OtlError::Db(e)),
        }
    }
    Err(OtlError::Time(
        "token uniqueness retry exhausted".to_string(),
    ))
}

/// Download step for `GET /cnf/:token` against `now` (`db::now_iso8601`
/// shape). Returns the owning client id.
///
/// On the first download (while the row still holds its initial 5 min TTL)
/// the expiry is shortened to `now + 10 s` so a near-simultaneous second
/// browser request still succeeds. Once the row is already within that grace
/// window (`expires_at <= now + grace`) it is served **without** touching the
/// expiry: re-touching on every request would let polling keep the link alive
/// indefinitely (I3). Total lifetime is therefore bounded by the initial TTL,
/// and the grace never extends it.
pub fn consume_for_download(
    conn: &Connection,
    token: &str,
    now: &str,
) -> Result<i64, ConsumeError> {
    let row = crate::store::otl::get_by_token(conn, token)
        .map_err(|_| ConsumeError::Unknown)?
        .ok_or(ConsumeError::Unknown)?;
    let now_at = parse_iso8601(now).map_err(|_| ConsumeError::Expired)?;
    let expires_at = parse_iso8601(&row.expires_at).map_err(|_| ConsumeError::Expired)?;
    if expires_at <= now_at {
        return Err(ConsumeError::Expired);
    }
    let grace_at = now_at
        .checked_add(time::Duration::seconds(OTL_GRACE_SECS))
        .ok_or(ConsumeError::Expired)?;
    // Only shorten while the row is still strictly beyond the grace deadline
    // (i.e. it is still at the initial TTL). A row already at/below the grace
    // has been touched once; extending it again is the infinite-renewal bug.
    if expires_at > grace_at {
        let grace = crate::db::format_iso8601(grace_at).map_err(|_| ConsumeError::Expired)?;
        crate::store::otl::touch(conn, row.client_id, &grace).map_err(|_| ConsumeError::Expired)?;
    }
    Ok(row.client_id)
}

/// Purge expired links (60 s cron, never touches WireGuard).
pub fn purge_expired(conn: &Connection, now: &str) -> Result<usize, OtlError> {
    Ok(crate::store::otl::delete_expired(conn, now)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memdb() -> Connection {
        let conn = Connection::open_in_memory().expect("memdb");
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE clients (id INTEGER PRIMARY KEY);
             CREATE TABLE one_time_links (
                id INTEGER PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
                token TEXT NOT NULL UNIQUE,
                expiresAt TEXT NOT NULL);
             INSERT INTO clients (id) VALUES (1), (2);",
        )
        .expect("ddl");
        conn
    }

    /// Overwrite the stored expiry of `client_id` (test fixture).
    fn set_expiry(conn: &Connection, client_id: i64, iso: &str) {
        conn.execute(
            "UPDATE one_time_links SET expiresAt = ?1 WHERE id = ?2",
            rusqlite::params![iso, client_id],
        )
        .expect("set expiry");
    }

    fn stored_expiry(conn: &Connection, client_id: i64) -> String {
        conn.query_row(
            "SELECT expiresAt FROM one_time_links WHERE id = ?1",
            [client_id],
            |r| r.get(0),
        )
        .expect("stored expiry")
    }

    /// Generation instant of `link` (= expiry - TTL), so tests can drive
    /// `consume_for_download` with explicit, increasing `now` values.
    fn generated_at(link: &GeneratedLink) -> String {
        add_secs_iso8601(&link.expires_at, -OTL_TTL_SECS).expect("generation instant")
    }

    /// `base + secs` in the same RFC 3339 shape.
    fn at(base: &str, secs: i64) -> String {
        add_secs_iso8601(base, secs).expect("shifted instant")
    }

    #[test]
    fn token_is_128bit_base64url() {
        for _ in 0..50 {
            let t = generate_token();
            assert_eq!(t.len(), 22, "16 bytes -> 22 chars, no padding");
            assert!(
                t.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "urlsafe alphabet: {t}"
            );
        }
        assert_ne!(generate_token(), generate_token());
    }

    /// Finding FAIBLE OTL : le token clair n'est jamais persiste, seul son
    /// SHA-256 hex l'est (meme hygiene que les sessions). La recherche par
    /// token clair reste fonctionnelle (hachage interne au store).
    #[test]
    fn token_is_hashed_at_rest() {
        let conn = memdb();
        let link = generate_for_client(&conn, 1).expect("gen");
        let stored: String = conn
            .query_row("SELECT token FROM one_time_links WHERE id = 1", [], |r| {
                r.get(0)
            })
            .expect("stored token");
        assert_eq!(
            stored,
            crate::store::otl::hash_token(&link.token),
            "la DB stocke le SHA-256 hex"
        );
        assert_ne!(stored, link.token, "le token clair n'est jamais stocke");
        assert_eq!(stored.len(), 64, "SHA-256 hex = 64 caracteres");
        // La recherche par token clair hache en interne et retrouve la ligne.
        let now = crate::db::now_iso8601().expect("now");
        assert_eq!(
            consume_for_download(&conn, &link.token, &now).expect("valid"),
            1
        );
    }

    #[test]
    fn generate_renews_single_row_with_5min_ttl() {
        let conn = memdb();
        let now = crate::db::now_iso8601().expect("now");
        let first = generate_for_client(&conn, 1).expect("gen");
        assert!(first.expires_at.as_str() > now.as_str());
        let second = generate_for_client(&conn, 1).expect("regen");
        assert_ne!(first.token, second.token, "renewal rotates the token");
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM one_time_links WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(n, 1, "a single link per client");
    }

    #[test]
    fn download_flow_unknown_expired_valid() {
        let conn = memdb();
        let now = at("2024-01-01T00:00:00Z", 0);
        assert_eq!(
            consume_for_download(&conn, "nope", &now).expect_err("unknown"),
            ConsumeError::Unknown
        );
        let link = generate_for_client(&conn, 1).expect("gen");
        // Force expiry in the past.
        set_expiry(&conn, 1, "2000-01-01T00:00:00Z");
        assert_eq!(
            consume_for_download(&conn, &link.token, &now).expect_err("expired"),
            ConsumeError::Expired
        );
        // Fresh link: valid, expiry shortened to ~+10 s (below the 5-min TTL).
        let link = generate_for_client(&conn, 2).expect("gen2");
        let base = generated_at(&link);
        let before = link.expires_at.clone();
        let now = at(&base, 1);
        let id = consume_for_download(&conn, &link.token, &now).expect("valid");
        assert_eq!(id, 2);
        let after = stored_expiry(&conn, 2);
        assert!(after.as_str() < before.as_str(), "grace shortens the TTL");
        assert!(after.as_str() > now.as_str(), "grace is in the future");
        // Near-simultaneous second request still valid.
        assert_eq!(
            consume_for_download(&conn, &link.token, &now).expect("double"),
            2
        );
    }

    /// A single download shortens the expiry, and a second one issued at the
    /// exact same instant still succeeds (anti-double-request) without moving
    /// the expiry again.
    #[test]
    fn double_download_at_same_instant_succeeds() {
        let conn = memdb();
        let link = generate_for_client(&conn, 1).expect("gen");
        let base = generated_at(&link);
        let now = at(&base, 1);
        assert_eq!(
            consume_for_download(&conn, &link.token, &now).expect("first"),
            1
        );
        let after_first = stored_expiry(&conn, 1);
        assert_eq!(after_first, at(&now, OTL_GRACE_SECS));
        assert_eq!(
            consume_for_download(&conn, &link.token, &now).expect("second"),
            1
        );
        assert_eq!(
            stored_expiry(&conn, 1),
            after_first,
            "the second request must not push the expiry again"
        );
    }

    /// Regression I3: repeatedly polling less than the grace before each
    /// expiry must not keep the link alive. At most one extension is applied;
    /// after `generation + TTL + grace` the link is definitively `Expired`.
    #[test]
    fn polling_cannot_keep_link_alive_beyond_ttl_plus_grace() {
        let conn = memdb();
        let link = generate_for_client(&conn, 1).expect("gen");
        let base = generated_at(&link);
        let hard_deadline = at(&base, OTL_TTL_SECS + OTL_GRACE_SECS);
        // Attack pattern: one request every 5 s starting 1 s after generation.
        let mut now = at(&base, 1);
        let mut served = 0u32;
        while now.as_str() <= hard_deadline.as_str() {
            match consume_for_download(&conn, &link.token, &now) {
                Ok(1) => served += 1,
                Ok(other) => panic!("unexpected client id {other}"),
                Err(ConsumeError::Expired) => break,
                Err(ConsumeError::Unknown) => panic!("token vanished while valid"),
            }
            assert!(
                stored_expiry(&conn, 1).as_str() <= hard_deadline.as_str(),
                "expiry must stay within TTL + grace"
            );
            now = at(&now, 5);
        }
        assert!(served >= 1, "the link is served while genuinely valid");
        assert_eq!(
            consume_for_download(&conn, &link.token, &hard_deadline).expect_err("expired"),
            ConsumeError::Expired,
            "polling cannot extend the link to (or past) TTL + grace"
        );
    }

    /// Adversarial variant: the attacker always polls 1 s before the currently
    /// stored expiry, then 1 s later (wall clock only moves forward). The
    /// stored expiry must never move after the first download, so the link
    /// dies at that first shortened deadline.
    #[test]
    fn polling_just_before_each_expiry_does_not_extend() {
        let conn = memdb();
        let link = generate_for_client(&conn, 1).expect("gen");
        let base = generated_at(&link);
        let hard_deadline = at(&base, OTL_TTL_SECS + OTL_GRACE_SECS);
        // First download right away: expiry -> base+1+10 = base+11.
        let first = at(&base, 1);
        assert_eq!(
            consume_for_download(&conn, &link.token, &first).expect("first"),
            1
        );
        let frozen = stored_expiry(&conn, 1);
        // First attack tick lands 1 s before the stored (shortened) expiry.
        let mut poll_at = at(&frozen, -1);
        for _ in 0..64 {
            if poll_at.as_str() > hard_deadline.as_str() {
                break;
            }
            match consume_for_download(&conn, &link.token, &poll_at) {
                Ok(1) => {}
                Ok(other) => panic!("unexpected client id {other}"),
                Err(ConsumeError::Expired) => break,
                Err(ConsumeError::Unknown) => panic!("token vanished while valid"),
            }
            assert_eq!(
                stored_expiry(&conn, 1),
                frozen,
                "a grace-window download must not push the expiry"
            );
            // Next wall-clock tick.
            poll_at = at(&poll_at, 1);
        }
        assert_eq!(
            consume_for_download(&conn, &link.token, &hard_deadline).expect_err("expired"),
            ConsumeError::Expired
        );
    }

    /// Edge case: a download at `TTL - 1 s` (≈4 min 59 s after generation) is
    /// still served (200) but not extended, and the link dies at the initial
    /// expiry.
    #[test]
    fn late_download_is_served_without_extending() {
        let conn = memdb();
        let link = generate_for_client(&conn, 1).expect("gen");
        let base = generated_at(&link);
        let late = at(&base, OTL_TTL_SECS - 1);
        // Less than the grace remains, so the row is left untouched.
        assert_eq!(
            consume_for_download(&conn, &link.token, &late).expect("served"),
            1
        );
        assert_eq!(stored_expiry(&conn, 1), link.expires_at);
        // A near-simultaneous second request is still valid...
        assert_eq!(
            consume_for_download(&conn, &link.token, &late).expect("double"),
            1
        );
        // ...but at the initial expiry the link is gone.
        let expiry_instant = at(&base, OTL_TTL_SECS);
        assert_eq!(
            consume_for_download(&conn, &link.token, &expiry_instant).expect_err("expired"),
            ConsumeError::Expired
        );
    }

    #[test]
    fn purge_keeps_valid_links() {
        let conn = memdb();
        let now = crate::db::now_iso8601().expect("now");
        generate_for_client(&conn, 1).expect("gen1");
        generate_for_client(&conn, 2).expect("gen2");
        conn.execute(
            "UPDATE one_time_links SET expiresAt = '2000-01-01T00:00:00Z' WHERE id = 2",
            [],
        )
        .expect("expire");
        assert_eq!(purge_expired(&conn, &now).expect("purge"), 1);
        assert!(
            crate::store::otl::get_for_client(&conn, 1)
                .expect("get")
                .is_some()
        );
        assert!(
            crate::store::otl::get_for_client(&conn, 2)
                .expect("get")
                .is_none()
        );
    }

    /// Le Debug ne doit jamais divulguer le token porteur du lien (hygiene
    /// log/panic/message d'erreur), tout en gardant les autres champs lisibles.
    #[test]
    fn generated_link_debug_redacts_token() {
        let link = GeneratedLink {
            client_id: 7,
            token: "SECRET-TOKEN-value".to_string(),
            expires_at: "2024-01-01T00:05:00Z".to_string(),
        };
        let debug = format!("{link:?}");
        assert!(
            debug.contains("<redacted>"),
            "token field is redacted: {debug}"
        );
        assert!(
            !debug.contains("SECRET-TOKEN-value"),
            "token must never leak through Debug: {debug}"
        );
        assert!(debug.contains("client_id"));
        assert!(debug.contains("2024-01-01T00:05:00Z"));
    }
}
