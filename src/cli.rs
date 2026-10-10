#![forbid(unsafe_code)]

//! Offline rescue CLI (`wg-ez cli ...`): direct SQLite access, usable
//! when the web server is broken.
//!
//! - `db:admin:reset` sets a new 12+ char password for admin id 1 and
//!   clears `totpKey`/`totpVerified` (v15 prompts when `--password` is
//!   absent; here one stdin line is read instead).
//! - `clients:list` prints id, name, public key and state.
//! - `clients:qr <id>` prints the client `.conf` as a terminal
//!   QR (half-block renderer, maison). The payload reuses the canonical
//!   [`crate::web::backend::build_client_conf`] — the exact resolution behind
//!   the SVG QR and `/cnf/*` download — so both stay in sync by construction.
//!
//! No `clap`/`citty`: hand-rolled parsing keeps the binary small. Never
//! touches WireGuard: CLI mutations are DB-only by design.

use std::io::IsTerminal;
use std::path::Path;

use qrcode::{EcLevel, QrCode};
use thiserror::Error;

use crate::auth::password::{self, PasswordError};
use crate::validate::{self, ValidationError};
use crate::wg::render::RenderError;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("cannot open database: {0}")]
    DbOpen(String),
    #[error("{0}")]
    Validate(#[from] ValidationError),
    #[error("{0}")]
    Password(#[from] PasswordError),
    #[error("config render error: {0}")]
    Render(String),
    #[error("QR error: {0}")]
    Qr(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("usage: {0}")]
    Usage(String),
}

impl From<RenderError> for CliError {
    fn from(e: RenderError) -> Self {
        Self::Render(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Command model + hand-rolled parsing
// ---------------------------------------------------------------------------

/// Offline subcommands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    /// Reset admin id 1 (password + clear TOTP).
    DbAdminReset {
        username: Option<String>,
        password: Option<String>,
    },
    /// List id, name, public key and state.
    ClientsList,
    /// Terminal QR for a client.
    ClientsQr { id: i64 },
}

pub const USAGE: &str = "usage:
  wg-ez cli db:admin:reset [--username <name>] [--password <password>]
  wg-ez cli clients:list
  wg-ez cli clients:qr <id>";

fn usage_error() -> CliError {
    CliError::Usage(USAGE.to_string())
}

/// Parse the tail args (everything after `cli`).
pub fn parse_cli_args(args: &[String]) -> Result<CliCommand, CliError> {
    let (head, rest) = args.split_first().ok_or_else(usage_error)?;
    match head.as_str() {
        "db:admin:reset" => {
            let mut username = None;
            let mut password = None;
            let mut it = rest.iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--username" => {
                        username = Some(it.next().ok_or_else(usage_error)?.to_string());
                    }
                    "--password" => {
                        password = Some(it.next().ok_or_else(usage_error)?.to_string());
                    }
                    _ => return Err(usage_error()),
                }
            }
            Ok(CliCommand::DbAdminReset { username, password })
        }
        "clients:list" => {
            if rest.is_empty() {
                Ok(CliCommand::ClientsList)
            } else {
                Err(usage_error())
            }
        }
        "clients:qr" => {
            let mut id: Option<i64> = None;
            for a in rest {
                if id.is_none() {
                    id = Some(
                        a.parse::<i64>()
                            .map_err(|_| CliError::Usage(format!("bad client id: {a}")))?,
                    );
                } else {
                    return Err(usage_error());
                }
            }
            Ok(CliCommand::ClientsQr {
                id: id.ok_or_else(usage_error)?,
            })
        }
        _ => Err(usage_error()),
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Execute an offline command, returning printable output (`main` prints
/// it). Opens the DB with migrations + a busy timeout so a running server
/// does not make the rescue CLI fail on a locked database.
pub fn run_offline(db_path: &Path, cmd: &CliCommand) -> Result<String, CliError> {
    let conn = crate::db::open(db_path)
        .map_err(|e| CliError::DbOpen(format!("{}: {e}", db_path.display())))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    match cmd {
        CliCommand::DbAdminReset { username, password } => {
            reset_admin(&conn, username.clone(), password.clone())
        }
        CliCommand::ClientsList => list_clients(&conn),
        CliCommand::ClientsQr { id } => qr_for_client(&conn, *id),
    }
}

/// Read a password from stdin when `--password` was omitted.
fn read_password_stdin() -> Result<String, CliError> {
    use std::io::BufRead;
    if std::io::stdin().is_terminal() {
        eprint!("Please enter a new password: ");
    }
    let mut line = String::new();
    std::io::BufReader::new(std::io::stdin())
        .read_line(&mut line)
        .map_err(|e| CliError::Io(e.to_string()))?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Reset admin id 1: new password (12+ chars) + clear `totpKey` /
/// `totpVerified`. Errors when id 1 is missing (no silent creation).
pub fn reset_admin(
    conn: &rusqlite::Connection,
    username: Option<String>,
    password: Option<String>,
) -> Result<String, CliError> {
    let password = match password {
        Some(p) if !p.is_empty() => p,
        _ => read_password_stdin()?,
    };
    if password.is_empty() {
        return Err(CliError::Usage("password is required".to_string()));
    }
    validate::validate_password(&password)?;
    if let Some(u) = &username {
        validate::validate_username(u.trim())?;
    }
    let hash = password::hash_password_blocking(&password)?;
    let current = crate::store::user::get(conn, 1)?
        .ok_or_else(|| CliError::NotFound("admin user (id 1) not found".to_string()))?;
    if let Some(u) = username {
        let u = u.trim().to_string();
        conn.execute(
            "UPDATE users SET username = ?1, password = ?2 WHERE id = 1",
            rusqlite::params![u, hash],
        )?;
        crate::store::user::set_totp(conn, 1, None, false)?;
        Ok(format!("Successfully updated admin user 1 ({u})\n"))
    } else {
        crate::store::user::set_password_hash(conn, 1, Some(hash.as_str()))?;
        crate::store::user::set_totp(conn, 1, None, false)?;
        Ok(format!(
            "Successfully updated admin user 1 ({})\n",
            current.username
        ))
    }
}

/// `id, name, public key, state` table over every interface (v15
/// `clients:list` columns).
pub fn list_clients(conn: &rusqlite::Connection) -> Result<String, CliError> {
    let mut rows = Vec::new();
    for iface in crate::store::interface::list(conn)? {
        rows.extend(crate::store::client::list(conn, &iface.name)?);
    }
    rows.sort_by_key(|c| c.id);
    if rows.is_empty() {
        return Ok("No clients found\n".to_string());
    }
    let mut out = format!(
        "{:<5} {:<32} {:<48} {}\n",
        "ID", "NAME", "PUBLIC_KEY", "ENABLED"
    );
    for c in rows {
        out.push_str(&format!(
            "{:<5} {:<32} {:<48} {}\n",
            c.id,
            c.name,
            c.public_key,
            if c.enabled { "yes" } else { "no" }
        ));
    }
    Ok(out)
}

/// Build the terminal QR for a client via the canonical client `.conf`
/// resolver. `IP_MODE` (detection IPv4+IPv6 en `auto`) decide, comme le serveur.
/// The returned payload is byte-identical to the SVG QR and `/cnf/*` download.
pub fn qr_for_client(conn: &rusqlite::Connection, id: i64) -> Result<String, CliError> {
    if id < 0 {
        return Err(CliError::Usage(format!("bad client id: {id}")));
    }
    let client = crate::store::client::get(conn, id)?
        .ok_or_else(|| CliError::NotFound(format!("client with ID {id} not found")))?;
    // Meme resolution que le serveur : `IP_MODE` puis detection en auto.
    let mut env = std::collections::HashMap::new();
    if let Ok(v) = std::env::var("IP_MODE") {
        env.insert("IP_MODE".to_string(), v);
    }
    let (disable_v4, disable_v6) = crate::config::resolve_ip_mode(
        &env,
        crate::config::detect_ipv4_available(),
        crate::config::detect_ipv6_available(),
    )
    .unwrap_or((false, false));
    // Reuse the canonical server-side resolution instead of re-implementing
    // it: the QR cannot drift from the server output.
    let (_file_name, text) =
        crate::web::backend::build_client_conf(conn, &client, disable_v4, disable_v6)
            .map_err(|e| CliError::Render(e.to_string()))?;
    qr_to_terminal(&text)
}

// ---------------------------------------------------------------------------
// Terminal QR (maison half-block renderer; same payload as the SVG QR)
// ---------------------------------------------------------------------------

/// Encode as QR, retrying ECC levels high -> low on capacity overflow
/// (mirrors v15 `tryECCModes`).
pub fn qr_encode_with_fallback(text: &str) -> Result<QrCode, CliError> {
    for level in [EcLevel::H, EcLevel::Q, EcLevel::M, EcLevel::L] {
        match QrCode::with_error_correction_level(text, level) {
            Ok(code) => return Ok(code),
            Err(qrcode::types::QrError::DataTooLong) => continue,
            Err(e) => return Err(CliError::Qr(e.to_string())),
        }
    }
    Err(CliError::Qr(
        "failed to generate QR code: capacity overflow at all ECC levels".to_string(),
    ))
}

/// Render QR modules as terminal half-blocks (`█▀▄` + space), two module
/// rows per text row, one-module quiet zone. Pure function over the grid.
pub fn qr_grid_to_terminal(code: &QrCode) -> String {
    let w = code.width() as i32;
    let dark = |x: i32, y: i32| -> bool {
        if x < 0 || y < 0 || x >= w || y >= w {
            return false;
        }
        code[(x as usize, y as usize)] == qrcode::Color::Dark
    };
    // Total span incl. quiet zone: x in [-1, w], y in [-2, w + 1].
    // Two quiet module rows top/bottom = one full blank text row each side,
    // matching the one-module side columns (half-blocks are two rows tall).
    let mut out = String::new();
    let mut y = -2;
    while y <= w + 1 {
        for x in -1..=w {
            let top = dark(x, y);
            let bottom = dark(x, y + 1);
            out.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push('\n');
        y += 2;
    }
    out
}

/// Encode `text` as QR and render it for the terminal.
pub fn qr_to_terminal(text: &str) -> Result<String, CliError> {
    Ok(qr_grid_to_terminal(&qr_encode_with_fallback(text)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args() {
        assert_eq!(
            parse_cli_args(&["clients:list".to_string()]).expect("list"),
            CliCommand::ClientsList
        );
        assert_eq!(
            parse_cli_args(&["clients:qr".to_string(), "7".to_string()]).expect("qr"),
            CliCommand::ClientsQr { id: 7 }
        );
        assert!(parse_cli_args(&[]).is_err());
        assert!(parse_cli_args(&["nope".to_string()]).is_err());
        assert!(parse_cli_args(&["clients:qr".to_string()]).is_err());
        assert_eq!(
            parse_cli_args(&[
                "db:admin:reset".to_string(),
                "--password".to_string(),
                "long-enough-12".to_string(),
            ])
            .expect("reset"),
            CliCommand::DbAdminReset {
                username: None,
                password: Some("long-enough-12".to_string())
            }
        );
    }

    #[test]
    fn qr_terminal_uses_half_blocks() {
        let code = qr_encode_with_fallback("hello wg-ez").expect("qr");
        let term = qr_grid_to_terminal(&code);
        assert!(term.chars().any(|c| matches!(c, '█' | '▀' | '▄')));
        assert!(term.ends_with('\n'));
        let first = term.lines().next().expect("row");
        assert!(first.chars().all(|c| c == ' '), "quiet zone on top");
        let big = "x".repeat(2000);
        assert!(qr_encode_with_fallback(&big).is_ok(), "ECC fallback");
    }

    fn cli_memdb() -> rusqlite::Connection {
        let conn = crate::test_support::memdb();
        // The seed leaves server keys empty until boot generates them; the
        // offline QR path needs a real server public key.
        conn.execute(
            "UPDATE interfaces SET privateKey = 'srvpriv', publicKey = 'srvpub' WHERE name = 'wg0'",
            [],
        )
        .expect("keys");
        crate::store::user::create(&conn, "admin", Some("old-hash"), "Administrator")
            .expect("admin");
        let now = "2026-01-01T00:00:00Z";
        let input = crate::store::client::NewClient {
            ipv4_address: Some("10.8.0.2".to_string()),
            ipv6_address: Some("fdcc::2".to_string()),
            mtu: Some(1420),
            persistent_keepalive: Some(25),
            ..crate::store::client::NewClient::base(
                1,
                "wg0".to_string(),
                "phone".to_string(),
                "cpriv".to_string(),
                "cpub".to_string(),
                "psk".to_string(),
            )
        };
        crate::store::client::create(&conn, &input, now).expect("client");
        conn.execute(
            "UPDATE user_configs SET host = 'vpn.example.com' WHERE id = 'wg0'",
            [],
        )
        .expect("host");
        conn
    }

    #[test]
    fn reset_clears_totp_and_sets_hash() {
        let conn = cli_memdb();
        let out =
            reset_admin(&conn, None, Some("a-brand-new-password".to_string())).expect("reset");
        assert!(out.contains("Successfully updated admin user 1 (admin)"));
        let user = crate::store::user::get(&conn, 1)
            .expect("get")
            .expect("row");
        let hash = user.password.expect("hash");
        assert!(hash.starts_with("$argon2id$"));
        assert!(user.totp_key.is_none());
        assert!(!user.totp_verified);
        assert!(reset_admin(&conn, None, Some("short".to_string())).is_err());
    }

    #[test]
    fn list_and_qr_offline() {
        let conn = cli_memdb();
        let list = list_clients(&conn).expect("list");
        assert!(list.contains("phone") && list.contains("cpub"));
        let qr = qr_for_client(&conn, 1).expect("qr");
        assert!(qr.chars().any(|c| c == '█'));
        assert!(qr_for_client(&conn, 999).is_err());
    }
}
