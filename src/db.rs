//! Acces SQLite via `rusqlite` + requetes preparees parametrees, sans ORM.
//!
//! - Fichier DB en production : `/etc/wireguard/wg-ez.db` (`DB_PATH`).
//! - Mode WAL actif (lectures non bloquees) + `foreign_keys = ON`.
//! - Dates en TEXT ISO-8601, booleens en INTEGER 0/1.
//! - Migrations versionnees dans `src/migrations/*.sql`, appliquees dans
//!   l'ordre au boot.

use std::path::{Path, PathBuf};

use thiserror::Error;

/// Erreur DB : toute fonction faillible retourne un `Result` explicite.
#[derive(Debug, Error)]
pub enum DbError {
    /// Erreur SQLite sous-jacente.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Echec d'une migration versionnee.
    #[error("migration {0} failed: {1}")]
    Migration(&'static str, String),
    /// Echec de formatage temporel.
    #[error("time: {0}")]
    Time(String),
    /// Echec de durcissement des permissions (pre-creation en `0600`).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Migrations appliquees dans l'ordre au boot.
const MIGRATIONS: &[(&str, &str)] = &[
    ("001_schema", include_str!("migrations/001_schema.sql")),
    ("002_seed", include_str!("migrations/002_seed.sql")),
    (
        "003_ipv6_hooks",
        include_str!("migrations/003_ipv6_hooks.sql"),
    ),
    (
        "004_totp_last_counter",
        include_str!("migrations/004_totp_last_counter.sql"),
    ),
    (
        "005_api_tokens",
        include_str!("migrations/005_api_tokens.sql"),
    ),
];

/// Chemin DB par defaut (`DB_PATH`, sinon `/etc/wireguard/wg-ez.db`).
pub fn default_path() -> PathBuf {
    match std::env::var("DB_PATH") {
        Ok(v) if !v.trim().is_empty() => PathBuf::from(v.trim().to_string()),
        _ => PathBuf::from("/etc/wireguard/wg-ez.db"),
    }
}

/// Ouvre la DB, active WAL + cles etrangeres, applique les migrations.
pub fn open(path: &Path) -> Result<rusqlite::Connection, DbError> {
    // Pre-creation `0600` AVANT `Connection::open` : SQLite derive les
    // permissions des fichiers `-wal`/`-shm` de celles de la DB. En creant la
    // DB en `0600` des le depart, WAL et SHM naissent en `0600` : plus de
    // fenetre ou la DB (cles privees, hash Argon2, secrets TOTP) apparait en
    // `0644` selon l'umask.
    precreate_0600(path)?;
    let conn = rusqlite::Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
    run_migrations(&conn)?;
    // Second passage best-effort apres la creation de WAL/SHM.
    harden_perms(path);
    Ok(conn)
}

/// Pre-cree (ou durcit) le fichier DB en `0600` sans jamais le tronquer.
///
/// `mode(0o600)` ne s'applique qu'a la creation ; `set_permissions` couvre un
/// fichier deja present avec des permissions plus larges. L'ouverture passe
/// `O_NOFOLLOW` : un symlink plante a `DB_PATH` fait echouer l'ouverture
/// (`ELOOP` mappe en erreur explicite) plutot que d'ecrire a travers. Le
/// `set_permissions` de rattrapage s'applique au descripteur ouvert, jamais a
/// un chemin re-resolu, donc ne peut pas atteindre une cible de symlink.
#[cfg(unix)]
fn precreate_0600(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    let file = opts.open(path).map_err(|e| {
        if e.raw_os_error() == Some(libc::ELOOP) {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "refusing to open database through symlink at {}",
                    path.display()
                ),
            )
        } else {
            e
        }
    })?;
    let mut perms = file.metadata()?.permissions();
    perms.set_mode(0o600);
    file.set_permissions(perms)
}

/// Hors Unix (stub) : aucune permission a durcir.
#[cfg(not(unix))]
fn precreate_0600(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Force `0600` sur la base et ses fichiers annexes `-wal`/`-shm`.
#[cfg(unix)]
fn harden_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let mut targets = vec![path.to_path_buf()];
    for suffix in ["-wal", "-shm"] {
        targets.push(PathBuf::from(format!("{}{suffix}", path.display())));
    }
    for target in targets {
        // `symlink_metadata` ne suit jamais les liens : un symlink plante a
        // `DB_PATH` (ou sur `-wal`/`-shm`) est detecte et ignore, pour ne
        // jamais chmoder `0600` une cible arbitraire.
        let meta = match std::fs::symlink_metadata(&target) {
            Ok(meta) => meta,
            // Fichier absent (WAL/SHM pas encore crees) : rien a durcir, ce
            // n'est pas une erreur.
            Err(_) => continue,
        };
        if meta.file_type().is_symlink() {
            tracing::warn!(
                path = %target.display(),
                "refusing to harden database file permissions through symlink"
            );
            continue;
        }
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        if let Err(e) = std::fs::set_permissions(&target, perms) {
            // Best-effort : un FS sans permissions Unix ne doit pas faire
            // echouer le boot, mais l'echec n'est plus silencieux.
            tracing::warn!(
                path = %target.display(),
                error = %e,
                "cannot harden database file permissions to 0600"
            );
        }
    }
}

#[cfg(not(unix))]
fn harden_perms(_path: &Path) {}

/// Applique les migrations `*.sql` non encore versionnees, dans l'ordre.
///
/// L'avancement est fige dans `PRAGMA user_version` (0 = aucune migration).
/// Les bases existantes creees avant ce versionnement ont `user_version = 0` :
/// les migrations 001-003 sont idempotentes, 004 est additive.
///
/// ```rust
/// # fn main() -> Result<(), wgez::db::DbError> {
/// let conn = rusqlite::Connection::open_in_memory()?;
/// conn.execute_batch("PRAGMA foreign_keys=ON;")?;
/// wgez::db::run_migrations(&conn)?;
/// // Seed : ligne general (setup non termine) + interface wg0.
/// let step: i64 =
///     conn.query_row("SELECT setupStep FROM general WHERE id = 1", [], |r| r.get(0))?;
/// assert_eq!(step, 1);
/// let cidr: String =
///     conn.query_row("SELECT ipv4Cidr FROM interfaces WHERE name = 'wg0'", [], |r| {
///         r.get(0)
///     })?;
/// assert_eq!(cidr, "10.8.0.0/24");
/// # Ok(())
/// # }
/// ```
pub fn run_migrations(conn: &rusqlite::Connection) -> Result<(), DbError> {
    let applied: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    for (idx, (name, sql)) in MIGRATIONS.iter().enumerate() {
        let version = (idx as i64) + 1;
        if version <= applied {
            continue;
        }
        conn.execute_batch(sql)
            .map_err(|e| DbError::Migration(name, e.to_string()))?;
        conn.execute_batch(&format!("PRAGMA user_version = {version};"))
            .map_err(|e| DbError::Migration(name, e.to_string()))?;
    }
    Ok(())
}

/// Instant present en secondes Unix (`0` si l'horloge est pre-epoch).
pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Formate un instant en TEXT ISO-8601 **canonique** : UTC, seconde entiere
/// (`YYYY-MM-DDTHH:MM:SSZ`), sans fraction.
///
/// C'est la seule forme ecrite dans les colonnes de dates, ce qui rend les
/// comparaisons lexicographiques (`expiresAt <= now`, sessions, OTL) valides :
/// un offset non-UTC est converti en UTC et les nanosecondes sont supprimees
/// (`...:00.5Z` se comparerait sinon *avant* `...:00Z`).
pub fn format_iso8601(t: time::OffsetDateTime) -> Result<String, DbError> {
    let utc = t
        .to_offset(time::UtcOffset::UTC)
        .replace_nanosecond(0)
        .map_err(|e| DbError::Time(e.to_string()))?;
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second()
    ))
}

/// Instant present en TEXT ISO-8601 canonique (UTC, seconde entiere) pour les
/// colonnes de dates.
pub fn now_iso8601() -> Result<String, DbError> {
    format_iso8601(time::OffsetDateTime::now_utc())
}

/// Vrai si `e` est une violation de contrainte d'unicite SQLite.
///
/// Ne regarde **que** les codes etendus `SQLITE_CONSTRAINT_UNIQUE` et
/// `SQLITE_CONSTRAINT_PRIMARYKEY` : le code de base `ConstraintViolation`
/// couvrirait aussi `NOT NULL`/`CHECK`/`FOREIGN KEY`, qui sont de vraies
/// corruptions a remonter en 500, pas des conflits 400.
pub fn is_unique_violation(e: &rusqlite::Error) -> bool {
    matches!(
        e.sqlite_extended_error_code(),
        Some(code)
            if code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
                || code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
    )
}

/// Convertit un booleen vers INTEGER 0/1.
pub fn bool_int(v: bool) -> i64 {
    if v { 1 } else { 0 }
}

/// Convertit INTEGER 0/1 vers booleen (toute valeur non nulle = vrai).
pub fn int_bool(v: i64) -> bool {
    v != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_preshared_column(conn: &rusqlite::Connection) -> bool {
        let mut stmt = conn
            .prepare("PRAGMA table_info(user_configs)")
            .expect("stmt");
        let names = stmt
            .query_map([], |r| r.get::<_, String>(1))
            .expect("query");
        names
            .filter_map(Result::ok)
            .any(|n| n == "defaultPreSharedKey")
    }

    /// Canonical date shape shared by every date column: UTC, whole seconds.
    #[test]
    fn iso8601_is_utc_whole_seconds() {
        use time::format_description::well_known::Rfc3339;
        // Nanos are dropped: a fractional part would break lexicographic order.
        let with_nanos =
            time::OffsetDateTime::parse("2026-01-01T00:00:00.987654321Z", &Rfc3339).expect("parse");
        assert_eq!(
            format_iso8601(with_nanos).expect("format"),
            "2026-01-01T00:00:00Z"
        );
        // A non-UTC offset is converted to UTC.
        let offset =
            time::OffsetDateTime::parse("2026-01-01T05:30:00+05:30", &Rfc3339).expect("parse");
        assert_eq!(
            format_iso8601(offset).expect("format"),
            "2026-01-01T00:00:00Z"
        );
        // `now_iso8601` shares the same shape: no `.` before the trailing `Z`.
        let now = now_iso8601().expect("now");
        assert!(now.ends_with('Z'), "{now}");
        assert!(!now[..now.len() - 1].contains('.'), "{now}");
    }

    #[test]
    fn migrations_are_versioned_and_replay_safe() {
        let conn = rusqlite::Connection::open_in_memory().expect("memdb");
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .expect("pragma");
        run_migrations(&conn).expect("first run");
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .expect("user_version");
        assert_eq!(version, MIGRATIONS.len() as i64);
        // Un second passage ne rejoue rien.
        run_migrations(&conn).expect("second run");
        assert!(has_preshared_column(&conn));
    }

    /// La DB (et ses annexes WAL/SHM) naît en `0600`, avant tout accès
    /// applicatif : la pré-création `0600` précède `Connection::open`, donc
    /// SQLite hérite de permissions restrictives pour WAL/SHM quel que soit
    /// l'umask.
    #[cfg(unix)]
    #[test]
    fn open_hardens_db_files_to_0600() {
        use std::os::unix::fs::PermissionsExt as _;

        fn mode_of(p: &Path) -> u32 {
            std::fs::metadata(p).expect("metadata").permissions().mode() & 0o777
        }

        let dir = std::env::temp_dir().join("wgez-db-perms");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("wg-ez.db");
        assert!(!path.exists(), "db must not exist before open");

        let conn = open(&path).expect("open");
        // Écriture supplémentaire : garantit que le WAL est sollicité.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS perm_probe (x INTEGER);
             INSERT INTO perm_probe VALUES (1);",
        )
        .expect("write");

        // Vérifier pendant que la connexion est ouverte : WAL/SHM existent.
        assert_eq!(mode_of(&path), 0o600, "db file must be 0600");
        for suffix in ["-wal", "-shm"] {
            let annex = PathBuf::from(format!("{}{suffix}", path.display()));
            if annex.exists() {
                assert_eq!(mode_of(&annex), 0o600, "{annex:?} must be 0600");
            }
        }
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Un symlink plante a `DB_PATH` ne doit jamais faire ecrire/chmoder sa
    /// cible : `precreate_0600` ouvre avec `O_NOFOLLOW` et mappe `ELOOP` en
    /// erreur explicite, donc la cible (contenu et permissions) reste intacte.
    #[cfg(unix)]
    #[test]
    fn open_refuses_symlinked_db_and_leaves_target_untouched() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let dir = std::env::temp_dir().join("wgez-db-symlink");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");

        let target = dir.join("target.txt");
        std::fs::write(&target, b"do not touch").expect("target");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644))
            .expect("target perms");

        let link = dir.join("wg-ez.db");
        symlink(&target, &link).expect("symlink");

        match open(&link) {
            Err(DbError::Io(e)) => {
                assert_eq!(
                    e.kind(),
                    std::io::ErrorKind::InvalidInput,
                    "symlink rejection must be an explicit InvalidInput: {e}"
                );
                assert!(
                    e.to_string().contains("symlink"),
                    "error must mention symlink explicitly: {e}"
                );
            }
            other => panic!("symlinked db must be refused, got {other:?}"),
        }

        // La cible n'a pas ete modifiee : ni contenu, ni permissions.
        assert_eq!(
            std::fs::read(&target).expect("read target"),
            b"do not touch",
            "target content must be untouched"
        );
        let mode = std::fs::metadata(&target)
            .expect("target meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644, "target permissions must be untouched");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `is_unique_violation` doit reconnaitre les vrais doublons
    /// (`UNIQUE` / `PRIMARY KEY`) sans elargir aux autres contraintes.
    #[test]
    fn is_unique_violation_detects_only_uniqueness() {
        let conn = rusqlite::Connection::open_in_memory().expect("memdb");
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE t (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                parent INTEGER REFERENCES t(id)
             );",
        )
        .expect("ddl");
        conn.execute("INSERT INTO t (id, name) VALUES (1, 'a')", [])
            .expect("seed");

        // Violation UNIQUE reelle (nom deja present).
        let dup = conn
            .execute("INSERT INTO t (id, name) VALUES (2, 'a')", [])
            .expect_err("duplicate name must fail");
        assert!(is_unique_violation(&dup), "UNIQUE must be detected: {dup}");

        // Violation PRIMARY KEY reelle (rowid deja present).
        let dup_pk = conn
            .execute("INSERT INTO t (id, name) VALUES (1, 'b')", [])
            .expect_err("duplicate pk must fail");
        assert!(
            is_unique_violation(&dup_pk),
            "PRIMARY KEY must be detected: {dup_pk}"
        );

        // NOT NULL et FOREIGN KEY ne sont PAS des doublons.
        let not_null = conn
            .execute("INSERT INTO t (id, name) VALUES (3, NULL)", [])
            .expect_err("not null must fail");
        assert!(
            !is_unique_violation(&not_null),
            "NOT NULL must not be classified as unique: {not_null}"
        );
        let foreign = conn
            .execute("INSERT INTO t (id, name, parent) VALUES (4, 'd', 999)", [])
            .expect_err("fk must fail");
        assert!(
            !is_unique_violation(&foreign),
            "FOREIGN KEY must not be classified as unique: {foreign}"
        );

        // Toute autre erreur rusqlite n'est pas une violation d'unicite.
        let no_rows = conn
            .query_row("SELECT name FROM t WHERE id = 4242", [], |r| {
                r.get::<_, String>(0)
            })
            .expect_err("no rows");
        assert!(!is_unique_violation(&no_rows));
    }
}
