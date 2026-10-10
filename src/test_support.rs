#![forbid(unsafe_code)]

//! Helpers partagés aux tests unitaires.

/// Connexion SQLite en mémoire : clés étrangères activées, migrations appliquées.
pub(crate) fn memdb() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().expect("memdb");
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .expect("pragma");
    crate::db::run_migrations(&conn).expect("migrations");
    conn
}
