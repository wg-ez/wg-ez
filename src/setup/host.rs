#![forbid(unsafe_code)]

//! Step 3: host/port (`POST /api/setup/3` -> step 0).

use super::{SetupError, validate_host_port};

/// Store the public host/port (`user_configs`) and finish setup.
pub fn save_host_port(
    conn: &rusqlite::Connection,
    interface_name: &str,
    host: &str,
    port: i64,
) -> Result<(), SetupError> {
    let (host, port) = validate_host_port(host, port)?;
    let mut cfg = crate::store::userconfig::get(conn, interface_name)?.ok_or_else(|| {
        SetupError::State("user config for this interface is missing".to_string())
    })?;
    cfg.host = host;
    cfg.port = port;
    crate::store::userconfig::upsert(conn, &cfg)?;
    crate::store::general::complete_setup(conn)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::save_host_port;
    use crate::setup::complete_step2;
    use crate::test_support::memdb;

    #[test]
    fn step2_moves_to_3_and_step3_finishes() {
        let mut conn = memdb();
        complete_step2(&mut conn, "admin", "long-enough-12").expect("step2");
        let step: i64 = conn
            .query_row("SELECT setupStep FROM general WHERE id = 1", [], |r| {
                r.get(0)
            })
            .expect("step");
        assert_eq!(step, 3);
        save_host_port(&conn, "wg0", "vpn.example.com", 51820).expect("step3");
        assert!(crate::store::general::is_setup_done(&conn).expect("done"));
        let host: String = conn
            .query_row("SELECT host FROM user_configs WHERE id = 'wg0'", [], |r| {
                r.get(0)
            })
            .expect("host");
        assert_eq!(host, "vpn.example.com");
    }
}
