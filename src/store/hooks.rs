//! CRUD SQL des hooks serveur par interface.
//!
//! - `id` = nom d'interface, CASCADE.
//! - `postUp` seed pose le MASQUERADE NAT et les ACCEPT ; `postDown` les `-D`.
//! - Les hooks passent par `removeNewlines` en couche web (anti-injection).

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

/// Ligne `hooks` (`id` = nom d'interface).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hooks {
    pub id: String,
    pub pre_up: String,
    pub post_up: String,
    pub pre_down: String,
    pub post_down: String,
}

fn map(row: &rusqlite::Row<'_>) -> Result<Hooks, rusqlite::Error> {
    Ok(Hooks {
        id: row.get("id")?,
        pre_up: row.get("preUp")?,
        post_up: row.get("postUp")?,
        pre_down: row.get("preDown")?,
        post_down: row.get("postDown")?,
    })
}

pub fn get(conn: &Connection, id: &str) -> Result<Option<Hooks>, rusqlite::Error> {
    conn.query_row(
        "SELECT id, preUp, postUp, preDown, postDown FROM hooks WHERE id = ?1",
        [id],
        map,
    )
    .optional()
}

pub fn upsert(conn: &Connection, hooks: &Hooks) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO hooks (id, preUp, postUp, preDown, postDown) VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT(id) DO UPDATE SET preUp = excluded.preUp, postUp = excluded.postUp, \
         preDown = excluded.preDown, postDown = excluded.postDown",
        rusqlite::params![
            hooks.id,
            hooks.pre_up,
            hooks.post_up,
            hooks.pre_down,
            hooks.post_down
        ],
    )?;
    Ok(())
}

/// Répercute un changement de CIDR dans les quatre hooks : remplace les
/// occurrences littérales de `old` par `new`. Les hooks par défaut
/// référencent le sous-réseau (`-s 10.8.0.0/24`), qui doit suivre l'interface.
///
/// Renvoie `true` si au moins un champ a été modifié. `old` vide, `new` vide
/// ou `old == new` ne changent rien.
pub fn replace_cidr(hooks: &mut Hooks, old: &str, new: &str) -> bool {
    if old.is_empty() || new.is_empty() || old == new {
        return false;
    }
    let mut changed = false;
    for field in [
        &mut hooks.pre_up,
        &mut hooks.post_up,
        &mut hooks.pre_down,
        &mut hooks.post_down,
    ] {
        if field.contains(old) {
            *field = field.replace(old, new);
            changed = true;
        }
    }
    changed
}

/// Répercute un changement de CIDR d'interface dans les hooks persistés :
/// lit la ligne `hooks`, remplace l'ancien CIDR v4 puis v6, et ne réécrit
/// (`upsert`) que si au moins un champ a effectivement changé.
///
/// L'absence de ligne est un no-op silencieux (`Ok(())`), tout comme un
/// changement neutre (`old == new` ou CIDR vide). Centralise la propagation
/// CIDR → hooks utilisée par le setup initial et l'admin.
pub fn sync_cidr(
    conn: &Connection,
    interface_id: &str,
    old_v4: &str,
    new_v4: &str,
    old_v6: &str,
    new_v6: &str,
) -> Result<(), rusqlite::Error> {
    let Some(mut hooks) = get(conn, interface_id)? else {
        return Ok(());
    };
    let mut changed = replace_cidr(&mut hooks, old_v4, new_v4);
    changed |= replace_cidr(&mut hooks, old_v6, new_v6);
    if changed {
        upsert(conn, &hooks)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Hooks {
        Hooks {
            id: "wg0".to_string(),
            pre_up: String::new(),
            post_up: "iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE"
                .to_string(),
            pre_down: String::new(),
            post_down: "iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE"
                .to_string(),
        }
    }

    #[test]
    fn replace_cidr_rewrites_all_fields() {
        let mut h = sample();
        assert!(replace_cidr(&mut h, "10.8.0.0/24", "10.9.0.0/24"));
        assert!(h.post_up.contains("10.9.0.0/24"));
        assert!(!h.post_up.contains("10.8.0.0/24"));
        assert!(h.post_down.contains("10.9.0.0/24"));
        assert!(!h.post_down.contains("10.8.0.0/24"));
    }

    #[test]
    fn replace_cidr_is_noop_when_absent_or_unchanged() {
        let mut h = sample();
        assert!(!replace_cidr(&mut h, "", "10.9.0.0/24"));
        assert!(!replace_cidr(&mut h, "10.8.0.0/24", "10.8.0.0/24"));
        assert!(!replace_cidr(&mut h, "192.168.0.0/24", "10.9.0.0/24"));
        assert!(h.post_up.contains("10.8.0.0/24"));
    }
}
