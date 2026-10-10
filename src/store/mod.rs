//! CRUD SQL parametre par table (`rusqlite`, requetes preparees, aucun ORM).
//!
//! Conventions :
//! - tout SQL est parametre (`?1`, `?2`, ...), aucune concatenation de valeurs ;
//!   les rares `SET` dynamiques n'assemblent que des noms de colonnes fixes ;
//! - `null` = heritage (`allowedIpsV4`/`V6` et `dnsV4`/`V6` -> defaut global de
//!   la meme famille, `firewallIpsV4`/`V6` -> `allowedIps` de la famille ->
//!   defaut global), jamais confondu avec `[]` ;
//! - dates en TEXT ISO-8601, booleens en INTEGER 0/1 (helpers `db::bool_int`,
//!   `db::int_bool`).

pub mod client;
pub mod general;
pub mod hooks;
pub mod interface;
pub mod otl;
pub mod session;
pub mod user;
pub mod userconfig;
