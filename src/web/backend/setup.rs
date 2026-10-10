#![forbid(unsafe_code)]

//! Setup operations for [`super::SqliteBackend`] plus the meta query that
//! never touches the kernel (`setup_step`).

use serde_json::{Value, json};

use super::SqliteBackend;
use super::common::{db_err, parse_json_vec, setup_err, userconfig_row};
use crate::web::ctx::WebError;

impl SqliteBackend {
    pub(crate) async fn setup_step_inner(&self) -> Result<i64, WebError> {
        self.with_db(move |conn| {
            let step = crate::store::general::get(&conn)
                .map_err(db_err)?
                .map(|g| g.setup_step)
                .unwrap_or(1);
            Ok(step)
        })
        .await
    }

    pub(crate) async fn setup_create_admin_inner(
        &self,
        username: &str,
        password: &str,
    ) -> Result<i64, WebError> {
        let username = username.to_string();
        let password = password.to_string();
        self.with_db(move |mut conn| {
            let id = crate::setup::complete_step2(&mut conn, username.trim(), &password)
                .map_err(setup_err)?;
            Ok(id)
        })
        .await
    }

    pub(crate) async fn setup_set_host_inner(&self, host: &str, port: u16) -> Result<(), WebError> {
        let iface_name = self.iface_name();
        let host = host.to_string();
        self.with_db(move |conn| {
            crate::setup::save_host_port(&conn, &iface_name, host.trim(), i64::from(port))
                .map_err(setup_err)?;
            Ok(())
        })
        .await
    }

    /// Read-only facts shown by the setup wizard (endpoint pre-fill + the
    /// recap panel of step 3). `defaultAllowedIps` is stored as a JSON
    /// array in `user_configs`: it is joined here so the template never
    /// parses anything.
    pub(crate) async fn setup_suggest_inner(&self) -> Result<Value, WebError> {
        let iface_name = self.iface_name();
        self.with_db(move |conn| {
            let cfg = userconfig_row(&conn, &iface_name)?;
            let mut allowed = parse_json_vec(&cfg.default_allowed_ips_v4);
            allowed.extend(parse_json_vec(&cfg.default_allowed_ips_v6));
            let iface = crate::store::interface::get(&conn, &iface_name).map_err(db_err)?;
            Ok(json!({
                "hosts": cfg.host,
                "port": cfg.port,
                "iface": iface_name,
                "ipv4Cidr": iface.as_ref().map(|i| i.ipv4_cidr.clone()).unwrap_or_default(),
                "defaultAllowedIps": allowed.join(", "),
            }))
        })
        .await
    }
}
