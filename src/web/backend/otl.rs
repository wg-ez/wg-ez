#![forbid(unsafe_code)]

//! One-time links for [`super::SqliteBackend`].
//!
//! `generate_otl` is the ONLY client mutation without `Tunnel::apply`.
//! The first valid download shortens the expiry to now + 10 s
//! (anti-double-request) while the row is still at its initial TTL; later
//! polls are served without extending it (I3); the 60 s cron purges the row.

use super::SqliteBackend;
use super::common::{build_client_conf, db_err, now_iso};
use crate::web::ctx::{OtlOutcome, OtlView, WebError};

impl SqliteBackend {
    pub(crate) async fn generate_otl_inner(&self, id: i64) -> Result<OtlView, WebError> {
        self.with_db(move |conn| {
            if crate::store::client::get(&conn, id)
                .map_err(db_err)?
                .is_none()
            {
                return Err(WebError::not_found("client not found"));
            }
            // The ONLY client mutation without `Tunnel::apply`.
            let link = crate::otl::generate_for_client(&conn, id)
                .map_err(|e| WebError::internal(e.to_string()))?;
            Ok(OtlView {
                token: link.token.clone(),
                expires_at: link.expires_at.clone(),
                url: format!("/cnf/{}", link.token),
            })
        })
        .await
    }

    pub(crate) async fn consume_otl_inner(&self, token: &str) -> Result<OtlOutcome, WebError> {
        let token = token.to_string();
        let disable_v4 = self.config.disable_ipv4;
        let disable_v6 = self.config.disable_ipv6;
        self.with_db(move |conn| {
            let now = now_iso()?;
            let client_id = match crate::otl::consume_for_download(&conn, &token, &now) {
                Ok(id) => id,
                Err(crate::otl::ConsumeError::Unknown) => return Ok(OtlOutcome::Unknown),
                Err(crate::otl::ConsumeError::Expired) => return Ok(OtlOutcome::Expired),
            };
            let client = crate::store::client::get(&conn, client_id).map_err(db_err)?;
            let Some(client) = client else {
                return Ok(OtlOutcome::Unknown);
            };
            let (file_name, conf) = build_client_conf(&conn, &client, disable_v4, disable_v6)?;
            Ok(OtlOutcome::Ok { file_name, conf })
        })
        .await
    }
}
