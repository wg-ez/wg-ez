#![forbid(unsafe_code)]

//! Router-level tests: guards via the REAL axum router.
//! Never call handlers directly (`panic = "abort"` would kill the runner).

use std::sync::Arc;

use super::*;
use crate::web::ctx::{
    ApiTokenCreated, ApiTokenView, AppState, Backend, ClientView, GlobalDefaults, LoginOutcome,
    MetricsSnapshot, OtlOutcome, OtlView, PendingLogin, StatusSignal, TotpSetup, UserView,
    WebError,
};
use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode},
};
use serde_json::Value;
use tower::ServiceExt;

/// Minimal in-memory backend for guard tests (no privileges needed).
///
/// `metrics` + `metrics_password` are interior-mutable so a sequence
/// `POST /api/admin/general` then `GET /metrics/*` shares state through the
/// real router. `set_general` reuses the production pure merge
/// (`crate::web::backend::general_update`) so the I6 guard is the real one.
/// API tokens live in `api_tokens` (hashed, like production): created through
/// the real `POST /api/me/tokens` router path, resolvable via `Bearer`.
#[derive(Debug, Default)]
pub struct TestBackend {
    pub setup_step: i64,
    /// `INSECURE` flag backing [`Backend::insecure`]: drives the `Secure`
    /// attribute of the session AND pending-2FA cookies (M8).
    pub insecure: bool,
    pub metrics: std::sync::Mutex<(bool, bool)>,
    /// Test-only "stored hash": the clear Bearer itself (production stores an
    /// Argon2 hash). Router tests only need presence + comparison semantics.
    pub metrics_password: std::sync::Mutex<Option<String>>,
    /// Long-lived API tokens: `(stored_hash, view)`. The clear value is
    /// returned once at creation (like production) and never stored.
    pub api_tokens: std::sync::Mutex<Vec<(String, ApiTokenView)>>,
    /// Next API-token id (monotonic, never reused after revoke).
    pub api_next_id: std::sync::Mutex<i64>,
    /// User ids treated as disabled (fail-closed Bearer on disabled owner).
    pub disabled_users: std::sync::Mutex<Vec<i64>>,
}

/// Construct a [`TestBackend`] with the given flags/password.
fn backend(setup_step: i64, metrics: (bool, bool), password: Option<&str>) -> TestBackend {
    backend_with_insecure(setup_step, metrics, password, true)
}

/// Same as [`backend`] but with an explicit `INSECURE` flag.
fn backend_with_insecure(
    setup_step: i64,
    metrics: (bool, bool),
    password: Option<&str>,
    insecure: bool,
) -> TestBackend {
    TestBackend {
        setup_step,
        insecure,
        metrics: std::sync::Mutex::new(metrics),
        metrics_password: std::sync::Mutex::new(password.map(str::to_string)),
        api_tokens: std::sync::Mutex::new(Vec::new()),
        api_next_id: std::sync::Mutex::new(1),
        disabled_users: std::sync::Mutex::new(Vec::new()),
    }
}

fn admin_user() -> UserView {
    UserView {
        id: 1,
        username: "admin".into(),
        name: "Admin".into(),
        role: 1,
        totp_enabled: false,
        totp_verified: false,
    }
}

/// Non-admin principal used to prove `admin.any` answers 403.
fn client_user() -> UserView {
    UserView {
        id: 2,
        username: "bob".into(),
        name: "Bob".into(),
        role: 2,
        totp_enabled: false,
        totp_verified: false,
    }
}

/// Client expose par le backend de test pour `/clients/1` (preuve de rendu de
/// la fiche client via le vrai routeur). Tous les champs de la vue sont
/// renseignes pour exercer les branches v4+v6, expiration et nombres.
fn sample_client() -> ClientView {
    ClientView {
        id: 1,
        user_id: 1,
        name: "Alice".into(),
        enabled: true,
        has_pre_shared_key: false,
        ipv4_address: "10.8.0.2".into(),
        ipv6_address: Some("fd42::2".into()),
        allowed_ips_v4: None,
        allowed_ips_v6: None,
        server_allowed_ips_v4: vec![],
        server_allowed_ips_v6: vec![],
        firewall_ips_v4: None,
        firewall_ips_v6: None,
        dns_v4: None,
        dns_v6: None,
        mtu: 1420,
        persistent_keepalive: 25,
        server_endpoint: Some("vpn.example.com:51820".into()),
        expires_at: Some("2031-12-25T00:00:00Z".into()),
        created_at: "2026-01-01T00:00:00Z".into(),
        endpoint: Some("1.2.3.4:51820".into()),
        latest_handshake_at: None,
        rx_bytes: 0,
        tx_bytes: 0,
        connected: false,
    }
}

/// `Some` pour les clients connus du backend de test (id 1 = admin/user 1,
/// id 2 = utilisateur CLIENT), `None` sinon. Centralise la propriete pour que
/// `get_client` et les mutations id-scopees partagent le meme modele : une
/// route qui atteint le backend ne peut plus renvoyer 404 pour un client
/// possede, ce qui rend les tests d'autorisation independants du backend.
fn client_view(id: i64) -> Option<ClientView> {
    match id {
        1 => Some(sample_client()),
        2 => Some(ClientView {
            id: 2,
            user_id: 2,
            name: "Bob".into(),
            ..sample_client()
        }),
        _ => None,
    }
}

/// Real `rusqlite` UNIQUE violation produced by an in-memory table shaped like
/// `clients` (name / ipv4Address / publicKey+interfaceId). Used to exercise the
/// genuine SQLite detail (`UNIQUE constraint failed: clients.ipv4Address`)
/// through the router: the 400 body must never echo it (M10).
fn unique_conflict_error() -> rusqlite::Error {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory sqlite");
    conn.execute_batch(
        "CREATE TABLE clients (\
             id INTEGER PRIMARY KEY, \
             name TEXT NOT NULL UNIQUE, \
             ipv4Address TEXT UNIQUE, \
             publicKey TEXT NOT NULL, \
             interfaceId TEXT NOT NULL, \
             UNIQUE (publicKey, interfaceId));",
    )
    .expect("schema");
    conn.execute(
        "INSERT INTO clients (name, ipv4Address, publicKey, interfaceId) \
         VALUES ('dup', '10.8.0.2', 'pubkey', 'wg0')",
        [],
    )
    .expect("first insert");
    conn.execute(
        "INSERT INTO clients (name, ipv4Address, publicKey, interfaceId) \
         VALUES ('dup', '10.8.0.2', 'pubkey', 'wg0')",
        [],
    )
    .expect_err("duplicate insert must violate a UNIQUE constraint")
}

impl Backend for TestBackend {
    fn app_version(&self) -> String {
        "0.0.0-test".into()
    }
    fn insecure(&self) -> bool {
        self.insecure
    }
    async fn setup_step(&self) -> Result<i64, WebError> {
        Ok(self.setup_step)
    }
    async fn password_auth_allowed(&self) -> Result<bool, WebError> {
        Ok(true)
    }
    async fn login_password(&self, u: &str, _p: &str) -> Result<LoginOutcome, WebError> {
        // `totp` is the deterministic 2FA account for the M8 pending-cookie
        // tests: a successful password step that still requires a second
        // factor. Anything else is a wrong credential.
        if u == "totp" {
            return Ok(LoginOutcome::TotpRequired {
                user_id: 2,
                username: "totp".into(),
            });
        }
        // `okuser` is the deterministic non-2FA success; the cookie is always
        // a browser-session cookie.
        if u == "okuser" {
            return Ok(LoginOutcome::Ok {
                user: admin_user(),
                token: "tok".into(),
            });
        }
        Err(WebError::unauthorized("invalid credentials"))
    }
    async fn get_user(&self, id: i64) -> Result<UserView, WebError> {
        if id == 1 {
            Ok(admin_user())
        } else {
            Err(WebError::not_found("user"))
        }
    }
    async fn verify_totp(&self, _u: i64, c: &str) -> Result<bool, WebError> {
        // Deterministic code for the M2 pending-flow router tests: any other
        // 6-digit code is wrong, so failures are reproducible.
        Ok(c == "123456")
    }
    async fn create_session(&self, _u: i64) -> Result<String, WebError> {
        Ok("tok".into())
    }
    async fn lookup_session(&self, h: &str) -> Result<Option<UserView>, WebError> {
        // `authenticate` hashes the clear cookie token before calling us:
        // the cookie `wg-ez=valid` therefore arrives here as its SHA-256.
        if h == crate::web::guards::hash_token("valid") {
            return Ok(Some(admin_user()));
        }
        if h == crate::web::guards::hash_token("client") {
            return Ok(Some(client_user()));
        }
        Ok(None)
    }
    async fn destroy_session(&self, _h: &str) -> Result<(), WebError> {
        Ok(())
    }
    async fn update_me(&self, _u: i64, _n: &str) -> Result<UserView, WebError> {
        Ok(admin_user())
    }
    async fn change_username(
        &self,
        _u: i64,
        current: &str,
        username: &str,
    ) -> Result<UserView, WebError> {
        // Mirrors the production guard: a wrong current password is refused
        // (401 + seclog `password`) and a duplicate replays a real SQLite
        // UNIQUE violation, mapped by `db_err` to a generic 400.
        if current != "correct" {
            return Err(WebError::unauthorized("password is wrong").with_seclog("password"));
        }
        if username == "taken" {
            return Err(crate::web::backend::db_err(unique_conflict_error()));
        }
        Ok(UserView {
            username: username.into(),
            ..admin_user()
        })
    }
    async fn change_password(&self, _u: i64, _c: &str, _n: &str) -> Result<(), WebError> {
        Ok(())
    }
    async fn totp_setup_start(&self, _u: i64, password: &str) -> Result<TotpSetup, WebError> {
        // Miroir de la garde de production : le démarrage exige toujours le
        // mot de passe courant (y compris au premier enrôlement). Le test
        // routeur prouve que le handler transmet le `password` du corps au
        // lieu de réimplémenter le contrôle.
        match password {
            "correct" => Ok(TotpSetup {
                secret: "SECRET".into(),
                otpauth_url: "otpauth://x".into(),
                qr_svg: "<svg></svg>".into(),
            }),
            _ => Err(WebError::unauthorized("password is wrong").with_seclog("password")),
        }
    }
    async fn totp_setup_confirm(&self, _u: i64, _c: &str, password: &str) -> Result<(), WebError> {
        // Miroir de la garde de production : la confirmation exige elle aussi
        // le mot de passe courant.
        if password != "correct" {
            return Err(WebError::unauthorized("password is wrong").with_seclog("password"));
        }
        Ok(())
    }
    async fn totp_remove(&self, _u: i64, _p: &str) -> Result<(), WebError> {
        Ok(())
    }
    async fn list_clients(&self) -> Result<Vec<ClientView>, WebError> {
        Ok(vec![])
    }
    async fn get_client(&self, id: i64) -> Result<Option<ClientView>, WebError> {
        Ok(client_view(id))
    }
    async fn create_client(&self, n: &str) -> Result<ClientView, WebError> {
        // M10 : `"duplicate"` rejoue une VRAIE violation d'unicite SQLite
        // (nom/IP/cle deja pris) pour prouver, via le vrai routeur, que le
        // corps 400 ne divulgue aucun detail interne. Tout autre nom produit
        // un client pour que les tests d'autorisation ADMIN atteignent 200.
        if n == "duplicate" {
            return Err(crate::web::backend::db_err(unique_conflict_error()));
        }
        Ok(ClientView {
            id: 3,
            name: n.into(),
            ..sample_client()
        })
    }
    async fn update_client(&self, _id: i64, p: Value) -> Result<ClientView, WebError> {
        // Succes : les tests I4 prouvent qu'un patch autorise atteint bien le
        // backend (200) au lieu d'etre bloque par la garde. On rejoue la
        // validation de production (comme `set_general` avec `general_update`)
        // pour que le 400 M4 d'un DNS invalide soit exerce via le vrai routeur.
        crate::web::backend::parse_client_update(&p)?;
        // Echo d'un `enabled: false` explicite : prouve quel patch le handler
        // a transmis apres `coerce_patch` (non-regression du bug "PATCH JSON
        // partiel sans `enabled`", qui eteignait le client en silence).
        let mut c = sample_client();
        if p.get("enabled") == Some(&Value::Bool(false)) {
            c.enabled = false;
        }
        Ok(c)
    }
    async fn delete_client(&self, _id: i64) -> Result<(), WebError> {
        Ok(())
    }
    async fn enable_client(&self, _id: i64) -> Result<ClientView, WebError> {
        Err(WebError::unprocessable("expired"))
    }
    async fn disable_client(&self, _id: i64) -> Result<ClientView, WebError> {
        Err(WebError::not_found("x"))
    }
    async fn set_client_psk(&self, id: i64, enabled: bool) -> Result<ClientView, WebError> {
        match client_view(id) {
            Some(mut c) => {
                c.has_pre_shared_key = enabled;
                Ok(c)
            }
            None => Err(WebError::not_found("x")),
        }
    }
    async fn rotate_client_keys(&self, id: i64) -> Result<ClientView, WebError> {
        client_view(id).ok_or_else(|| WebError::not_found("x"))
    }
    async fn generate_otl(&self, id: i64) -> Result<OtlView, WebError> {
        match client_view(id) {
            Some(_) => Ok(OtlView {
                token: "OTLTOKEN".into(),
                expires_at: "2031-01-01T00:00:00Z".into(),
                url: "/cnf/OTLTOKEN".into(),
            }),
            None => Err(WebError::not_found("x")),
        }
    }
    async fn client_conf(&self, id: i64) -> Result<(String, String), WebError> {
        // I7 : la route configuration/QR doit produire une reponse reelle
        // pour prouver que le `.conf` (cle privee) est `no-store`.
        match client_view(id) {
            Some(_) => Ok((
                if id == 1 { "alice.conf" } else { "bob.conf" }.to_string(),
                "[Interface]\nPrivateKey = SECRET\n".to_string(),
            )),
            None => Err(WebError::not_found("x")),
        }
    }
    async fn global_defaults(&self) -> Result<GlobalDefaults, WebError> {
        Ok(GlobalDefaults::default())
    }
    fn ipv4_enabled(&self) -> bool {
        true
    }
    fn ipv6_enabled(&self) -> bool {
        true
    }
    async fn consume_otl(&self, t: &str) -> Result<OtlOutcome, WebError> {
        match t {
            "expired" => Ok(OtlOutcome::Expired),
            // I7 : un token valide sert un `.conf` (cle privee) qui doit
            // arriver en `no-store`.
            "valid" => Ok(OtlOutcome::Ok {
                file_name: "otl.conf".to_string(),
                conf: "[Interface]\nPrivateKey = SECRET\n".to_string(),
            }),
            _ => Ok(OtlOutcome::Unknown),
        }
    }
    async fn create_api_token(
        &self,
        user_id: i64,
        name: &str,
        expires_at: Option<&str>,
    ) -> Result<ApiTokenCreated, WebError> {
        // Miroir de la validation de production (nom 1-64) : le 400 est
        // exercé via le vrai routeur.
        let name = name.trim().to_string();
        if name.is_empty() || name.chars().count() > 64 {
            return Err(WebError::bad_request("token name must be 1-64 chars"));
        }
        let (token, stored) = crate::auth::session::generate_token_pair()
            .map_err(|e| WebError::internal(e.to_string()))?;
        let expires = expires_at
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string);
        let mut next = self
            .api_next_id
            .lock()
            .map_err(|_| WebError::internal("lock"))?;
        let id = *next;
        *next += 1;
        drop(next);
        let created_at = "2026-01-01T00:00:00Z".to_string();
        let view = ApiTokenView {
            id,
            user_id,
            name: name.clone(),
            expires_at: expires.clone(),
            last_used_at: None,
            created_at: created_at.clone(),
            enabled: true,
        };
        self.api_tokens
            .lock()
            .map_err(|_| WebError::internal("lock"))?
            .push((stored, view));
        Ok(ApiTokenCreated {
            id,
            name,
            token,
            expires_at: expires,
            created_at,
        })
    }
    async fn list_api_tokens(&self, user_id: i64) -> Result<Vec<ApiTokenView>, WebError> {
        Ok(self
            .api_tokens
            .lock()
            .map_err(|_| WebError::internal("lock"))?
            .iter()
            .filter(|(_, v)| v.user_id == user_id)
            .map(|(_, v)| v.clone())
            .collect())
    }
    async fn list_all_api_tokens(&self) -> Result<Vec<ApiTokenView>, WebError> {
        Ok(self
            .api_tokens
            .lock()
            .map_err(|_| WebError::internal("lock"))?
            .iter()
            .map(|(_, v)| v.clone())
            .collect())
    }
    async fn delete_api_token(
        &self,
        caller_id: i64,
        is_admin: bool,
        id: i64,
    ) -> Result<bool, WebError> {
        // Non-ADMIN scopé à ses lignes : id inconnu et id d'autrui répondent
        // pareil (`false` -> 404 anti-énumération dans le handler).
        let mut store = self
            .api_tokens
            .lock()
            .map_err(|_| WebError::internal("lock"))?;
        let pos = store
            .iter()
            .position(|(_, v)| v.id == id && (is_admin || v.user_id == caller_id));
        Ok(match pos {
            Some(i) => {
                store.remove(i);
                true
            }
            None => false,
        })
    }
    async fn auth_api_token(&self, token_hash_hex: &str) -> Result<Option<UserView>, WebError> {
        // Miroir fail-closed de la production : `enabled`, expiry
        // lexicographique (forme canonique), propriétaire activé, puis touch
        // best-effort de `lastUsedAt`.
        let now = crate::db::now_iso8601().map_err(|e| WebError::internal(format!("db: {e}")))?;
        let disabled: Vec<i64> = self
            .disabled_users
            .lock()
            .map_err(|_| WebError::internal("lock"))?
            .clone();
        let mut store = self
            .api_tokens
            .lock()
            .map_err(|_| WebError::internal("lock"))?;
        let Some((_, view)) = store.iter_mut().find(|(h, _)| h == token_hash_hex) else {
            return Ok(None);
        };
        if !view.enabled {
            return Ok(None);
        }
        if view
            .expires_at
            .as_deref()
            .is_some_and(|exp| exp <= now.as_str())
        {
            return Ok(None);
        }
        if disabled.contains(&view.user_id) {
            return Ok(None);
        }
        let user = match view.user_id {
            1 => admin_user(),
            2 => client_user(),
            _ => return Ok(None),
        };
        view.last_used_at = Some(now);
        Ok(Some(user))
    }
    async fn get_general(&self) -> Result<Value, WebError> {
        let (prom, js) = self
            .metrics
            .lock()
            .map(|g| *g)
            .map_err(|_| WebError::internal("lock"))?;
        let set = self
            .metrics_password
            .lock()
            .map(|g| g.is_some())
            .map_err(|_| WebError::internal("lock"))?;
        Ok(serde_json::json!({
            "sessionTimeout": 3600,
            "metricsPrometheus": prom,
            "metricsJson": js,
            "metricsPasswordSet": set,
        }))
    }
    async fn set_general(&self, p: Value) -> Result<Value, WebError> {
        let (prom, js, password) = {
            let m = self
                .metrics
                .lock()
                .map(|g| *g)
                .map_err(|_| WebError::internal("lock"))?;
            let p = self
                .metrics_password
                .lock()
                .map(|g| g.clone())
                .map_err(|_| WebError::internal("lock"))?;
            (m.0, m.1, p)
        };
        let cur = crate::store::general::General {
            id: 1,
            setup_step: 0,
            session_timeout: 3600,
            metrics_prometheus: prom,
            metrics_json: js,
            metrics_password: password,
        };
        let empty = serde_json::Map::new();
        let map = p.as_object().unwrap_or(&empty);
        // Reuse the production merge: the I6 guard and the "empty field keeps
        // the stored password" rule under test are the real ones.
        let upd = crate::web::backend::general_update(&cur, map, |clear| Ok(clear.to_string()))?;
        {
            let mut flags = self
                .metrics
                .lock()
                .map_err(|_| WebError::internal("lock"))?;
            *flags = (upd.metrics_prometheus, upd.metrics_json);
        }
        {
            let mut stored = self
                .metrics_password
                .lock()
                .map_err(|_| WebError::internal("lock"))?;
            *stored = upd.metrics_password;
        }
        self.get_general().await
    }
    async fn get_hooks(&self) -> Result<Value, WebError> {
        Ok(Value::Null)
    }
    async fn set_hooks(&self, _p: Value) -> Result<Value, WebError> {
        Ok(Value::Null)
    }
    async fn get_interface(&self) -> Result<Value, WebError> {
        Ok(Value::Null)
    }
    async fn set_interface(&self, _p: Value) -> Result<Value, WebError> {
        Ok(Value::Null)
    }
    async fn get_userconfig(&self) -> Result<Value, WebError> {
        Ok(Value::Null)
    }
    async fn set_userconfig(&self, _p: Value) -> Result<Value, WebError> {
        Ok(Value::Null)
    }
    async fn change_cidr(&self, _a: Option<&str>, _b: Option<&str>) -> Result<Value, WebError> {
        Ok(Value::Null)
    }
    async fn restart_interface(&self) -> Result<(), WebError> {
        Ok(())
    }
    async fn ip_info(&self) -> Result<Value, WebError> {
        Ok(Value::Null)
    }
    async fn metrics_enabled(&self) -> Result<(bool, bool), WebError> {
        self.metrics
            .lock()
            .map(|g| *g)
            .map_err(|_| WebError::internal("lock"))
    }
    async fn metrics_check(&self, p: Option<&str>) -> Result<bool, WebError> {
        let stored = self
            .metrics_password
            .lock()
            .map(|g| g.clone())
            .map_err(|_| WebError::internal("lock"))?;
        // Fail-closed, mirroring `SqliteBackend::metrics_check_inner`: a
        // missing stored hash always refuses.
        Ok(match stored.as_deref() {
            None => false,
            Some(hash) => p == Some(hash),
        })
    }
    async fn metrics_snapshot(&self) -> Result<MetricsSnapshot, WebError> {
        Ok(MetricsSnapshot {
            interface: "wg0".into(),
            ..Default::default()
        })
    }
    async fn setup_create_admin(&self, _u: &str, _p: &str) -> Result<i64, WebError> {
        Ok(1)
    }
    async fn setup_set_host(&self, _h: &str, _p: u16) -> Result<(), WebError> {
        Ok(())
    }
    async fn setup_suggest(&self) -> Result<Value, WebError> {
        Ok(Value::Null)
    }
    async fn apply_tunnel(&self) -> Result<(), WebError> {
        Ok(())
    }
    async fn status_signal(&self) -> Result<StatusSignal, WebError> {
        // Strictly increasing fingerprint: the watcher observes a change on
        // its second tick, which makes the long-poll test deterministic.
        static TICKS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = TICKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(StatusSignal {
            state: n,
            traffic: 0,
            connected: 1,
        })
    }
}

pub fn test_state() -> AppState<TestBackend> {
    AppState::new(
        Arc::new(backend(1, (true, true), Some("scrape-secret"))),
        crate::web::ctx::Locales::load().expect("locales"),
        vec![],
    )
}

pub fn finished_state() -> AppState<TestBackend> {
    AppState::new(
        Arc::new(backend(0, (true, true), Some("scrape-secret"))),
        crate::web::ctx::Locales::load().expect("locales"),
        vec![],
    )
}

/// Setup mid-flight at step 3: the endpoint step is the valid API step and
/// an admin session already exists (minted by step 2). Used by the
/// endpoint-step auth tests.
pub fn setup_step3_state() -> AppState<TestBackend> {
    AppState::new(
        Arc::new(backend(3, (true, true), Some("scrape-secret"))),
        crate::web::ctx::Locales::load().expect("locales"),
        vec![],
    )
}

/// Finished setup with an explicit `INSECURE` flag, for the M8 cookie-flag
/// tests (`Secure` present iff `!INSECURE`).
pub fn insecure_state(insecure: bool) -> AppState<TestBackend> {
    AppState::new(
        Arc::new(backend_with_insecure(
            0,
            (true, true),
            Some("scrape-secret"),
            insecure,
        )),
        crate::web::ctx::Locales::load().expect("locales"),
        vec![],
    )
}

async fn req(
    app: Router,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
) -> (StatusCode, HeaderMap, String) {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(c) = cookie {
        b = b.header("cookie", c);
    }
    let mut built = b.body(Body::empty()).unwrap();
    // `ConnectInfo` is always present behind a real listener; oneshot
    // tests must inject it or extraction 500s.
    built
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::IpAddr::from([127, 0, 0, 1]),
            12345,
        ))));
    let res = app.oneshot(built).await.unwrap();
    let s = res.status();
    let h = res.headers().clone();
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    (s, h, String::from_utf8_lossy(&body).into_owned())
}

/// GET/POST with `Authorization: Bearer <token>` through the real router,
/// from the fixed peer IP `127.0.0.1` so the failure throttle is observable
/// (used by the I1 credential-throttle tests and the I6 metrics tests).
async fn req_bearer(
    app: Router,
    method: &str,
    uri: &str,
    token: &str,
) -> (StatusCode, HeaderMap, String) {
    req_authorization(app, method, uri, &format!("Bearer {token}")).await
}

/// GET/POST with a raw `Authorization` header value (any scheme), so the
/// scheme-parsing rules can be exercised without hardcoding `Bearer`.
async fn req_authorization(
    app: Router,
    method: &str,
    uri: &str,
    value: &str,
) -> (StatusCode, HeaderMap, String) {
    let mut built = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", value)
        .body(Body::empty())
        .unwrap();
    built
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::IpAddr::from([127, 0, 0, 1]),
            12345,
        ))));
    let res = app.oneshot(built).await.unwrap();
    let s = res.status();
    let h = res.headers().clone();
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    (s, h, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn private_routes_401_without_auth() {
    let app = build_router(test_state());
    for (m, u) in [
        ("GET", "/api/session"),
        ("GET", "/api/client"),
        ("POST", "/api/client"),
        ("POST", "/api/client/1/psk"),
        ("DELETE", "/api/client/1/psk"),
        ("GET", "/api/admin/general"),
        ("POST", "/api/admin/interface/restart"),
        ("GET", "/api/client/1/configuration"),
        ("GET", "/api/me/tokens"),
        ("POST", "/api/me/tokens"),
        ("DELETE", "/api/me/tokens/1"),
        ("GET", "/api/admin/tokens"),
        ("DELETE", "/api/admin/tokens/1"),
    ] {
        let (s, _, _) = req(app.clone(), m, u, None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{m} {u}");
    }
}

#[tokio::test]
async fn information_never_500_and_public() {
    let app = build_router(test_state());
    let (s, _, body) = req(app, "GET", "/api/information", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("oauthEnabled"), "{body}");
    // M11: no in-process GitHub check, the field is a constant null.
    assert!(body.contains("\"release\":null"), "{body}");
}

#[tokio::test]
async fn cnf_unknown_404_expired_410() {
    let app = build_router(test_state());
    let (s, _, _) = req(app.clone(), "GET", "/cnf/nope", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s2, _, _) = req(app, "GET", "/cnf/expired", None).await;
    assert_eq!(s2, StatusCode::GONE);
}

/// Real-router proof that the 404 fallback renders `ui::oops` (lot 9) and not
/// the `render().unwrap_or_else(|_| "not found")` safety string: the `oops`
/// markup is the only thing that can produce `<div class="oops">`.
#[tokio::test]
async fn fallback_404_renders_shared_oops_macro() {
    let app = build_router(test_state());
    let (s, _, body) = req(app, "GET", "/definitely-not-a-route", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(body.contains(r#"<div class="oops">"#), "{body}");
    assert!(body.contains(r#"class="oops__code">404</span>"#), "{body}");
    assert!(body.contains(r#"class="btn" href="/""#), "{body}");
    assert!(body.contains("Page not found."), "{body}");
}

/// The 500 page has no HTTP route: `internal_page` is the only entry point,
/// so the shared `oops` macro is proven here.
#[tokio::test]
async fn internal_page_500_renders_shared_oops_macro() {
    let page =
        crate::web::handlers::ui::internal_page(&test_state(), "en", "system".to_owned()).await;
    let body = askama::Template::render(&page).unwrap();
    assert!(body.contains(r#"<div class="oops">"#), "{body}");
    assert!(body.contains(r#"class="oops__code">500</span>"#), "{body}");
    assert!(body.contains(r#"class="btn" href="/""#), "{body}");
}

#[tokio::test]
async fn setup_api_forbidden_when_finished() {
    let app = build_router(finished_state());
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/setup/2")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"username":"a","password":"123456789012"}"#))
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::IpAddr::from([127, 0, 0, 1]),
            12345,
        ))));
    let res = app.oneshot(req).await.unwrap();
    // v15 answers 400 outside the valid setup step.
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// POST with a JSON body + optional session cookie through the real router.
async fn post_json(
    app: Router,
    uri: &str,
    cookie: Option<&str>,
    body: &str,
) -> (StatusCode, HeaderMap, String) {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(c) = cookie {
        b = b.header("cookie", c);
    }
    let mut built = b.body(Body::from(body.to_owned())).unwrap();
    built
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::IpAddr::from([127, 0, 0, 1]),
            12345,
        ))));
    let res = app.oneshot(built).await.unwrap();
    let s = res.status();
    let h = res.headers().clone();
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    (s, h, String::from_utf8_lossy(&body).into_owned())
}

/// `POST /api/setup/2` (bootstrap, step 1) must mint the admin session cookie
/// on the same response so the wizard's browser is authenticated for the
/// endpoint step.
#[tokio::test]
async fn setup_step2_mints_admin_session_cookie() {
    let app = build_router(test_state());
    let (s, h, _) = post_json(
        app,
        "/api/setup/2",
        None,
        r#"{"username":"admin","password":"long-enough-12"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let cookie = h
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(cookie.starts_with("wg-ez="), "cookie manquant: {cookie:?}");
    assert!(
        cookie.contains("HttpOnly"),
        "cookie non HttpOnly: {cookie:?}"
    );
    assert!(
        cookie.contains("SameSite=Lax"),
        "cookie SameSite: {cookie:?}"
    );
}

/// I5: after step 2 an admin exists, so the endpoint step must be
/// admin-authenticated. Anonymous -> 401, non-admin -> 403, admin -> 200.
/// Proven through the real axum router (never by calling the handler directly).
#[tokio::test]
async fn setup_step3_requires_admin_session() {
    let app = build_router(setup_step3_state());
    let body = r#"{"host":"vpn.example.com","port":51820}"#;

    // Anonymous POST -> 401 (Auth extractor rejects before the step check).
    let (s, _, _) = post_json(app.clone(), "/api/setup/3", None, body).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "anon POST step3");

    // Non-admin session -> 403.
    let (s, _, _) = post_json(app.clone(), "/api/setup/3", Some("wg-ez=client"), body).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "client POST step3");

    // Admin session -> 200.
    let (s, _, _) = post_json(app.clone(), "/api/setup/3", Some("wg-ez=valid"), body).await;
    assert_eq!(s, StatusCode::OK, "admin POST step3");

    // GET suggest is admin-gated too.
    let (s, _, _) = req(app.clone(), "GET", "/api/setup/3", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "anon GET step3");
    let (s, _, _) = req(app, "GET", "/api/setup/3", Some("wg-ez=valid")).await;
    assert_eq!(s, StatusCode::OK, "admin GET step3");
}

/// Un appelant htmx dont la session est morte ne doit jamais recevoir la
/// page de login : htmx suit un 303 et l'echange dans sa cible, ce qui
/// incrustait une seconde `<nav>/<main>/<footer>` dans `#grid` (le sondage
/// de `/`). Il doit recevoir `401` + `HX-Redirect`.
#[tokio::test]
async fn dead_session_hx_get_uses_hx_redirect_not_a_swappable_page() {
    let app = build_router(finished_state());
    for u in ["/", "/me", "/admin/general"] {
        let mut r = Request::builder()
            .method("GET")
            .uri(u)
            .header("hx-request", "true")
            .body(Body::empty())
            .unwrap();
        r.extensions_mut()
            .insert(ConnectInfo(std::net::SocketAddr::from((
                std::net::IpAddr::from([127, 0, 0, 1]),
                12345,
            ))));
        let res = app.clone().oneshot(r).await.unwrap();
        let s = res.status();
        let h = res.headers().clone();
        let body = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{u}");
        assert_eq!(
            h.get("hx-redirect").map(|v| v.to_str().unwrap()),
            Some("/login"),
            "{u}"
        );
        assert!(
            !h.contains_key("location"),
            "{u} ne doit pas rediriger par 3xx"
        );
        assert!(!body.contains("<footer"), "{u} ne renvoie aucune page HTML");
    }
    // Sans htmx : le 303 vers /login reste la reponse attendue.
    let (s, h, body) = req(app, "GET", "/", None).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(
        h.get("location").map(|v| v.to_str().unwrap()),
        Some("/login")
    );
    assert!(body.is_empty());
}

#[tokio::test]
async fn csp_headers_present_no_inline() {
    let app = build_router(test_state());
    let (s, h, _) = req(app, "GET", "/api/information", None).await;
    assert_eq!(s, StatusCode::OK);
    let csp = h.get("content-security-policy").unwrap().to_str().unwrap();
    assert!(csp.contains("script-src 'self'"), "{csp}");
}

/// M9 : la page authentifiée porte tous les en-têtes de durcissement, y
/// compris les nouveaux (`Permissions-Policy`, COOP, CORP), sans que les
/// existants (CSP/nosniff/XFO/Referrer-Policy) ni le `no-store` I7 ne
/// disparaissent.
#[tokio::test]
async fn security_headers_present_on_authenticated_page() {
    let app = build_router(insecure_state(false));
    let (s, h, _) = req(app, "GET", "/", Some("wg-ez=valid")).await;
    assert_eq!(s, StatusCode::OK);

    assert_eq!(
        h.get("permissions-policy").and_then(|v| v.to_str().ok()),
        Some(
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), \
             magnetometer=(), microphone=(), payment=(), usb=()"
        )
    );
    assert_eq!(
        h.get("cross-origin-opener-policy")
            .and_then(|v| v.to_str().ok()),
        Some("same-origin")
    );
    assert_eq!(
        h.get("cross-origin-resource-policy")
            .and_then(|v| v.to_str().ok()),
        Some("same-origin")
    );

    // En-têtes historiques toujours présents.
    let csp = h
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(csp.contains("script-src 'self'"), "{csp}");
    assert_eq!(
        h.get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        h.get("x-frame-options").and_then(|v| v.to_str().ok()),
        Some("DENY")
    );
    assert_eq!(
        h.get("referrer-policy").and_then(|v| v.to_str().ok()),
        Some("same-origin")
    );

    // I7 : le no-store dynamique reste posé.
    assert_eq!(
        h.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
}

/// M9 : HSTS est conditionnel à `!INSECURE`. En HTTPS il est posé avec la
/// longue durée partagée ; en HTTP il est **absent** (sinon le navigateur
/// forcerait HTTPS et casserait le déploiement `INSECURE=true`).
#[tokio::test]
async fn hsts_present_only_when_https() {
    let app = build_router(insecure_state(false));
    let (s, h, _) = req(app, "GET", "/", Some("wg-ez=valid")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        h.get("strict-transport-security")
            .and_then(|v| v.to_str().ok()),
        Some("max-age=31536000; includeSubDomains"),
        "HTTPS doit porter HSTS"
    );

    let app = build_router(insecure_state(true));
    let (s2, h2, _) = req(app, "GET", "/", Some("wg-ez=valid")).await;
    assert_eq!(s2, StatusCode::OK);
    assert!(
        !h2.contains_key("strict-transport-security"),
        "HTTP ne doit JAMAIS porter HSTS"
    );
}

/// M9 : les assets `static/` passent par le middleware global et reçoivent
/// donc les en-têtes de sécurité, mais gardent leur `Cache-Control` I7, ne
/// reçoivent pas de `Vary: Cookie` et — en HTTP — aucun HSTS incohérent.
#[tokio::test]
async fn static_assets_get_security_headers_without_hsts_in_http() {
    let app = build_router(insecure_state(true));
    let (s, h, _) = req(app, "GET", "/static/js/app.js", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        h.get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert!(
        !h.contains_key("strict-transport-security"),
        "asset en HTTP : pas de HSTS"
    );
    assert!(!h.contains_key("vary"), "assets sans Vary: Cookie");
    let cc = h
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(cc.starts_with("public"), "cache-control asset: {cc:?}");
    assert!(!cc.contains("no-store"), "asset surmarque: {cc:?}");
}

/// I7 : toute reponse DYNAMIQUE est `no-store` (page HTML authentifiee, JSON
/// API, `.conf` qui porte la cle privee, QR SVG qui l'encode, lien OTL public,
/// metriques). Le middleware global s'en charge ; `conf_attachment` le pose
/// aussi explicitement. `Vary: Cookie` accompagne le `no-store`.
#[tokio::test]
async fn dynamic_responses_are_no_store() {
    let app = build_router(finished_state());
    fn cc(h: &HeaderMap) -> Option<&str> {
        h.get("cache-control").and_then(|v| v.to_str().ok())
    }

    // Page HTML authentifiee.
    let (s, h, _) = req(app.clone(), "GET", "/", Some("wg-ez=valid")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(cc(&h), Some("no-store"), "GET / doit etre no-store");
    assert_eq!(
        h.get("vary").and_then(|v| v.to_str().ok()),
        Some("Cookie"),
        "Vary: Cookie manquant"
    );

    // JSON API authentifiee.
    let (s, h, _) = req(app.clone(), "GET", "/api/client/1", Some("wg-ez=valid")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(cc(&h), Some("no-store"), "JSON API no-store");

    // `.conf` : contient la cle privee -> defense en profondeur explicite.
    let (s, h, body) = req(
        app.clone(),
        "GET",
        "/api/client/1/configuration",
        Some("wg-ez=valid"),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("PrivateKey"), "{body}");
    assert_eq!(cc(&h), Some("no-store"), ".conf no-store");

    // QR SVG : encode la meme cle privee.
    let (s, h, _) = req(
        app.clone(),
        "GET",
        "/api/client/1/qrcode.svg",
        Some("wg-ez=valid"),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(cc(&h), Some("no-store"), "QR SVG no-store");

    // Lien OTL public (sans auth).
    let (s, h, _) = req(app.clone(), "GET", "/cnf/valid", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(cc(&h), Some("no-store"), "/cnf/:token no-store");

    // Metriques (Bearer requis, I6).
    let (s, h, _) = req_bearer(app, "GET", "/metrics/json", "scrape-secret").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(cc(&h), Some("no-store"), "metriques no-store");
}

/// I7 : les assets `static/` gardent leur propre politique de cache et ne
/// recoivent NI le `no-store` global NI un `Vary: Cookie` parasite.
#[tokio::test]
async fn static_assets_keep_their_cache_control() {
    let app = build_router(finished_state());

    let (s, h, _) = req(app.clone(), "GET", "/static/js/app.js", None).await;
    assert_eq!(s, StatusCode::OK);
    let cc = h
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(cc.starts_with("public"), "asset cache-control: {cc:?}");
    assert!(!cc.contains("no-store"), "asset surmarque: {cc:?}");
    assert!(!h.contains_key("vary"), "assets sans Vary: Cookie");

    let (s, h, _) = req(app, "GET", "/static/vendor/htmx.min.js", None).await;
    assert_eq!(s, StatusCode::OK);
    let cc = h
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        cc.contains("max-age=31536000"),
        "vendor cache-control: {cc:?}"
    );
}

/// I7 : une requete conditionnelle sur un asset renvoie `304` en CONSERVANT
/// `Cache-Control` et `ETag` (le middleware ne les remplace pas).
#[tokio::test]
async fn static_304_keeps_cache_control() {
    let app = build_router(finished_state());
    let (s, h, _) = req(app.clone(), "GET", "/static/js/app.js", None).await;
    assert_eq!(s, StatusCode::OK);
    let etag = h
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .expect("static_file doit poser un ETag");

    let mut built = Request::builder()
        .method("GET")
        .uri("/static/js/app.js")
        .header("if-none-match", &etag)
        .body(Body::empty())
        .unwrap();
    built
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::IpAddr::from([127, 0, 0, 1]),
            12345,
        ))));
    let res = app.oneshot(built).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(
        res.headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("public, no-cache"),
        "le 304 doit conserver son cache-control"
    );
    assert_eq!(
        res.headers().get("etag").and_then(|v| v.to_str().ok()),
        Some(etag.as_str()),
        "le 304 doit conserver son ETag"
    );
}

#[tokio::test]
async fn metrics_disabled_400() {
    // A configured Bearer is required to reach the "disabled" branch now
    // that `metrics_check` is fail-closed (no password would answer 401
    // before the flag is even consulted).
    let state = AppState::new(
        Arc::new(backend(0, (false, false), Some("scrape-secret"))),
        crate::web::ctx::Locales::load().expect("locales"),
        vec![],
    );
    let app = build_router(state);
    // v15 answers 400 (not 404) when the endpoint is disabled.
    let (s, _, _) = req_bearer(app.clone(), "GET", "/metrics/prometheus", "scrape-secret").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s2, _, _) = req_bearer(app, "GET", "/metrics/json", "scrape-secret").await;
    assert_eq!(s2, StatusCode::BAD_REQUEST);
}

/// M10 : créer un client en doublon (nom/IP/clé déjà pris) via le VRAI routeur
/// répond 400 et le corps ne divulgue aucun détail SQLite : ni `UNIQUE`, ni
/// `constraint`, ni nom de table/colonne (`clients.`, `ipv4Address`), ni
/// `sqlite`. Le détail reste côté serveur (loggé par `db_err`).
#[tokio::test]
async fn duplicate_client_400_hides_sqlite_details() {
    let app = build_router(finished_state());
    let (s, _, body) = post_json(
        app,
        "/api/client",
        Some("wg-ez=valid"),
        r#"{"name":"duplicate"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    for needle in [
        "UNIQUE",
        "constraint",
        "clients.",
        "clients(",
        "ipv4Address",
        "publicKey",
        "sqlite",
        "SQLite",
    ] {
        assert!(
            !body.contains(needle),
            "fuite interne {needle:?} dans le corps 400 : {body}"
        );
    }
    assert!(
        body.contains("conflict"),
        "corps générique attendu : {body}"
    );
}

/// I6 : les métriques ne peuvent PAS être exposées sans Bearer.
/// 1. activation sans mot de passe -> 400, rien n'est persisté ;
/// 2. activation avec mot de passe -> 200 ;
/// 3. `/metrics/json` sans Bearer -> 401, avec le bon Bearer -> 200 ;
/// 4. un champ password vide conserve le hash existant ;
/// 5. `GET /api/admin/general` n'expose jamais la valeur, seulement
///    `metricsPasswordSet` ;
/// 6. désactivation -> 200.
#[tokio::test]
async fn metrics_require_bearer_and_password_is_never_exposed() {
    let state = AppState::new(
        Arc::new(backend(0, (false, false), None)),
        crate::web::ctx::Locales::load().expect("locales"),
        vec![],
    );
    let app = build_router(state);

    // 1 · activation sans mot de passe -> 400.
    let (s, _, body) = post_json(
        app.clone(),
        "/api/admin/general",
        Some("wg-ez=valid"),
        r#"{"metricsPrometheus":true}"#,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");

    // 2 · activation avec mot de passe -> 200.
    let (s, _, body) = post_json(
        app.clone(),
        "/api/admin/general",
        Some("wg-ez=valid"),
        r#"{"metricsPrometheus":true,"metricsJson":true,"metricsPassword":"scrape-secret"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert!(body.contains(r#""metricsPasswordSet":true"#), "{body}");
    assert!(
        !body.contains("scrape-secret"),
        "le clair ne doit jamais sortir : {body}"
    );

    // 3 · sans Bearer -> 401 ; avec le bon Bearer -> 200.
    let (s, _, _) = req(app.clone(), "GET", "/metrics/json", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, _) = req_bearer(app.clone(), "GET", "/metrics/json", "scrape-secret").await;
    assert_eq!(s, StatusCode::OK);

    // 4 · champ password vide = inchangé (le Bearer existant marche encore).
    let (s, _, body) = post_json(
        app.clone(),
        "/api/admin/general",
        Some("wg-ez=valid"),
        r#"{"metricsPassword":"","metricsPrometheus":true,"metricsJson":true}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert!(body.contains(r#""metricsPasswordSet":true"#), "{body}");
    let (s, _, _) = req_bearer(app.clone(), "GET", "/metrics/json", "scrape-secret").await;
    assert_eq!(s, StatusCode::OK, "le mot de passe doit avoir été conservé");

    // 5 · l'API ne renvoie que le booléen.
    let (s, _, body) = req(
        app.clone(),
        "GET",
        "/api/admin/general",
        Some("wg-ez=valid"),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains(r#""metricsPasswordSet":true"#), "{body}");
    assert!(!body.contains("scrape-secret"), "{body}");

    // 6 · désactivation -> 200.
    let (s, _, body) = post_json(
        app.clone(),
        "/api/admin/general",
        Some("wg-ez=valid"),
        r#"{"metricsPrometheus":false,"metricsJson":false}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
}

/// I6 : la page admin expose un champ password jamais pré-rempli.
#[tokio::test]
async fn admin_general_exposes_password_field() {
    let app = build_router(finished_state());
    let (s, _, body) = req(app, "GET", "/admin", Some("wg-ez=valid")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        body.contains(r#"type="password" name="metricsPassword""#),
        "{body}"
    );
    assert!(body.contains(r#"autocomplete="new-password""#), "{body}");
    assert!(
        body.contains("Leave empty to keep the current password"),
        "{body}"
    );
}

#[tokio::test]
async fn noncanonical_paths_redirect_308() {
    let app = build_router(finished_state());
    // `//` doubling always redirects (audit T11).
    for u in ["//api//information", "/setup/"] {
        let (s, h, _) = req(app.clone(), "GET", u, None).await;
        assert_eq!(s, StatusCode::PERMANENT_REDIRECT, "{u}");
        assert!(h.contains_key("location"), "{u}");
    }
    // API-style trailing slashes are strict like v15 (audit K04/T12/T19).
    for u in ["/api/information/", "/metrics/prometheus/", "/cnf/"] {
        let (s, _, _) = req(app.clone(), "GET", u, None).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{u}");
    }
    // Canonical paths are untouched.
    let (s, _, _) = req(app, "GET", "/api/information", None).await;
    assert_eq!(s, StatusCode::OK);
}

/// Bandeau d'identite : `/` et l'administration reprennent la grammaire de
/// `/me` (`.pad` > `h1.display--h3` + `.row` de `.pill`). Teste via le vrai
/// routeur authentifie, jamais en appelant les handlers.
#[tokio::test]
async fn identity_band_on_clients_and_admin() {
    let app = build_router(finished_state());
    let (s, _, body) = req(app.clone(), "GET", "/", Some("wg-ez=valid")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains(r#"class="pad""#), "bandeau clients absent");
    assert!(body.contains("display display--h3"), "titre clients absent");
    assert!(
        body.contains(r#"class="row""#),
        "pastilles clients absentes"
    );
    assert!(body.contains("0 Clients"), "compteur clients absent");
    assert!(
        body.contains("version 0.0.0-test"),
        "version clients absente"
    );
    // Le compte de pairs connectes de la topbar est le composant temps reel
    // partage (partial `peers.html`) : long-poll htmx, plus de `#watch` sur `/`.
    assert!(
        body.contains(r#"id="peer-count""#),
        "compte pairs topbar absent"
    );
    assert!(
        body.contains(r#"hx-get="/api/status/stream""#),
        "long-poll topbar absent"
    );
    assert!(
        !body.contains(r#"id="watch""#),
        "ancien sondeur #watch encore la"
    );

    let (s2, _, body2) = req(app, "GET", "/admin", Some("wg-ez=valid")).await;
    assert_eq!(s2, StatusCode::OK);
    assert!(body2.contains(r#"class="pad""#), "bandeau admin absent");
    assert!(body2.contains(r#"class="row""#), "pastilles admin absentes");
    assert!(
        body2.contains(r#"pill pill--live">Admin"#),
        "role admin absent"
    );
    assert!(
        body2.contains("version 0.0.0-test"),
        "version admin absente"
    );
}

/// Long-poll `/api/status/stream`: aucune mutation — il pousse le trigger et
/// le compte de pairs connectes. Non authentifie il suit la regle UI (303
/// sans htmx, 401 + `HX-Redirect` avec), pour ne jamais incruster la page de
/// login.
#[tokio::test]
async fn status_stream_requires_auth_with_hx_redirect() {
    let app = build_router(finished_state());
    let (s, h, _) = req(app.clone(), "GET", "/api/status/stream", None).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(
        h.get("location").and_then(|v| v.to_str().ok()),
        Some("/login")
    );

    let mut r = Request::builder()
        .method("GET")
        .uri("/api/status/stream")
        .header("hx-request", "true")
        .body(Body::empty())
        .unwrap();
    r.extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::IpAddr::from([127, 0, 0, 1]),
            12345,
        ))));
    let res = app.oneshot(r).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        res.headers()
            .get("hx-redirect")
            .map(|v| v.to_str().unwrap()),
        Some("/login")
    );
}

/// Le long-poll authentifie resout des le premier changement de statut (au
/// 2e tick du watcher : le 1er ne fait que s'initialiser), renvoie les deux
/// triggers (`refreshGridLive` pour la grille, `pollAgain` pour le
/// re-armement) ET le compte de pairs connectes comme corps.
#[tokio::test]
async fn status_stream_pushes_live_refresh() {
    let app = build_router(finished_state());
    // Le watcher sonde toutes les 5 s (`POLL_INTERVAL`) : marge au-dessus.
    let (s, h, body) = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        req(app, "GET", "/api/status/stream", Some("wg-ez=valid")),
    )
    .await
    .expect("le stream doit resoudre en un tick du watcher");
    assert_eq!(s, StatusCode::OK);
    let trigger = h
        .get("hx-trigger")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(trigger.contains("refreshGridLive"), "{trigger}");
    assert!(trigger.contains("pollAgain"), "{trigger}");
    assert_eq!(body, "1", "le corps porte le compte connecte");
}

/// M5 : le long-poll est plafonne. On sature tous les slots sur le watcher
/// partage (le `AppState` cloné par le routeur pointe le même `Arc`), puis la
/// route VRAIE doit répondre `429` **immédiatement** au lieu de garer la
/// connexion. Déterministe — la réserve échoue avant tout `await` de flux.
#[tokio::test]
async fn status_stream_is_429_when_stream_cap_reached() {
    let state = finished_state();
    let mut held = Vec::new();
    for i in 0..crate::web::watcher::MAX_STREAMS {
        // Une IP distincte par slot pour ne pas déclencher le plafond par IP.
        let ip = std::net::IpAddr::from([10, 0, 0, i as u8 + 1]);
        held.push(
            state
                .watcher
                .subscribe(ip)
                .unwrap_or_else(|| panic!("slot {i} must be granted")),
        );
    }
    let app = build_router(state);
    let (s, _, _) = req(app, "GET", "/api/status/stream", Some("wg-ez=valid")).await;
    assert_eq!(
        s,
        StatusCode::TOO_MANY_REQUESTS,
        "un stream au-dela du plafond doit repondre 429"
    );
}

/// Preuve de rendu de la fiche client via le VRAI routeur (lot 10) : la page
/// consomme desormais les macros `ui::` (phead/pill/field/hidden/note) au lieu
/// de balisage duplique. On verifie les marqueurs produits par chaque macro,
/// dont les attributs `placeholder`/`min`/`max` ajoutes a `ui::field`.
#[tokio::test]
async fn client_detail_renders_shared_ui_macros() {
    let app = build_router(finished_state());
    let (s, _, body) = req(app, "GET", "/clients/1", Some("wg-ez=valid")).await;
    assert_eq!(s, StatusCode::OK);
    // Bandeau d'identite : `ui::pill` d'etat + IP v4/v6 joignes par `·`.
    assert!(body.contains("pill pill--live"), "{body}");
    assert!(body.contains("pill pill--warn"), "{body}");
    assert!(body.contains("10.8.0.2 · fd42::2"), "{body}");
    // `ui::phead` (trois panneaux) au lieu du `.panel__head` inline.
    assert!(body.contains(r#"class="panel__head""#), "{body}");
    // `ui::field` : nombres bornes + placeholders herites.
    assert!(body.contains(r#"name="mtu""#), "{body}");
    assert!(
        body.contains(r#"min="1024""#) && body.contains(r#"max="9000""#),
        "{body}"
    );
    assert!(body.contains(r#"name="persistentKeepalive""#), "{body}");
    assert!(body.contains(r#"placeholder="25-12-2031""#), "{body}");
    assert!(
        body.contains(r#"placeholder="vpn.example.com:51820""#),
        "{body}"
    );
    // `ui::hidden` : rejoue `enabled` (sinon chaque Save desactiverait).
    assert!(
        body.contains(r#"type="hidden" name="enabled" value="true""#),
        "{body}"
    );
    // `ui::note` (PSK) + zone danger partagee.
    assert!(body.contains(r#"class="note""#), "{body}");
    assert!(body.contains("Danger zone"), "{body}");
}

/// La fiche UI `/clients/{id}` ne doit pas fuir l'existence : un CLIENT sur
/// l'id d'un autre obtient le même 404 qu'un id inconnu (parité avec
/// `load_client` côté API), tandis que son propre client et un ADMIN
/// obtiennent 200. Prouvé via le vrai routeur.
#[tokio::test]
async fn ui_client_detail_foreign_is_404_not_403() {
    let app = build_router(finished_state());

    // CLIENT (user 2) sur le client id 1 (user 1) : 404, pas 403 ...
    let (s, _, body) = req(app.clone(), "GET", "/clients/1", Some("wg-ez=client")).await;
    assert_eq!(
        s,
        StatusCode::NOT_FOUND,
        "CLIENT étranger /clients/1 : {body}"
    );
    // ... identique à un id inconnu (pas d'oracle).
    let (s_unknown, _, body_unknown) =
        req(app.clone(), "GET", "/clients/999999", Some("wg-ez=client")).await;
    assert_eq!(s_unknown, StatusCode::NOT_FOUND);
    assert_eq!(
        body, body_unknown,
        "les deux 404 doivent être indiscernables"
    );

    // Son propre client reste visible ...
    let (s, _, _) = req(app.clone(), "GET", "/clients/2", Some("wg-ez=client")).await;
    assert_eq!(s, StatusCode::OK, "propre client");
    // ... comme pour un ADMIN sur n'importe quel client.
    let (s, _, _) = req(app, "GET", "/clients/1", Some("wg-ez=valid")).await;
    assert_eq!(s, StatusCode::OK, "ADMIN");
}

/// login/2FA : titres-cartes passes par `ui::phead_h1` (lot 10) et champs
/// `ui::field`. Depuis le durcissement FAIBLE, la 2FA ne reflechit plus aucun
/// id `pending` (ni champ cache, ni URL) : il vit uniquement dans le cookie
/// `wg-ez-pending`.
#[tokio::test]
async fn login_pages_use_shared_phead_h1() {
    let app = build_router(finished_state());
    let (s, _, body) = req(app.clone(), "GET", "/login", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        body.contains(r#"<h1 class="panel__t display display--h3">"#),
        "{body}"
    );
    assert!(body.contains("version 0.0.0-test"), "{body}");
    let (s2, _, body2) = req(app, "GET", "/login/2fa", None).await;
    assert_eq!(s2, StatusCode::OK);
    assert!(
        body2.contains(r#"<h1 class="panel__t display display--h3">"#),
        "{body2}"
    );
    // Aucun id `pending` dans la page (le cookie porte le secret).
    assert!(
        !body2.contains(r#"name="pending""#),
        "le champ cache pending ne doit plus exister : {body2}"
    );
    assert!(!body2.contains("?pending="), "{body2}");
}

/// Setup step1..3 : rail `ui::wizard`, titre-carte `ui::phead_h1`, et le port
/// de step3 desormais via `ui::field` (`min`/`max`). Le bandeau `ui::hint` a
/// ete retire.
#[tokio::test]
async fn setup_pages_render_shared_macros() {
    let app = build_router(test_state());
    for step in ["/setup/1", "/setup/2", "/setup/3"] {
        let (s, _, body) = req(app.clone(), "GET", step, None).await;
        assert_eq!(s, StatusCode::OK, "{step}");
        assert!(body.contains(r#"class="wizard""#), "{step}");
        assert!(
            body.contains(r#"<h1 class="panel__t display display--h3">"#),
            "{step}"
        );
        assert!(!body.contains(r#"class="hint""#), "{step}");
    }
    let (_, _, body3) = req(app, "GET", "/setup/3", None).await;
    assert!(body3.contains(r#"name="port""#), "{body3}");
    assert!(
        body3.contains(r#"min="1""#) && body3.contains(r#"max="65535""#),
        "{body3}"
    );
}

/// R4 : le socle `SetupCommon` garde les 3 etapes localisees FR/EN (rail,
/// titre, nav) et le gating `setupStep == 0` redirige vers `/login` (303)
/// au lieu de rendre le wizard.
#[tokio::test]
async fn setup_pages_localized_and_gated() {
    let app = build_router(test_state());
    // FR : titres, CTA, nav et rail traduits sur chaque etape.
    let (s, _, fr1) = req(app.clone(), "GET", "/setup/1?lang=fr", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(fr1.contains("Bienvenue sur wg-ez"), "{fr1}");
    assert!(fr1.contains("Suivant"), "{fr1}");
    let (s, _, fr2) = req(app.clone(), "GET", "/setup/2?lang=fr", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(fr2.contains("Créer le compte admin"), "{fr2}");
    assert!(
        fr2.contains("Créer l&#39;admin") || fr2.contains("Créer l'admin"),
        "{fr2}"
    );
    assert!(fr2.contains("Retour"), "{fr2}");
    assert!(fr2.contains("Admin"), "{fr2}");
    let (s, _, fr3) = req(app.clone(), "GET", "/setup/3?lang=fr", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(fr3.contains("Endpoint public"), "{fr3}");
    assert!(fr3.contains("Terminer le setup"), "{fr3}");
    assert!(fr3.contains("Retour"), "{fr3}");
    // EN : memes etapes, autres libelles, meme squelette.
    let (s, _, en1) = req(app.clone(), "GET", "/setup/1?lang=en", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(en1.contains("Welcome to wg-ez"), "{en1}");
    assert!(en1.contains("Next"), "{en1}");
    assert!(en1.contains("Welcome"), "{en1}");
    let (s, _, en2) = req(app.clone(), "GET", "/setup/2?lang=en", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(en2.contains("Create the admin account"), "{en2}");
    assert!(en2.contains("Create admin"), "{en2}");
    assert!(en2.contains("Back"), "{en2}");
    let (s, _, en3) = req(app.clone(), "GET", "/setup/3?lang=en", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(en3.contains("Public endpoint"), "{en3}");
    assert!(en3.contains("Finish setup"), "{en3}");
    assert!(en3.contains(r#"name="host""#), "{en3}");
    assert!(en3.contains(r#"name="port""#), "{en3}");
    assert!(en3.contains(r#"href="/setup/2""#), "{en3}");
    // Gating : setup termine -> 303 /login sur les 3 etapes.
    let done = build_router(finished_state());
    for step in ["/setup/1", "/setup/2", "/setup/3"] {
        let (s, h, body) = req(done.clone(), "GET", step, None).await;
        assert_eq!(s, StatusCode::SEE_OTHER, "{step}");
        assert_eq!(
            h.get("location").map(|v| v.to_str().unwrap()),
            Some("/login"),
            "{step}"
        );
        assert!(body.is_empty(), "{step}");
    }
}

/// `/me` : bandeau `ui::pill`, panneaux `ui::phead`, lecture-seule `ui::kv1`,
/// champs `ui::field`, envoi `ui::submit`, queue `ui::tail`.
#[tokio::test]
async fn me_page_renders_shared_macros() {
    let app = build_router(finished_state());
    let (s, _, body) = req(app, "GET", "/me", Some("wg-ez=valid")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains(r#"class="panel__head""#), "{body}");
    assert!(body.contains(r#"class="flabel""#), "{body}");
    assert!(body.contains(r#"class="actions""#), "{body}");
    assert!(body.contains("mesh--tail"), "{body}");
    // Le profil expose le changement de nom de connexion (garde mot de passe
    // courant cote backend, validation unique cote backend).
    assert!(body.contains(r#"hx-post="/api/me/username""#), "{body}");
    assert!(body.contains(r#"name="currentPassword""#), "{body}");
}

/// Jetons d'API sur `/me` : aucun commentaire askama ne fuit (`#}` brut
/// absent de `/me` comme de `/admin`), les champs de création portent leurs
/// exemples (`placeholder`), et la liste rend une grille à colonnes fixes
/// (nom en `strong` + 3 valeurs en `.trow__v.num` mono tabulaires + ligne de
/// tête `trow--head` en `.hud`, sans carte ni pastille ni préfixe ni `dl.kv`,
/// dates courtes `JJ-MM-AAAA`, expiration permanente comme les clients,
/// révocation `hx-delete`).
/// Prouvé via le vrai routeur, après création par la vraie route
/// `POST /api/me/tokens`.
#[tokio::test]
async fn me_tokens_list_dense_rows_placeholders_no_template_leak() {
    let (app, _) = token_state();
    for url in ["/me", "/admin"] {
        let (s, _, body) = req(app.clone(), "GET", url, Some("wg-ez=valid")).await;
        assert_eq!(s, StatusCode::OK, "{url}");
        assert!(
            !body.contains("#}"),
            "commentaire askama en fuite sur {url}"
        );
    }
    let (s, _, body) = req(app.clone(), "GET", "/me", Some("wg-ez=valid")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains(r#"placeholder="25-12-2031""#), "{body}");
    // Chapeau du panneau jetons : compteur « X API tokens » (meme `.hud` que le
    // username a droite de « Profile ») au lieu de l'ancien etat vide texte.
    assert!(body.contains("0 API tokens"), "{body}");
    assert!(!body.contains("No API tokens yet."), "{body}");
    // Crée un jeton daté par la vraie route : la liste doit rendre la ligne
    // en grille (nom en gras, valeurs mono alignées, révocation).
    let (s, _, created) = post_json(
        app.clone(),
        "/api/me/tokens",
        Some("wg-ez=valid"),
        r#"{"name":"ci","expiresAt":"2027-01-02T00:00:00Z"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, _) = created_token(&created);
    let (s, _, body) = req(app.clone(), "GET", "/me", Some("wg-ez=valid")).await;
    assert_eq!(s, StatusCode::OK);
    // Le compteur du chapeau suit la liste (un jeton créé ci-dessus).
    assert!(body.contains("1 API tokens"), "{body}");
    // Le formulaire de création ne swap rien et porte les libellés de la
    // modale en `data-t-*` (lus par `app.js`, zéro texte en dur côté JS) ;
    // l'ancien slot d'affichage unique a disparu.
    assert!(body.contains(r#"id="token-form""#), "{body}");
    assert!(
        body.contains(r#"id="token-form" hx-post="/api/me/tokens" hx-swap="none""#),
        "{body}"
    );
    assert!(body.contains(r#"data-t-title="New API token""#), "{body}");
    assert!(body.contains(r#"data-t-copy="Copy token""#), "{body}");
    assert!(body.contains(r#"data-t-copied="Token copied.""#), "{body}");
    assert!(!body.contains("token-slot"), "{body}");
    // UNE ligne de grille par jeton : tête en `.hud`, nom en gras, 3 valeurs
    // mono tabulaires alignées (`trow__v num`), RÉVOQUER en dernière colonne.
    // Pas de colonne préfixe (reste dans l'API JSON uniquement).
    assert!(body.contains(r#"<li class="trow">"#), "{body}");
    assert!(body.contains(r#"class="trow trow--head""#), "{body}");
    // Fantôme du bouton dans l'en-tête : sans lui la piste `auto` vaudrait 0
    // et toutes les colonnes seraient décalées par rapport aux lignes.
    assert!(body.contains("trow__ghost"), "{body}");
    assert!(body.contains(r#"<strong>ci</strong>"#), "{body}");
    assert!(body.contains(r#"class="trow__v num""#), "{body}");
    // Chaque valeur voyage avec son libellé (affiché en mobile).
    assert!(body.contains(r#"class="hud trow__lab""#), "{body}");
    // Le préfixe n'est plus exposé nulle part (ni UI, ni API).
    assert!(!body.contains("prefix"), "préfixe en fuite : {body}");
    assert!(body.contains("02-01-2027"), "{body}");
    assert!(body.contains("01-01-2026"), "{body}");
    assert!(body.contains("Never"), "{body}");
    // Jeton permanent : même système que les clients (`clients.never_expires`,
    // dates `JJ-MM-AAAA` via `display_date`).
    let (s, _, _) = post_json(
        app.clone(),
        "/api/me/tokens",
        Some("wg-ez=valid"),
        r#"{"name":"perm"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, body) = req(app, "GET", "/me", Some("wg-ez=valid")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains(r#"<strong>perm</strong>"#), "{body}");
    assert!(body.contains("Permanent"), "{body}");
    // Ni carte, ni pastille, ni tableau `kv` dans la section jetons.
    let sec = body
        .split(r#"id="api-tokens""#)
        .nth(1)
        .expect("section jetons");
    assert!(!sec.contains("<article"), "carte interdite : {sec}");
    assert!(!sec.contains("<dl"), "tableau kv interdit : {sec}");
    assert!(!sec.contains("class=\"pill"), "pastille interdite : {sec}");
    assert!(
        !body.contains("2026-01-01T00:00:00Z"),
        "ISO brut en fuite : {body}"
    );
    assert!(
        !body.contains("2027-01-02T00:00:00Z"),
        "ISO brut en fuite : {body}"
    );
    assert!(body.contains(r#"hx-delete="/api/me/tokens/1""#), "{body}");
    assert!(!body.contains("#}"), "commentaire askama en fuite : {body}");
}

/// `POST /api/me/username`: the handler forwards both the current password
/// and the new username to the backend (single validation + guard source).
/// Without a session it is 401; with a wrong password the backend refuses
/// (401 + seclog `password`); a UNIQUE conflict surfaces as the generic 400
/// (`conflict`) with no schema detail in the body (M10).
#[tokio::test]
async fn change_username_requires_password_and_hides_conflicts() {
    let app = build_router(finished_state());

    let (s0, _, _) = post_json(
        app.clone(),
        "/api/me/username",
        None,
        r#"{"currentPassword":"correct","username":"newname"}"#,
    )
    .await;
    assert_eq!(s0, StatusCode::UNAUTHORIZED, "no session must be refused");

    let (s1, _, _) = post_json(
        app.clone(),
        "/api/me/username",
        Some("wg-ez=valid"),
        r#"{"currentPassword":"nope","username":"newname"}"#,
    )
    .await;
    assert_eq!(
        s1,
        StatusCode::UNAUTHORIZED,
        "wrong current password must be refused"
    );

    let (s2, _, body2) = post_json(
        app.clone(),
        "/api/me/username",
        Some("wg-ez=valid"),
        r#"{"currentPassword":"correct","username":"newname"}"#,
    )
    .await;
    assert_eq!(s2, StatusCode::OK, "valid password must reach the backend");
    assert!(body2.contains("newname"), "{body2}");

    let (s3, _, body3) = post_json(
        app,
        "/api/me/username",
        Some("wg-ez=valid"),
        r#"{"currentPassword":"correct","username":"taken"}"#,
    )
    .await;
    assert_eq!(s3, StatusCode::BAD_REQUEST, "duplicate must conflict");
    for needle in ["UNIQUE", "constraint", "clients", "sqlite"] {
        assert!(
            !body3.contains(needle),
            "fuite interne {needle:?} dans {body3}"
        );
    }
}

/// `POST /api/me/totp {action:"start"}` doit transmettre le `password` du
/// corps au backend, où vit la garde mot-de-passe-courant (partagée par l'API
/// JSON et l'UI, exigée y compris au premier enrôlement). Sans mot de passe le
/// backend refuse (401 + seclog `password`) ; avec le bon l'enrôlement démarre
/// (200).
#[tokio::test]
async fn totp_start_forwards_password_for_active_2fa_guard() {
    let app = build_router(finished_state());
    let (s, _, _) = post_json(
        app.clone(),
        "/api/me/totp",
        Some("wg-ez=valid"),
        r#"{"action":"start"}"#,
    )
    .await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "missing password must be refused"
    );

    let (s2, _, _) = post_json(
        app,
        "/api/me/totp",
        Some("wg-ez=valid"),
        r#"{"action":"start","password":"correct"}"#,
    )
    .await;
    assert_eq!(
        s2,
        StatusCode::OK,
        "correct password must reach the backend"
    );
}

/// `POST /api/me/totp {action:"confirm"}` exige lui aussi le mot de passe
/// courant : sans lui le backend refuse (401), avec le bon la confirmation
/// passe (200). Prouvé via le vrai routeur.
#[tokio::test]
async fn totp_confirm_requires_current_password() {
    let app = build_router(finished_state());
    let (s, _, _) = post_json(
        app.clone(),
        "/api/me/totp",
        Some("wg-ez=valid"),
        r#"{"action":"confirm","code":"123456"}"#,
    )
    .await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "confirm without password must be refused"
    );

    let (s2, _, _) = post_json(
        app,
        "/api/me/totp",
        Some("wg-ez=valid"),
        r#"{"action":"confirm","code":"123456","password":"correct"}"#,
    )
    .await;
    assert_eq!(
        s2,
        StatusCode::OK,
        "correct password must reach the backend"
    );
}

/// I1: Bearer-credential **failures** are throttled 10/min/IP. Ten wrong
/// attempts pass (401), the 11th is refused 429 before the token lookup.
#[tokio::test]
async fn bearer_failures_rate_limited_after_ten() {
    let app = build_router(finished_state());
    for i in 0..10 {
        let (s, _, _) = req_bearer(app.clone(), "GET", "/api/session", "wrong-token").await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "failure #{i} must be 401");
    }
    let (s, _, _) = req_bearer(app, "GET", "/api/session", "wrong-token").await;
    assert_eq!(
        s,
        StatusCode::TOO_MANY_REQUESTS,
        "11th Bearer failure must be 429"
    );
}

// ---------------------------------------------------------------------------
// M1 — the password-login limiter is per `(IP, username)` (fine) plus a
// coarse per-IP bucket. An attacker behind a shared origin (or an undeclared
// proxy collapsing every request to one IP) must no longer be able to lock
// out every account with ten failures.
// ---------------------------------------------------------------------------

/// Ten wrong attempts on `alice` throttle `(IP, alice)` only: `bob` from the
/// same IP still reaches the backend (401), never 429.
#[tokio::test]
async fn login_limiter_is_per_account_not_global_per_ip() {
    let app = build_router(finished_state());
    for i in 0..10 {
        let (s, _, _) = post_json(
            app.clone(),
            "/api/auth/password",
            None,
            r#"{"username":"alice","password":"wrongpassword12"}"#,
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "alice failure #{i}");
    }
    // The 11th alice attempt is throttled...
    let (s, _, _) = post_json(
        app.clone(),
        "/api/auth/password",
        None,
        r#"{"username":"alice","password":"wrongpassword12"}"#,
    )
    .await;
    assert_eq!(
        s,
        StatusCode::TOO_MANY_REQUESTS,
        "alice must be throttled after 10 failures"
    );

    // ...but bob from the same IP is not locked out: the request reaches the
    // backend and gets the normal 401 (never 429).
    let (s, _, _) = post_json(
        app,
        "/api/auth/password",
        None,
        r#"{"username":"bob","password":"wrongpassword12"}"#,
    )
    .await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "bob must not be locked out by alice's failures"
    );
}

/// The coarse per-IP bucket still bounds credential spraying: 50 distinct
/// usernames pass, the 51st request from that origin is refused 429 even
/// though its own `(IP, username)` bucket is untouched.
#[tokio::test]
async fn login_coarse_ip_bucket_bounds_spraying_across_usernames() {
    let app = build_router(finished_state());
    for i in 0..50 {
        let body = format!(r#"{{"username":"spray{i}","password":"wrongpassword12"}}"#);
        let (s, _, _) = post_json(app.clone(), "/api/auth/password", None, &body).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "spray #{i}");
    }
    let (s, _, _) = post_json(
        app,
        "/api/auth/password",
        None,
        r#"{"username":"spray50","password":"wrongpassword12"}"#,
    )
    .await;
    assert_eq!(
        s,
        StatusCode::TOO_MANY_REQUESTS,
        "the coarse per-IP bucket must throttle the 51st spraying attempt"
    );
}

/// I1: Bearer successes are never counted, so a legitimate API client
/// polling 20 times is not throttled (unlike the interactive login bucket).
#[tokio::test]
async fn bearer_success_never_throttled() {
    let (app, _) = token_state();
    let (s, _, body) = post_json(
        app.clone(),
        "/api/me/tokens",
        Some("wg-ez=valid"),
        r#"{"name":"polling"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let (_, clear) = created_token(&body);
    for i in 0..20 {
        let (s, _, _) = req_bearer(app.clone(), "GET", "/api/session", &clear).await;
        assert_eq!(
            s,
            StatusCode::OK,
            "legitimate Bearer request #{i} throttled"
        );
    }
}

/// RFC 6750 §2.1: the `Bearer` scheme is case-insensitive. `bearer`/`BEARER`
/// authenticate; an unrelated scheme or an empty credential fails closed `401`.
#[tokio::test]
async fn bearer_scheme_is_case_insensitive() {
    let (app, _) = token_state();
    let (s, _, body) = post_json(
        app.clone(),
        "/api/me/tokens",
        Some("wg-ez=valid"),
        r#"{"name":"ci"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let (_, clear) = created_token(&body);

    for scheme in ["Bearer", "bearer", "BEARER", "bEaReR"] {
        let (s, _, _) = req_authorization(
            app.clone(),
            "GET",
            "/api/session",
            &format!("{scheme} {clear}"),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "schéma `{scheme}` refusé");
    }
    // Another scheme must not authenticate the same credential.
    let (s, _, _) = req_authorization(
        app.clone(),
        "GET",
        "/api/session",
        &format!("Token {clear}"),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "scheme != Bearer doit échouer");
    // Scheme with no credential, and a bare scheme word, both fail closed.
    for value in ["Bearer", "Bearer   ", "bearer"] {
        let (s, _, _) = req_authorization(app.clone(), "GET", "/api/session", value).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "`{value}` doit échouer");
    }
}

/// Breaking change: `Authorization: Basic` is no longer honored (only the
/// session cookie and `Bearer` tokens authenticate). A Basic header answers
/// 401 like a missing credential — `curl -u` must never authenticate.
#[tokio::test]
async fn basic_auth_header_is_rejected_like_no_credential() {
    let app = build_router(finished_state());
    let mut built = Request::builder()
        .method("GET")
        .uri("/api/session")
        .header("authorization", "Basic YWRtaW46d3JvbmctcGFzc3dvcmQxMg==")
        .body(Body::empty())
        .unwrap();
    built
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::IpAddr::from([127, 0, 0, 1]),
            12345,
        ))));
    let res = app.oneshot(built).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

/// I1: an unknown Bearer token is answered 401 + the `password` security log
/// (observable as the 401 JSON from the real router).
#[tokio::test]
async fn bearer_failure_is_401_password_seclog_path() {
    let app = build_router(finished_state());
    let (s, _, body) = req_bearer(app, "GET", "/api/session", "definitely-wrong").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(body.contains("bad token"), "{body}");
}

/// I4: `serverAllowedIps` is an ADMIN-only field (it injects extra server-side
/// `AllowedIPs`, letting a CLIENT route or intercept traffic). A CLIENT
/// patching its OWN client with either key is refused 403 before the backend
/// is reached; admin is unrestricted; an unrelated patch still works.
#[tokio::test]
async fn client_cannot_set_server_allowed_ips_admin_can() {
    let app = build_router(finished_state());

    // CLIENT on its own client (id 2, owner user 2) -> 403.
    for key in ["serverAllowedIpsV4", "serverAllowedIpsV6"] {
        let body = format!(r#"{{"{key}":["0.0.0.0/0"]}}"#);
        let (s, _, _) = post_json(app.clone(), "/api/client/2", Some("wg-ez=client"), &body).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{key} must be admin-only");
    }

    // A harmless patch on the same own client still reaches the backend.
    let (s, _, _) = post_json(
        app.clone(),
        "/api/client/2",
        Some("wg-ez=client"),
        r#"{"name":"bob","allowedIpsV4":["10.0.0.0/24"]}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "non-admin patch must still work");

    // ADMIN may set `0.0.0.0/0` / `::/0`.
    let (s, _, _) = post_json(
        app,
        "/api/client/1",
        Some("wg-ez=valid"),
        r#"{"serverAllowedIpsV4":["0.0.0.0/0"],"serverAllowedIpsV6":["::/0"]}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "admin must be unrestricted");
}

/// I4: the admin-only guard inspects the RAW patch, so an urlencoded form with
/// an empty `serverAllowedIpsV4` (which `coerce_patch` would turn into `null`)
/// is still refused 403 for a CLIENT.
#[tokio::test]
async fn client_empty_form_server_allowed_ips_is_also_403() {
    let app = build_router(finished_state());
    let mut built = Request::builder()
        .method("POST")
        .uri("/api/client/2")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("cookie", "wg-ez=client")
        .body(Body::from("name=bob&serverAllowedIpsV4="))
        .unwrap();
    built
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::IpAddr::from([127, 0, 0, 1]),
            12345,
        ))));
    let res = app.oneshot(built).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

/// M3: `expiresAt` is ADMIN-only. A CLIENT patching its OWN client with it is
/// refused 403 before the backend (it would otherwise clear or push back the
/// expiry and bypass auto-disable); admin is unrestricted.
#[tokio::test]
async fn client_cannot_set_expires_at_admin_can() {
    let app = build_router(finished_state());

    let (s, _, _) = post_json(
        app.clone(),
        "/api/client/2",
        Some("wg-ez=client"),
        r#"{"expiresAt":"2999-01-01T00:00:00Z"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "expiresAt must be admin-only");

    // The raw patch is inspected: an urlencoded empty value (which
    // `coerce_patch` would turn into `null` = permanent) is refused too.
    let mut built = Request::builder()
        .method("POST")
        .uri("/api/client/2")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("cookie", "wg-ez=client")
        .body(Body::from("name=bob&expiresAt="))
        .unwrap();
    built
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::IpAddr::from([127, 0, 0, 1]),
            12345,
        ))));
    let res = app.clone().oneshot(built).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let (s, _, _) = post_json(
        app,
        "/api/client/1",
        Some("wg-ez=valid"),
        r#"{"expiresAt":"2999-01-01T00:00:00Z"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "admin must be unrestricted");
}

/// FAIBLE: a CLIENT probing a client id it does **not** own must get the same
/// 404 as an unknown id (existence hidden, no enumeration oracle), while its
/// own client and an ADMIN still get 200. Admin routes keep answering 403 for
/// a non-admin (unchanged). Proven through the real axum router.
#[tokio::test]
async fn client_foreign_resource_is_404_not_403() {
    let app = build_router(finished_state());

    // CLIENT (user 2) on client id 1 (owner user 1): 404 ...
    let (s, _, body) = req(app.clone(), "GET", "/api/client/1", Some("wg-ez=client")).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "GET foreign client: {body}");
    // ... byte-identical to an unknown id, so the status is not an oracle.
    let (s_unknown, _, body_unknown) = req(
        app.clone(),
        "GET",
        "/api/client/999999",
        Some("wg-ez=client"),
    )
    .await;
    assert_eq!(s_unknown, StatusCode::NOT_FOUND);
    assert_eq!(
        body, body_unknown,
        "the two 404 bodies must be indistinguishable"
    );

    // POST / DELETE and id-scoped sub-routes are masked identically.
    let (s, _, _) = post_json(
        app.clone(),
        "/api/client/1",
        Some("wg-ez=client"),
        r#"{"name":"x"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "POST foreign client");
    let (s, _, _) = req(app.clone(), "DELETE", "/api/client/1", Some("wg-ez=client")).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "DELETE foreign client");
    let (s, _, _) = req(
        app.clone(),
        "GET",
        "/api/client/1/configuration",
        Some("wg-ez=client"),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "foreign .conf");
    let (s, _, _) = post_json(
        app.clone(),
        "/api/client/1/enable",
        Some("wg-ez=client"),
        "{}",
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "foreign enable");

    // The owner (id 2 belongs to user 2) still gets 200 ...
    let (s, _, _) = req(app.clone(), "GET", "/api/client/2", Some("wg-ez=client")).await;
    assert_eq!(s, StatusCode::OK, "own client");
    // ... as does an ADMIN on any client.
    let (s, _, _) = req(app.clone(), "GET", "/api/client/1", Some("wg-ez=valid")).await;
    assert_eq!(s, StatusCode::OK, "admin GET");

    // Admin routes keep their 403 for a non-admin.
    let (s, _, _) = req(app, "GET", "/api/admin/general", Some("wg-ez=client")).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "admin route must stay 403");
}

/// FAIBLE : couverture CLIENT sur les sous-routes id-scopees. Un CLIENT
/// (user 2) sur le client d'un AUTRE (id 1) obtient le MEME 404 qu'un id
/// inconnu (anti-enumeration, lot B) sur qrcode/OTL/rotate/psk ; sur SON
/// client (id 2) ces routes atteignent le backend (200) ; un ADMIN est libre
/// (200). Le tout via le vrai routeur axum.
#[tokio::test]
async fn client_subroutes_are_404_foreign_and_200_own() {
    let app = build_router(finished_state());
    let client = "wg-ez=client";
    let admin = "wg-ez=valid";

    // (methode, gabarit) de chaque route id-scopee sensible.
    let routes = [
        ("GET", "/api/client/{id}/qrcode.svg"),
        ("POST", "/api/client/{id}/generateOneTimeLink"),
        ("POST", "/api/client/{id}/rotateKeys"),
        ("POST", "/api/client/{id}/psk"),
        ("DELETE", "/api/client/{id}/psk"),
    ];

    for (m, tmpl) in routes {
        let foreign = tmpl.replace("{id}", "1");
        let own = tmpl.replace("{id}", "2");

        // CLIENT sur le client d'un autre -> 404 (pas 403, pas de fuite).
        let (s, _, body) = req(app.clone(), m, &foreign, Some(client)).await;
        assert_eq!(
            s,
            StatusCode::NOT_FOUND,
            "CLIENT étranger {m} {foreign}: {body}"
        );
        // CLIENT sur son propre client -> 200.
        let (s, _, body) = req(app.clone(), m, &own, Some(client)).await;
        assert_eq!(s, StatusCode::OK, "CLIENT propre {m} {own}: {body}");
        // ADMIN -> 200.
        let (s, _, body) = req(app.clone(), m, &foreign, Some(admin)).await;
        assert_eq!(s, StatusCode::OK, "ADMIN {m} {foreign}: {body}");
    }
}

/// FAIBLE : un CLIENT ne peut ni toucher aux routes admin (403) ni creer un
/// client (`clients.create` est ADMIN-only, 403) ; un ADMIN reussit (200).
#[tokio::test]
async fn client_admin_routes_and_create_are_forbidden() {
    let app = build_router(finished_state());
    let client = Some("wg-ez=client");
    let admin = "wg-ez=valid";

    // GET /api/admin/hooks
    let (s, _, _) = req(app.clone(), "GET", "/api/admin/hooks", client).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "CLIENT GET admin/hooks");
    let (s, _, _) = req(app.clone(), "GET", "/api/admin/hooks", Some(admin)).await;
    assert_eq!(s, StatusCode::OK, "ADMIN GET admin/hooks");

    // POST /api/admin/interface/cidr
    let (s, _, _) = post_json(app.clone(), "/api/admin/interface/cidr", client, "{}").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "CLIENT POST admin/interface/cidr");
    let (s, _, _) = post_json(app.clone(), "/api/admin/interface/cidr", Some(admin), "{}").await;
    assert_eq!(s, StatusCode::OK, "ADMIN POST admin/interface/cidr");

    // GET /api/admin/ip-info
    let (s, _, _) = req(app.clone(), "GET", "/api/admin/ip-info", client).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "CLIENT GET admin/ip-info");
    let (s, _, _) = req(app.clone(), "GET", "/api/admin/ip-info", Some(admin)).await;
    assert_eq!(s, StatusCode::OK, "ADMIN GET admin/ip-info");

    // POST /api/client (creation) : ADMIN-only.
    let (s, _, _) = post_json(app.clone(), "/api/client", client, r#"{"name":"new"}"#).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "CLIENT POST /api/client");
    let (s, _, _) = post_json(app, "/api/client", Some(admin), r#"{"name":"new"}"#).await;
    assert_eq!(s, StatusCode::OK, "ADMIN POST /api/client");
}

/// M4 : un `dnsV4`/`dnsV6` qui n'est pas une IP nue de la bonne famille est
/// refusé 400 par le vrai parseur de patch (le backend de test rejoue
/// `parse_client_update`, comme `set_general` rejoue `general_update`).
#[tokio::test]
async fn client_dns_patch_is_validated_by_the_router() {
    let app = build_router(finished_state());

    let (s, _, _) = post_json(
        app.clone(),
        "/api/client/1",
        Some("wg-ez=valid"),
        r#"{"dnsV4":["not-an-ip"]}"#,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "non-IP DNS must be rejected");

    let (s, _, _) = post_json(
        app.clone(),
        "/api/client/1",
        Some("wg-ez=valid"),
        r#"{"dnsV4":["1.1.1.1"]}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "a valid v4 DNS is accepted");

    let (s, _, _) = post_json(
        app,
        "/api/client/1",
        Some("wg-ez=valid"),
        r#"{"dnsV6":["1.1.1.1"]}"#,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "wrong family must be rejected");
}

/// Un `firewallIpsV4`/`V6` qui n'est pas une IP/CIDR (nom, `*`, préfixe
/// invalide) est refusé 400 à l'écriture : la destination part verbatim en
/// `-d` iptables et une ligne empoisonnée ferait avorter tout l'apply avant
/// le `DROP` final. Les formes valides (IP, CIDR, port, proto, `[]`) restent
/// acceptées. Prouvé via le vrai routeur (le backend de test rejoue
/// `parse_client_update`).
#[tokio::test]
async fn client_firewall_patch_rejects_non_ip_destinations() {
    let app = build_router(finished_state());
    for bad in [
        "evil",
        "*",
        "10.0.0.0/999",
        "999.999.999.999",
        "example.com",
    ] {
        for key in ["firewallIpsV4", "firewallIpsV6"] {
            let body = format!(r#"{{"{key}":["{bad}"]}}"#);
            let (s, _, _) =
                post_json(app.clone(), "/api/client/1", Some("wg-ez=valid"), &body).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{key}={bad} doit être refusé");
        }
    }

    for good in [
        r#"{"firewallIpsV4":["10.0.0.1"]}"#,
        r#"{"firewallIpsV4":["10.0.0.0/24"]}"#,
        r#"{"firewallIpsV4":["10.0.0.1:51820"]}"#,
        r#"{"firewallIpsV4":["10.0.0.0/24:443/udp"]}"#,
        r#"{"firewallIpsV6":["::/0"]}"#,
        r#"{"firewallIpsV4":[]}"#,
    ] {
        let (s, _, body) = post_json(app.clone(), "/api/client/1", Some("wg-ez=valid"), good).await;
        assert_eq!(s, StatusCode::OK, "{good} accepté : {body}");
    }
}

/// Non-regression du bug live "PATCH JSON partiel sans `enabled`" : un
/// `{"mtu":...}` JSON eteignait le client en silence car `coerce_patch`
/// appliquait la regle checkbox (absent = `false`) aux corps JSON. Prouve via
/// le vrai routeur : le backend de test repercute un `enabled: false`
/// explicite, donc la reponse montre quel patch le handler a transmis.
#[tokio::test]
async fn json_partial_patch_without_enabled_keeps_client_on() {
    let app = build_router(finished_state());

    // JSON sans `enabled` : reste allume.
    let (s, _, body) = post_json(
        app.clone(),
        "/api/client/1",
        Some("wg-ez=valid"),
        r#"{"mtu":1500}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "partial JSON patch: {body}");
    assert!(
        body.contains(r#""enabled":true"#),
        "a partial JSON patch must not disable the client: {body}"
    );

    // JSON avec `enabled: false` explicite : toujours honore.
    let (s, _, body) = post_json(
        app,
        "/api/client/1",
        Some("wg-ez=valid"),
        r#"{"enabled":false}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "explicit disable: {body}");
    assert!(
        body.contains(r#""enabled":false"#),
        "an explicit disable must still work: {body}"
    );
}

/// Pendant formulaire : la semantique checkbox est inchangee (cle absente =
/// decoche = `false`), l'UI en depend (`ui::hidden` rejoue `enabled`).
#[tokio::test]
async fn form_patch_without_enabled_still_disables() {
    let app = build_router(finished_state());
    let mut built = Request::builder()
        .method("POST")
        .uri("/api/client/1")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("cookie", "wg-ez=valid")
        .body(Body::from("mtu=1500"))
        .unwrap();
    built
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::IpAddr::from([127, 0, 0, 1]),
            12345,
        ))));
    let res = app.oneshot(built).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body).into_owned();
    assert!(
        body.contains(r#""enabled":false"#),
        "a form patch without the checkbox must still read as unchecked: {body}"
    );
}

// ---------------------------------------------------------------------------
// M2 — `POST /api/auth/verify-2fa` verifies BEFORE consuming the pending.
// A wrong code must not destroy the pending (retry + anti-DoS), and a valid
// code must be single-use (no replay) once the session is minted.
// ---------------------------------------------------------------------------

/// Valid 22-char base64url-shaped pending id (the handler enforces len == 22).
const PENDING_ID: &str = "ABCDEFGHIJKLMNOPQRSTUV";
/// The only code [`TestBackend::verify_totp`] accepts.
const GOOD_CODE: &str = "123456";
/// A well-formed but wrong 6-digit code.
const BAD_CODE: &str = "000000";

/// Seed a pending 2FA login directly in the shared in-memory map (test setup,
/// never a handler call). The handler only accepts 22-char ids.
async fn seed_pending_until(
    state: &AppState<TestBackend>,
    expires_at: std::time::Instant,
) -> String {
    let id = PENDING_ID.to_string();
    state.pending.lock().await.insert(
        id.clone(),
        PendingLogin {
            user_id: 1,
            username: "admin".into(),
            expires_at,
            failed_attempts: 0,
        },
    );
    id
}

async fn seed_pending(state: &AppState<TestBackend>) -> String {
    seed_pending_until(
        state,
        std::time::Instant::now() + std::time::Duration::from_secs(300),
    )
    .await
}

/// `GET /api/auth/pending` with the `X-Pending` header (the handler reads the
/// id from the header/cookie, not the body).
async fn pending_exists(app: Router, id: &str) -> bool {
    let mut built = Request::builder()
        .method("GET")
        .uri("/api/auth/pending")
        .header("x-pending", id)
        .body(Body::empty())
        .unwrap();
    built
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::IpAddr::from([127, 0, 0, 1]),
            12345,
        ))));
    let res = app.oneshot(built).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&body).unwrap();
    v.get("pending").and_then(Value::as_bool).unwrap_or(false)
}

fn verify_body(id: &str, code: &str) -> String {
    format!(r#"{{"pending":"{id}","code":"{code}"}}"#)
}

/// A wrong code answers 401 **and leaves the pending alive** so a legitimate
/// user can retry after a typo (M2 core fix).
#[tokio::test]
async fn bad_2fa_code_keeps_pending_for_retry() {
    let state = finished_state();
    let id = seed_pending(&state).await;
    let app = build_router(state);

    let (s, h, _) = post_json(
        app.clone(),
        "/api/auth/verify-2fa",
        None,
        &verify_body(&id, BAD_CODE),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(!h.contains_key("set-cookie"), "no session on failure");
    assert!(
        pending_exists(app, &id).await,
        "a wrong code must not consume the pending"
    );
}

/// Five wrong codes exhaust the per-pending budget: the entry is invalidated
/// and any further verify (even a correct code) is refused.
#[tokio::test]
async fn five_bad_codes_invalidate_pending() {
    let state = finished_state();
    let id = seed_pending(&state).await;
    let app = build_router(state);

    for i in 1..=PendingLogin::MAX_FAILED_ATTEMPTS {
        let (s, _, _) = post_json(
            app.clone(),
            "/api/auth/verify-2fa",
            None,
            &verify_body(&id, BAD_CODE),
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "bad code #{i}");
        if i < PendingLogin::MAX_FAILED_ATTEMPTS {
            assert!(
                pending_exists(app.clone(), &id).await,
                "pending must survive until the cap (#{i})"
            );
        }
    }
    assert!(
        !pending_exists(app.clone(), &id).await,
        "the 5th failure must invalidate the pending"
    );
    // With the pending gone, even the correct code cannot mint a session.
    let (s, _, _) = post_json(
        app,
        "/api/auth/verify-2fa",
        None,
        &verify_body(&id, GOOD_CODE),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

/// A correct code mints the session cookie, consumes the pending, and cannot
/// be replayed for a second session.
#[tokio::test]
async fn correct_2fa_code_creates_session_then_replay_is_refused() {
    let state = finished_state();
    let id = seed_pending(&state).await;
    let app = build_router(state);

    let (s, h, _) = post_json(
        app.clone(),
        "/api/auth/verify-2fa",
        None,
        &verify_body(&id, GOOD_CODE),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let cookie = h
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(cookie.starts_with("wg-ez="), "session cookie: {cookie:?}");
    assert!(
        !pending_exists(app.clone(), &id).await,
        "success consumes the pending"
    );

    // Replay of the same valid code must not create a second session.
    let (s2, h2, _) = post_json(
        app,
        "/api/auth/verify-2fa",
        None,
        &verify_body(&id, GOOD_CODE),
    )
    .await;
    assert_eq!(s2, StatusCode::UNAUTHORIZED, "replay must be refused");
    assert!(!h2.contains_key("set-cookie"), "no second session cookie");
}

/// Unknown and expired pendings are both refused 401.
#[tokio::test]
async fn unknown_or_expired_pending_is_401() {
    let state = finished_state();
    // Expired by one second: still present in the map, but unusable.
    let expired = seed_pending_until(
        &state,
        std::time::Instant::now() - std::time::Duration::from_secs(1),
    )
    .await;
    let app = build_router(state);

    let unknown = "ZYXWVUTSRQPONMLKJIHGFE";
    let (s, _, _) = post_json(
        app.clone(),
        "/api/auth/verify-2fa",
        None,
        &verify_body(unknown, GOOD_CODE),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "unknown pending");

    let (s, _, _) = post_json(
        app,
        "/api/auth/verify-2fa",
        None,
        &verify_body(&expired, GOOD_CODE),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "expired pending");
}

// ---------------------------------------------------------------------------
// M8 — the pending-2FA cookie must carry `Secure` iff `!INSECURE`, exactly
// like the session cookie. Otherwise the opaque pending id can leak over a
// cleartext request on an HTTPS deployment.
// ---------------------------------------------------------------------------

/// Extract the single `Set-Cookie` value, failing loudly when absent.
fn set_cookie(h: &HeaderMap) -> String {
    h.get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

/// All `Set-Cookie` values (a response may carry several, e.g. the session
/// cookie plus the pending-cookie clear on `verify-2fa`).
fn set_cookies(h: &HeaderMap) -> Vec<String> {
    h.get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_owned))
        .collect()
}

/// Extract one cookie's value from the `Set-Cookie` header (`name` -> value).
fn set_cookie_value(h: &HeaderMap, name: &str) -> Option<String> {
    let raw = h.get("set-cookie")?.to_str().ok()?;
    let first = raw.split(';').next()?;
    let (k, v) = first.split_once('=')?;
    (k.trim() == name).then(|| v.trim().to_owned())
}

/// `POST /api/auth/password` on a 2FA account: with `INSECURE=false` the
/// pending cookie MUST be `Secure` (same rule as `wg-ez`).
#[tokio::test]
async fn pending_cookie_is_secure_when_https() {
    let app = build_router(insecure_state(false));
    let (s, h, body) = post_json(
        app,
        "/api/auth/password",
        None,
        r#"{"username":"totp","password":"whatever"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert!(body.contains(r#""totpRequired":true"#), "{body}");

    let cookie = set_cookie(&h);
    assert!(cookie.starts_with("wg-ez-pending="), "cookie: {cookie:?}");
    assert!(
        cookie.contains("; Secure"),
        "le pending doit porter Secure en HTTPS: {cookie:?}"
    );
    // The other attributes are unchanged.
    assert!(cookie.contains("Path=/api/auth"), "{cookie:?}");
    assert!(cookie.contains("HttpOnly"), "{cookie:?}");
    assert!(cookie.contains("SameSite=Lax"), "{cookie:?}");
    assert!(cookie.contains("Max-Age=300"), "{cookie:?}");
}

/// Symmetric case: with `INSECURE=true` the pending cookie has no `Secure`
/// (the deployment is plain HTTP, forcing the flag would drop the cookie).
#[tokio::test]
async fn pending_cookie_is_not_secure_when_insecure() {
    let app = build_router(insecure_state(true));
    let (s, h, body) = post_json(
        app,
        "/api/auth/password",
        None,
        r#"{"username":"totp","password":"whatever"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");

    let cookie = set_cookie(&h);
    assert!(cookie.starts_with("wg-ez-pending="), "cookie: {cookie:?}");
    assert!(
        !cookie.contains("Secure"),
        "le pending ne doit pas porter Secure en HTTP: {cookie:?}"
    );
    assert!(cookie.contains("Path=/api/auth"), "{cookie:?}");
    assert!(cookie.contains("HttpOnly"), "{cookie:?}");
    assert!(cookie.contains("SameSite=Lax"), "{cookie:?}");
    assert!(cookie.contains("Max-Age=300"), "{cookie:?}");
}

/// Non-2FA password login mints a browser-session cookie: no `Max-Age` on the
/// `wg-ez` cookie.
#[tokio::test]
async fn password_login_sets_session_cookie_without_max_age() {
    let app = build_router(finished_state());

    let (s, h, body) = post_json(
        app,
        "/api/auth/password",
        None,
        r#"{"username":"okuser","password":"whatever"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let cookie = set_cookie(&h);
    assert!(cookie.starts_with("wg-ez="), "cookie: {cookie:?}");
    assert!(
        !cookie.contains("Max-Age"),
        "session cookie must carry no Max-Age: {cookie:?}"
    );
}

// ---------------------------------------------------------------------------
// FAIBLE — the pending-2FA cookie must be *erased* once its pending is gone
// (`verify-2fa` success) or abandoned (`cancel`), and `GET /api/auth/pending`
// (a public validity oracle) must be rate-limited.
// ---------------------------------------------------------------------------

/// `cancel` drops the pending from the map **and** from the browser: the
/// response carries a `wg-ez-pending=…; Max-Age=0` clear cookie.
#[tokio::test]
async fn cancel_clears_pending_cookie() {
    let app = build_router(finished_state());
    let (s, h, _) = post_json(app, "/api/auth/cancel", None, "{}").await;
    assert_eq!(s, StatusCode::OK);
    let clear = set_cookie(&h);
    assert!(
        clear.starts_with("wg-ez-pending="),
        "clear cookie attendu: {clear:?}"
    );
    assert!(
        clear.contains("Max-Age=0"),
        "le cookie pending doit être expiré: {clear:?}"
    );
    assert!(clear.contains("Path=/api/auth"), "{clear:?}");
}

/// A successful `verify-2fa` mints the session cookie **and** clears the
/// pending cookie on the same response, so the opaque id does not survive in
/// the browser.
#[tokio::test]
async fn verify_2fa_success_clears_pending_cookie() {
    let state = finished_state();
    let id = seed_pending(&state).await;
    let app = build_router(state);
    let (s, h, _) = post_json(
        app,
        "/api/auth/verify-2fa",
        None,
        &verify_body(&id, GOOD_CODE),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let cookies = set_cookies(&h);
    assert!(
        cookies.iter().any(|c| c.starts_with("wg-ez=")),
        "session cookie manquant: {cookies:?}"
    );
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("wg-ez-pending=") && c.contains("Max-Age=0")),
        "clear pending cookie manquant: {cookies:?}"
    );
}

/// The public pending-probe route is bounded at 60/min/IP: the first 60
/// probes are answered (200), the 61st is refused 429.
#[tokio::test]
async fn pending_probes_are_rate_limited() {
    let app = build_router(finished_state());
    let cookie = format!("wg-ez-pending={PENDING_ID}");
    for i in 0..60 {
        let (s, _, _) = req(app.clone(), "GET", "/api/auth/pending", Some(&cookie)).await;
        assert_ne!(
            s,
            StatusCode::TOO_MANY_REQUESTS,
            "probe #{i} ne doit pas être throttlée"
        );
    }
    let (s, _, _) = req(app, "GET", "/api/auth/pending", Some(&cookie)).await;
    assert_eq!(
        s,
        StatusCode::TOO_MANY_REQUESTS,
        "la 61e sonde doit être 429"
    );
}

// ---------------------------------------------------------------------------
// FAIBLE — the pending-2FA id must not transit through the URL. The browser
// flow relies on the `wg-ez-pending` cookie; the JSON body keeps `pending`
// for API clients (v15 contract).
// ---------------------------------------------------------------------------

/// `POST /api/auth/password` (htmx) on a 2FA account:
/// - answers `TOTP_REQUIRED` with the id in the JSON body (API contract),
/// - sets the id as the `wg-ez-pending` cookie,
/// - sends `HX-Redirect: /login/2fa` **without** any `?pending=` parameter.
///
/// Then the whole `password` -> `verify-2fa` flow works with the cookie alone
/// (body carries only `code`), proving the URL removal does not break it.
#[tokio::test]
async fn password_2fa_pending_is_out_of_url_and_verifies_via_cookie() {
    let app = build_router(finished_state());

    // 1 · password step (htmx caller so `HX-Redirect` is emitted).
    let mut built = Request::builder()
        .method("POST")
        .uri("/api/auth/password")
        .header("content-type", "application/json")
        .header("hx-request", "true")
        .body(Body::from(r#"{"username":"totp","password":"whatever"}"#))
        .unwrap();
    built
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::IpAddr::from([127, 0, 0, 1]),
            12345,
        ))));
    let res = app.clone().oneshot(built).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let h = res.headers().clone();
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body).into_owned();

    // JSON contract preserved.
    assert!(body.contains(r#""totpRequired":true"#), "{body}");
    let pending_id = set_cookie_value(&h, "wg-ez-pending").expect("pending cookie");
    assert_eq!(pending_id.len(), 22, "opaque 128-bit base64url id");
    assert!(
        body.contains(&format!(r#""pending":"{pending_id}""#)),
        "le corps JSON garde `pending` : {body}"
    );

    // The id is NOT in the redirect (nor anywhere in the URL).
    let redirect = h
        .get("hx-redirect")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(redirect, "/login/2fa");
    assert!(
        !redirect.contains(&pending_id) && !redirect.contains("pending="),
        "l'id ne doit pas passer par l'URL : {redirect:?}"
    );

    // 2 · verify with the cookie only: no `pending` in the body.
    let cookie = format!("wg-ez-pending={pending_id}");
    let (s, h2, _) = post_json(
        app,
        "/api/auth/verify-2fa",
        Some(&cookie),
        r#"{"code":"123456"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "la vérification via cookie doit marcher");
    let session = set_cookie(&h2);
    assert!(session.starts_with("wg-ez="), "session cookie: {session:?}");
}

// ---------------------------------------------------------------------------
// M12 — request body size is bounded uniformly (1 MiB) with a clear 413.
// ---------------------------------------------------------------------------

/// A small, legitimate patch still succeeds (non-regression): the global
/// limit does not break normal writes.
#[tokio::test]
async fn normal_small_patch_is_accepted() {
    let app = build_router(finished_state());
    let (s, _, body) = post_json(
        app,
        "/api/admin/general",
        Some("wg-ez=valid"),
        r#"{"metricsPrometheus":true,"metricsJson":true}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
}

/// `PatchBody` (admin + client patches) rejects an over-limit body with 413
/// through the real router, before the body is read/parsed (M12).
#[tokio::test]
async fn oversized_patch_body_is_413() {
    let app = build_router(finished_state());
    let big = format!(
        r#"{{"name":"{}"}}"#,
        "a".repeat(super::routes::MAX_BODY_BYTES)
    );
    assert!(big.len() > super::routes::MAX_BODY_BYTES);

    let (s, _, body) =
        post_json(app.clone(), "/api/admin/general", Some("wg-ez=valid"), &big).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert!(
        body.contains("request body too large"),
        "corps 413 controle attendu : {body}"
    );

    let (s2, _, _) = post_json(app, "/api/client/1", Some("wg-ez=valid"), &big).await;
    assert_eq!(s2, StatusCode::PAYLOAD_TOO_LARGE);
}

/// `JsonOrForm` (JSON branch) also maps the overflow to 413 instead of the
/// generic 400 used for malformed bodies.
#[tokio::test]
async fn oversized_json_body_is_413() {
    let app = build_router(finished_state());
    let big = format!(
        r#"{{"username":"{}","password":"x"}}"#,
        "a".repeat(super::routes::MAX_BODY_BYTES)
    );
    let (s, _, body) = post_json(app, "/api/auth/password", None, &big).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
}

/// `JsonOrForm` (urlencoded branch) is bounded too.
#[tokio::test]
async fn oversized_form_body_is_413() {
    let app = build_router(finished_state());
    let big = format!(
        "username={}&password=x",
        "a".repeat(super::routes::MAX_BODY_BYTES)
    );
    let mut built = Request::builder()
        .method("POST")
        .uri("/api/auth/password")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(big))
        .unwrap();
    built
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::IpAddr::from([127, 0, 0, 1]),
            12345,
        ))));
    let res = app.oneshot(built).await.unwrap();
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// A body-less route (GET) is not affected by the limit.
#[tokio::test]
async fn body_less_get_is_not_affected_by_limit() {
    let app = build_router(finished_state());
    let (s, _, _) = req(app, "GET", "/api/information", None).await;
    assert_eq!(s, StatusCode::OK);
}

/// POST with a JSON body, optional cookie and an explicit `Sec-Fetch-Site`
/// browser metadata header, through the real router. Same shape as
/// [`post_json`] but lets the CSRF-guard tests drive the header; `None`
/// leaves it entirely absent (non-browser client).
async fn post_json_fetch_site(
    app: Router,
    uri: &str,
    cookie: Option<&str>,
    fetch_site: Option<&str>,
    body: &str,
) -> (StatusCode, HeaderMap, String) {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(c) = cookie {
        b = b.header("cookie", c);
    }
    if let Some(v) = fetch_site {
        b = b.header("sec-fetch-site", v);
    }
    let mut built = b.body(Body::from(body.to_owned())).unwrap();
    built
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::IpAddr::from([127, 0, 0, 1]),
            12345,
        ))));
    let res = app.oneshot(built).await.unwrap();
    let s = res.status();
    let h = res.headers().clone();
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    (s, h, String::from_utf8_lossy(&body).into_owned())
}

/// GET with an explicit `Sec-Fetch-Site` header, through the real router.
async fn get_fetch_site(
    app: Router,
    uri: &str,
    fetch_site: &str,
) -> (StatusCode, HeaderMap, String) {
    let mut built = Request::builder()
        .method("GET")
        .uri(uri)
        .header("sec-fetch-site", fetch_site)
        .body(Body::empty())
        .unwrap();
    built
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::IpAddr::from([127, 0, 0, 1]),
            12345,
        ))));
    let res = app.oneshot(built).await.unwrap();
    let s = res.status();
    let h = res.headers().clone();
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    (s, h, String::from_utf8_lossy(&body).into_owned())
}

/// CSRF: a browser same-origin `POST` (normal htmx/JSON mutation) must reach
/// the handler untouched.
#[tokio::test]
async fn csrf_post_same_origin_passes() {
    let app = build_router(finished_state());
    let (s, _, _) = post_json_fetch_site(
        app,
        "/api/client",
        Some("wg-ez=valid"),
        Some("same-origin"),
        r#"{"name":"hello"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}

/// CSRF: a browser cross-site `POST` is refused with 403 before the handler,
/// even with a valid session cookie (the guard is independent of auth).
#[tokio::test]
async fn csrf_post_cross_site_forbidden() {
    let app = build_router(finished_state());
    let (s, _, _) = post_json_fetch_site(
        app,
        "/api/client",
        Some("wg-ez=valid"),
        Some("cross-site"),
        r#"{"name":"hello"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

/// CSRF: `same-site` is also refused (a sibling subdomain is still a
/// cross-origin initiator for our purposes).
#[tokio::test]
async fn csrf_post_same_site_forbidden() {
    let app = build_router(finished_state());
    let (s, _, _) = post_json_fetch_site(
        app,
        "/api/client",
        Some("wg-ez=valid"),
        Some("same-site"),
        r#"{"name":"hello"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

/// CSRF: the guard runs globally, not only behind auth. A cross-site `POST`
/// to the public login endpoint is refused before the handler too.
#[tokio::test]
async fn csrf_post_cross_site_public_endpoint_forbidden() {
    let app = build_router(finished_state());
    let (s, _, _) = post_json_fetch_site(
        app,
        "/api/auth/password",
        None,
        Some("cross-site"),
        r#"{"username":"admin","password":"whatever"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

/// CSRF: a non-browser client (curl / Bearer API / parity audit) sends no
/// `Sec-Fetch-Site` at all: it must still pass (fail-open by design).
#[tokio::test]
async fn csrf_post_without_header_passes() {
    let app = build_router(finished_state());
    let (s, _, _) = post_json(
        app,
        "/api/client",
        Some("wg-ez=valid"),
        r#"{"name":"hello"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}

/// CSRF: the guard only covers mutating methods; a `GET` carrying a
/// cross-site header (e.g. a cross-site image/script tag, harmless for us)
/// passes untouched.
#[tokio::test]
async fn csrf_get_cross_site_passes() {
    let app = build_router(finished_state());
    let (s, _, _) = get_fetch_site(app, "/api/information", "cross-site").await;
    assert_eq!(s, StatusCode::OK);
}

/// Finished setup with direct access to the [`TestBackend`] underneath, so
/// API-token rows can be aged/disabled in place (expiry, revocation and
/// disabled-owner cases) through the real router.
fn token_state() -> (Router, Arc<TestBackend>) {
    let backend = Arc::new(backend(0, (true, true), Some("scrape-secret")));
    let state = AppState::new(
        backend.clone(),
        crate::web::ctx::Locales::load().expect("locales"),
        vec![],
    );
    (build_router(state), backend)
}

fn created_token(body: &str) -> (i64, String) {
    let v: Value = serde_json::from_str(body).expect("created token json");
    assert!(
        v.get("prefix").is_none(),
        "le préfixe ne doit plus être exposé : {body}"
    );
    (
        v.get("id").and_then(Value::as_i64).expect("id"),
        v.get("token")
            .and_then(Value::as_str)
            .expect("token")
            .to_string(),
    )
}

fn expire_token(backend: &TestBackend, id: i64) {
    let mut store = backend.api_tokens.lock().expect("lock");
    let (_, view) = store.iter_mut().find(|(_, v)| v.id == id).expect("row");
    view.expires_at = Some("2000-01-01T00:00:00Z".to_string());
}

fn disable_token(backend: &TestBackend, id: i64) {
    let mut store = backend.api_tokens.lock().expect("lock");
    let (_, view) = store.iter_mut().find(|(_, v)| v.id == id).expect("row");
    view.enabled = false;
}

/// `POST /api/me/tokens` returns the clear value exactly once (never the
/// hash); the list hides both; the Bearer guard resolves the token through
/// the real router.
#[tokio::test]
async fn api_tokens_create_once_list_hides_secrets_bearer_resolves() {
    let (app, _) = token_state();
    let (s, _, body) = post_json(
        app.clone(),
        "/api/me/tokens",
        Some("wg-ez=valid"),
        r#"{"name":"ci","expiresAt":"2999-01-01T00:00:00Z"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let (id, clear) = created_token(&body);
    assert_eq!(clear.len(), 43, "256 bits en base64url sans padding");
    assert!(
        !body.contains("tokenHash"),
        "le hash ne doit pas fuiter : {body}"
    );
    assert_eq!(id, 1);

    // La liste ne contient ni le clair ni le hash.
    let (s, _, body) = req(app.clone(), "GET", "/api/me/tokens", Some("wg-ez=valid")).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert!(body.contains("ci"), "{body}");
    assert!(
        !body.contains(&clear),
        "le clair n'est montré qu'une fois : {body}"
    );
    assert!(!body.contains("tokenHash"), "{body}");

    // Le Bearer résout le principal : une route gardée répond 200.
    let (s, _, _) = req_bearer(app.clone(), "GET", "/api/client", &clear).await;
    assert_eq!(s, StatusCode::OK);
    // Mauvais token -> même 401 sans oracle.
    let (s, _, _) = req_bearer(app, "GET", "/api/client", "nope-not-a-token").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

/// Noms invalides -> 400 via le vrai routeur (vide, trop long).
#[tokio::test]
async fn api_tokens_create_validates_name() {
    let (app, _) = token_state();
    for body in [
        r#"{"name":""}"#,
        &format!(r#"{{"name":"{}"}}"#, "x".repeat(65)),
    ] {
        let (s, _, resp) =
            post_json(app.clone(), "/api/me/tokens", Some("wg-ez=valid"), body).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{resp}");
    }
}

/// Bearer expiré / désactivé / propriétaire désactivé / révoqué -> 401.
#[tokio::test]
async fn api_tokens_bearer_fails_closed() {
    let (app, backend) = token_state();
    let (_, clear_exp) = {
        let (s, _, body) = post_json(
            app.clone(),
            "/api/me/tokens",
            Some("wg-ez=valid"),
            r#"{"name":"exp"}"#,
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{body}");
        created_token(&body)
    };
    let (_, clear_off) = {
        let (s, _, body) = post_json(
            app.clone(),
            "/api/me/tokens",
            Some("wg-ez=valid"),
            r#"{"name":"off"}"#,
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{body}");
        created_token(&body)
    };
    // Jeton d'un CLIENT, dont le compte sera désactivé.
    let (_, clear_user) = {
        let (s, _, body) = post_json(
            app.clone(),
            "/api/me/tokens",
            Some("wg-ez=client"),
            r#"{"name":"bobtok"}"#,
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{body}");
        created_token(&body)
    };
    expire_token(&backend, 1);
    disable_token(&backend, 2);
    backend.disabled_users.lock().expect("lock").push(2);

    for clear in [&clear_exp, &clear_off, &clear_user] {
        let (s, _, _) = req_bearer(app.clone(), "GET", "/api/client", clear).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "fail-closed attendu");
    }
    // Un jeton révoqué ne résout plus rien.
    let (s, _, _) = req(
        app.clone(),
        "DELETE",
        "/api/me/tokens/1",
        Some("wg-ez=valid"),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = req_bearer(app, "GET", "/api/client", &clear_exp).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

/// Isolation par utilisateur : un CLIENT ne liste/révoque que ses jetons
/// (id d'autrui == id inconnu : 404) ; l'ADMIN voit et révoque tout.
#[tokio::test]
async fn api_tokens_scoped_revoke_and_admin_view() {
    let (app, _) = token_state();
    let (s, _, body) = post_json(
        app.clone(),
        "/api/me/tokens",
        Some("wg-ez=valid"),
        r#"{"name":"admintok"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let (admin_id, _) = created_token(&body);
    let (s, _, body) = post_json(
        app.clone(),
        "/api/me/tokens",
        Some("wg-ez=client"),
        r#"{"name":"bobtock"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let (bob_id, _) = created_token(&body);

    // Le CLIENT ne voit que le sien.
    let (s, _, body) = req(app.clone(), "GET", "/api/me/tokens", Some("wg-ez=client")).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert!(body.contains("bobtock"), "{body}");
    assert!(!body.contains("admintok"), "{body}");

    // Le CLIENT qui vise le jeton de l'ADMIN : même 404 qu'un inconnu.
    let (s, _, _) = req(
        app.clone(),
        "DELETE",
        &format!("/api/me/tokens/{admin_id}"),
        Some("wg-ez=client"),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _, _) = req(
        app.clone(),
        "DELETE",
        "/api/me/tokens/999999",
        Some("wg-ez=client"),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Non-ADMIN sur les routes ADMIN -> 403 ; ADMIN -> 200 avec tout.
    let (s, _, _) = req(
        app.clone(),
        "GET",
        "/api/admin/tokens",
        Some("wg-ez=client"),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, body) = req(app.clone(), "GET", "/api/admin/tokens", Some("wg-ez=valid")).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert!(
        body.contains("admintok") && body.contains("bobtock"),
        "{body}"
    );

    // L'ADMIN révoque le jeton d'autrui ; le propriétaire révoque le sien.
    let (s, _, _) = req(
        app.clone(),
        "DELETE",
        &format!("/api/admin/tokens/{bob_id}"),
        Some("wg-ez=valid"),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = req(
        app.clone(),
        "DELETE",
        &format!("/api/me/tokens/{admin_id}"),
        Some("wg-ez=valid"),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    // Seconde révocation -> 404 (déjà parti).
    let (s, _, _) = req(
        app,
        "DELETE",
        &format!("/api/me/tokens/{admin_id}"),
        Some("wg-ez=valid"),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

/// Création htmx : corps ignoré (`hx-swap="none"`, `{"ok":true}`) + triggers
/// `refreshMe` pour la liste et `showToken` (le clair, ASCII seul) pour la
/// modale `app.js` ; la page `/me` embarque la section jetons avec les
/// libellés de la modale en `data-t-*` (zéro texte en dur côté JS), en EN
/// comme en FR. Les appelants non-htmx gardent le JSON complet (cf.
/// `api_tokens_create_once_list_hides_secrets_bearer_resolves`).
#[tokio::test]
async fn api_tokens_hx_create_modal_trigger_and_me_section() {
    let (app, _) = token_state();
    let mut built = Request::builder()
        .method("POST")
        .uri("/api/me/tokens")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .header("cookie", "wg-ez=valid")
        .body(Body::from("name=script"))
        .unwrap();
    built
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::IpAddr::from([127, 0, 0, 1]),
            12345,
        ))));
    let res = app.clone().oneshot(built).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let trigger = res
        .headers()
        .get("hx-trigger")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(trigger.contains("refreshMe"), "{trigger}");
    let trig: Value = serde_json::from_str(trigger).expect("trigger json");
    let shown = trig
        .get("showToken")
        .and_then(Value::as_str)
        .expect("showToken");
    assert_eq!(shown.len(), 43, "256 bits en base64url sans padding");
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body);
    // Corps ignoré par `hx-swap="none"` : le clair n'y figure jamais, il ne
    // voyage que dans le trigger vers la modale.
    assert!(body.contains(r#""ok":true"#), "{body}");
    assert!(!body.contains(shown), "{body}");

    // La page `/me` liste le jeton (nom + préfixe, jamais le clair complet)
    // et porte les libellés de la modale pour `app.js`.
    let (s, _, page) = req(app.clone(), "GET", "/me", Some("wg-ez=valid")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        page.contains(r#"id="api-tokens""#),
        "section jetons absente"
    );
    assert!(page.contains("script"), "nom du jeton absent");
    assert!(
        page.contains(r#"data-t-title="New API token""#),
        "titre de modale absent"
    );
    assert!(
        page.contains(r#"data-t-warning="Copy it now"#),
        "consigne de modale absente"
    );
    assert!(
        page.contains(r#"data-t-copy="Copy token""#),
        "bouton Copier de modale absent"
    );
    assert!(!page.contains(r#"id="token-slot""#), "ancien slot présent");
    assert!(!page.contains(shown), "le clair ne doit pas fuiter");
    // FR : mêmes libellés traduits, lus par la même modale.
    let (s, _, fr) = req(app, "GET", "/me?lang=fr", Some("wg-ez=valid")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(fr.contains("Nouveau jeton"), "{fr}");
    assert!(fr.contains("Copiez-le maintenant"), "{fr}");
}
