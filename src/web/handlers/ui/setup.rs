#![forbid(unsafe_code)]

//! Setup wizard pages (valid only while setupStep != 0; else -> /login).
//!
//! Trois etapes : welcome (step1), admin (step2), endpoint (step3).
//! La logique (gating, redirections) reste portee par `src/setup/`.

use askama::Template;
use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::Response,
};
use axum_extra::extract::CookieJar;

use super::chrome::{Base, LangQuery, get_str, setup_context};
use crate::web::ctx::{AppState, Backend, WebError};

/// Rail de progression : les trois intitules, dans l'ordre.
fn rail(state: &AppState<impl Backend>, lang: &str) -> [String; 3] {
    [
        state.locales.t(lang, "setup.step_welcome"),
        state.locales.t(lang, "setup.step_admin"),
        state.locales.t(lang, "setup.step_endpoint"),
    ]
}

#[derive(Template)]
#[template(path = "setup/step1.html")]
pub struct Setup1 {
    pub base: Base,
    pub s1: String,
    pub s2: String,
    pub s3: String,
    pub title: String,
    pub body: String,
    pub next: String,
}
#[derive(Template)]
#[template(path = "setup/step2.html")]
pub struct Setup2 {
    pub base: Base,
    pub s1: String,
    pub s2: String,
    pub s3: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub back: String,
    pub cta: String,
}
#[derive(Template)]
#[template(path = "setup/step3.html")]
pub struct Setup3 {
    pub base: Base,
    pub s1: String,
    pub s2: String,
    pub s3: String,
    pub hosts: String,
    pub port: String,
    pub title: String,
    pub host: String,
    pub port_label: String,
    pub back: String,
    pub cta: String,
}

macro_rules! setup_page {
    ($fn:ident, $tpl:ident, $step:literal, $($field:ident : $key:literal),*) => {
        pub async fn $fn<B: Backend>(
            State(state): State<AppState<B>>,
            jar: CookieJar,
            headers: HeaderMap,
            Query(q): Query<LangQuery>,
        ) -> Result<Response, WebError> {
            let prefs = match setup_context(&state, &jar, &headers, q.prefs()).await {
                Ok(p) => p,
                Err(r) => return Ok(*r),
            };
            let (lang, theme, set) = (prefs.lang, prefs.theme, prefs.set);
            let t = |k: &str| state.locales.t(lang, k);
            let [s1, s2, s3] = rail(&state, lang);
            let page = $tpl {
                base: Base::load(&state, lang, theme, t("setup.title"), None)
                    .await
                    .eyebrow("", format!("{:02} / 03", $step)),
                s1,
                s2,
                s3,
                $($field: t($key)),*
            };
            super::render_page(&page, &set)
        }
    };
}

setup_page!(
    setup1,
    Setup1,
    1,
    title: "setup.welcome_title",
    body: "setup.welcome_body",
    next: "setup.next"
);
setup_page!(
    setup2,
    Setup2,
    2,
    title: "setup.admin_title",
    username: "setup.username",
    password: "setup.password",
    back: "setup.back",
    cta: "setup.create_admin"
);

pub async fn setup3<B: Backend>(
    State(state): State<AppState<B>>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<LangQuery>,
) -> Result<Response, WebError> {
    let prefs = match setup_context(&state, &jar, &headers, q.prefs()).await {
        Ok(p) => p,
        Err(r) => return Ok(*r),
    };
    let (lang, theme, set) = (prefs.lang, prefs.theme, prefs.set);
    let v = state
        .backend
        .setup_suggest()
        .await
        .unwrap_or(serde_json::Value::Null);
    let t = |k: &str| state.locales.t(lang, k);
    let [s1, s2, s3] = rail(&state, lang);
    let page = Setup3 {
        base: Base::load(&state, lang, theme, t("setup.title"), None)
            .await
            .eyebrow("", "03 / 03"),
        s1,
        s2,
        s3,
        hosts: get_str(&v, "hosts"),
        port: get_str(&v, "port"),
        title: t("setup.host_title"),
        host: t("setup.host"),
        port_label: t("setup.port"),
        back: t("setup.back"),
        cta: t("setup.finish"),
    };
    super::render_page(&page, &set)
}
