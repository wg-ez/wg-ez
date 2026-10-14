#![forbid(unsafe_code)]

//! Setup wizard pages (valid only while setupStep != 0; else -> /login).
//!
//! Trois etapes : welcome (step1), admin (step2), endpoint (step3).
//! La logique (gating, redirections) reste portee par `src/setup/`.
//!
//! Socle commun : `SetupCommon` (rail `s1..s3` + `title` + nav `back`/`cta`)
//! embarque dans les trois templates ; `base` reste a plat car `layout.html`
//! (partage par toutes les pages) accede a `base.*`. Les corps specifiques
//! (welcome/admin/endpoint) restent des champs propres a chaque etape.
//! `setup_page!` couvre les trois etapes, `setup3` passant ses suggestions
//! dynamiques (`hosts`/`port` via `setup_suggest`) par le hook `extra`.

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

/// Socle partage des trois etapes : rail de progression, titre de carte et
/// navigation. `back`/`cta` sont vides sur step1 (pas de nav) ; step2/3 les
/// remplissent via `setup.back`/`setup.create_admin|finish`.
pub struct SetupCommon {
    pub s1: String,
    pub s2: String,
    pub s3: String,
    pub title: String,
    pub back: String,
    pub cta: String,
}

/// Charge le chrome d'une etape : `Base` (eyebrow `NN / 03`) + socle commun.
async fn setup_chrome<B: Backend>(
    state: &AppState<B>,
    lang: &'static str,
    theme: String,
    step: u8,
    title: String,
    back: String,
    cta: String,
) -> (Base, SetupCommon) {
    let [s1, s2, s3] = rail(state, lang);
    let base = Base::load(
        state,
        lang,
        theme,
        state.locales.t(lang, "setup.title"),
        None,
    )
    .await
    .eyebrow("", format!("{step:02} / 03"));
    (
        base,
        SetupCommon {
            s1,
            s2,
            s3,
            title,
            back,
            cta,
        },
    )
}

#[derive(Template)]
#[template(path = "setup/step1.html")]
pub struct Setup1 {
    pub base: Base,
    pub common: SetupCommon,
    pub body: String,
    pub next: String,
}
#[derive(Template)]
#[template(path = "setup/step2.html")]
pub struct Setup2 {
    pub base: Base,
    pub common: SetupCommon,
    pub username: String,
    pub password: String,
}
#[derive(Template)]
#[template(path = "setup/step3.html")]
pub struct Setup3 {
    pub base: Base,
    pub common: SetupCommon,
    pub hosts: String,
    pub port: String,
    pub host: String,
    pub port_label: String,
}

macro_rules! setup_page {
    // Etape sans navigation (step1) : `back`/`cta` restent vides.
    ($fn:ident, $tpl:ident, $step:literal, title: $title_key:literal ; $($field:ident : $key:literal),* $(,)?) => {
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
            let (base, common) =
                setup_chrome(&state, lang, theme, $step, t($title_key), String::new(), String::new())
                    .await;
            let page = $tpl {
                base,
                common,
                $($field: t($key)),*
            };
            super::render_page(&page, &set)
        }
    };
    // Etape avec navigation (step2).
    ($fn:ident, $tpl:ident, $step:literal, title: $title_key:literal, back: $back_key:literal, cta: $cta_key:literal ; $($field:ident : $key:literal),* $(,)?) => {
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
            let (base, common) =
                setup_chrome(&state, lang, theme, $step, t($title_key), t($back_key), t($cta_key))
                    .await;
            let page = $tpl {
                base,
                common,
                $($field: t($key)),*
            };
            super::render_page(&page, &set)
        }
    };
    // Etape avec navigation + suggestions dynamiques (step3) : le hook
    // `extra` liste les champs lus dans `setup_suggest` (`hosts`/`port`).
    ($fn:ident, $tpl:ident, $step:literal, title: $title_key:literal, back: $back_key:literal, cta: $cta_key:literal ; $($field:ident : $key:literal),* $(,)? ; extra $($efield:ident),+ $(,)?) => {
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
            let suggest = state
                .backend
                .setup_suggest()
                .await
                .unwrap_or(serde_json::Value::Null);
            let (base, common) =
                setup_chrome(&state, lang, theme, $step, t($title_key), t($back_key), t($cta_key))
                    .await;
            let page = $tpl {
                base,
                common,
                $($field: t($key),)*
                $($efield: get_str(&suggest, stringify!($efield)),)+
            };
            super::render_page(&page, &set)
        }
    };
}

setup_page!(
    setup1,
    Setup1,
    1,
    title: "setup.welcome_title";
    body: "setup.welcome_body",
    next: "setup.next",
);
setup_page!(
    setup2,
    Setup2,
    2,
    title: "setup.admin_title",
    back: "setup.back",
    cta: "setup.create_admin";
    username: "setup.username",
    password: "setup.password",
);
setup_page!(
    setup3,
    Setup3,
    3,
    title: "setup.host_title",
    back: "setup.back",
    cta: "setup.finish";
    host: "setup.host",
    port_label: "setup.port";
    extra hosts, port,
);
