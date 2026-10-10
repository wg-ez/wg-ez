#![forbid(unsafe_code)]

//! Error pages + fallback handler.

use askama::Template;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::CookieJar;

use super::chrome::{Base, PrefsQuery, page_prefs};
use crate::web::ctx::{AppState, Backend};

#[derive(Template)]
#[template(path = "error_404.html")]
pub struct NotFoundPage {
    pub base: Base,
    pub t_e404: String,
    pub t_back_home: String,
}

#[derive(Template)]
#[template(path = "error_500.html")]
pub struct InternalPage {
    pub base: Base,
    pub t_e500: String,
    pub t_back_home: String,
}

pub async fn not_found<B: Backend>(
    State(state): State<AppState<B>>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Response {
    let prefs = page_prefs(&state, &jar, &headers, PrefsQuery::NONE);
    let (lang, theme) = (prefs.lang, prefs.theme);
    let base = Base::load(&state, lang, theme, "404".to_owned(), None)
        .await
        .eyebrow("", "");
    let page = NotFoundPage {
        base,
        t_e404: state.locales.t(lang, "error.e404"),
        t_back_home: state.locales.t(lang, "error.back_home"),
    };
    let body = page.render().unwrap_or_else(|_| "not found".to_owned());
    (StatusCode::NOT_FOUND, Html(body)).into_response()
}

/// Rendu de `error_500.html`.
///
/// Aucun handler HTTP n'appelle encore `internal_page` (`WebError` sort en
/// JSON et le fallback ne couvre que la 404), mais le gabarit reste homogene
/// avec la 404 via la macro partagee `ui::oops`. Le test
/// `internal_page_500_renders_shared_oops_macro` verrouille le rendu via
/// l'unique point d'entree.
pub async fn internal_page<B: Backend>(
    state: &AppState<B>,
    lang: &'static str,
    theme: String,
) -> InternalPage {
    InternalPage {
        base: Base::load(state, lang, theme, "500".to_owned(), None)
            .await
            .eyebrow("", "500"),
        t_e500: state.locales.t(lang, "error.e500"),
        t_back_home: state.locales.t(lang, "error.back_home"),
    }
}
