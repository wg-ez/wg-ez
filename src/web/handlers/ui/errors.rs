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

/// Page d'erreur (`error.html`) : unique tuile `ui::oops` partagee par la 404
/// du fallback et la 500.
///
/// Les deux statuts ne divergent que par `code` (« 404 »/« 500 », affiche dans
/// `oops__code` ET titre du document) et `message` (`error.e404`/`error.e500`,
/// resolu par l'appelant). Une seule struct et un seul gabarit remplacent la
/// paire quasi identique.
#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorPage {
    pub base: Base,
    pub code: String,
    pub message: String,
    pub t_back_home: String,
}

impl ErrorPage {
    /// Construit la page : `code` = statut affiche (aussi titre du document),
    /// `msg_key` = cle i18n du message. Pas d'`.eyebrow` : une page d'erreur
    /// n'appartient a aucune serie et le code est deja la tuile `oops__code`
    /// (normalisation 404/500 sur `("", "")`).
    async fn new<B: Backend>(
        state: &AppState<B>,
        lang: &'static str,
        theme: String,
        code: &'static str,
        msg_key: &'static str,
    ) -> Self {
        Self {
            base: Base::load(state, lang, theme, code.to_owned(), None).await,
            code: code.to_owned(),
            message: state.locales.t(lang, msg_key),
            t_back_home: state.locales.t(lang, "error.back_home"),
        }
    }
}

pub async fn not_found<B: Backend>(
    State(state): State<AppState<B>>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Response {
    let prefs = page_prefs(&state, &jar, &headers, PrefsQuery::NONE);
    let page = ErrorPage::new(&state, prefs.lang, prefs.theme, "404", "error.e404").await;
    let body = page.render().unwrap_or_else(|_| "not found".to_owned());
    (StatusCode::NOT_FOUND, Html(body)).into_response()
}

/// Rendu de `error.html` pour le statut 500.
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
) -> ErrorPage {
    ErrorPage::new(state, lang, theme, "500", "error.e500").await
}
