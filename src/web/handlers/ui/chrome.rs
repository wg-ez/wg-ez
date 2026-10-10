#![forbid(unsafe_code)]

//! Shared chrome for server-rendered UI pages: language/theme prefs,
//! translated header/footer strings, base template context, and small
//! JSON/redirect helpers. No routes or templates live here.

use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::web::{
    ctx::{AppState, Backend, Principal},
    guards::{LANG_COOKIE, THEME_COOKIE, authenticate},
};

#[derive(Debug, Deserialize, Default)]
pub struct LangQuery {
    #[serde(default)]
    pub lang: Option<String>,
    /// `?theme=system|light|dark` (menu de la topbar, cf. `layout.html`).
    /// Un rechargement htmx (`/?lang=…`) n'envoie pas cette cle :
    /// la resolution retombe alors sur le cookie, jamais sur un reset.
    #[serde(default)]
    pub theme: Option<String>,
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub sort: Option<String>,
}

impl LangQuery {
    /// Les deux preferences de chrome portees par la query, pour
    /// [`page_prefs`] — qui n'a besoin de rien d'autre.
    pub fn prefs(&self) -> PrefsQuery<'_> {
        PrefsQuery {
            lang: self.lang.as_deref(),
            theme: self.theme.as_deref(),
        }
    }
}

/// `?lang=` + `?theme=`, isolees des autres query params (`filter`, `sort`…)
/// pour que [`page_prefs`] n'ait que deux arguments de prefs.
#[derive(Debug, Clone, Copy, Default)]
pub struct PrefsQuery<'a> {
    pub lang: Option<&'a str>,
    pub theme: Option<&'a str>,
}

impl<'a> PrefsQuery<'a> {
    /// Query vide : la page ne se soucie que des cookies.
    pub const NONE: Self = Self {
        lang: None,
        theme: None,
    };
}

/// Les trois etats de theme, dans l'ordre du menu de la topbar.
const THEMES: [&str; 3] = ["system", "light", "dark"];

/// `Some(v)` si `v` est un theme connu — validation stricte partagee par le
/// cookie et le query param, pour qu'un `theme=blue` retombe sur `system`.
fn valid_theme(v: &str) -> Option<&'static str> {
    THEMES.iter().copied().find(|t| *t == v)
}

/// Preferences resolues pour une page + les `Set-Cookie` a poser.
///
/// `set` porte les DEUX cookies de prefs (`lang` et `theme`), pas un seul :
/// le menu de la topbar pose les deux via query param, donc une reponse peut
/// avoir a les renvoyer ensemble. Vecteur plutot que `Option` pour que
/// `redirect` / `with_pref_cookies` n'aient rien de special a gerer.
#[derive(Debug, Clone, Default)]
pub struct Prefs {
    pub lang: &'static str,
    pub theme: String,
    /// Valeurs completes (`name=value; Path=/; …`), pretes a etre appendues.
    pub set: Vec<String>,
}

/// Resolve `(lang, theme)` et les cookies a poser.
///
/// Priorite query > cookie > defaut, en miroir exact pour les deux prefs :
/// `?lang=` passe par `Locales::resolve` (qui ignore les codes inconnus),
/// `?theme=` par [`valid_theme`]. Un query param invalide ne pose AUCUN cookie
/// (le cookie existant reste la valeur de reference) et ne change rien au
/// rendu — un `?theme=` bricole ne peut donc ni casser la page ni figer un
/// theme invalide dans le cookie.
pub fn page_prefs<B: Backend>(
    state: &AppState<B>,
    jar: &CookieJar,
    headers: &HeaderMap,
    q: PrefsQuery<'_>,
) -> Prefs {
    let cookie_lang = jar.get(LANG_COOKIE).map(|c| c.value().to_owned());
    let accept = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok());
    let lang = state
        .locales
        .resolve(q.lang, cookie_lang.as_deref(), accept);

    let q_theme = q.theme.and_then(valid_theme);
    let theme = q_theme
        .map(str::to_owned)
        .or_else(|| {
            jar.get(THEME_COOKIE)
                .and_then(|c| valid_theme(c.value()))
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "system".to_owned());

    let mut set = Vec::new();
    if q.lang
        .is_some_and(|l| state.locales.resolve(Some(l), None, None) == lang)
    {
        set.push(format!(
            "{LANG_COOKIE}={lang}; Path=/; SameSite=Lax; Max-Age=31536000"
        ));
    }
    if q_theme.is_some() {
        set.push(format!(
            "{THEME_COOKIE}={theme}; Path=/; SameSite=Lax; Max-Age=31536000"
        ));
    }
    Prefs { lang, theme, set }
}

// ---------------------------------------------------------------------------
// Translated chrome (precomputed; templates never call methods)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Tr {
    pub nav_clients: String,
    pub nav_admin: String,
    pub nav_me: String,
    pub nav_logout: String,
    pub nav_login: String,
    pub nav_new: String,
    /// Caption du champ « nom » du modal « nouveau client » : le `<dialog>`
    /// est unique (partage avec le QR) et vit dans `layout.html`, qui n'a pas
    /// d'acces aux libelles de `client_form.*` autrement.
    pub m_name: String,
    /// Libelle du bouton « annuler » de la modale de confirmation
    /// (`htmx:confirm` interpellee par `app.js`).
    pub m_cancel: String,
    pub h_up: String,
    pub h_down: String,
    pub h_peers: String,
    pub h_theme: String,
    pub h_t_system: String,
    pub h_t_light: String,
    pub h_t_dark: String,
    pub h_lang: String,
    pub h_menu: String,
    pub b_insecure: String,
    pub f_version: String,
    pub f_tagline: String,
    pub f_res: String,
}

impl Tr {
    pub fn for_lang<B: Backend>(state: &AppState<B>, lang: &str) -> Self {
        let t = |k: &str| state.locales.t(lang, k);
        Self {
            nav_clients: t("nav.clients"),
            nav_admin: t("nav.admin"),
            nav_me: t("nav.me"),
            nav_logout: t("nav.logout"),
            nav_login: t("nav.login"),
            nav_new: t("nav.new"),
            m_name: t("client_form.name"),
            m_cancel: t("client_form.cancel"),
            h_up: t("header.up"),
            h_down: t("header.down"),
            h_peers: t("header.peers"),
            h_theme: t("header.theme"),
            h_t_system: t("header.theme_system"),
            h_t_light: t("header.theme_light"),
            h_t_dark: t("header.theme_dark"),
            h_lang: t("header.language"),
            h_menu: t("header.menu"),
            b_insecure: t("banner.insecure"),
            f_version: t("footer.version"),
            f_tagline: t("footer.tagline"),
            f_res: t("footer.resources"),
        }
    }
}

/// Discriminants de l'onglet actif de la nav. Le layout compare
/// `base.nav_on` a ces chaines pour poser `is-on` (le petit bloc noir) ;
/// aucune de ces chaines n'est affichee, donc aucune n'est traduite.
pub const NAV_NONE: &str = "";
pub const NAV_CLIENTS: &str = "clients";
pub const NAV_ADMIN: &str = "admin";
pub const NAV_ME: &str = "me";

#[derive(Debug, Clone)]
pub struct Base {
    pub lang: String,
    pub theme: String,
    pub title: String,
    /// Numero de section affiche dans le `.eyebrow` sticky ("" = pas de
    /// numero, la page n'appartient pas a une serie).
    pub eb_num: String,
    /// Chapeau de droite du `.eyebrow` (progression, role, interface...).
    pub eb_aside: String,
    /// Onglet actif de la nav, discriminant EXPLICITE compare tel quel par
    /// `layout.html` (`""` = aucun, cf. [`NAV_NONE`]). Avant on comparait
    /// `title` a un libelle traduit : fragile (un titre traduit pouvait
    /// valoir un libelle de nav) et incomplet (les 4 pages admin).
    pub nav_on: String,
    pub version: String,
    pub insecure: bool,
    pub is_admin: bool,
    pub username: String,
    pub iface: String,
    pub iface_up: bool,
    pub peers: u64,
    /// Famille IPv4 active (`IP_MODE`), pour griser les champs associes.
    pub ipv4_enabled: bool,
    /// Famille IPv6 active.
    pub ipv6_enabled: bool,
    pub tr: Tr,
}

impl Base {
    pub async fn load<B: Backend>(
        state: &AppState<B>,
        lang: &'static str,
        theme: String,
        title: String,
        user: Option<(String, bool)>,
    ) -> Self {
        let version = state.backend.app_version();
        let (iface_up, peers, iface) = match state.backend.metrics_snapshot().await {
            Ok(s) => (true, s.connected_peers, s.interface.clone()),
            Err(_) => (false, 0, "wg0".to_owned()),
        };
        let tr = Tr::for_lang(state, lang);
        Self {
            lang: lang.to_owned(),
            theme,
            title,
            eb_num: String::new(),
            eb_aside: String::new(),
            nav_on: NAV_NONE.to_owned(),
            version,
            insecure: state.backend.insecure(),
            is_admin: user.as_ref().is_some_and(|(_, a)| *a),
            username: user.map(|(u, _)| u).unwrap_or_default(),
            iface,
            iface_up,
            peers,
            ipv4_enabled: state.backend.ipv4_enabled(),
            ipv6_enabled: state.backend.ipv6_enabled(),
            tr,
        }
    }

    /// Numero + chapeau du `.eyebrow`. Le chrome sticky (section, filet,
    /// pins, eyebrow) est rendu une seule fois par `layout.html` : les
    /// pages ne fournissent que le corps, donc aucune page ne peut
    /// diverger de la chrome des autres.
    pub fn eyebrow(mut self, num: impl Into<String>, aside: impl Into<String>) -> Self {
        self.eb_num = num.into();
        self.eb_aside = aside.into();
        self
    }

    /// Onglet actif de la nav : un des [`NAV_CLIENTS`] / [`NAV_ADMIN`] /
    /// [`NAV_ME`] (ou [`NAV_NONE`], defaut : login, setup, 404/500).
    ///
    /// Meme idee que [`Base::eyebrow`] : la page declare son onglet, la nav
    /// n'a plus qu'a le comparer. Les 4 pages admin partagent la meme
    /// chaine, donc elles materialisent toutes le bloc.
    pub fn nav(mut self, sec: &str) -> Self {
        self.nav_on = sec.to_owned();
        self
    }
}

// ---------------------------------------------------------------------------
// Redirect + cookie + JSON helpers (unit-free, no templates)
// ---------------------------------------------------------------------------

/// Append every pref cookie carried by [`Prefs::set`] to a response.
///
/// `append` (and not `insert`) : `lang` and `theme` are two DISTINCT names, so
/// one `Set-Cookie` per value, both preserved.
pub(super) fn with_pref_cookies(mut r: Response, set: &[String]) -> Response {
    for c in set {
        if let Ok(v) = c.parse() {
            r.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    r
}

pub(super) fn redirect(to: &str, set: &[String]) -> Response {
    let r = (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, to.to_owned())],
        Html(String::new()),
    )
        .into_response();
    with_pref_cookies(r, set)
}

/// Redirection vers `/login` apres un echec d'authentification.
///
/// Un appelant **htmx** ne doit pas recevoir le 303 : htmx le suivrait et
/// echangerait la page de login entiere dans sa cible (sur `/`, le sondage de
/// `#grid` incrustait alors une seconde `<nav>/<main>/<footer>` dans la grille
/// des clients). On renvoie donc `401` + `HX-Redirect` : htmx traite ce header
/// avant tout swap et fait une navigation navigateur, donc rien n'est echange
/// dans la page.
pub(crate) fn login_redirect(headers: &HeaderMap, set: &[String]) -> Response {
    if !crate::web::ctx::is_hx(headers) {
        return redirect("/login", set);
    }
    with_pref_cookies(
        crate::web::ctx::with_hx(
            (
                StatusCode::UNAUTHORIZED,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                "session expired",
            )
                .into_response(),
            headers,
            Some("/login"),
            None,
        ),
        set,
    )
}

/// Contexte d'une page **authentifiee** : les [`Prefs`] resolues (avec leurs
/// `Set-Cookie`) + le [`Principal`].
///
/// `Err(response)` porte deja la reponse d'echec d'authentification : la
/// redirection `303 /login`, ou `401` + `HX-Redirect` pour un appelant htmx
/// (cf. [`login_redirect`]). Les cookies de preferences sont calcules puis
/// joints a la reponse meme en cas d'echec.
///
/// La reponse est boxee (chemin d'echec froid) pour eviter le lint
/// `result_large_err` : `Response` depasse la taille conseillee pour une
/// variante `Err`.
pub(crate) async fn page_context<B: Backend>(
    state: &AppState<B>,
    jar: &CookieJar,
    headers: &HeaderMap,
    ip: Option<std::net::IpAddr>,
    q: PrefsQuery<'_>,
) -> Result<(Prefs, Principal), Box<Response>> {
    let prefs = page_prefs(state, jar, headers, q);
    match authenticate(state, jar, headers, ip).await {
        Ok(principal) => Ok((prefs, principal)),
        Err(_) => Err(Box::new(login_redirect(headers, &prefs.set))),
    }
}

/// Contexte d'une page du **setup** : les [`Prefs`] resolues puis le gating
/// sur `setupStep`. `Err(response)` = redirection `/login` (cookies de prefs
/// poses) quand le setup est deja termine (`setupStep == 0`). Reponse boxee
/// pour la meme raison que [`page_context`].
pub(crate) async fn setup_context<B: Backend>(
    state: &AppState<B>,
    jar: &CookieJar,
    headers: &HeaderMap,
    q: PrefsQuery<'_>,
) -> Result<Prefs, Box<Response>> {
    let prefs = page_prefs(state, jar, headers, q);
    if state.backend.setup_step().await.unwrap_or(0) == 0 {
        return Err(Box::new(login_redirect(headers, &prefs.set)));
    }
    Ok(prefs)
}

/// String/bool extractors over backend JSON (missing -> empty, never panic).
pub(super) fn get_str(v: &serde_json::Value, key: &str) -> String {
    match v.get(key) {
        Some(serde_json::Value::String(x)) => x.clone(),
        Some(serde_json::Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

pub(super) fn get_bool(v: &serde_json::Value, key: &str) -> bool {
    match v.get(key) {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::Number(n)) => n.as_i64().is_some_and(|i| i != 0),
        _ => false,
    }
}

/// Render a JSON string array as the CSV a text input must show: the fields
/// are submitted as CSV and `coerce_patch` splits on `,`, so showing the raw
/// `["1.1.1.1","::1"]` would round-trip the brackets as part of the values.
pub(super) fn get_list(v: &serde_json::Value, key: &str) -> String {
    match v.get(key) {
        Some(serde_json::Value::String(s)) => serde_json::from_str::<Vec<String>>(s)
            .map(|items| items.join(", "))
            .unwrap_or_default(),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|x| x.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        _ => String::new(),
    }
}
