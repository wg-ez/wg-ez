#![forbid(unsafe_code)]

//! Full-page handlers: index grid, client detail, me, login (+2FA).

use askama::Template;
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use axum_extra::extract::CookieJar;

use super::{
    cards::{Card, display_date, grid_fillers, load_cards},
    chrome::{Base, LangQuery, NAV_CLIENTS, NAV_ME, page_context, page_prefs, redirect},
    partials::{
        ClientLabels, ClientPlaceholders, GridLabels, GridPartial, MeInnerPartial, MeLabels,
        TokenRow,
    },
    render_fragment, render_page,
};
use crate::web::{
    ctx::{AppState, Backend, ClientView, WebError},
    guards::{authenticate, check},
};

#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexPage {
    pub base: Base,
    pub cards: Vec<Card>,
    /// Bouchons de fin de rangee (`cards.len() % 6`, cf. `grid_fillers`).
    pub fillers: Vec<&'static str>,
    /// Nombre de clients du bandeau : calcule avant que `cards` ne soit
    /// deplace dans la page (le template ne peut pas appeler `.len()`).
    pub client_count: usize,
    pub q: String,
    pub q_enc: String,
    pub sort: String,
    pub sort_label: String,
    pub t_search: String,
    pub t_asc: String,
    pub t_desc: String,
    pub t_created_asc: String,
    pub t_created_desc: String,
    /// Libelles partages avec `GridPartial` (cf. `GridLabels`), embarques au
    /// lieu d'etre aplatis : un ajout ne touche que `GridLabels` + gabarits.
    pub labels: GridLabels,
}

impl IndexPage {
    /// [`GridLabels`] porte la source unique des 15 libelles communs avec
    /// `GridPartial` ; seules les cles propres a la page (recherche/tri)
    /// sont resolues ici.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        base: Base,
        cards: Vec<Card>,
        client_count: usize,
        q: String,
        q_enc: String,
        sort: String,
        sort_label: String,
        t: &impl Fn(&str) -> String,
    ) -> Self {
        let labels = GridLabels::load(t);
        Self {
            base,
            fillers: grid_fillers(cards.len()),
            cards,
            client_count,
            q,
            q_enc,
            sort,
            sort_label,
            t_search: t("clients.search_placeholder"),
            t_asc: t("clients.sort_asc"),
            t_desc: t("clients.sort_desc"),
            t_created_asc: t("clients.sort_created_asc"),
            t_created_desc: t("clients.sort_created_desc"),
            labels,
        }
    }
}

pub async fn index<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<LangQuery>,
) -> Result<Response, WebError> {
    let ip = super::super::client_ip(&state, addr, &headers);
    let (prefs, me) = match page_context(&state, &jar, &headers, Some(ip), q.prefs()).await {
        Ok(ctx) => ctx,
        Err(r) => return Ok(*r),
    };
    let (lang, theme, set) = (prefs.lang, prefs.theme, prefs.set);
    let base = Base::load(
        &state,
        lang,
        theme,
        state.locales.t(lang, "clients.title"),
        Some((me.username.clone(), me.is_admin())),
    )
    .await;
    // Numero de section = position dans la nav (Clients=01, Admin=02,
    // Me=03) ; le chapeau rappelle l'etat de l'interface.
    let aside = format!(
        "{} · {} {}",
        state.locales.t(lang, "clients.stat_iface"),
        base.iface,
        if base.iface_up {
            state.locales.t(lang, "header.up")
        } else {
            state.locales.t(lang, "header.down")
        }
    );
    let base = base.eyebrow("01", aside).nav(NAV_CLIENTS);
    let cards = load_cards(
        &state,
        lang,
        Some((me.user_id, me.is_admin())),
        q.filter.as_deref(),
        q.sort.as_deref(),
    )
    .await;
    let t = |k: &str| state.locales.t(lang, k);
    // htmx poll/search hits the same URL: return the grid partial only.
    if headers.contains_key("hx-request") {
        let fillers = grid_fillers(cards.len());
        let grid = GridPartial::new(cards, fillers, &t);
        return render_fragment(&grid);
    }
    let client_count = cards.len();
    // Tri courant + libelle affiche dans le resume du menu. Le champ cache
    // `#sort` (pour le sondage htmx) et le lien de chaque option partagent
    // la meme valeur.
    let sort = q.sort.clone().unwrap_or_else(|| "name".to_owned());
    let sort_label = match sort.as_str() {
        "-name" => t("clients.sort_desc"),
        "created" => t("clients.sort_created_asc"),
        "-created" => t("clients.sort_created_desc"),
        _ => t("clients.sort_asc"),
    };
    // Le filtre est reinjecte dans les liens de tri (qui naviguent) : encode
    // pour ne pas casser la query (`&`, espaces, `#`...).
    let q_enc = q
        .filter
        .as_deref()
        .map(|f| {
            percent_encoding::utf8_percent_encode(f, percent_encoding::NON_ALPHANUMERIC).to_string()
        })
        .unwrap_or_default();
    let page = IndexPage::new(
        base,
        cards,
        client_count,
        q.filter.clone().unwrap_or_default(),
        q_enc,
        sort,
        sort_label,
        &t,
    );
    render_page(&page, &set)
}

#[derive(Template)]
#[template(path = "client.html")]
pub struct ClientPage {
    pub base: Base,
    pub c: ClientView,
    pub firewall_on: bool,
    /// Adresse v4 du client (telle que stockee, meme famille desactivee).
    pub ipv4: String,
    pub allowed_ips_v4: String,
    pub allowed_ips_v6: String,
    pub server_allowed_ips_v4: String,
    pub server_allowed_ips_v6: String,
    pub firewall_ips_v4: String,
    pub firewall_ips_v6: String,
    pub dns_v4: String,
    pub dns_v6: String,
    pub expires: String,
    pub ipv6: String,
    pub endpoint: String,
    // Libelles localises du formulaire (`client_form.*`, cf. `ClientLabels`),
    // precalcules pour que le template ne contienne aucun texte en dur.
    pub labels: ClientLabels,
    // Placeholders = valeur effective quand le champ est vide (heritage du
    // defaut global ou `auto`, cf. `ClientPlaceholders`).
    pub ph: ClientPlaceholders,
}

pub async fn client_detail<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(q): Query<LangQuery>,
) -> Result<Response, WebError> {
    let ip = super::super::client_ip(&state, addr, &headers);
    let (prefs, auth) = match page_context(&state, &jar, &headers, Some(ip), q.prefs()).await {
        Ok(ctx) => ctx,
        Err(r) => return Ok(*r),
    };
    let (lang, theme, set) = (prefs.lang, prefs.theme, prefs.set);
    let c = state
        .backend
        .get_client(id)
        .await?
        .ok_or_else(|| WebError::not_found("client not found"))?;
    // Anti-enumeration comme `handlers/client.rs::load_client` : un CLIENT qui
    // sonde l'id d'un autre obtient le même 404 qu'un id inconnu (pas de 403
    // oracle). Toute autre erreur (500, permission inconnue) est propagée.
    check(&auth, "clients.view", Some(c.user_id)).map_err(|e| {
        if e.status() == StatusCode::FORBIDDEN {
            WebError::not_found("client not found")
        } else {
            e
        }
    })?;
    let def = state.backend.global_defaults().await.unwrap_or_default();
    let join = |v: Option<&Vec<String>>| v.map(|x| x.join(", ")).unwrap_or_default();
    let base = Base::load(
        &state,
        lang,
        theme,
        c.name.clone(),
        Some((auth.username.clone(), auth.is_admin())),
    )
    .await
    // Le detail d'un pair appartient a la section Clients (01), pas a une
    // section a part entiere : meme numero que `/`.
    .eyebrow("01", state.locales.t(lang, "nav.clients"))
    .nav(NAV_CLIENTS);
    let t = |k: &str| state.locales.t(lang, k);
    let allowed_v4 = join(c.allowed_ips_v4.as_ref());
    let allowed_v6 = join(c.allowed_ips_v6.as_ref());
    let def_allowed_v4 = def.default_allowed_ips_v4.join(", ");
    let def_allowed_v6 = def.default_allowed_ips_v6.join(", ");
    let ph_firewall_v4 = if allowed_v4.trim().is_empty() {
        def_allowed_v4.clone()
    } else {
        allowed_v4.clone()
    };
    let ph_firewall_v6 = if allowed_v6.trim().is_empty() {
        def_allowed_v6.clone()
    } else {
        allowed_v6.clone()
    };

    let labels = ClientLabels::load(&t);
    // Exemples au format EXIGE (`backend/clients.rs::parse_expires_at`,
    // RFC 3339 historique accepte, tout le reste = 400) et de sous-reseau
    // supplementaire route vers ce pair (le `/32`+`/128` du tunnel est deja
    // automatique, cf. `push_peer`), par famille : le placeholder du champ
    // v6 ne doit jamais montrer une adresse v4. Exemple de domaine public
    // expose (format `host:port`) pour l'endpoint.
    let ph = ClientPlaceholders::new(
        "25-12-2031".to_string(),
        def_allowed_v4,
        def_allowed_v6,
        def.default_dns_v4.join(", "),
        def.default_dns_v6.join(", "),
        ph_firewall_v4,
        ph_firewall_v6,
        "vpn.example.com:51820".to_string(),
        "192.168.5.0/24".to_string(),
        "fd00:dead:beef::/64".to_string(),
    );

    let page = ClientPage {
        base,
        ipv4: c.ipv4_address.clone(),
        allowed_ips_v4: allowed_v4,
        allowed_ips_v6: allowed_v6,
        server_allowed_ips_v4: c.server_allowed_ips_v4.join(", "),
        server_allowed_ips_v6: c.server_allowed_ips_v6.join(", "),
        firewall_ips_v4: join(c.firewall_ips_v4.as_ref()),
        firewall_ips_v6: join(c.firewall_ips_v6.as_ref()),
        dns_v4: join(c.dns_v4.as_ref()),
        dns_v6: join(c.dns_v6.as_ref()),
        // Affiche `JJ-MM-AAAA` (l'input le renvoie tel quel au save, ce qui
        // renormalise vers le meme RFC 3339 : aller-retour stable).
        expires: c
            .expires_at
            .as_deref()
            .map(display_date)
            .unwrap_or_default(),
        ipv6: c.ipv6_address.clone().unwrap_or_default(),
        endpoint: c.server_endpoint.clone().unwrap_or_default(),
        firewall_on: def.firewall_enabled,
        labels,
        ph,
        c,
    };
    render_page(&page, &set)
}

#[derive(Template)]
#[template(path = "me.html")]
pub struct MePage {
    pub base: Base,
    pub user: crate::web::ctx::UserView,
    /// Libelles partages avec `MeInnerPartial` (cf. `MeLabels`).
    pub labels: MeLabels,
    /// Jetons d'API propres de l'appelant (affichage, cf. `TokenRow`).
    pub tokens: Vec<TokenRow>,
    /// Chapeau `.hud` du panneau jetons (« X API tokens », cf. `MeLabels::tokens_count`).
    pub tokens_count: String,
}

impl MePage {
    /// [`MeLabels`] porte la source unique des libelles communs avec
    /// `MeInnerPartial`.
    pub(crate) fn new(
        base: Base,
        user: crate::web::ctx::UserView,
        tokens: Vec<crate::web::ctx::ApiTokenView>,
        t: &impl Fn(&str) -> String,
    ) -> Self {
        let labels = MeLabels::load(t);
        let tokens_count = labels.tokens_count(tokens.len());
        Self {
            base,
            user,
            labels,
            tokens: tokens.iter().map(|v| TokenRow::new(v, t)).collect(),
            tokens_count,
        }
    }
}

pub async fn me<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<LangQuery>,
) -> Result<Response, WebError> {
    let ip = super::super::client_ip(&state, addr, &headers);
    let (prefs, auth) = match page_context(&state, &jar, &headers, Some(ip), q.prefs()).await {
        Ok(ctx) => ctx,
        Err(r) => return Ok(*r),
    };
    let (lang, theme, set) = (prefs.lang, prefs.theme, prefs.set);
    let user = state.backend.get_user(auth.user_id).await?;
    // Best-effort : un échec de lecture des jetons ne doit pas casser la page
    // de profil (la liste API reste la source de vérité).
    let tokens = state
        .backend
        .list_api_tokens(auth.user_id)
        .await
        .unwrap_or_default();
    let t = |k: &str| state.locales.t(lang, k);
    let base = Base::load(
        &state,
        lang,
        theme,
        state.locales.t(lang, "me.title"),
        Some((auth.username.clone(), auth.is_admin())),
    )
    .await
    .eyebrow("03", auth.username.clone())
    .nav(NAV_ME);
    // Refresh htmx (trigger `refreshMe` apres confirm/remove 2FA) : seul le
    // corps, comme `GET /` renvoie `GridPartial` aux appelants htmx.
    if headers.contains_key("hx-request") {
        let inner = MeInnerPartial::new(base, user, tokens, &t);
        return render_fragment(&inner);
    }
    let page = MePage::new(base, user, tokens, &t);
    render_page(&page, &set)
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginPage {
    pub base: Base,
    pub password_disabled: bool,
    pub t_user: String,
    pub t_pass: String,
    pub t_submit: String,
    pub t_disabled: String,
    pub t_note: String,
    /// Chapeau du titre-carte (`ui::phead_h1`) : « version X ». Pre-calcule
    /// cote Rust, jamais concatene dans le gabarit.
    pub t_version: String,
}

pub async fn login<B: Backend>(
    State(state): State<AppState<B>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<LangQuery>,
) -> Result<Response, WebError> {
    let prefs = page_prefs(&state, &jar, &headers, q.prefs());
    let (lang, theme, set) = (prefs.lang, prefs.theme, prefs.set);
    let ip = super::super::client_ip(&state, addr, &headers);
    if authenticate(&state, &jar, &headers, Some(ip)).await.is_ok() {
        return Ok(redirect("/", &set));
    }
    let disabled = !state.backend.password_auth_allowed().await.unwrap_or(true);
    let t = |k: &str| state.locales.t(lang, k);
    // Pas de numero de section : le login n'appartient pas a la serie.
    let base = Base::load(
        &state,
        lang,
        theme,
        state.locales.t(lang, "login.title"),
        None,
    )
    .await
    .eyebrow("", "wg-ez");
    let t_version = format!("{} {}", t("footer.version"), base.version);
    let page = LoginPage {
        base,
        password_disabled: disabled,
        t_user: t("login.username"),
        t_pass: t("login.password"),
        t_submit: t("login.submit"),
        t_disabled: t("login.disabled"),
        t_note: t("login.note"),
        t_version,
    };
    render_page(&page, &set)
}

#[derive(Template)]
#[template(path = "login_2fa.html")]
pub struct Login2faPage {
    pub base: Base,
    pub code_label: String,
    pub t_verify: String,
    pub t_cancel: String,
    pub t_note: String,
    /// Chapeau du titre-carte (`ui::phead_h1`) : « version X », pre-calcule
    /// cote Rust (cf. `LoginPage::t_version`).
    pub t_version: String,
}

pub async fn login_2fa<B: Backend>(
    State(state): State<AppState<B>>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<LangQuery>,
) -> Result<Response, WebError> {
    let prefs = page_prefs(&state, &jar, &headers, q.prefs());
    let (lang, theme, set) = (prefs.lang, prefs.theme, prefs.set);
    let t = |k: &str| state.locales.t(lang, k);
    let base = Base::load(
        &state,
        lang,
        theme,
        state.locales.t(lang, "login.need_2fa"),
        None,
    )
    .await
    .eyebrow("", "2FA");
    let t_version = format!("{} {}", t("footer.version"), base.version);
    let page = Login2faPage {
        base,
        code_label: t("login.code"),
        t_verify: t("login.verify"),
        t_cancel: t("login.cancel"),
        t_note: t("login.note_2fa"),
        t_version,
    };
    render_page(&page, &set)
}
