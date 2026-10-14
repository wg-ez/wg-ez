#![forbid(unsafe_code)]

//! Admin page (single page, no sub-tabs).
//!
//! Les six blocs d'administration (general / userconfig / interface / hooks
//! / pool d'adresses / redemarrage) sont empiles sur une seule page ; chaque
//! bloc garde son propre `<form>` car il vise un endpoint distinct. Les URL
//! historiques `/admin/general`, `/admin/config`, `/admin/interface` et
//! `/admin/hooks` rendent cette meme page (cf. `router/routes.rs`).
//!
//! Le contexte est un simple `Vec<Block>` : un bloc = un `.panel` decrit par
//! des donnees, dont le rendu est centralise dans
//! `templates/admin/macros.html`. Un libelle est resolu a cote du champ qu'il
//! decrit, donc ajouter un champ ne touche qu'un seul endroit.

use askama::Template;
use axum::{
    extract::{ConnectInfo, Query, State},
    http::HeaderMap,
    response::Response,
};
use axum_extra::extract::CookieJar;

use super::chrome::{Base, LangQuery, NAV_ADMIN, get_bool, get_list, get_str, page_context};
use crate::web::ctx::{AppState, Backend, WebError};

/// Cible `hx-post` de chaque bloc : un bloc = un formulaire = un endpoint.
const P_GENERAL: &str = "/api/admin/general";
const P_USERCONFIG: &str = "/api/admin/userconfig";
const P_INTERFACE: &str = "/api/admin/interface";
const P_CIDR: &str = "/api/admin/interface/cidr";
const P_RESTART: &str = "/api/admin/interface/restart";
const P_HOOKS: &str = "/api/admin/hooks";

/// Balise rendue par `ui::field` (via `adm::field`) : `input[type=text]`,
/// `input[type=number]`, `input[type=password]` ou `textarea`
/// (`multiline = true`). La case a cocher a sa propre entree ([`Check`]) :
/// sa valeur POST vaut toujours `true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Text,
    Number,
    Password,
    Area,
}

/// Un champ `<label class="flabel">`.
///
/// `name` est la cle attendue par l'API, ecrite **telle quelle** dans le
/// HTML rendu : c'est ce que l'audit verifie (`scripts/audit.d/ui.sh`
/// cherche `Allowed` et `firewall` sur `/admin/config|interface`).
pub struct Field {
    pub name: &'static str,
    pub label: String,
    pub value: String,
    pub kind: FieldKind,
    /// Attributs `min`/`max` : chaine vide = attribut absent.
    pub min: &'static str,
    pub max: &'static str,
    /// Attribut `placeholder` : chaine vide = attribut absent.
    pub placeholder: String,
    /// Famille indisponible : le champ est grise (`disabled`), donc jamais
    /// soumis, donc la valeur stockee en base reste inchangee.
    pub disabled: bool,
}

impl Field {
    pub fn text(name: &'static str, label: String, value: String) -> Self {
        Self {
            name,
            label,
            value,
            kind: FieldKind::Text,
            min: "",
            max: "",
            placeholder: String::new(),
            disabled: false,
        }
    }

    /// `bounds` = `(min, max)` ; un membre vide omet l'attribut.
    pub fn num(
        name: &'static str,
        label: String,
        value: String,
        bounds: (&'static str, &'static str),
    ) -> Self {
        Self {
            name,
            label,
            value,
            kind: FieldKind::Number,
            min: bounds.0,
            max: bounds.1,
            placeholder: String::new(),
            disabled: false,
        }
    }

    /// Champ mot de passe : jamais pre-rempli (on n'ecrit jamais le hash dans
    /// le HTML), `placeholder` porte l'indication « laisser vide pour
    /// conserver » / « requis ». Un POST vide signifie « inchange ».
    pub fn password(name: &'static str, label: String, placeholder: String) -> Self {
        Self {
            name,
            label,
            value: String::new(),
            kind: FieldKind::Password,
            min: "",
            max: "",
            placeholder,
            disabled: false,
        }
    }

    pub fn area(name: &'static str, label: String, value: String) -> Self {
        Self {
            name,
            label,
            value,
            kind: FieldKind::Area,
            min: "",
            max: "",
            placeholder: String::new(),
            disabled: false,
        }
    }

    /// Marque le champ comme grise (famille IPv4/IPv6 desactivee).
    pub fn disabled(mut self) -> Self {
        self.disabled = true;
        self
    }

    pub fn is_area(&self) -> bool {
        self.kind == FieldKind::Area
    }

    pub fn is_number(&self) -> bool {
        self.kind == FieldKind::Number
    }

    pub fn is_password(&self) -> bool {
        self.kind == FieldKind::Password
    }
}

/// Un interrupteur (`label.switch`), rendu hors de la grille de champs.
pub struct Check {
    pub name: &'static str,
    pub label: String,
    pub on: bool,
}

/// Bouton de bas de bloc.
///
/// `submit: true` = `<button type=submit>` du `<form>` (Save, « Changer
/// le CIDR ») ; `false` = bouton libre `hx-post` + `hx-confirm`, rendu
/// hors formulaire parce qu'il ne soumet rien (bloc Restart).
pub struct Action {
    pub label: String,
    pub submit: bool,
    pub confirm: String,
    /// Classes du bouton : `.btn` par defaut, rouge pour ce qui realloue
    /// les adresses ou coupe les tunnels.
    pub cls: &'static str,
}

impl Action {
    /// Bouton `submit` du formulaire (Save).
    pub fn submit(label: String) -> Self {
        Self {
            label,
            submit: true,
            confirm: String::new(),
            cls: "btn",
        }
    }

    /// Variante rouge du `submit` (re-allocation d'adresses).
    pub fn submit_danger(label: String) -> Self {
        Self {
            label,
            submit: true,
            confirm: String::new(),
            cls: "btn btn--danger btn--wrap",
        }
    }

    /// Bouton libre hors formulaire : `hx-post` + `hx-confirm`.
    pub fn danger(label: String, confirm: String) -> Self {
        Self {
            label,
            submit: false,
            confirm,
            cls: "btn btn--danger",
        }
    }
}

/// Un bloc de la page = un `.panel`.
pub struct Block {
    pub title: String,
    /// Chapeau mono a droite de la tete du panneau (interface, user...).
    pub aside: String,
    /// Fond `--danger` (bloc Restart).
    pub danger: bool,
    /// Cible `hx-post` du bloc (formulaire ou bouton libre).
    pub post: &'static str,
    /// 1 = champs pleine largeur, 2 = deux par rangee (`.form-2`).
    pub cols: usize,
    pub fields: Vec<Field>,
    pub checks: Vec<Check>,
    pub action: Action,
    /// Note mono sous les actions (`save_hint`, `restart_hint`).
    pub note: String,
}

impl Block {
    /// Bloc de la page. `action.submit` decide s'il devient un `<form>`
    /// (cf. [`Action`]) ; les champs par defunt sont en pleine largeur,
    /// `cols: 2` passe le bloc en `.form-2`.
    pub fn new(title: String, aside: String, post: &'static str, action: Action) -> Self {
        Self {
            title,
            aside,
            danger: false,
            post,
            cols: 1,
            fields: Vec::new(),
            checks: Vec::new(),
            action,
            note: String::new(),
        }
    }
}

/// La page : chrome + une liste de blocs. `templates/admin/index.html` se
/// limite a itérer `blocks` (une boucle, pas cinq squelettes).
#[derive(Template)]
#[template(path = "admin/index.html")]
pub struct AdminPage {
    pub base: Base,
    pub blocks: Vec<Block>,
}

/// `/admin` — et ses quatre alias historiques `/admin/{general,config,
/// interface,hooks}` : une seule page, une seule passe de prefs + auth.
pub async fn admin_page<B: Backend>(
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
    crate::web::guards::check(&auth, "admin.any", None)?;
    let (general, userconfig, interface, hooks) = (
        state.backend.get_general().await?,
        state.backend.get_userconfig().await?,
        state.backend.get_interface().await?,
        state.backend.get_hooks().await?,
    );
    let t = |k: &str| state.locales.t(lang, k);
    // Section Admin = 02 (Clients=01, Me=03).
    let base = Base::load(
        &state,
        lang,
        theme,
        t("admin.title"),
        Some((auth.username.clone(), true)),
    )
    .await
    .eyebrow("02", t("nav.admin"))
    .nav(NAV_ADMIN);
    let save = t("admin.save");
    let (iface, user) = (base.iface.clone(), base.username.clone());
    let (v4_on, v6_on) = (base.ipv4_enabled, base.ipv6_enabled);
    let device = get_str(&interface, "device");
    let blocks = vec![
        // 01 · general : duree de session + exposition des metriques, qui
        // exige un Bearer. Deux champs en demi-largeur (`.form-2`) ; le mot
        // de passe n'est jamais pre-rempli, son placeholder dit s'il faut le
        // definir ou s'il est deja configure.
        Block {
            cols: 2,
            fields: vec![
                Field::num(
                    "sessionTimeout",
                    t("admin.session_timeout"),
                    get_str(&general, "sessionTimeout"),
                    ("0", ""),
                ),
                Field::password(
                    "metricsPassword",
                    t("admin.metrics_password"),
                    if get_bool(&general, "metricsPasswordSet") {
                        t("admin.metrics_password_keep")
                    } else {
                        t("admin.metrics_password_required")
                    },
                ),
            ],
            checks: vec![
                Check {
                    name: "metricsPrometheus",
                    label: t("admin.metrics_prometheus"),
                    on: get_bool(&general, "metricsPrometheus"),
                },
                Check {
                    name: "metricsJson",
                    label: t("admin.metrics_json"),
                    on: get_bool(&general, "metricsJson"),
                },
            ],
            ..Block::new(
                t("admin.general"),
                user,
                P_GENERAL,
                Action::submit(save.clone()),
            )
        },
        // 02 · defaults clients : hote, port, DNS, allowed IPs, MTU,
        // keepalive. Six champs pairs -> deux par rangee.
        Block {
            cols: 2,
            fields: vec![
                Field::text("host", t("admin.host"), get_str(&userconfig, "host")),
                Field::num(
                    "port",
                    t("admin.port"),
                    get_str(&userconfig, "port"),
                    ("1", "65535"),
                ),
                Field {
                    disabled: !v4_on,
                    ..Field::text(
                        "defaultDnsV4",
                        t("admin.default_dns_v4"),
                        get_list(&userconfig, "defaultDnsV4"),
                    )
                },
                Field {
                    disabled: !v6_on,
                    ..Field::text(
                        "defaultDnsV6",
                        t("admin.default_dns_v6"),
                        get_list(&userconfig, "defaultDnsV6"),
                    )
                },
                Field {
                    disabled: !v4_on,
                    ..Field::text(
                        "defaultAllowedIpsV4",
                        t("admin.default_allowed_ips_v4"),
                        get_list(&userconfig, "defaultAllowedIpsV4"),
                    )
                },
                Field {
                    disabled: !v6_on,
                    ..Field::text(
                        "defaultAllowedIpsV6",
                        t("admin.default_allowed_ips_v6"),
                        get_list(&userconfig, "defaultAllowedIpsV6"),
                    )
                },
                Field::num(
                    "defaultMtu",
                    t("admin.default_mtu"),
                    get_str(&userconfig, "defaultMtu"),
                    ("1024", "9000"),
                ),
                Field::num(
                    "defaultKeepalive",
                    t("admin.default_keepalive"),
                    get_str(&userconfig, "defaultKeepalive"),
                    ("0", "65535"),
                ),
            ],
            checks: vec![Check {
                name: "defaultPreSharedKey",
                label: t("admin.default_preshared_key"),
                on: get_bool(&userconfig, "defaultPreSharedKey"),
            }],
            ..Block::new(
                t("admin.userconfig"),
                iface.clone(),
                P_USERCONFIG,
                Action::submit(save.clone()),
            )
        },
        // 03 · interface : rendu noyau + firewall par client.
        Block {
            cols: 2,
            fields: vec![
                Field::text("device", t("admin.device"), device.clone()),
                Field::num(
                    "port",
                    t("admin.listen_port"),
                    get_str(&interface, "port"),
                    ("1", "65535"),
                ),
                Field::num(
                    "mtu",
                    t("admin.mtu"),
                    get_str(&interface, "mtu"),
                    ("1024", "9000"),
                ),
                Field::text(
                    "routingTable",
                    t("admin.routing_table"),
                    get_str(&interface, "routingTable"),
                ),
            ],
            checks: vec![Check {
                name: "firewallEnabled",
                label: t("admin.firewall_enabled"),
                on: get_bool(&interface, "firewallEnabled"),
            }],
            note: t("admin.save_hint"),
            ..Block::new(
                t("admin.interface"),
                device.clone(),
                P_INTERFACE,
                Action::submit(save.clone()),
            )
        },
        // 04 · hooks : quatre zones de texte pleine largeur, juste sous
        // l'interface qu'ils instrumentent (PreUp/PostUp/PreDown/PostDown).
        Block {
            fields: vec![
                Field::area("preUp", t("admin.pre_up"), get_str(&hooks, "preUp")),
                Field::area("postUp", t("admin.post_up"), get_str(&hooks, "postUp")),
                Field::area("preDown", t("admin.pre_down"), get_str(&hooks, "preDown")),
                Field::area(
                    "postDown",
                    t("admin.post_down"),
                    get_str(&hooks, "postDown"),
                ),
            ],
            ..Block::new(
                t("admin.hooks"),
                iface.clone(),
                P_HOOKS,
                Action::submit(save.clone()),
            )
        },
        // 05 · pool d'adresses : re-allocation complete, action rouge.
        Block {
            cols: 2,
            fields: vec![
                Field {
                    disabled: !v4_on,
                    ..Field::text(
                        "ipv4Cidr",
                        t("admin.ipv4_cidr"),
                        get_str(&interface, "ipv4Cidr"),
                    )
                },
                Field {
                    disabled: !v6_on,
                    ..Field::text(
                        "ipv6Cidr",
                        t("admin.ipv6_cidr"),
                        get_str(&interface, "ipv6Cidr"),
                    )
                },
            ],
            ..Block::new(
                t("admin.cidr_title"),
                iface,
                P_CIDR,
                Action::submit_danger(t("admin.change_cidr")),
            )
        },
        // 06 · redemarrage : bouton libre (pas de formulaire a soumettre).
        // En dernier : c'est la zone qui coupe les tunnels.
        Block {
            danger: true,
            note: t("admin.restart_hint"),
            ..Block::new(
                t("admin.restart_title"),
                device.clone(),
                P_RESTART,
                Action::danger(t("admin.restart"), t("admin.restart_confirm")),
            )
        },
    ];
    super::render_page(&AdminPage { base, blocks }, &set)
}
