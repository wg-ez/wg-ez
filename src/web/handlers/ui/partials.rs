#![forbid(unsafe_code)]

//! htmx partial templates (grid + TOTP setup). Returned for `hx-request`
//! callers and embedded in full pages; no routes here.

use askama::Template;

use super::{cards::Card, chrome::Base};
use crate::web::ctx::UserView;

/// Libelles partages par la grille : source unique des cles i18n utilisees a
/// la fois par `GridPartial` (fragment htmx) et `IndexPage` (page complete).
/// Tout ajout/renommage de cle se fait ici et nulle part ailleurs.
pub(crate) struct GridLabels {
    pub(crate) empty_title: String,
    pub(crate) empty_body: String,
    pub(crate) empty_cta: String,
    pub(crate) name: String,
    pub(crate) rx: String,
    pub(crate) tx: String,
    pub(crate) expires: String,
    pub(crate) endpoint: String,
    pub(crate) qrcode: String,
    pub(crate) config: String,
    pub(crate) otl: String,
    pub(crate) otl_short: String,
    pub(crate) enable: String,
    pub(crate) disable: String,
    pub(crate) disabled: String,
}

impl GridLabels {
    pub(crate) fn load(t: &impl Fn(&str) -> String) -> Self {
        Self {
            empty_title: t("clients.empty_title"),
            empty_body: t("clients.empty_body"),
            empty_cta: t("clients.empty_cta"),
            name: t("client_form.name"),
            rx: t("clients.rx"),
            tx: t("clients.tx"),
            expires: t("clients.expires"),
            endpoint: t("clients.endpoint"),
            qrcode: t("clients.qrcode"),
            config: t("clients.config"),
            otl: t("clients.one_time_link"),
            otl_short: t("clients.otl_short"),
            enable: t("clients.enable"),
            disable: t("clients.disable"),
            disabled: t("clients.disabled"),
        }
    }
}

#[derive(Template)]
#[template(path = "partials/grid.html")]
pub struct GridPartial {
    pub cards: Vec<Card>,
    /// Bouchons de fin de rangee (`cards.len() % 6`, cf. `grid_fillers`).
    pub fillers: Vec<&'static str>,
    pub t_empty_title: String,
    pub t_empty_body: String,
    pub t_empty_cta: String,
    /// Caption « Name » du champ du modal « nouveau client » declenche par le
    /// CTA de l'etat vide (`data-n`). Le libelle vient de `client_form.name`.
    pub t_name: String,
    pub t_rx: String,
    pub t_tx: String,
    pub t_expires: String,
    pub t_endpoint: String,
    pub t_qrcode: String,
    pub t_config: String,
    pub t_otl: String,
    pub t_otl_short: String,
    pub t_enable: String,
    pub t_disable: String,
    pub t_disabled: String,
}

impl GridPartial {
    pub(crate) fn new(
        cards: Vec<Card>,
        fillers: Vec<&'static str>,
        t: &impl Fn(&str) -> String,
    ) -> Self {
        let labels = GridLabels::load(t);
        Self {
            cards,
            fillers,
            t_empty_title: labels.empty_title,
            t_empty_body: labels.empty_body,
            t_empty_cta: labels.empty_cta,
            t_name: labels.name,
            t_rx: labels.rx,
            t_tx: labels.tx,
            t_expires: labels.expires,
            t_endpoint: labels.endpoint,
            t_qrcode: labels.qrcode,
            t_config: labels.config,
            t_otl: labels.otl,
            t_otl_short: labels.otl_short,
            t_enable: labels.enable,
            t_disable: labels.disable,
            t_disabled: labels.disabled,
        }
    }
}

#[derive(Template)]
#[template(path = "partials/totp_start.html")]
pub struct TotpStartPartial {
    pub secret: String,
    pub qr_svg: String,
    pub t_secret_k: String,
    pub t_code: String,
    pub t_verify: String,
}

/// Libelles partages par `/me` : source unique des cles i18n utilisees a la
/// fois par `MeInnerPartial` (fragment htmx) et `MePage` (page complete).
pub(crate) struct MeLabels {
    pub(crate) role_client: String,
    pub(crate) profile: String,
    pub(crate) username: String,
    pub(crate) username_note: String,
    pub(crate) change_username: String,
    pub(crate) password_title: String,
    pub(crate) password_note: String,
    pub(crate) current_password: String,
    pub(crate) new_password: String,
    pub(crate) change_password: String,
    pub(crate) totp_title: String,
    pub(crate) totp_enabled: String,
    pub(crate) totp_disabled: String,
    pub(crate) totp_setup: String,
    pub(crate) totp_remove: String,
    pub(crate) totp_active_note: String,
}

impl MeLabels {
    pub(crate) fn load(t: &impl Fn(&str) -> String) -> Self {
        Self {
            role_client: t("me.role_client"),
            profile: t("me.profile"),
            username: t("me.username"),
            username_note: t("me.username_note"),
            change_username: t("me.change_username"),
            password_title: t("me.password_title"),
            password_note: t("me.password_note"),
            current_password: t("me.current_password"),
            new_password: t("me.new_password"),
            change_password: t("me.change_password"),
            totp_title: t("me.totp_title"),
            totp_enabled: t("me.totp_enabled"),
            totp_disabled: t("me.totp_disabled"),
            totp_setup: t("me.totp_setup"),
            totp_remove: t("me.totp_remove"),
            totp_active_note: t("me.totp_active_note"),
        }
    }
}

/// Corps de `/me` (cf. `partials/me_inner.html`), renvoye seul aux appelants
/// htmx quand la 2FA change d'etat (trigger `refreshMe`). Meme motif que
/// `GridPartial` sur l'accueil : aucun `hx-select` cote client.
#[derive(Template)]
#[template(path = "partials/me_inner.html")]
pub struct MeInnerPartial {
    pub base: Base,
    pub user: UserView,
    pub t_role_client: String,
    pub t_profile: String,
    pub t_username: String,
    pub t_username_note: String,
    pub t_change_username: String,
    pub t_password_title: String,
    pub t_password_note: String,
    pub t_current_password: String,
    pub t_new_password: String,
    pub t_change_password: String,
    pub t_totp_title: String,
    pub t_totp_enabled: String,
    pub t_totp_disabled: String,
    pub t_totp_setup: String,
    pub t_totp_remove: String,
    pub t_totp_active_note: String,
}

impl MeInnerPartial {
    pub(crate) fn new(base: Base, user: UserView, t: &impl Fn(&str) -> String) -> Self {
        let labels = MeLabels::load(t);
        Self {
            base,
            user,
            t_role_client: labels.role_client,
            t_profile: labels.profile,
            t_username: labels.username,
            t_username_note: labels.username_note,
            t_change_username: labels.change_username,
            t_password_title: labels.password_title,
            t_password_note: labels.password_note,
            t_current_password: labels.current_password,
            t_new_password: labels.new_password,
            t_change_password: labels.change_password,
            t_totp_title: labels.totp_title,
            t_totp_enabled: labels.totp_enabled,
            t_totp_disabled: labels.totp_disabled,
            t_totp_setup: labels.totp_setup,
            t_totp_remove: labels.totp_remove,
            t_totp_active_note: labels.totp_active_note,
        }
    }
}
