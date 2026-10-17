#![forbid(unsafe_code)]

//! htmx partial templates (grid + TOTP setup). Returned for `hx-request`
//! callers and embedded in full pages; no routes here.

use askama::Template;

use super::{cards::Card, chrome::Base};
use crate::web::ctx::{ApiTokenView, UserView};

/// Libelles partages par la grille : source unique des cles i18n utilisees a
/// la fois par `GridPartial` (fragment htmx) et `IndexPage` (page complete).
/// Tout ajout/renommage de cle se fait ici et nulle part ailleurs.
/// Les pages embarquent ce struct (`labels`) au lieu d'aplatir ses champs :
/// un ajout ne touche que ce struct, son `load` et les gabarits (`labels.x`).
pub struct GridLabels {
    pub empty_title: String,
    pub empty_body: String,
    pub empty_cta: String,
    pub name: String,
    pub rx: String,
    pub tx: String,
    pub expires: String,
    pub endpoint: String,
    pub qrcode: String,
    pub config: String,
    pub otl: String,
    pub otl_short: String,
    pub enable: String,
    pub disable: String,
    pub disabled: String,
}

impl GridLabels {
    pub fn load(t: &impl Fn(&str) -> String) -> Self {
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
    /// Libelles partages avec `IndexPage` (cf. `GridLabels`).
    pub labels: GridLabels,
}

impl GridPartial {
    pub(crate) fn new(
        cards: Vec<Card>,
        fillers: Vec<&'static str>,
        t: &impl Fn(&str) -> String,
    ) -> Self {
        Self {
            cards,
            fillers,
            labels: GridLabels::load(t),
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
    pub t_password: String,
}

/// Libelles partages par `/me` : source unique des cles i18n utilisees a la
/// fois par `MeInnerPartial` (fragment htmx) et `MePage` (page complete).
/// Embarque via `labels` (cf. `GridLabels`) : un ajout ne touche que ce
/// struct, son `load` et `me_inner.html` (`labels.x`).
pub struct MeLabels {
    pub role_client: String,
    pub profile: String,
    pub username: String,
    pub username_note: String,
    pub change_username: String,
    pub password_title: String,
    pub password_note: String,
    pub current_password: String,
    pub new_password: String,
    pub change_password: String,
    pub totp_title: String,
    pub totp_enabled: String,
    pub totp_disabled: String,
    pub totp_setup: String,
    pub totp_remove: String,
    pub totp_active_note: String,
    pub tokens_title: String,
    pub tokens_note: String,
    pub tokens_name: String,
    pub tokens_expires: String,
    pub tokens_expires_ph: String,
    pub tokens_create: String,
    pub tokens_revoke: String,
    pub tokens_created: String,
    pub tokens_expires_col: String,
    pub tokens_last_used: String,
    pub tokens_new_token: String,
    pub tokens_token: String,
    pub tokens_shown_once: String,
    pub tokens_copy: String,
    pub tokens_copied: String,
}

impl MeLabels {
    pub fn load(t: &impl Fn(&str) -> String) -> Self {
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
            tokens_title: t("me.api_tokens_title"),
            tokens_note: t("me.api_tokens_note"),
            tokens_name: t("me.api_tokens_name"),
            tokens_expires: t("me.api_tokens_expires"),
            tokens_expires_ph: t("me.api_tokens_expires_ph"),
            tokens_create: t("me.api_tokens_create"),
            tokens_revoke: t("me.api_tokens_revoke"),
            tokens_created: t("me.api_tokens_created"),
            tokens_expires_col: t("me.api_tokens_expires_col"),
            tokens_last_used: t("me.api_tokens_last_used"),
            tokens_new_token: t("me.api_tokens_new_token"),
            tokens_token: t("me.api_tokens_token"),
            tokens_shown_once: t("me.api_tokens_shown_once"),
            tokens_copy: t("me.api_tokens_copy"),
            tokens_copied: t("me.api_tokens_copied"),
        }
    }

    /// Chapeau du panneau jetons : « X API tokens ». Le nom vient du titre
    /// (`api_tokens_title`) ; rendu en `.hud` (mono uppercase cote CSS), donc
    /// meme police/emplacement que le username a droite de « Profile ».
    pub fn tokens_count(&self, n: usize) -> String {
        format!("{n} {}", self.tokens_title)
    }
}

/// Libelles de la fiche client (`client_form.*` + `clients.disabled`) :
/// source unique des cles i18n de `ClientPage` (cf. `GridLabels`/`MeLabels`).
/// La page embarque ce struct (`labels`) au lieu d'aplatir ses champs : un
/// ajout ne touche que ce struct, son `load` et `client.html` (`labels.x`).
/// Les valeurs restent a plat sur `ClientPage` (contrat API : `name=`).
pub struct ClientLabels {
    pub title: String,
    pub name: String,
    pub enabled: String,
    pub expires_at: String,
    pub ipv4: String,
    pub ipv6: String,
    pub dns_v4: String,
    pub dns_v6: String,
    pub allowed_ips_v4: String,
    pub allowed_ips_v6: String,
    pub server_allowed_ips_v4: String,
    pub server_allowed_ips_v6: String,
    pub firewall_ips_v4: String,
    pub firewall_ips_v6: String,
    pub mtu: String,
    pub keepalive: String,
    pub endpoint: String,
    pub save: String,
    pub back: String,
    pub hooks_note: String,
    pub disabled: String,
    pub danger_zone: String,
    pub delete: String,
    pub delete_confirm: String,
    pub rotate_keys: String,
    pub rotate_confirm: String,
    pub psk_title: String,
    pub psk_on: String,
    pub psk_off: String,
    pub psk_generate: String,
    pub psk_remove: String,
    pub psk_remove_confirm: String,
    pub psk_note: String,
}

impl ClientLabels {
    pub fn load(t: &impl Fn(&str) -> String) -> Self {
        Self {
            title: t("client_form.title"),
            name: t("client_form.name"),
            enabled: t("client_form.enabled"),
            expires_at: t("client_form.expires_at"),
            ipv4: t("client_form.ipv4"),
            ipv6: t("client_form.ipv6"),
            dns_v4: t("client_form.dns_v4"),
            dns_v6: t("client_form.dns_v6"),
            allowed_ips_v4: t("client_form.allowed_ips_v4"),
            allowed_ips_v6: t("client_form.allowed_ips_v6"),
            server_allowed_ips_v4: t("client_form.server_allowed_ips_v4"),
            server_allowed_ips_v6: t("client_form.server_allowed_ips_v6"),
            firewall_ips_v4: t("client_form.firewall_ips_v4"),
            firewall_ips_v6: t("client_form.firewall_ips_v6"),
            mtu: t("client_form.mtu"),
            keepalive: t("client_form.keepalive"),
            endpoint: t("client_form.endpoint"),
            save: t("client_form.save"),
            back: t("client_form.back"),
            hooks_note: t("client_form.hooks_note"),
            disabled: t("clients.disabled"),
            danger_zone: t("client_form.danger_zone"),
            delete: t("client_form.delete"),
            delete_confirm: t("client_form.delete_confirm"),
            rotate_keys: t("client_form.rotate_keys"),
            rotate_confirm: t("client_form.rotate_confirm"),
            psk_title: t("client_form.pre_shared_key"),
            psk_on: t("client_form.pre_shared_key_on"),
            psk_off: t("client_form.pre_shared_key_off"),
            psk_generate: t("client_form.pre_shared_key_generate"),
            psk_remove: t("client_form.pre_shared_key_remove"),
            psk_remove_confirm: t("client_form.pre_shared_key_remove_confirm"),
            psk_note: t("client_form.pre_shared_key_note"),
        }
    }
}

/// Placeholders de la fiche client : valeur effective quand le champ est vide
/// (heritage du defaut global ou `auto`). Le placeholder natif ne s'affiche
/// que si `value` est vide, donc la page les renseigne sans condition.
/// Aucune cle i18n ici (valeurs calculees + exemples figes) : le `new` prend
/// les valeurs calculees, les exemples vivent dans le constructeur.
pub struct ClientPlaceholders {
    pub expires: String,
    pub allowed_v4: String,
    pub allowed_v6: String,
    pub dns_v4: String,
    pub dns_v6: String,
    pub firewall_v4: String,
    pub firewall_v6: String,
    pub endpoint: String,
    pub server_allowed_v4: String,
    pub server_allowed_v6: String,
}

impl ClientPlaceholders {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        expires: String,
        allowed_v4: String,
        allowed_v6: String,
        dns_v4: String,
        dns_v6: String,
        firewall_v4: String,
        firewall_v6: String,
        endpoint: String,
        server_allowed_v4: String,
        server_allowed_v6: String,
    ) -> Self {
        Self {
            expires,
            allowed_v4,
            allowed_v6,
            dns_v4,
            dns_v6,
            firewall_v4,
            firewall_v6,
            endpoint,
            server_allowed_v4,
            server_allowed_v6,
        }
    }
}

/// Ligne d'affichage d'un jeton d'API (`me_inner.html`, ligne dense
/// `li.trow` : nom en gras + faits en texte courant sur une seule ligne).
/// L'ISO canonique est pré-formaté en `JJ-MM-AAAA` (cf. `cards::display_date`, même rendu que
/// les expirations de la grille et de la fiche client) ; une expiration
/// absente rend `clients.never_expires` (comme les clients), une dernière
/// utilisation absente rend `me.api_tokens_never`. L'API JSON garde la forme
/// brute (`ApiTokenView`, préfixe inclus) : ce struct ne sert qu'au gabarit.
pub struct TokenRow {
    pub id: i64,
    pub name: String,
    pub created: String,
    pub expires: String,
    pub last_used: String,
}

impl TokenRow {
    pub fn new(v: &ApiTokenView, t: &impl Fn(&str) -> String) -> Self {
        Self {
            id: v.id,
            name: v.name.clone(),
            created: super::cards::display_date(&v.created_at),
            expires: v
                .expires_at
                .as_deref()
                .map(super::cards::display_date)
                .unwrap_or_else(|| t("clients.never_expires")),
            last_used: v
                .last_used_at
                .as_deref()
                .map(super::cards::display_date)
                .unwrap_or_else(|| t("me.api_tokens_never")),
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
    /// Libelles partages avec `MePage` (cf. `MeLabels`).
    pub labels: MeLabels,
    /// Jetons d'API propres de l'appelant (affichage, cf. `TokenRow`).
    pub tokens: Vec<TokenRow>,
    /// Chapeau `.hud` du panneau jetons (« X API tokens », cf. `MeLabels::tokens_count`).
    pub tokens_count: String,
}

impl MeInnerPartial {
    pub(crate) fn new(
        base: Base,
        user: UserView,
        tokens: Vec<ApiTokenView>,
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
