#![forbid(unsafe_code)]

//! Client card view-model for the index grid: everything precomputed so
//! templates stay logic-free (initials avatars, localized expiration /
//! last-seen labels).

use crate::web::ctx::{AppState, Backend, ClientView};

/// Card view: everything precomputed so templates stay logic-free.
#[derive(Debug, Clone)]
pub struct Card {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    pub connected: bool,
    pub initials: String,
    /// Live endpoint (`wg dump`), empty when the peer never handshaked.
    pub endpoint: String,
    /// Assigned tunnel address (v4, plus v6 when present).
    pub ip: String,
    /// Traffic counters, human readable (`12.4 MB`).
    pub rx_h: String,
    pub tx_h: String,
    /// Localized expiration label (`Permanent` when `expiresAt` is null).
    pub expires: String,
    pub expired: bool,
    /// Short connection label (`Connected` / `Disconnected`).
    pub seen: String,
}

fn human_bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0usize;
    while v >= 1000.0 && i + 1 < UNITS.len() {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} {}", UNITS[0])
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

fn initials(name: &str) -> String {
    let mut out = String::new();
    for w in name.split_whitespace().take(2) {
        if let Some(c) = w.chars().next() {
            out.push(c.to_ascii_uppercase());
        }
    }
    if out.is_empty() {
        out.push('?');
    }
    out
}

async fn card_from<B: Backend>(state: &AppState<B>, lang: &str, c: &ClientView) -> Card {
    let t = |k: &str| state.locales.t(lang, k);
    let expires = match c.expires_at.as_deref() {
        None => t("clients.never_expires"),
        Some(iso) => display_date(iso),
    };
    let seen = if c.connected {
        t("clients.connected")
    } else {
        t("clients.disconnected")
    };
    let mut parts = Vec::new();
    if !c.ipv4_address.trim().is_empty() {
        parts.push(c.ipv4_address.trim().to_string());
    }
    if let Some(v6) = c
        .ipv6_address
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        parts.push(v6.to_string());
    }
    let ip = parts.join(" · ");
    Card {
        id: c.id,
        name: c.name.clone(),
        enabled: c.enabled,
        connected: c.connected,
        initials: initials(&c.name),
        // Pas de handshake connu : libelle localise plutot qu'une ligne vide.
        endpoint: c
            .endpoint
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| t("clients.disconnected")),
        ip,
        rx_h: human_bytes(c.rx_bytes),
        tx_h: human_bytes(c.tx_bytes),
        expires,
        expired: false,
        seen,
    }
}

/// Display date: ISO `YYYY-MM-DD[T..]` -> `DD-MM-YYYY` (both locales,
/// same as the accepted input format). Falls back to the raw value when
/// unparseable.
pub(super) fn display_date(iso: &str) -> String {
    let date = iso.split('T').next().unwrap_or(iso);
    let mut parts = date.split('-');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(y), Some(m), Some(d)) if y.len() == 4 && m.len() == 2 && d.len() == 2 => {
            format!("{d}-{m}-{y}")
        }
        _ => iso.to_owned(),
    }
}

/// Bouchons de fin de rangee pour `#grid` : classes CSS posees selon
/// `n % 6` (ppcm des decoupages 2 et 3 colonnes). Le CSS n'affiche que
/// ceux du breakpoint courant ; la rangee reste complete, mais les
/// bouchons ne peignent pas le filet bas : le trait de fermeture
/// s'arrete au dernier client de la rangee, il ne court plus sous les
/// cellules vides.
pub(super) fn grid_fillers(n: usize) -> Vec<&'static str> {
    match n % 6 {
        1 => vec!["fill-both", "fill-3only"],
        2 => vec!["fill-3only"],
        3 => vec!["fill-2only"],
        4 => vec!["fill-3only", "fill-3only"],
        5 => vec!["fill-both"],
        _ => Vec::new(),
    }
}

pub(super) async fn load_cards<B: Backend>(
    state: &AppState<B>,
    lang: &str,
    user_id: Option<(i64, bool)>,
    filter: Option<&str>,
    sort: Option<&str>,
) -> Vec<Card> {
    let mut list = state.backend.list_clients().await.unwrap_or_default();
    super::super::filter_and_sort_clients(&mut list, user_id, filter, sort);
    let mut out = Vec::with_capacity(list.len());
    for c in &list {
        out.push(card_from(state, lang, c).await);
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn initials_fallback() {
        assert_eq!(super::initials("Alice Cooper"), "AC");
        assert_eq!(super::initials(""), "?");
    }

    #[test]
    fn grid_fillers_complete_the_row() {
        assert!(super::grid_fillers(0).is_empty());
        assert!(super::grid_fillers(6).is_empty());
        assert_eq!(super::grid_fillers(1), ["fill-both", "fill-3only"]);
        assert_eq!(super::grid_fillers(2), ["fill-3only"]);
        assert_eq!(super::grid_fillers(3), ["fill-2only"]);
        assert_eq!(super::grid_fillers(4), ["fill-3only", "fill-3only"]);
        assert_eq!(super::grid_fillers(5), ["fill-both"]);
        assert_eq!(super::grid_fillers(7), ["fill-both", "fill-3only"]);
    }

    #[test]
    fn dates_displayed_day_first() {
        assert_eq!(super::display_date("2031-12-25T00:00:00Z"), "25-12-2031");
        assert_eq!(super::display_date("2026-10-04T12:00:00Z"), "04-10-2026");
        assert_eq!(super::display_date("garbage"), "garbage");
    }

    #[test]
    fn human_bytes_scales_decimal_units() {
        assert_eq!(super::human_bytes(0), "0 B");
        assert_eq!(super::human_bytes(999), "999 B");
        assert_eq!(super::human_bytes(1_000), "1.0 KB");
        assert_eq!(super::human_bytes(2_400_000), "2.4 MB");
        assert_eq!(super::human_bytes(3_000_000_000), "3.0 GB");
        // Saturates on the largest unit instead of panicking.
        assert_eq!(super::human_bytes(u64::MAX), "18446744.1 TB");
    }
}
