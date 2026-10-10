#![forbid(unsafe_code)]

//! Locales (compile-time embedded, `locales/en.json` is canonical).

use std::collections::HashMap;

use serde_json::Value;

use super::errors::WebError;

/// Supported locales. V1 ships EN + FR only.
pub const SUPPORTED_LANGS: [&str; 2] = ["en", "fr"];

/// Flat `dotted.key -> template` map per language.
#[derive(Debug, Clone, Default)]
pub struct Locales {
    en: HashMap<String, String>,
    fr: HashMap<String, String>,
}

fn flatten(prefix: &str, v: &Value, out: &mut HashMap<String, String>) {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(&key, child, out);
            }
        }
        Value::String(s) => {
            out.insert(prefix.to_owned(), s.clone());
        }
        _ => {}
    }
}

impl Locales {
    /// Load from the canonical locale files. Fails only on corrupt JSON.
    pub fn load() -> Result<Self, WebError> {
        let en_raw: Value = serde_json::from_str(include_str!("../../../locales/en.json"))
            .map_err(|e| WebError::internal(format!("bad en.json: {e}")))?;
        let fr_raw: Value = serde_json::from_str(include_str!("../../../locales/fr.json"))
            .map_err(|e| WebError::internal(format!("bad fr.json: {e}")))?;
        let mut en = HashMap::new();
        let mut fr = HashMap::new();
        flatten("", &en_raw, &mut en);
        flatten("", &fr_raw, &mut fr);
        Ok(Self { en, fr })
    }

    /// Resolve the request locale: `?lang=` > `lang` cookie >
    /// `Accept-Language` > `en`.
    pub fn resolve(
        &self,
        query_lang: Option<&str>,
        cookie_lang: Option<&str>,
        accept: Option<&str>,
    ) -> &'static str {
        for cand in [query_lang, cookie_lang] {
            if let Some(l) = normalize_lang(cand) {
                return l;
            }
        }
        if let Some(h) = accept {
            // First supported primary tag wins; q-values ignored (2 locales).
            for part in h.split(',') {
                let tag = part.split(';').next().unwrap_or("").trim();
                let primary = tag
                    .split('-')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase();
                if primary == "fr" {
                    return "fr";
                }
                if primary == "en" {
                    return "en";
                }
            }
        }
        "en"
    }

    /// Translate `key`, falling back to `en`, then to the key itself.
    pub fn t(&self, lang: &str, key: &str) -> String {
        let map = if lang == "fr" { &self.fr } else { &self.en };
        map.get(key)
            .or_else(|| self.en.get(key))
            .cloned()
            .unwrap_or_else(|| key.to_owned())
    }

    /// Every `fr` key must exist in `en` and vice versa (V1 full coverage).
    #[cfg(test)]
    pub fn coverage_ok(&self) -> bool {
        self.en.keys().all(|k| self.fr.contains_key(k))
            && self.fr.keys().all(|k| self.en.contains_key(k))
    }
}

fn normalize_lang(v: Option<&str>) -> Option<&'static str> {
    match v.map(str::trim).map(str::to_ascii_lowercase) {
        Some(s) if s == "fr" || s.starts_with("fr-") || s.starts_with("fr_") => Some("fr"),
        Some(s) if s == "en" || s.starts_with("en-") || s.starts_with("en_") => Some("en"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locales_have_full_coverage() {
        let l = Locales::load().expect("locales load");
        assert!(
            l.coverage_ok(),
            "fr.json must cover every en.json key and vice versa"
        );
    }

    #[test]
    fn lang_priority_query_over_cookie_over_header() {
        let l = Locales::load().expect("locales load");
        assert_eq!(l.resolve(Some("fr"), Some("en"), Some("en")), "fr");
        assert_eq!(l.resolve(None, Some("fr"), Some("en")), "fr");
        assert_eq!(l.resolve(None, None, Some("fr-FR, fr;q=0.9")), "fr");
        assert_eq!(l.resolve(None, None, Some("de, es;q=0.8")), "en");
        assert_eq!(l.resolve(None, None, None), "en");
        assert_eq!(l.resolve(Some("de"), None, None), "en");
    }
}
