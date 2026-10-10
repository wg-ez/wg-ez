#![forbid(unsafe_code)]

//! Dual body extractor + htmx response helpers (no new dependencies).

use axum::{
    body::Bytes,
    extract::{
        Form, FromRequest, Json,
        rejection::{BytesRejection, FailedToBufferBody, FormRejection, JsonRejection},
    },
    response::Response,
};
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::errors::WebError;

/// True when an axum buffering rejection is a `DefaultBodyLimit` overflow.
///
/// A body over the limit must surface as `413 Payload Too Large` (M12), not
/// the generic 400 used for malformed bodies. The detail stays server-side.
fn is_body_too_large(rej: &BytesRejection) -> bool {
    matches!(
        rej,
        BytesRejection::FailedToBufferBody(FailedToBufferBody::LengthLimitError(_))
    )
}

/// Accept `application/json` (API/audit clients) or
/// `application/x-www-form-urlencoded` (htmx/plain HTML forms). Checkboxes
/// must use `value="true"` with `#[serde(default)]` on the bool fields.
pub struct JsonOrForm<T>(pub T);

impl<T, S> FromRequest<S> for JsonOrForm<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = WebError;

    async fn from_request(
        req: axum::http::Request<axum::body::Body>,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let ctype = req
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        if ctype.starts_with("application/json") {
            let Json(v) = Json::<T>::from_request(req, state).await.map_err(|e| {
                tracing::debug!("json extractor rejected: {e}");
                if let JsonRejection::BytesRejection(b) = &e
                    && is_body_too_large(b)
                {
                    WebError::payload_too_large("request body too large")
                } else {
                    WebError::bad_request("invalid request body")
                }
            })?;
            Ok(Self(v))
        } else {
            let Form(v) = Form::<T>::from_request(req, state).await.map_err(|e| {
                tracing::debug!("form extractor rejected: {e}");
                if let FormRejection::BytesRejection(b) = &e
                    && is_body_too_large(b)
                {
                    WebError::payload_too_large("request body too large")
                } else {
                    WebError::bad_request("invalid request body")
                }
            })?;
            Ok(Self(v))
        }
    }
}

/// True when the request comes from htmx (partial UX: redirect/trigger
/// headers instead of relying on the JSON body).
pub fn is_hx(headers: &axum::http::HeaderMap) -> bool {
    headers.contains_key("hx-request")
}

/// Attach `HX-Redirect` / `HX-Trigger {"toast": ...}` for htmx callers.
/// Pure API clients ignore the extra headers; the JSON body is unchanged.
pub fn with_hx(
    resp: Response,
    headers: &axum::http::HeaderMap,
    redirect: Option<&str>,
    toast: Option<&str>,
) -> Response {
    let trigger = toast.map(|t| serde_json::json!({ "toast": t }));
    with_hx_trigger(resp, headers, redirect, trigger)
}

/// Generic variant with an arbitrary `HX-Trigger` JSON payload (htmx parses
/// it when it starts with `{`). `None` payload sends no trigger.
pub fn with_hx_trigger(
    mut resp: Response,
    headers: &axum::http::HeaderMap,
    redirect: Option<&str>,
    trigger: Option<Value>,
) -> Response {
    if !is_hx(headers) {
        return resp;
    }
    let h = resp.headers_mut();
    if let Some(to) = redirect
        && let Ok(v) = to.parse()
    {
        h.insert("hx-redirect", v);
    }
    if let Some(t) = trigger
        && let Ok(v) = t.to_string().parse()
    {
        h.insert("hx-trigger", v);
    }
    resp
}

/// Raw urlencoded/form patch (admin + client `Value` endpoints): normalizes
/// known checkbox keys (`"true"`/`"on"`/present -> bool, absent -> false)
/// since urlencoded has no native booleans.
pub fn normalize_bools(mut v: Value, keys: &[&str]) -> Value {
    if let Value::Object(ref mut map) = v {
        for k in keys {
            match map.remove(*k) {
                Some(Value::String(s)) => {
                    map.insert(
                        (*k).to_owned(),
                        Value::Bool(s == "true" || s == "on" || s == "1"),
                    );
                }
                Some(Value::Bool(b)) => {
                    map.insert((*k).to_owned(), Value::Bool(b));
                }
                Some(Value::Number(n)) => {
                    map.insert(
                        (*k).to_owned(),
                        Value::Bool(n.as_i64().is_some_and(|i| i != 0)),
                    );
                }
                Some(Value::Null) | None => {
                    map.insert((*k).to_owned(), Value::Bool(false));
                }
                Some(other) => {
                    map.insert((*k).to_owned(), other);
                }
            }
        }
    }
    v
}

/// Dual `Value` patch body: JSON passes through untouched (audit clients
/// send typed values); urlencoded forms arrive as flat strings and are
/// parsed by hand (`percent-encoding` is already in the stack, no new dep).
///
/// The body is buffered through the `Bytes` extractor so the global
/// `DefaultBodyLimit` (M12) applies to it too — the handler never reads an
/// unbounded body.
pub struct PatchBody(pub Value);

impl<S> FromRequest<S> for PatchBody
where
    S: Send + Sync,
{
    type Rejection = WebError;

    async fn from_request(
        req: axum::http::Request<axum::body::Body>,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let ctype = req
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let bytes = Bytes::from_request(req, state).await.map_err(|e| {
            if is_body_too_large(&e) {
                // Limit overflow: 413, detail kept server-side (M10/M12).
                tracing::warn!("request body too large");
                WebError::payload_too_large("request body too large")
            } else {
                // Body read failure (IO): keep the detail server-side.
                tracing::warn!("request body read failed: {e}");
                WebError::bad_request("invalid request body")
            }
        })?;
        if ctype.starts_with("application/json") || (bytes.first().is_some_and(|b| *b == b'{')) {
            let v: Value = serde_json::from_slice(&bytes).map_err(|e| {
                // serde detail can name DTO fields: log it, never echo it.
                tracing::debug!("invalid JSON body: {e}");
                WebError::bad_request("invalid JSON body")
            })?;
            return Ok(Self(v));
        }
        Ok(Self(parse_form(&bytes)?))
    }
}

/// Minimal `application/x-www-form-urlencoded` parser (flat key/value pairs).
/// Values stay strings; typing happens in [`coerce_patch`].
fn parse_form(bytes: &[u8]) -> Result<Value, WebError> {
    let raw = std::str::from_utf8(bytes).map_err(|_| WebError::bad_request("bad form encoding"))?;
    let mut map = serde_json::Map::with_capacity(16);
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let key = decode(k)?;
        let val = decode(v)?;
        if key.len() > 128 || val.len() > 1_048_576 {
            return Err(WebError::bad_request("bad form field"));
        }
        map.insert(key, Value::String(val));
    }
    return Ok(Value::Object(map));

    fn decode(field: &str) -> Result<String, WebError> {
        let plus = field.replace('+', " ");
        percent_encoding::percent_decode_str(&plus)
            .decode_utf8()
            .map(|s| s.into_owned())
            .map_err(|_| WebError::bad_request("bad form field"))
    }
}

/// Coerce a form-origin (all-string) patch into typed JSON. JSON-origin
/// values that already have the right type are left untouched; only
/// `String` values are transformed:
/// - `lists`: `""` -> `null` (inherit), `"a, b"` -> `["a", "b"]`.
/// - `bools`: `"true"/"on"/"1"` -> true, anything else (or absent) -> false.
/// - `nums`: integer-looking strings -> Number, else left as-is.
/// - `nullables`: `""` -> `null` (e.g. `expiresAt` = permanent).
pub fn coerce_patch(
    mut v: Value,
    lists: &[&str],
    bools: &[&str],
    nums: &[&str],
    nullables: &[&str],
) -> Value {
    if let Value::Object(map) = &mut v {
        for k in lists {
            // `map.get` + `map.insert` (et non `map.remove` dans le `if let`) :
            // une valeur deja typee (tableau JSON, ou `null`) doit survivre au
            // patch au lieu d'etre supprimee en silence.
            if let Some(Value::String(s)) = map.get(*k) {
                let items: Vec<Value> = s
                    .split(',')
                    .map(str::trim)
                    .filter(|x| !x.is_empty())
                    .map(|x| Value::String(x.to_owned()))
                    .collect();
                let value = if items.is_empty() {
                    Value::Null
                } else {
                    Value::Array(items)
                };
                map.insert((*k).to_owned(), value);
            }
        }
        for k in nullables {
            if matches!(map.get(*k), Some(Value::String(s)) if s.trim().is_empty()) {
                map.insert((*k).to_owned(), Value::Null);
            }
        }
        for k in nums {
            if let Some(Value::String(s)) = map.get(*k)
                && let Ok(n) = s.trim().parse::<i64>()
            {
                map.insert((*k).to_owned(), Value::Number(n.into()));
            }
        }
    }
    normalize_bools(v, bools)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn form_patch_coercion() {
        // urlencoded-style all-string patch -> typed JSON.
        let v = json!({
            "name": "bob",
            "enabled": "on",
            "mtu": "1420",
            "allowedIps": "10.0.0.0/24, ::/0",
            "dns": "",
            "expiresAt": "",
        });
        let out = coerce_patch(
            v,
            &["allowedIps", "dns"],
            &["enabled"],
            &["mtu"],
            &["expiresAt"],
        );
        assert_eq!(out["name"], json!("bob"));
        assert_eq!(out["enabled"], json!(true));
        assert_eq!(out["mtu"], json!(1420));
        assert_eq!(out["allowedIps"], json!(["10.0.0.0/24", "::/0"]));
        assert_eq!(out["dns"], json!(null));
        assert_eq!(out["expiresAt"], json!(null));
        // JSON-origin typed values pass through untouched.
        let v2 = json!({ "enabled": true, "mtu": 1500, "allowedIps": ["a"], "name": "123" });
        let out2 = coerce_patch(v2, &["allowedIps"], &["enabled"], &["mtu"], &[]);
        assert_eq!(out2["name"], json!("123"));
        assert_eq!(out2["mtu"], json!(1500));
        // non-regression : une liste JSON deja typee n'est pas supprimee.
        assert_eq!(out2["allowedIps"], json!(["a"]));
        // absent checkbox -> false.
        let out3 = coerce_patch(json!({}), &[], &["firewallEnabled"], &[], &[]);
        assert_eq!(out3["firewallEnabled"], json!(false));
    }

    #[test]
    fn json_lists_are_preserved() {
        // Tableau JSON : conserve tel quel (l'API doit pouvoir ecrire les
        // 4 champs de `CLIENT_LISTS`, pas seulement l'UI form-urlencoded).
        let v = json!({
            "allowedIps": ["10.99.0.0/24"],
            "firewallIps": ["0.0.0.0/0:51820"],
            "dns": ["9.9.9.9"],
            "serverAllowedIps": ["10.50.0.0/16"],
        });
        let out = coerce_patch(
            v,
            &["allowedIps", "firewallIps", "dns", "serverAllowedIps"],
            &[],
            &[],
            &[],
        );
        assert_eq!(out["allowedIps"], json!(["10.99.0.0/24"]));
        assert_eq!(out["firewallIps"], json!(["0.0.0.0/0:51820"]));
        assert_eq!(out["dns"], json!(["9.9.9.9"]));
        assert_eq!(out["serverAllowedIps"], json!(["10.50.0.0/16"]));
        // `null` JSON = heritage : conserve tel quel, jamais retire du patch.
        let v2 = json!({ "allowedIps": null, "dns": null, "name": "bob" });
        let out2 = coerce_patch(v2, &["allowedIps", "dns"], &[], &[], &[]);
        assert!(out2.get("allowedIps").is_some_and(Value::is_null));
        assert!(out2.get("dns").is_some_and(Value::is_null));
        assert_eq!(out2["name"], json!("bob"));
        // Tableau vide JSON : conserve (c'est une liste explicite, pas un champ
        // de formulaire vide qui deviendrait `null`).
        let v3 = json!({ "serverAllowedIps": [] });
        let out3 = coerce_patch(v3, &["serverAllowedIps"], &[], &[], &[]);
        assert_eq!(out3["serverAllowedIps"], json!([]));
        // Une cle de `lists` absente reste absente.
        let out4 = coerce_patch(json!({ "name": "bob" }), &["allowedIps"], &[], &[], &[]);
        assert!(out4.get("allowedIps").is_none());
    }

    #[test]
    fn form_parser_splits_pairs() {
        let v = parse_form(b"name=a+b&mtu=1420&empty=").expect("parse");
        assert_eq!(v["name"], json!("a b"));
        assert_eq!(v["mtu"], json!("1420"));
        assert_eq!(v["empty"], json!(""));
        assert!(parse_form(b"bad=%FF").is_err());
    }
}
