#![forbid(unsafe_code)]

//! Static files (CSP-safe, no inline). Served from `./static` (baked into the
//! image; `build.rs` additionally embeds pre-gzipped copies).

use axum::{
    body::Body,
    extract::Path,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::web::ctx::WebError;

pub async fn static_file(
    Path(path): Path<String>,
    req_headers: HeaderMap,
) -> Result<Response, WebError> {
    if path.contains("..") || path.contains('\0') {
        return Err(WebError::not_found("not found"));
    }
    let fs_path = format!("static/{path}");
    let bytes = tokio::fs::read(&fs_path)
        .await
        .map_err(|_| WebError::not_found("not found"))?;
    // ETag = mtime + taille : `app.css` et `app.js` sont des artefacts de
    // build (le CSS est regenere par le stage css du Dockerfile), pas des fichiers stables.
    // Sans revalidation, un `max-age` long fait tourner l'ancien design
    // pendant une heure apres chaque redeploiement.
    let etag = tokio::fs::metadata(&fs_path).await.ok().and_then(|m| {
        let len = m.len();
        m.modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| {
                let secs = d.as_secs();
                let nanos = d.subsec_nanos();
                format!("W/\"{len:x}-{secs:x}{nanos:x}\"")
            })
    });
    let ctype = if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".js") {
        "text/javascript; charset=utf-8"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".json") {
        "application/json"
    } else {
        "application/octet-stream"
    };
    let cache = if path.starts_with("vendor/") {
        "public, max-age=31536000, immutable"
    } else {
        // `no-cache` = toujours revalider (304 via ETag), pas "ne jamais
        // revalider" : le cache navigateur reste utile, le CSS stale non.
        "public, no-cache"
    };
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    // 304 si le client a deja la version courante. `ETag` ET `Cache-Control`
    // restent joints a la reponse 304 : un revalidateur qui perd son
    // cache-control retomberait sinon dans la politique `no-store` du
    // middleware et casserait le cache des assets.
    let not_modified = etag.as_ref().is_some_and(|tag| {
        req_headers
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(',').any(|c| c.trim() == tag))
    });
    if let Some(tag) = etag
        && let Ok(v) = HeaderValue::from_str(&tag)
    {
        headers.insert(header::ETAG, v);
    }
    if not_modified {
        return Ok((StatusCode::NOT_MODIFIED, headers, Body::empty()).into_response());
    }
    Ok((headers, Body::from(bytes)).into_response())
}
