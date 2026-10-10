#![forbid(unsafe_code)]

//! Rendu QR SVG partagé (client `.conf`, setup TOTP) : mêmes dimensions.

/// Encode `data` en QR SVG 200x200 minimum.
pub(crate) fn render_qr_svg(data: &[u8]) -> Result<String, qrcode::types::QrError> {
    Ok(qrcode::QrCode::new(data)?
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(200, 200)
        .build())
}
