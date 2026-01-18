//! Security header injection.
//!
//! Handles the addition of security headers like HSTS, CSP, and COOP/COEP.

use crate::config::Config;
use pingora::Result;
use pingora::http::ResponseHeader;

/// Injects standard and configured security headers.
///
/// # Errors
///
/// Returns an error if header insertion fails.
pub fn inject_security_headers(
    upstream_response: &mut ResponseHeader,
    config: &Config,
) -> Result<()> {
    upstream_response.remove_header("Server");
    upstream_response.remove_header("X-Powered-By");
    upstream_response.remove_header("X-AspNet-Version");
    upstream_response.remove_header("X-AspNetMvc-Version");
    upstream_response.remove_header("X-XSS-Protection");
    upstream_response.remove_header("Expect-CT");
    upstream_response.remove_header("Via");
    upstream_response.remove_header("ETag");
    upstream_response.remove_header("Pragma");
    upstream_response.remove_header("Warning");
    upstream_response.remove_header("Feature-Policy");
    upstream_response.remove_header("Public-Key-Pins");

    upstream_response.insert_header(
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains; preload",
    )?;

    let csp_extra = if config.csp_extra_sources.is_empty() {
        ""
    } else {
        &config.csp_extra_sources
    };

    let csp = if csp_extra.is_empty() {
        "default-src * data: blob: filesystem: about: ws: wss: 'unsafe-inline' 'unsafe-eval' 'unsafe-dynamic'; \
         script-src 'self' 'unsafe-inline'; \
         connect-src * data: blob: 'unsafe-inline'; \
         img-src * data: blob: 'unsafe-inline'; \
         frame-src * data: blob: ; \
         style-src * data: blob: 'unsafe-inline'; \
         font-src * data: blob: 'unsafe-inline';"
            .to_string()
    } else {
        format!(
            "default-src * data: blob: filesystem: about: ws: wss: 'unsafe-inline' 'unsafe-eval' 'unsafe-dynamic' {csp_extra}; \
             script-src 'self' 'unsafe-inline' {csp_extra}; \
             connect-src * data: blob: 'unsafe-inline' {csp_extra}; \
             img-src * data: blob: 'unsafe-inline' {csp_extra}; \
             frame-src * data: blob: {csp_extra}; \
             style-src * data: blob: 'unsafe-inline' {csp_extra}; \
             font-src * data: blob: 'unsafe-inline' {csp_extra};"
        )
    };

    upstream_response.insert_header("Content-Security-Policy", &csp)?;

    upstream_response.insert_header("X-Content-Type-Options", "nosniff")?;
    upstream_response.insert_header("Referrer-Policy", "no-referrer")?;
    upstream_response.insert_header(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=(), payment=(), usb=(), vr=(), \
         autoplay=(), fullscreen=(), gyroscope=(), magnetometer=(), midi=(), \
         sync-xhr=(), interest-cohort=()",
    )?;

    if config.coop_policy != "off" {
        upstream_response.insert_header("Cross-Origin-Opener-Policy", &config.coop_policy)?;
    }
    upstream_response.insert_header("Cross-Origin-Resource-Policy", "same-origin")?;

    Ok(())
}
