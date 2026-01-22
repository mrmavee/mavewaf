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
    upstream_response.insert_header("Server", "CERN-httpd/3.0 (Mave)")?;
    upstream_response.insert_header("X-Powered-By", "you-shall-not-pass")?;

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
        "default-src 'none'; \
         base-uri 'self'; \
         object-src 'none'; \
         form-action 'self'; \
         frame-ancestors 'none'; \
         script-src 'self'; \
         style-src 'self'; \
         img-src 'self' data: blob:; \
         font-src 'self' data:; \
         connect-src 'self';"
            .to_string()
    } else {
        format!(
            "default-src 'none'; \
             base-uri 'self'; \
             object-src 'none'; \
             form-action 'self'; \
             frame-ancestors 'none'; \
             script-src 'self' {csp_extra}; \
             style-src 'self' {csp_extra}; \
             img-src 'self' data: blob: {csp_extra}; \
             font-src 'self' data: {csp_extra}; \
             connect-src 'self' {csp_extra};"
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_header_injection() {
        let config = crate::test_utils::create_test_config();
        let mut header = ResponseHeader::build(200, None).unwrap();
        header.insert_header("Server", "OldServer").unwrap();
        header.insert_header("X-Powered-By", "OldPower").unwrap();

        inject_security_headers(&mut header, &config).unwrap();

        assert_eq!(
            header.headers.get("Server").unwrap().to_str().unwrap(),
            "CERN-httpd/3.0 (Mave)"
        );
        assert_eq!(
            header
                .headers
                .get("X-Powered-By")
                .unwrap()
                .to_str()
                .unwrap(),
            "you-shall-not-pass"
        );
        assert!(header.headers.get("Strict-Transport-Security").is_some());
    }
}
