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
    let has_upstream_csp = upstream_response
        .headers
        .contains_key("Content-Security-Policy");

    let is_widget_allowed = upstream_response
        .headers
        .get("X-Frame-Options")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("ALLOWALL"));

    let is_cross_origin_allowed = upstream_response
        .headers
        .get("Access-Control-Allow-Origin")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == "*");

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

    if config.features.csp_injected || !has_upstream_csp {
        let csp_extra = if config.csp_extra_sources.is_empty() {
            ""
        } else {
            &config.csp_extra_sources
        };

        let frame_ancestors = if is_widget_allowed { "*" } else { "'none'" };

        let csp = if csp_extra.is_empty() {
            format!(
                "default-src 'self'; \
                 base-uri 'self'; \
                 object-src 'none'; \
                 form-action 'self'; \
                 frame-ancestors {frame_ancestors}; \
                 script-src 'self' 'unsafe-inline'; \
                 style-src 'self' 'unsafe-inline'; \
                 img-src 'self' data: blob:; \
                 font-src 'self' data:; \
                 connect-src 'self';"
            )
        } else {
            format!(
                "default-src 'self' {csp_extra}; \
                 base-uri 'self' {csp_extra}; \
                 object-src 'none'; \
                 form-action 'self' {csp_extra}; \
                 frame-ancestors {frame_ancestors}; \
                 script-src 'self' 'unsafe-inline' {csp_extra}; \
                 style-src 'self' 'unsafe-inline' {csp_extra}; \
                 img-src 'self' data: blob: {csp_extra}; \
                 font-src 'self' data: {csp_extra}; \
                 connect-src 'self' {csp_extra};"
            )
        };

        upstream_response.insert_header("Content-Security-Policy", &csp)?;
    }

    upstream_response.insert_header("X-Content-Type-Options", "nosniff")?;
    upstream_response.insert_header("Referrer-Policy", "no-referrer")?;

    if config.coop_policy != "off" {
        upstream_response.insert_header("Cross-Origin-Opener-Policy", &config.coop_policy)?;
    }

    let corp_policy = if is_cross_origin_allowed {
        "cross-origin"
    } else {
        "same-origin"
    };
    upstream_response.insert_header("Cross-Origin-Resource-Policy", corp_policy)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

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

    #[test]
    fn test_header_injection_with_widget_allowed() {
        let config = crate::test_utils::create_test_config();
        let mut header = ResponseHeader::build(200, None).unwrap();
        header.insert_header("X-Frame-Options", "ALLOWALL").unwrap();

        inject_security_headers(&mut header, &config).unwrap();

        let csp = header
            .headers
            .get("Content-Security-Policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("frame-ancestors *"));
        assert!(!csp.contains("frame-ancestors 'none'"));
    }

    #[test]
    fn test_header_injection_with_cross_origin_allowed() {
        let config = crate::test_utils::create_test_config();
        let mut header = ResponseHeader::build(200, None).unwrap();
        header
            .insert_header("Access-Control-Allow-Origin", "*")
            .unwrap();

        inject_security_headers(&mut header, &config).unwrap();

        assert_eq!(
            header
                .headers
                .get("Cross-Origin-Resource-Policy")
                .unwrap()
                .to_str()
                .unwrap(),
            "cross-origin"
        );
    }

    #[test]
    fn test_header_injection_no_csp_if_turned_off() {
        let mut config_inner = (*crate::test_utils::create_test_config()).clone();
        config_inner.features.csp_injected = false;

        let config = Arc::new(config_inner);

        let mut header = ResponseHeader::build(200, None).unwrap();
        header
            .insert_header("Content-Security-Policy", "default-src 'none'")
            .unwrap();

        inject_security_headers(&mut header, &config).unwrap();

        assert_eq!(
            header
                .headers
                .get("Content-Security-Policy")
                .unwrap()
                .to_str()
                .unwrap(),
            "default-src 'none'"
        );
    }
}
