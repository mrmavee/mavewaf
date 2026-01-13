//! HTTP response utilities.
//!
//! Provides shared functions for serving HTML responses with proper headers.

use crate::config::Config;
use crate::core::proxy::headers::inject_security_headers;
use pingora::Result;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;

/// Serves an HTML response with proper headers and optional cookie.
///
/// # Errors
///
/// Returns an error if headers cannot be built or response cannot be written.
pub async fn serve_html(
    session: &mut Session,
    config: &Config,
    status: u16,
    html: String,
    set_cookie: Option<&str>,
) -> Result<bool> {
    let mut header = ResponseHeader::build(status, None)?;
    header.insert_header("Content-Type", "text/html; charset=utf-8")?;
    header.insert_header("Content-Length", html.len().to_string())?;
    header.insert_header(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, max-age=0",
    )?;
    header.insert_header("Pragma", "no-cache")?;
    header.insert_header("Expires", "0")?;

    if let Some(cookie) = set_cookie {
        header.insert_header("Set-Cookie", cookie)?;
    }

    inject_security_headers(&mut header, config)?;

    session
        .write_response_header(Box::new(header), false)
        .await?;
    session
        .write_response_body(Some(bytes::Bytes::from(html)), true)
        .await?;
    Ok(true)
}

/// Serves a redirect response with optional cookie.
///
/// # Errors
///
/// Returns an error if headers cannot be built or response cannot be written.
pub async fn serve_redirect(
    session: &mut Session,
    config: &Config,
    location: &str,
    set_cookie: Option<&str>,
    clear_cache: bool,
) -> Result<bool> {
    let mut header = ResponseHeader::build(303, None)?;
    header.insert_header("Location", location)?;
    header.insert_header(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, max-age=0",
    )?;
    header.insert_header("Pragma", "no-cache")?;
    header.insert_header("Expires", "0")?;

    if let Some(cookie) = set_cookie {
        header.insert_header("Set-Cookie", cookie)?;
    }

    if clear_cache {
        header.insert_header("Clear-Site-Data", "\"cache\"")?;
    }

    inject_security_headers(&mut header, config)?;

    session
        .write_response_header(Box::new(header), true)
        .await?;
    Ok(true)
}

/// Parses URL-encoded form data for CAPTCHA submission.
///
/// Returns (token, answer) tuple.
#[must_use]
pub fn parse_form_submission(body: &[u8]) -> (String, String) {
    use percent_encoding::percent_decode_str;
    use std::collections::HashMap;

    let body_str = String::from_utf8_lossy(body);
    let mut token = String::new();
    let mut solution = String::new();
    let mut c_map = HashMap::new();

    for pair in body_str.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        let dk = percent_decode_str(&k.replace('+', " "))
            .decode_utf8_lossy()
            .into_owned();
        let dv = percent_decode_str(&v.replace('+', " "))
            .decode_utf8_lossy()
            .into_owned();

        match dk.as_str() {
            "s" => token = dv,
            "solution" => solution = dv,
            key if key.starts_with('c') && key.len() == 2 => {
                c_map.insert(key.to_string(), dv);
            }
            _ => {}
        }
    }

    let answer = if solution.is_empty() {
        format!(
            "{}{}{}{}{}{}",
            c_map.get("c1").map_or("", String::as_str),
            c_map.get("c2").map_or("", String::as_str),
            c_map.get("c3").map_or("", String::as_str),
            c_map.get("c4").map_or("", String::as_str),
            c_map.get("c5").map_or("", String::as_str),
            c_map.get("c6").map_or("", String::as_str),
        )
    } else {
        solution
    };

    (token, answer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_form_submission_with_individual_chars() {
        let body = b"s=token_123&c1=A&c2=B&c3=C&c4=D&c5=E&c6=F";
        let (token, answer) = parse_form_submission(body);
        assert_eq!(token, "token_123");
        assert_eq!(answer, "ABCDEF");
    }

    #[test]
    fn test_parse_form_submission_with_solution() {
        let body = b"s=token_456&solution=XYZ123";
        let (token, answer) = parse_form_submission(body);
        assert_eq!(token, "token_456");
        assert_eq!(answer, "XYZ123");
    }

    #[test]
    fn test_parse_form_submission_empty() {
        let (token, answer) = parse_form_submission(b"");
        assert!(token.is_empty());
        assert!(answer.is_empty());
    }

    #[test]
    fn test_parse_form_submission_url_encoded() {
        let body = b"s=token%20test&solution=A%2BB";
        let (token, answer) = parse_form_submission(body);
        assert_eq!(token, "token test");
        assert_eq!(answer, "A+B");
    }

    #[test]
    fn test_parse_form_submission_plus_as_space() {
        let body = b"s=hello+world&solution=test";
        let (token, answer) = parse_form_submission(body);
        assert_eq!(token, "hello world");
        assert_eq!(answer, "test");
    }

    #[test]
    fn test_parse_form_submission_partial_chars() {
        let body = b"s=tok&c1=A&c3=C&c5=E";
        let (token, answer) = parse_form_submission(body);
        assert_eq!(token, "tok");
        assert_eq!(answer, "ACE");
    }

    #[test]
    fn test_parse_form_submission_ignores_invalid_keys() {
        let body = b"s=tok&c10=X&c=Y&cx=Z&c1=A";
        let (token, answer) = parse_form_submission(body);
        assert_eq!(token, "tok");
        assert_eq!(answer, "A");
    }
}
