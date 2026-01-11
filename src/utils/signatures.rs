//! Binary file signature detection utilities.
//!
//! Identifies the MIME type of a byte slice based on its file signature.
#[must_use]
pub fn detect_safe_mime(data: &[u8]) -> Option<&'static str> {
    if data.len() < 3 {
        return None;
    }

    if data.starts_with(b"%PDF-") {
        return Some("application/pdf");
    }

    if data.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some("image/png");
    }

    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg");
    }

    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return Some("image/gif");
    }

    if data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WEBP" {
        return Some("image/webp");
    }

    if data.len() >= 12
        && &data[4..8] == b"ftyp"
        && (&data[8..12] == b"avif" || &data[8..12] == b"avis")
    {
        return Some("image/avif");
    }

    if data.len() >= 12 && &data[4..8] == b"ftyp" {
        let subtype = &data[8..12];
        if subtype == b"isom" || subtype == b"mp41" || subtype == b"mp42" || subtype == b"qt  " {
            return Some("video/mp4");
        }
    }

    if data.starts_with(b"ID3") {
        return Some("audio/mpeg");
    }

    if data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WAVE" {
        return Some("audio/wav");
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_safe_mime_images() {
        assert_eq!(detect_safe_mime(b"\x89PNG\r\n\x1a\n"), Some("image/png"));
        assert_eq!(detect_safe_mime(b"\xFF\xD8\xFF"), Some("image/jpeg"));
        assert_eq!(detect_safe_mime(b"GIF89a"), Some("image/gif"));
        assert_eq!(detect_safe_mime(b"RIFF....WEBP"), Some("image/webp"));
    }

    #[test]
    fn test_detect_safe_mime_others() {
        assert_eq!(detect_safe_mime(b"%PDF-"), Some("application/pdf"));
        assert_eq!(detect_safe_mime(b"ID3"), Some("audio/mpeg"));
        assert_eq!(detect_safe_mime(b"RIFF....WAVE"), Some("audio/wav"));
    }

    #[test]
    fn test_detect_safe_mime_video() {
        assert_eq!(detect_safe_mime(b"....ftypisom"), Some("video/mp4"));
        assert_eq!(detect_safe_mime(b"....ftypmp42"), Some("video/mp4"));
    }

    #[test]
    fn test_detect_unknown() {
        assert_eq!(detect_safe_mime(b"randomdata"), None);
        assert_eq!(detect_safe_mime(b""), None);
    }
}
