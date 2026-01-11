//! Circuit identity extraction for Tor hidden services.
//!
//! Parses Tor circuit IDs from synthetic IPv6 addresses sent via PROXY protocol.

use pingora::protocols::l4::socket::SocketAddr;

/// Extracts circuit ID from an IPv6 address if it matches the configured prefix.
#[must_use]
pub fn extract_circuit_id(addr: &SocketAddr, prefix: &str) -> Option<String> {
    match addr {
        SocketAddr::Inet(inet_addr) => {
            if let std::net::SocketAddr::V6(v6_addr) = inet_addr {
                let ip_str = v6_addr.ip().to_string();
                if ip_str.starts_with(prefix) {
                    return Some(ip_str);
                }
            }
            None
        }
        SocketAddr::Unix(_) => None,
    }
}

/// Determines the rate limit key (Circuit ID or Session ID).
#[must_use]
pub fn rate_limit_key(circuit_id: Option<&str>, session_id: Option<&str>) -> Option<String> {
    circuit_id
        .or(session_id)
        .map(std::string::ToString::to_string)
}

/// Decodes a haproxy-encoded synthetic IPv6 address to a numeric circuit ID.
#[must_use]
pub fn decode_circuit_id(ipv6_str: &str) -> Option<String> {
    use std::net::Ipv6Addr;

    let addr: Ipv6Addr = ipv6_str.parse().ok()?;
    let segments = addr.segments();
    let circuit_id = u64::from(segments[7]);

    if circuit_id > 0 {
        Some(circuit_id.to_string())
    } else {
        let lower = (u64::from(segments[4]) << 48)
            | (u64::from(segments[5]) << 32)
            | (u64::from(segments[6]) << 16)
            | u64::from(segments[7]);
        if lower > 0 {
            Some(lower.to_string())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv6Addr, SocketAddr as StdSocketAddr};

    #[test]
    fn test_extract_circuit_id() {
        let ip = IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1));
        let addr = SocketAddr::Inet(StdSocketAddr::new(ip, 12345));
        assert_eq!(
            extract_circuit_id(&addr, "fc00"),
            Some("fc00::1".to_string())
        );

        let ip2 = IpAddr::V6(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1));
        let addr2 = SocketAddr::Inet(StdSocketAddr::new(ip2, 12345));
        assert_eq!(extract_circuit_id(&addr2, "fc00"), None);
    }

    #[test]
    fn test_rate_limit_key() {
        assert_eq!(rate_limit_key(Some("cid"), None), Some("cid".to_string()));
        assert_eq!(rate_limit_key(None, Some("sid")), Some("sid".to_string()));
        assert_eq!(
            rate_limit_key(Some("cid"), Some("sid")),
            Some("cid".to_string())
        );
        assert_eq!(rate_limit_key(None, None), None);
    }

    #[test]
    fn test_decode_circuit_id() {
        assert_eq!(decode_circuit_id("::1"), Some("1".to_string()));
    }
}
