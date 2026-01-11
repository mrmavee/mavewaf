//! PROXY protocol TCP wrapper.
//!
//! Handles the parsing of PROXY v1 headers from upstream load balancers or Tor.

use std::net::SocketAddr;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// Wraps a TCP stream to parse the PROXY protocol v1 header.
///
/// Returns the stream (with header consumed) and the parsed client address.
///
/// # Panics
///
/// Panics if the default fallback address "0.0.0.0:0" fails to parse (impossible).
pub async fn handle_proxy_protocol(mut stream: TcpStream) -> (TcpStream, SocketAddr) {
    let peer_addr = stream
        .peer_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));

    let mut buf = [0u8; 1024];

    let Ok(peek_len) = stream.peek(&mut buf).await else {
        return (stream, peer_addr);
    };

    if peek_len < 6 || &buf[..6] != b"PROXY " {
        return (stream, peer_addr);
    }

    let mut newline_pos = None;
    for i in 0..peek_len - 1 {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            newline_pos = Some(i);
            break;
        }
    }

    let Some(valid_len) = newline_pos.map(|pos| pos + 2) else {
        return (stream, peer_addr);
    };

    let Ok(header_str) = std::str::from_utf8(&buf[..valid_len]) else {
        return (stream, peer_addr);
    };

    let parts: Vec<&str> = header_str.trim().split(' ').collect();

    if parts.len() < 6 {
        return (stream, peer_addr);
    }

    let src_ip_str = parts[2];
    let src_port_str = parts[4];

    let src_ip: std::net::IpAddr = match src_ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return (stream, peer_addr),
    };

    let src_port: u16 = match src_port_str.parse() {
        Ok(p) => p,
        Err(_) => return (stream, peer_addr),
    };

    let mut discard = vec![0u8; valid_len];
    if stream.read_exact(&mut discard).await.is_err() {
        return (stream, peer_addr);
    }

    let new_addr = SocketAddr::new(src_ip, src_port);
    (stream, new_addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn test_proxy_protocol_valid_ipv4() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
        let addr = listener.local_addr().expect("addr failed");

        tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.expect("connect failed");
            stream
                .write_all(b"PROXY TCP4 1.2.3.4 5.6.7.8 80 443\r\n")
                .await
                .expect("write failed");
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let (server_stream, _) = listener.accept().await.expect("accept failed");
        let (_, peer_addr) = handle_proxy_protocol(server_stream).await;

        assert_eq!(peer_addr.ip().to_string(), "1.2.3.4");
        assert_eq!(peer_addr.port(), 80);
    }

    #[tokio::test]
    async fn test_proxy_protocol_too_short() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
        let addr = listener.local_addr().expect("addr failed");

        tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.expect("connect failed");
            stream.write_all(b"SHORT\r\n").await.expect("write failed");
        });

        let (server_stream, original_peer) = listener.accept().await.expect("accept failed");
        let (_, result_addr) = handle_proxy_protocol(server_stream).await;

        assert_eq!(result_addr.ip(), original_peer.ip());
    }

    #[tokio::test]
    async fn test_proxy_protocol_missing_header() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
        let addr = listener.local_addr().expect("addr failed");

        tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.expect("connect failed");
            stream
                .write_all(b"GET / HTTP/1.1\r\n")
                .await
                .expect("write failed");
        });

        let (server_stream, original_peer) = listener.accept().await.expect("accept failed");
        let (_, result_addr) = handle_proxy_protocol(server_stream).await;

        assert_eq!(result_addr.ip(), original_peer.ip());
    }
}
