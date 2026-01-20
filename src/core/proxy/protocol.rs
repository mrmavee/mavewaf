//! PROXY protocol parser and HTTP forwarder.
//!
//! Accepts TCP connections with PROXY v1 headers from Tor,
//! extracts circuit ID, and forwards to Pingora on internal port.

use async_chunked_transfer::Encoder;
use async_compression::tokio::write::{BrotliEncoder, GzipEncoder};
use proxy_header::{ParseConfig, ProxyHeader};
use std::fmt::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

fn extract_circuit_id_from_ip(ip: &std::net::IpAddr, prefix: &str) -> Option<String> {
    match ip {
        std::net::IpAddr::V6(v6) => {
            let ip_str = v6.to_string();
            if ip_str.starts_with(prefix) {
                Some(ip_str)
            } else {
                None
            }
        }
        std::net::IpAddr::V4(_) => None,
    }
}

fn parse_proxy_header(buf: &[u8], prefix: &str) -> Option<(usize, SocketAddr, Option<String>)> {
    let config = ParseConfig::default();

    match ProxyHeader::parse(buf, config) {
        Ok((header, consumed)) => header.proxied_address().map_or_else(
            || {
                debug!("PROXY header: local connection");
                None
            },
            |addr| {
                let source = addr.source;
                let circuit_id = extract_circuit_id_from_ip(&source.ip(), prefix);

                debug!(
                    source = %source,
                    circuit_id = ?circuit_id,
                    "PROXY header parsed"
                );

                Some((consumed, source, circuit_id))
            },
        ),
        Err(e) => {
            debug!(error = ?e, "PROXY header parse failed");
            None
        }
    }
}

#[derive(Clone)]
pub struct ProxyProtocolConfig {
    pub listen_addr: SocketAddr,
    pub internal_addr: SocketAddr,
    pub circuit_prefix: String,
    pub concurrency_limit: usize,
    pub defense_monitor: Option<Arc<crate::DefenseMonitor>>,
}

/// Runs the PROXY protocol listener.
///
/// # Panics
///
/// Panics if the TCP listener fails to bind to the configured address (fatal startup error).
pub async fn run_proxy_listener(config: ProxyProtocolConfig) {
    let listener = TcpListener::bind(config.listen_addr)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "FATAL: Failed to bind PROXY listener to {}: {}",
                config.listen_addr, e
            )
        });

    info!(
        listen_addr = %config.listen_addr,
        "PROXY protocol listener started"
    );
    info!(
        internal_addr = %config.internal_addr,
        "Forwarding to Pingora"
    );

    let connection_limit =
        std::sync::Arc::new(tokio::sync::Semaphore::new(config.concurrency_limit));

    loop {
        let Ok(permit) = connection_limit.clone().acquire_owned().await else {
            break;
        };

        match listener.accept().await {
            Ok((mut client, peer_addr)) => {
                let cfg = config.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = Box::pin(handle_connection(&mut client, peer_addr, &cfg)).await
                    {
                        debug!(peer_addr = %peer_addr, error = %e, "Connection error");
                    }
                });
            }
            Err(e) => {
                error!(error = %e, "Accept error");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}
fn configure_tcp_stream(stream: &TcpStream) {
    let sock = socket2::SockRef::from(&stream);

    let _ = stream.set_nodelay(true);

    let mut ka = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(60))
        .with_interval(std::time::Duration::from_secs(10));

    #[cfg(not(target_os = "openbsd"))]
    {
        ka = ka.with_retries(3);
    }

    let _ = sock.set_tcp_keepalive(&ka);

    #[cfg(target_os = "linux")]
    {
        let _ = sock.set_tcp_user_timeout(Some(std::time::Duration::from_millis(10000)));
    }

}

async fn handle_connection(
    client: &mut TcpStream,
    _peer_addr: SocketAddr,
    config: &ProxyProtocolConfig,
) -> std::io::Result<()> {
    configure_tcp_stream(client);

    let mut buf = [0u8; 512];
    let n = client.peek(&mut buf).await?;

    if n == 0 {
        return Ok(());
    }

    let (skip_bytes, circuit_id) = if buf.starts_with(b"PROXY ") {
        match parse_proxy_header(&buf[..n], &config.circuit_prefix) {
            Some((consumed, _source, cid)) => (consumed, cid),
            None => (0, None),
        }
    } else {
        (0, None)
    };

    if skip_bytes > 0 {
        let mut discard = vec![0u8; skip_bytes];
        client.read_exact(&mut discard).await?;
    }

    if let Some(ref cid) = circuit_id
        && config
            .defense_monitor
            .as_ref()
            .is_some_and(|m| m.is_circuit_blocked(cid))
    {
        warn!(circuit_id = %cid, "Blocking malicious circuit at L4");
        return Ok(());
    }

    let mut upstream = TcpStream::connect(config.internal_addr).await?;
    configure_tcp_stream(&upstream);

    let accept_encoding = process_request(client, &mut upstream, circuit_id).await?;
    Box::pin(process_response(client, &mut upstream, accept_encoding)).await?;

    Ok(())
}

fn validate_and_build_headers(
    req: &httparse::Request,
    circuit_id: Option<&String>,
) -> std::io::Result<(String, Option<usize>, Option<String>)> {
    let mut content_length: Option<usize> = None;
    let mut transfer_encoding = false;
    let mut accept_encoding = None;

    for header in req.headers.iter() {
        let name = header.name.to_lowercase();
        if name == "content-length" {
            if content_length.is_some() {
                warn!(
                    action = "REJECT",
                    "Duplicate Content-Length headers detected"
                );
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Duplicate Content-Length",
                ));
            }
            let value_str = std::str::from_utf8(header.value)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            content_length = Some(
                value_str
                    .trim()
                    .parse()
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?,
            );
        } else if name == "transfer-encoding" {
            transfer_encoding = true;
        } else if name == "accept-encoding" {
            accept_encoding = Some(String::from_utf8_lossy(header.value).to_string());
        }
    }

    if transfer_encoding {
        warn!(
            action = "REJECT",
            "Chunked Transfer-Encoding not supported / TE disallowed"
        );
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Chunked Transfer-Encoding disallowed",
        ));
    }

    let mut modified_request = String::new();
    if let (Some(method), Some(path), Some(version)) = (req.method, req.path, req.version) {
        let _ = write!(modified_request, "{method} {path} HTTP/1.{version}\r\n");
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Malformed Request Line",
        ));
    }

    for header in req.headers.iter() {
        let name = header.name;
        if name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("x-circuit-id")
        {
            continue;
        }
        let value = std::str::from_utf8(header.value)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let _ = write!(modified_request, "{name}: {value}\r\n");
    }

    modified_request.push_str("Connection: close\r\n");
    if let Some(cid) = circuit_id {
        let _ = write!(modified_request, "X-Circuit-ID: {cid}\r\n");
    }
    if let Some(cl) = content_length {
        let _ = write!(modified_request, "Content-Length: {cl}\r\n");
    }
    modified_request.push_str("\r\n");

    Ok((modified_request, content_length, accept_encoding))
}

async fn process_request(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    circuit_id: Option<String>,
) -> std::io::Result<Option<String>> {
    let mut buf = [0u8; 8192];
    let mut pos = 0;

    loop {
        let bytes_read = if let Ok(result) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read(&mut buf[pos..]),
        )
        .await
        {
            result?
        } else {
            warn!("Request header read timed out");
            return Ok(None);
        };

        if bytes_read == 0 {
            return Ok(None);
        }
        pos += bytes_read;

        let mut headers = [httparse::Header {
            name: "",
            value: &[],
        }; 64];
        let mut req = httparse::Request::new(&mut headers);

        match req.parse(&buf[..pos]) {
            Ok(httparse::Status::Complete(header_len)) => {
                let Ok((modified_request, content_length, accept_encoding)) =
                    validate_and_build_headers(&req, circuit_id.as_ref())
                else {
                    return Ok(None);
                };

                upstream.write_all(modified_request.as_bytes()).await?;

                let body_start = header_len;
                let body_in_buf = pos - body_start;

                if body_in_buf > 0 {
                    upstream.write_all(&buf[body_start..pos]).await?;
                }

                let cl = content_length.unwrap_or(0);
                if cl > body_in_buf {
                    let remaining = (cl - body_in_buf) as u64;
                    let mut limited = client.take(remaining);
                    tokio::io::copy(&mut limited, upstream).await?;
                }

                upstream.flush().await?;
                return Ok(accept_encoding);
            }
            Ok(httparse::Status::Partial) => {
                if pos >= buf.len() {
                    warn!("Request headers too large");
                    return Ok(None);
                }
            }
            Err(e) => {
                warn!(error = ?e, "Invalid HTTP Request");
                return Ok(None);
            }
        }
    }
}

fn build_response_header_string(
    resp: &httparse::Response,
    compress: Option<&str>,
) -> std::io::Result<String> {
    let mut modified_response = String::new();
    if let (Some(version), Some(code), Some(reason)) = (resp.version, resp.code, resp.reason) {
        let _ = write!(modified_response, "HTTP/1.{version} {code} {reason}\r\n");
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Malformed Response",
        ));
    }

    for header in resp.headers.iter() {
        let name = header.name;
        if name.eq_ignore_ascii_case("connection")
            || (compress.is_some()
                && (name.eq_ignore_ascii_case("content-length")
                    || name.eq_ignore_ascii_case("transfer-encoding")
                    || name.eq_ignore_ascii_case("content-encoding")))
        {
            continue;
        }
        let value = std::str::from_utf8(header.value).unwrap_or("");
        let _ = write!(modified_response, "{name}: {value}\r\n");
    }

    modified_response.push_str("Connection: close\r\n");

    if let Some(enc) = compress {
        let _ = write!(modified_response, "Content-Encoding: {enc}\r\n");
        modified_response.push_str("Transfer-Encoding: chunked\r\n");
    }

    modified_response.push_str("\r\n");
    Ok(modified_response)
}

async fn forward_response_body(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    initial_body: &[u8],
    compress: Option<&str>,
    content_length: usize,
    is_chunked: bool,
) -> std::io::Result<()> {
    let cursor = std::io::Cursor::new(initial_body);
    let mut chain = cursor.chain(upstream);

    if let Some(enc) = compress {
        let mut chunked_writer = Encoder::new(&mut *client);
        if enc == "br" {
            let mut encoder = BrotliEncoder::new(&mut chunked_writer);
            tokio::io::copy(&mut chain, &mut encoder).await?;
            encoder.shutdown().await?;
        } else {
            let mut encoder = GzipEncoder::new(&mut chunked_writer);
            tokio::io::copy(&mut chain, &mut encoder).await?;
            encoder.shutdown().await?;
        }
        chunked_writer.shutdown().await?;
    } else if is_chunked {
        tokio::io::copy(&mut chain, client).await?;
    } else if content_length > 0 {
        let mut limited = chain.take(content_length as u64);
        tokio::io::copy(&mut limited, client).await?;
    } else {
        tokio::io::copy(&mut chain, client).await?;
    }

    client.flush().await?;
    Ok(())
}

async fn process_response(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    accept_encoding: Option<String>,
) -> std::io::Result<()> {
    let mut buf = [0u8; 8192];
    let mut pos = 0;

    loop {
        let bytes_read = upstream.read(&mut buf[pos..]).await?;
        if bytes_read == 0 {
            return Ok(());
        }
        pos += bytes_read;

        let mut headers = [httparse::Header {
            name: "",
            value: &[],
        }; 64];
        let mut resp = httparse::Response::new(&mut headers);

        match resp.parse(&buf[..pos]) {
            Ok(httparse::Status::Complete(header_len)) => {
                let body_start = header_len;

                let mut is_chunked = false;
                let mut content_length: usize = 0;
                let mut is_upstream_compressed = false;

                for header in resp.headers.iter() {
                    let name = header.name;
                    let value = std::str::from_utf8(header.value)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

                    if name.eq_ignore_ascii_case("content-length") {
                        if let Ok(cl) = value.trim().parse() {
                            content_length = cl;
                        }
                    } else if name.eq_ignore_ascii_case("transfer-encoding") {
                        if value.to_lowercase().contains("chunked") {
                            is_chunked = true;
                        }
                    } else if name.eq_ignore_ascii_case("content-encoding") {
                        is_upstream_compressed = true;
                    }
                }

                let compress = match accept_encoding {
                    Some(ref ae)
                        if !is_upstream_compressed && !is_chunked && content_length > 0 =>
                    {
                        let ae_lower = ae.to_lowercase();
                        if ae_lower.contains("br") {
                            Some("br")
                        } else if ae_lower.contains("gzip") {
                            Some("gzip")
                        } else {
                            None
                        }
                    }
                    _ => None,
                };
                let modified_response = build_response_header_string(&resp, compress)?;
                client.write_all(modified_response.as_bytes()).await?;

                forward_response_body(
                    client,
                    upstream,
                    &buf[body_start..pos],
                    compress,
                    content_length,
                    is_chunked,
                )
                .await?;
                return Ok(());
            }
            Ok(httparse::Status::Partial) => {
                if pos >= buf.len() {
                    warn!("Response headers too large");
                    return Ok(());
                }
            }
            Err(e) => {
                warn!(error = ?e, "Invalid HTTP Response");
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_extract_circuit_id() {
        let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(extract_circuit_id_from_ip(&v4, "fc00"), None);

        let v6_match = IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1));
        assert!(extract_circuit_id_from_ip(&v6_match, "fc00").is_some());

        let v6_no_match = IpAddr::V6(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(extract_circuit_id_from_ip(&v6_no_match, "fc00"), None);
    }

    #[test]
    fn test_parse_proxy_header_valid() {
        let input = b"PROXY TCP4 1.2.3.4 5.6.7.8 111 222\r\nDATA";
        let res = parse_proxy_header(input, "fc00");
        assert!(res.is_some());
        let (consumed, src, cid) = res.unwrap();
        assert_eq!(consumed, 36);
        assert_eq!(src.ip(), "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(cid, None);
    }

    #[test]
    fn test_parse_proxy_header_circuit_id() {
        let input = b"PROXY TCP6 fc00::1 fc00::2 111 222\r\n";
        let res = parse_proxy_header(input, "fc00");
        assert!(res.is_some());
        let (_, src, cid) = res.unwrap();
        assert_eq!(src.ip(), "fc00::1".parse::<IpAddr>().unwrap());
        assert!(cid.is_some());
        assert!(cid.unwrap().starts_with("fc00"));
    }

    #[test]
    fn test_parse_proxy_header_invalid() {
        let input = b"INVALID HEADER\r\n";
        assert!(parse_proxy_header(input, "fc00").is_none());
    }

    #[tokio::test]
    async fn test_process_request_integration() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);

            if req.contains("X-Circuit-ID: circuit123") {
                socket.write_all(b"OK").await.unwrap();
            } else {
                socket.write_all(b"FAIL").await.unwrap();
            }
        });

        let dummy_client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dummy_client_addr = dummy_client_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let mut stream = TcpStream::connect(dummy_client_addr).await.unwrap();
            stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        });

        let (mut client_stream, _) = dummy_client_listener.accept().await.unwrap();

        let mut upstream_conn = TcpStream::connect(upstream_addr).await.unwrap();

        process_request(
            &mut client_stream,
            &mut upstream_conn,
            Some("circuit123".into()),
        )
        .await
        .unwrap();

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_process_response_integration() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello")
                .await
                .unwrap();
        });

        let mut upstream_conn = TcpStream::connect(upstream_addr).await.unwrap();

        let dummy_client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dummy_client_addr = dummy_client_listener.local_addr().unwrap();

        let client_task = tokio::spawn(async move {
            let mut stream = TcpStream::connect(dummy_client_addr).await.unwrap();
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf[..n]).to_string()
        });

        let (mut client_stream, _) = dummy_client_listener.accept().await.unwrap();

        Box::pin(process_response(
            &mut client_stream,
            &mut upstream_conn,
            None,
        ))
        .await
        .unwrap();

        let res = client_task.await.unwrap();
        assert!(res.contains("Hello"));
        assert!(res.contains("Connection: close"));
    }

    #[test]
    fn test_extract_circuit_id_prefix_mismatch() {
        let v6 = IpAddr::V6(Ipv6Addr::new(0xfc01, 0, 0, 0, 0, 0, 0, 1));
        assert!(extract_circuit_id_from_ip(&v6, "fc00").is_none());
    }

    #[test]
    fn test_extract_circuit_id_different_prefix() {
        let v6 = IpAddr::V6(Ipv6Addr::new(0xdead, 0xbeef, 0, 0, 0, 0, 0, 1));
        assert!(extract_circuit_id_from_ip(&v6, "dead").is_some());
    }

    #[test]
    fn test_parse_proxy_header_local() {
        let input = b"PROXY UNKNOWN\r\n";
        assert!(parse_proxy_header(input, "fc00").is_none());
    }

    #[test]
    fn test_proxy_config_clone() {
        let config = ProxyProtocolConfig {
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            internal_addr: "127.0.0.1:8081".parse().unwrap(),
            circuit_prefix: "fc00".into(),
            concurrency_limit: 1024,
            defense_monitor: None,
        };
        let cloned = config;
        assert_eq!(cloned.circuit_prefix, "fc00");
    }

    #[tokio::test]
    async fn test_process_response_chunked() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let mut upstream_conn = TcpStream::connect(upstream_addr).await.unwrap();

        let dummy_client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dummy_client_addr = dummy_client_listener.local_addr().unwrap();

        let client_task = tokio::spawn(async move {
            let mut stream = TcpStream::connect(dummy_client_addr).await.unwrap();
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf[..n]).to_string()
        });

        let (mut client_stream, _) = dummy_client_listener.accept().await.unwrap();

        Box::pin(process_response(
            &mut client_stream,
            &mut upstream_conn,
            None,
        ))
        .await
        .unwrap();

        let res = client_task.await.unwrap();
        assert!(res.contains("Transfer-Encoding: chunked") || res.contains("Hello"));
    }

    #[tokio::test]
    async fn test_process_response_chunked_false_positive() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Debug: upstream doesn't support transfer-encoding: chunked\r\n\r\nHello",
                )
                .await
                .unwrap();
        });

        let mut upstream_conn = TcpStream::connect(upstream_addr).await.unwrap();

        let dummy_client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dummy_client_addr = dummy_client_listener.local_addr().unwrap();

        let client_task = tokio::spawn(async move {
            let mut stream = TcpStream::connect(dummy_client_addr).await.unwrap();
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf[..n]).to_string()
        });

        let (mut client_stream, _) = dummy_client_listener.accept().await.unwrap();

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            Box::pin(process_response(
                &mut client_stream,
                &mut upstream_conn,
                None,
            )),
        )
        .await;

        assert!(
            result.is_ok(),
            "Process response timed out - likely waiting for EOF due to false positive chunked detection"
        );
        result.unwrap().unwrap();

        let res = client_task.await.unwrap();
        assert!(res.contains("Hello"));
        assert!(!res.contains("Transfer-Encoding: chunked"));
    }

    #[tokio::test]
    async fn test_duplicate_content_length() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        let _server_task = tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            assert_eq!(n, 0, "Proxy forwarded duplicate Content-Length headers!");
        });

        let dummy_client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dummy_client_addr = dummy_client_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let mut stream = TcpStream::connect(dummy_client_addr).await.unwrap();
            stream
                .write_all(
                    b"POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nHello",
                )
                .await
                .unwrap();
        });

        let (mut client_stream, _) = dummy_client_listener.accept().await.unwrap();
        let mut upstream_conn = TcpStream::connect(upstream_addr).await.unwrap();

        let result = process_request(&mut client_stream, &mut upstream_conn, None).await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_smuggling_attempt_space_in_te() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        let _server_task = tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            assert_eq!(n, 0, "Proxy forwarded smuggling attempt!");
        });

        let dummy_client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dummy_client_addr = dummy_client_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let mut stream = TcpStream::connect(dummy_client_addr).await.unwrap();
            stream
                .write_all(b"POST / HTTP/1.1\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n")
                .await
                .unwrap();
        });

        let (mut client_stream, _) = dummy_client_listener.accept().await.unwrap();
        let mut upstream_conn = TcpStream::connect(upstream_addr).await.unwrap();

        let result = process_request(&mut client_stream, &mut upstream_conn, None).await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_smuggling_attempt_te_and_cl() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        let _server_task = tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            assert_eq!(n, 0, "Proxy forwarded ambiguous request!");
        });

        let dummy_client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dummy_client_addr = dummy_client_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let mut stream = TcpStream::connect(dummy_client_addr).await.unwrap();
            stream
                .write_all(b"POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nHello")
                .await
                .unwrap();
        });

        let (mut client_stream, _) = dummy_client_listener.accept().await.unwrap();
        let mut upstream_conn = TcpStream::connect(upstream_addr).await.unwrap();

        let result = process_request(&mut client_stream, &mut upstream_conn, None).await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_socket_configuration() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let _server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            configure_tcp_stream(&socket);

            assert!(socket.nodelay().unwrap());
        });

        let client = TcpStream::connect(addr).await.unwrap();
        configure_tcp_stream(&client);
        assert!(client.nodelay().unwrap());
    }
}
