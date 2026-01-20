use crate::common::{create_test_config, spawn_mock_backend, spawn_proxy};
use mavewaf::core::proxy::protocol::{ProxyProtocolConfig, run_proxy_listener};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_full_stack_proxy_protocol() {
    let backend_port = spawn_mock_backend().await;
    let config = create_test_config(backend_port);
    let (pingora_port, _) = spawn_proxy(config).await;

    let protocol_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let protocol_port = protocol_listener.local_addr().unwrap().port();
    drop(protocol_listener);

    let proto_config = ProxyProtocolConfig {
        listen_addr: format!("127.0.0.1:{protocol_port}").parse().unwrap(),
        internal_addr: format!("127.0.0.1:{pingora_port}").parse().unwrap(),
        circuit_prefix: "fc00".to_string(),
        concurrency_limit: 1024,
        defense_monitor: None,
    };

    tokio::spawn(async move {
        run_proxy_listener(proto_config).await;
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{protocol_port}"))
        .await
        .unwrap();

    stream
        .write_all(b"PROXY TCP4 1.2.3.4 5.6.7.8 111 222\r\n")
        .await
        .unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);

    assert!(response.contains("HTTP/1.1 200") || response.contains("HTTP/1.1 403"));
}

#[tokio::test]
async fn test_slowloris_timeout() {
    let backend_port = spawn_mock_backend().await;
    let config = create_test_config(backend_port);
    let (pingora_port, _) = spawn_proxy(config).await;

    let protocol_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let protocol_port = protocol_listener.local_addr().unwrap().port();
    drop(protocol_listener);

    let proto_config = ProxyProtocolConfig {
        listen_addr: format!("127.0.0.1:{protocol_port}").parse().unwrap(),
        internal_addr: format!("127.0.0.1:{pingora_port}").parse().unwrap(),
        circuit_prefix: "fc00".to_string(),
        concurrency_limit: 1024,
        defense_monitor: None,
    };

    tokio::spawn(async move {
        run_proxy_listener(proto_config).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{protocol_port}"))
        .await
        .unwrap();

    stream.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();

    tokio::time::sleep(Duration::from_secs(6)).await;

    let _ = stream.write_all(b"Host: example.com\r\n\r\n").await;

    let mut buf = [0u8; 1024];
    match stream.read(&mut buf).await {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Ok(n) => panic!("Expected connection close, got {n} bytes"),
        Err(e) => panic!("Expected ConnectionReset or Close, got error: {e}"),
    }
}

#[tokio::test]
async fn test_l4_circuit_blocking() {
    let backend_port = spawn_mock_backend().await;
    let config = create_test_config(backend_port);
    let (pingora_port, _) = spawn_proxy(config.clone()).await;

    let defense_monitor = std::sync::Arc::new(mavewaf::DefenseMonitor::new(config.clone()));

    defense_monitor.add_karma("fc00::dead:beef", 100);

    assert!(defense_monitor.is_circuit_blocked("fc00::dead:beef"));

    let protocol_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let protocol_port = protocol_listener.local_addr().unwrap().port();
    drop(protocol_listener);

    let proto_config = ProxyProtocolConfig {
        listen_addr: format!("127.0.0.1:{protocol_port}").parse().unwrap(),
        internal_addr: format!("127.0.0.1:{pingora_port}").parse().unwrap(),
        circuit_prefix: "fc00".to_string(),
        concurrency_limit: 1024,
        defense_monitor: Some(defense_monitor),
    };

    tokio::spawn(async move {
        run_proxy_listener(proto_config).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{protocol_port}"))
        .await
        .unwrap();

    stream
        .write_all(b"PROXY TCP6 fc00::dead:beef fc00::1 111 222\r\n")
        .await
        .unwrap();

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "Expected L4 blocking to close connection immediately");
}
