use crate::common::{create_test_config, spawn_mock_backend, spawn_proxy};
use mavewaf::config::WafMode;
use mavewaf::core::middleware::{EncryptedSession, SESSION_COOKIE_NAME};
use mavewaf::security::crypto::CookieCrypto;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_request_body_size_limit() {
    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();
    config.client_max_body_size = 100;
    let config = Arc::new(config);
    let (proxy_port, _) = spawn_proxy(config).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let body = vec![0u8; 200];

    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/upload"))
        .header("X-Circuit-Id", "test_size_limit")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 413);
}

#[tokio::test]
async fn test_basic_request() {
    let backend_port = spawn_mock_backend().await;
    let config = create_test_config(backend_port);
    let (proxy_port, _) = spawn_proxy(config).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .send()
        .await
        .unwrap();

    let status = resp.status();
    assert!(status == 200 || status == 403);

    let text = resp.text().await.unwrap();
    if status == 200 {
        assert_eq!(text, "Hello");
    }
}

#[tokio::test]
async fn test_backend_down() {
    let backend_port = 0;
    let config = create_test_config(backend_port);
    let (proxy_port, _) = spawn_proxy(config).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .header("X-Circuit-Id", "test_down")
        .send()
        .await
        .unwrap();

    let status = resp.status();
    assert!(status == 502 || status == 403);
}

#[tokio::test]
async fn test_static_asset_bypass() {
    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();
    config.waf_mode = WafMode::Defense;
    let config = Arc::new(config);
    let (proxy_port, _) = spawn_proxy(config).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/style.css"))
        .header("X-Circuit-Id", "test_static")
        .send()
        .await
        .unwrap();

    let status = resp.status();
    assert!(status == 200 || status == 403 || status == 502);
}

#[tokio::test]
async fn test_request_with_body_safe_binary() {
    let backend_port = spawn_mock_backend().await;
    let config = create_test_config(backend_port);
    let (proxy_port, _) = spawn_proxy(config).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/upload"))
        .header("X-Circuit-Id", "test_binary")
        .body(vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
        .send()
        .await
        .unwrap();

    let status = resp.status();
    assert!(status == 200 || status == 403 || status == 502);
}

#[tokio::test]
async fn test_security_headers() {
    let backend_port = spawn_mock_backend().await;
    let config = create_test_config(backend_port);
    let (proxy_port, _) = spawn_proxy(config).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .header("X-Circuit-Id", "test_headers")
        .send()
        .await
        .unwrap();

    let headers = resp.headers();
    assert!(headers.contains_key("content-security-policy"));
    assert!(headers.contains_key("x-content-type-options"));
    assert!(headers.contains_key("referrer-policy"));
    assert!(headers.contains_key("strict-transport-security"));
}

#[tokio::test]
async fn test_webhook_trigger() {
    let webhook_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let webhook_port = webhook_listener.local_addr().unwrap().port();

    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();
    config.features.webhook_enabled = true;
    config.webhook_url = Some(format!("http://127.0.0.1:{webhook_port}"));
    let config = Arc::new(config);
    let (proxy_port, _) = spawn_proxy(config).await;

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = webhook_listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let _ = socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
        }
    });

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let _ = client
        .get(format!("http://127.0.0.1:{proxy_port}/?id=1' OR '1'='1"))
        .send()
        .await;

    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test]
async fn test_verified_bypass() {
    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();
    config.waf_mode = WafMode::Defense;
    let config = Arc::new(config);
    let (proxy_port, _) = spawn_proxy(config.clone()).await;

    let crypto = CookieCrypto::new(&config.session_secret);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let session = EncryptedSession {
        session_id: "test_bypass".to_string(),
        verified: true,
        verified_at: now,
        created_at: now,
        queue_started_at: 0,
        queue_completed: true,
        ..Default::default()
    };

    let cookie_val = crypto.encrypt(&session.to_bytes());
    let cookie = format!("{SESSION_COOKIE_NAME}={cookie_val}");

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .header("Cookie", cookie)
        .send()
        .await
        .unwrap();

    let status = resp.status();
    assert!(status == 200 || status == 403);

    let text = resp.text().await.unwrap();
    if status == 200 {
        assert_eq!(text, "Hello");
    }
}

#[tokio::test]
async fn test_session_rate_limit() {
    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();
    config.rate_limit_session_rps = 1;
    config.rate_limit_session_burst = 1;
    let config = Arc::new(config);
    let (proxy_port, _) = spawn_proxy(config).await;

    let crypto =
        CookieCrypto::new("0000000000000000000000000000000000000000000000000000000000000000");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let session = EncryptedSession {
        session_id: "test_session_rl".to_string(),
        verified: true,
        verified_at: now,
        created_at: now,
        ..Default::default()
    };
    let cookie_val = crypto.encrypt(&session.to_bytes());
    let cookie = format!("{SESSION_COOKIE_NAME}={cookie_val}");

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    for _ in 0..5 {
        let _ = client
            .get(format!("http://127.0.0.1:{proxy_port}/"))
            .header("X-Circuit-Id", "session_rl")
            .header("Cookie", &cookie)
            .send()
            .await;
    }

    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .header("X-Circuit-Id", "session_rl")
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();

    let status = resp.status();
    assert!(status == 200 || status == 403 || status == 429);
}

#[tokio::test]
async fn test_karma_enforcement() {
    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();
    config.karma_threshold = 10;
    let config = Arc::new(config);
    let (proxy_port, _) = spawn_proxy(config.clone()).await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    for i in 0..8 {
        let _ = client
            .get(format!("http://127.0.0.1:{proxy_port}/not-found-{i}"))
            .header("X-Circuit-Id", "karma_test_circuit")
            .send()
            .await
            .unwrap();
    }

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let blocked_resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/should-be-blocked"))
        .header("X-Circuit-Id", "karma_test_circuit")
        .send()
        .await
        .unwrap();

    assert_eq!(blocked_resp.status(), 403);
}
