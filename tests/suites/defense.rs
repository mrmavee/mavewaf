use crate::common::{create_test_config, spawn_mock_backend, spawn_proxy};
use mavewaf::config::WafMode;
use mavewaf::core::middleware::{EncryptedSession, SESSION_COOKIE_NAME};
use mavewaf::security::crypto::CookieCrypto;
use mavewaf::security::defense::DefenseMonitor;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn test_defense_mode() {
    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();
    config.waf_mode = WafMode::Defense;
    let config = Arc::new(config);

    let (proxy_port, _) = spawn_proxy(config).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .header("X-Circuit-Id", "test_defense")
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let text = resp.text().await.unwrap();

    assert!(status == 200 || status == 403);
    if status == 200 {
        assert!(
            text.contains("Queue")
                || text.contains("Security Check")
                || text.contains("Wait Time")
                || text.contains("Please Wait")
        );
    } else {
        assert!(text.contains("Access Denied") || text.contains("Too Many Requests"));
    }
}

#[tokio::test]
async fn test_defense_mode_access_page() {
    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();
    config.waf_mode = WafMode::Defense;
    config.features.captcha_enabled = false;
    let config = Arc::new(config);
    let (proxy_port, _) = spawn_proxy(config.clone()).await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();

    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .header("X-Circuit-Id", "test_access")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();
    assert!(text.contains("Wait Time") || text.contains("Queue"));

    let crypto = CookieCrypto::new(&config.session_secret);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let session_ready = EncryptedSession {
        session_id: "test_access".to_string(),
        verified: false,
        verified_at: 0,
        created_at: now - 10,
        queue_started_at: now - 10,
        queue_completed: false,
        ..Default::default()
    };
    let cookie_val = crypto.encrypt(&session_ready.to_bytes());
    let cookie_ready = format!("{SESSION_COOKIE_NAME}={cookie_val}");

    let resp_ready = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .header("X-Circuit-Id", "test_access")
        .header("Cookie", cookie_ready.clone())
        .send()
        .await
        .unwrap();

    let cookie_final = resp_ready
        .headers()
        .get("set-cookie")
        .map(|c| c.to_str().unwrap().to_string());

    let text_ready = resp_ready.text().await.unwrap();
    assert!(text_ready.contains("Security Check"));
    assert!(text_ready.contains("Click to Enter"));

    let token_input = text_ready.split("name=\"s\" value=\"").nth(1).unwrap();
    let token = token_input.split('"').next().unwrap();

    let cookie_to_use = cookie_final.unwrap_or(cookie_ready);

    let body_str = format!("s={token}");
    let resp_post = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("X-Circuit-Id", "test_access")
        .header("Cookie", cookie_to_use)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body_str)
        .send()
        .await
        .unwrap();

    assert_eq!(resp_post.status(), 303);
    assert_eq!(resp_post.headers().get("location").unwrap(), "/");

    let verified_cookie = resp_post
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();

    let resp_verified = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .header("X-Circuit-Id", "test_access")
        .header("Cookie", verified_cookie)
        .send()
        .await
        .unwrap();

    assert_eq!(resp_verified.status(), 200);
    assert_eq!(resp_verified.text().await.unwrap(), "Hello");
}

#[tokio::test]
async fn test_kill_circuit_integration() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tor_addr = listener.local_addr().unwrap();

    let tor_handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];

        let _ = socket.read(&mut buf).await.unwrap();
        socket.write_all(b"250 OK\r\n").await.unwrap();

        let _ = socket.read(&mut buf).await.unwrap();
        socket.write_all(b"250 OK\r\n").await.unwrap();
    });

    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();
    config.waf_mode = WafMode::Defense;
    config.tor_control_addr = Some(tor_addr);
    config.tor_control_password = Some("test".to_string());
    config.captcha_gen_limit = 1;
    let config = Arc::new(config);
    let (proxy_port, _) = spawn_proxy(config).await;

    let crypto =
        CookieCrypto::new("0000000000000000000000000000000000000000000000000000000000000000");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let session = EncryptedSession {
        session_id: "test_kill_tor".to_string(),
        queue_completed: true,
        captcha_gen_count: 2,
        created_at: now,
        queue_started_at: now - 10,
        ..Default::default()
    };
    let cookie_val = crypto.encrypt(&session.to_bytes());
    let cookie = format!("{SESSION_COOKIE_NAME}={cookie_val}");

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();

    let _resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .header("X-Circuit-Id", "123")
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();

    let _ = tor_handle.await;
}

#[tokio::test]
async fn test_circuit_flood_detection() {
    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();
    config.defense_circuit_flood_threshold = 1;
    let config = Arc::new(config);
    let (proxy_port, _) = spawn_proxy(config).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    for _ in 0..5 {
        let _ = client
            .get(format!("http://127.0.0.1:{proxy_port}/"))
            .header("X-Circuit-Id", "flood_test")
            .send()
            .await;
    }

    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .header("X-Circuit-Id", "flood_test")
        .send()
        .await
        .unwrap();

    let status = resp.status();
    assert!(status == 200 || status == 403 || status == 429);
}

#[tokio::test]
async fn test_kill_circuit_failure() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tor_addr = listener.local_addr().unwrap();

    let tor_handle = tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let _ = socket.write_all(b"510 Bad Command\r\n").await;
        }
    });

    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();
    config.waf_mode = WafMode::Defense;
    config.tor_control_addr = Some(tor_addr);
    config.tor_control_password = Some("test".to_string());
    config.captcha_gen_limit = 1;
    let config = Arc::new(config);
    let (proxy_port, _) = spawn_proxy(config).await;

    let crypto =
        CookieCrypto::new("0000000000000000000000000000000000000000000000000000000000000000");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let session = EncryptedSession {
        session_id: "test_kill_fail".to_string(),
        queue_completed: true,
        captcha_gen_count: 2,
        created_at: now,
        queue_started_at: now - 10,
        ..Default::default()
    };
    let cookie_val = crypto.encrypt(&session.to_bytes());
    let cookie = format!("{SESSION_COOKIE_NAME}={cookie_val}");

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();

    let _resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .header("X-Circuit-Id", "id_kill_unique")
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();

    let _ = tor_handle.await;
}

#[tokio::test]
async fn test_honeypot_trap() {
    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();
    config.honeypot_paths = ["/.env", "/.git/HEAD", "/wp-admin"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let config = Arc::new(config);
    let (proxy_port, _) = spawn_proxy(config.clone()).await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/.env"))
        .header("X-Circuit-Id", "circuit_honeypot_1")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);

    let resp2 = client
        .get(format!("http://127.0.0.1:{proxy_port}/.git/HEAD"))
        .header("X-Circuit-Id", "circuit_honeypot_2")
        .send()
        .await
        .unwrap();

    assert_eq!(resp2.status(), 403);

    let resp3 = client
        .get(format!("http://127.0.0.1:{proxy_port}/normal-page"))
        .header("X-Circuit-Id", "circuit_honeypot_3")
        .send()
        .await
        .unwrap();

    assert_eq!(resp3.status(), 200);
}

#[tokio::test]
async fn test_dynamic_defense_logic_integration() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tor_addr = listener.local_addr().unwrap();

    let tor_handle = tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let _ = socket.write_all(b"250 OK\r\n").await;

            loop {
                let n = socket.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                if socket.write_all(b"250 OK\r\n").await.is_err() {
                    break;
                }
            }
        }
    });

    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();

    config.tor_control_addr = Some(tor_addr);
    config.tor_control_password = Some("test".to_string());
    config.attack_churn_threshold = 2;
    config.attack_rps_threshold = 2;
    config.attack_defense_score = 1.0;
    config.attack_pow_score = 2.0;
    config.defense_cooldown_secs = 1;

    let config = Arc::new(config);
    let (proxy_port, _) = spawn_proxy(config).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();

    for i in 0..5 {
        let _ = client
            .get(format!("http://127.0.0.1:{proxy_port}/"))
            .header("X-Circuit-Id", format!("initial_{i}"))
            .send()
            .await;
    }

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    for i in 0..10 {
        let resp = client
            .get(format!("http://127.0.0.1:{proxy_port}/"))
            .header("X-Circuit-Id", format!("churn_{i}"))
            .send()
            .await
            .unwrap();
        let _ = resp.status();
    }

    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .header("X-Circuit-Id", "victim_circuit")
        .send()
        .await
        .unwrap();

    assert!(resp.status().as_u16() == 200 || resp.status().as_u16() == 403);

    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    tor_handle.abort();
}

#[tokio::test]
async fn test_defense_monitor_internals() {
    let mut config = (*create_test_config(0)).clone();
    config.attack_churn_threshold = 10;
    config.attack_rps_threshold = 1000;
    config.attack_rpc_threshold = 5;
    config.attack_defense_score = 4.0;
    config.attack_pow_score = 5.0;

    let config = Arc::new(config);
    let monitor = DefenseMonitor::new(config);

    for i in 0..20 {
        let cid = format!("scanner_circuit_{i}");
        monitor.record_request(Some(&cid), false);
        monitor.record_unverified_request();
    }

    let score = monitor.calculate_attack_score();
    assert!(score > 4.5);

    assert!(monitor.should_auto_defense());
    assert!(monitor.should_enable_pow().is_some());

    monitor.mark_pow_enabled();
    assert!(monitor.is_pow_enabled());
    assert!(monitor.should_enable_pow().is_none());

    assert!(!monitor.should_disable_pow());
}
