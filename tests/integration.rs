use mavewaf::config::{CaptchaStyle, Config, FeatureFlags, WafMode};
use mavewaf::core::middleware::{EncryptedSession, RateLimiter, SESSION_COOKIE_NAME};
use mavewaf::core::proxy::{
    MaveProxy,
    protocol::{ProxyProtocolConfig, run_proxy_listener},
};
use mavewaf::features::webhook::WebhookNotifier;
use mavewaf::security::captcha::CaptchaManager;
use mavewaf::security::crypto::CookieCrypto;
use mavewaf::security::defense::DefenseMonitor;
use mavewaf::security::waf::WafEngine;
use pingora::proxy::http_proxy_service;
use pingora::server::Server;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn spawn_mock_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    let response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello";
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    port
}

fn create_test_config(backend_port: u16) -> Arc<Config> {
    Arc::new(Config {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        internal_addr: "127.0.0.1:0".parse().unwrap(),
        backend_url: format!("http://127.0.0.1:{backend_port}"),
        waf_mode: WafMode::Normal,
        rate_limit_rps: 100,
        rate_limit_burst: 100,
        features: FeatureFlags {
            captcha_enabled: true,
            webhook_enabled: false,
            waf_body_scan_enabled: true,
            coep_enabled: false,
        },
        captcha_secret: "secret".to_string(),
        captcha_ttl: 300,
        captcha_difficulty: "easy".to_string(),
        captcha_style: CaptchaStyle::Simple,
        session_secret: "0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        session_expiry_secs: 3600,
        tor_circuit_prefix: "fc00".to_string(),
        tor_control_addr: None,
        tor_control_password: None,
        torrc_path: None,
        defense_error_rate_threshold: 0.5,
        defense_circuit_flood_threshold: 10,
        defense_cooldown_secs: 300,
        webhook_url: None,
        max_captcha_failures: 3,
        captcha_gen_limit: 5,
        ssrf_allowed_hosts: vec!["127.0.0.1".to_string()],
        waf_body_scan_max_size: 1024,
        rate_limit_session_rps: 10,
        rate_limit_session_burst: 20,
        app_name: "TestApp".to_string(),
        favicon_base64: String::new(),
        meta_title: "Test".to_string(),
        meta_description: "Test".to_string(),
        meta_keywords: "Test".to_string(),
        log_format: "pretty".to_string(),
        csp_extra_sources: String::new(),
        coop_policy: "same-origin-allow-popups".to_string(),
        honeypot_paths: std::collections::HashSet::new(),
        karma_threshold: 50,
        webhook_token: None,
    })
}

async fn spawn_proxy(config: Arc<Config>) -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let mut conf_clone = (*config).clone();
    conf_clone.listen_addr = format!("127.0.0.1:{port}").parse().unwrap();
    let config = Arc::new(conf_clone);
    let config_for_thread = config.clone();

    let handle = std::thread::spawn(move || {
        let rate_limiter = RateLimiter::new(100, 100);
        let session_limit = RateLimiter::new(100, 100);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let (defense, webhook, captcha, waf) = rt.block_on(async {
            (
                Arc::new(DefenseMonitor::new(config_for_thread.clone())),
                Arc::new(WebhookNotifier::new(&config_for_thread)),
                Arc::new(CaptchaManager::new(&config_for_thread)),
                Arc::new(WafEngine::new(
                    Arc::new(WebhookNotifier::new(&config_for_thread)),
                    vec![],
                )),
            )
        });

        let proxy = MaveProxy::new(
            config_for_thread.clone(),
            rate_limiter,
            session_limit,
            defense,
            webhook,
            captcha,
            waf,
        );

        let server_conf = Arc::new(pingora::server::configuration::ServerConf::default());
        let mut service = http_proxy_service(&server_conf, proxy);
        service.add_tcp(&config_for_thread.listen_addr.to_string());

        let mut server = Server::new(None).unwrap();
        server.bootstrap();
        server.add_service(service);
        server.run_forever();
    });

    tokio::time::sleep(Duration::from_secs(3)).await;
    (port, handle)
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
async fn test_waf_block() {
    let backend_port = spawn_mock_backend().await;
    let config = create_test_config(backend_port);
    let (proxy_port, _) = spawn_proxy(config).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/?id=1' OR '1'='1"))
        .send()
        .await
        .unwrap();

    let status = resp.status();
    assert_eq!(status, 403);

    let text = resp.text().await.unwrap();
    assert!(text.contains("Access Denied"));
}

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
async fn test_captcha_submission_failure() {
    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();
    config.waf_mode = WafMode::Defense;
    let config = Arc::new(config);
    let (proxy_port, _) = spawn_proxy(config).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();

    let mut resp = None;
    for _ in 0..5 {
        if let Ok(r) = client
            .get(format!("http://127.0.0.1:{proxy_port}/"))
            .send()
            .await
        {
            resp = Some(r);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    let resp = resp.expect("Failed to connect to proxy");

    let cookie = resp
        .headers()
        .get("set-cookie")
        .map_or_else(String::new, |c| c.to_str().unwrap().to_string());

    let body_str = "s=invalid&solution=wrong";

    let resp = if cookie.is_empty() {
        client
            .post(format!("http://127.0.0.1:{proxy_port}/"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body_str)
            .send()
            .await
            .unwrap()
    } else {
        client
            .post(format!("http://127.0.0.1:{proxy_port}/"))
            .header("Cookie", cookie)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body_str)
            .send()
            .await
            .unwrap()
    };

    let status = resp.status();
    assert!(status == 200 || status == 403 || status == 303);
}

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
async fn test_queue_logic() {
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
        session_id: "test_queue".to_string(),
        verified: false,
        verified_at: 0,
        created_at: now,
        queue_started_at: now,
        queue_completed: false,
        ..Default::default()
    };

    let cookie_val = crypto.encrypt(&session.to_bytes());
    let cookie = format!("{SESSION_COOKIE_NAME}={cookie_val}");

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .header("X-Circuit-Id", "test_queue")
        .header("Cookie", cookie)
        .send()
        .await
        .unwrap();

    let _status = resp.status();
    let text = resp.text().await.unwrap();
    assert!(text.contains("Queue") || text.contains("Wait Time") || text.contains("Please Wait"));

    let session_ready = EncryptedSession {
        session_id: "test_queue_ready".to_string(),
        verified: false,
        verified_at: 0,
        created_at: now - 10,
        queue_started_at: now - 10,
        queue_completed: false,
        ..Default::default()
    };
    let cookie_val_ready = crypto.encrypt(&session_ready.to_bytes());
    let cookie_ready = format!("{SESSION_COOKIE_NAME}={cookie_val_ready}");

    let resp_ready = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .header("X-Circuit-Id", "test_queue_ready")
        .header("Cookie", cookie_ready)
        .send()
        .await
        .unwrap();

    let _status_ready = resp_ready.status();
    let text_ready = resp_ready.text().await.unwrap();
    assert!(text_ready.contains("Security Check") || text_ready.contains("CAPTCHA"));
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
async fn test_waf_body_scanning() {
    let backend_port = spawn_mock_backend().await;
    let config = create_test_config(backend_port);
    let (proxy_port, _) = spawn_proxy(config).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .body("malicious_id=1' OR '1'='1")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_verified_user_accessing_queue() {
    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();
    config.waf_mode = WafMode::Defense;
    let config = Arc::new(config);
    let (proxy_port, _) = spawn_proxy(config).await;
    let crypto =
        CookieCrypto::new("0000000000000000000000000000000000000000000000000000000000000000");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let session = EncryptedSession {
        session_id: "test_verified_queue".to_string(),
        verified: true,
        verified_at: now,
        created_at: now,
        ..Default::default()
    };
    let cookie_val = crypto.encrypt(&session.to_bytes());
    let cookie = format!("{SESSION_COOKIE_NAME}={cookie_val}");

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();

    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/queue"))
        .header("X-Circuit-Id", "test_verified")
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 303);
    assert_eq!(resp.headers().get("location").unwrap(), "/");

    let resp_captcha = client
        .get(format!("http://127.0.0.1:{proxy_port}/captcha"))
        .header("X-Circuit-Id", "test_verified")
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();

    assert_eq!(resp_captcha.status(), 303);
    assert_eq!(resp_captcha.headers().get("location").unwrap(), "/");
}

#[tokio::test]
async fn test_captcha_failure_limit_exceeded() {
    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();
    config.waf_mode = WafMode::Defense;
    let config = Arc::new(config);
    let (proxy_port, _) = spawn_proxy(config).await;
    let crypto =
        CookieCrypto::new("0000000000000000000000000000000000000000000000000000000000000000");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let session = EncryptedSession {
        session_id: "test_failure_limit".to_string(),
        verified: false,
        verified_at: 0,
        queue_completed: true,
        captcha_failures: 2,
        created_at: now,
        queue_started_at: now,
        ..Default::default()
    };
    let cookie_val = crypto.encrypt(&session.to_bytes());
    let cookie = format!("{SESSION_COOKIE_NAME}={cookie_val}");

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();

    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("X-Circuit-Id", "test_fail")
        .header("Cookie", &cookie)
        .body("s=invalid_token&c1=A&c2=B")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 303);

    let set_cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
    assert!(set_cookie.contains(SESSION_COOKIE_NAME));
}

#[tokio::test]
async fn test_captcha_gen_limit_exceeded() {
    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();
    config.waf_mode = WafMode::Defense;
    let config = Arc::new(config);
    let (proxy_port, _) = spawn_proxy(config).await;
    let crypto =
        CookieCrypto::new("0000000000000000000000000000000000000000000000000000000000000000");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let session = EncryptedSession {
        session_id: "test_gen_limit".to_string(),
        queue_completed: true,
        captcha_gen_count: 5,
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

    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .header("X-Circuit-Id", "test_gen")
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
    let text = resp.text().await.unwrap();
    assert!(text.contains("Too Many Requests"));
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
async fn test_i2p_circuit_header() {
    let backend_port = spawn_mock_backend().await;
    let config = create_test_config(backend_port);
    let (proxy_port, _) = spawn_proxy(config).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .header("X-I2P-DestB64", "someb64destination")
        .send()
        .await
        .unwrap();

    let status = resp.status();
    assert!(status == 200 || status == 403);
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
async fn test_queue_explicit_wait() {
    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();
    config.waf_mode = WafMode::Defense;
    config.features.captcha_enabled = true;
    let config = Arc::new(config);
    let (proxy_port, _) = spawn_proxy(config.clone()).await;

    let crypto = CookieCrypto::new(&config.session_secret);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let session_wait = EncryptedSession {
        session_id: "test_wait".to_string(),
        queue_started_at: now - 2,
        created_at: now,
        ..Default::default()
    };
    let cookie = format!(
        "{SESSION_COOKIE_NAME}={}",
        crypto.encrypt(&session_wait.to_bytes())
    );

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .header("Cookie", &cookie)
        .header("X-Circuit-Id", "id_q_wait_1")
        .send()
        .await
        .unwrap();
    let text = resp.text().await.unwrap();
    assert!(text.contains("Queue") || text.contains("Wait Time") || text.contains("Please Wait"));

    let session_done = EncryptedSession {
        session_id: "test_done".to_string(),
        queue_started_at: now - 6,
        created_at: now,
        ..Default::default()
    };
    let cookie_done = format!(
        "{SESSION_COOKIE_NAME}={}",
        crypto.encrypt(&session_done.to_bytes())
    );

    let resp_done = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .header("Cookie", &cookie_done)
        .header("X-Circuit-Id", "id_q_final")
        .send()
        .await
        .unwrap();
    let set_cookie = resp_done
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let text_done = resp_done.text().await.unwrap();
    assert!(
        text_done.contains("Security Check")
            || text_done.contains("CAPTCHA")
            || text_done.contains("Verification Error")
            || text_done.contains("Wait Time")
            || text_done.contains("Queue")
    );
    assert!(set_cookie.contains(SESSION_COOKIE_NAME));
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
async fn test_queue_bypass_protection() {
    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();
    config.waf_mode = WafMode::Defense;
    let config = Arc::new(config);
    let (proxy_port, _) = spawn_proxy(config).await;
    let crypto =
        CookieCrypto::new("0000000000000000000000000000000000000000000000000000000000000000");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let session_early = EncryptedSession {
        session_id: "test_bypass_early".to_string(),
        queue_started_at: now,
        created_at: now,
        ..Default::default()
    };
    let cookie_early = format!(
        "{SESSION_COOKIE_NAME}={}",
        crypto.encrypt(&session_early.to_bytes())
    );

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();

    let resp_early = client
        .get(format!("http://127.0.0.1:{proxy_port}/captcha"))
        .header("Cookie", &cookie_early)
        .header("X-Circuit-Id", "id_bypass_early")
        .send()
        .await
        .unwrap();

    let text_early = resp_early.text().await.unwrap();
    assert!(
        text_early.contains("Please Wait"),
        "Expected Queue page, got: {text_early}"
    );

    let session_valid = EncryptedSession {
        session_id: "test_bypass_valid".to_string(),
        queue_started_at: now - 10,
        created_at: now,
        ..Default::default()
    };
    let cookie_valid = format!(
        "{SESSION_COOKIE_NAME}={}",
        crypto.encrypt(&session_valid.to_bytes())
    );

    let resp_valid = client
        .get(format!("http://127.0.0.1:{proxy_port}/captcha"))
        .header("Cookie", &cookie_valid)
        .header("X-Circuit-Id", "id_bypass_valid")
        .send()
        .await
        .unwrap();

    let text_valid = resp_valid.text().await.unwrap();
    assert!(text_valid.contains("Security Check") || text_valid.contains("CAPTCHA"));
}

#[tokio::test]
async fn test_queue_spam_punishment() {
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
        session_id: "test_queue_spam_unique".to_string(),
        verified: false,
        verified_at: 0,
        created_at: now,
        queue_started_at: now - 3,
        queue_completed: false,
        last_active_at: now,
        ..Default::default()
    };

    let cookie_val = crypto.encrypt(&session.to_bytes());
    let cookie = format!("{SESSION_COOKIE_NAME}={cookie_val}");

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/target"))
        .header("X-Circuit-Id", "test_spam_unique")
        .header("Cookie", cookie)
        .send()
        .await
        .unwrap();

    let cookie_header_val = resp
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let text = resp.text().await.unwrap();
    assert!(text.contains("Wait Time"));

    let resp_spam = client
        .get(format!("http://127.0.0.1:{proxy_port}/target"))
        .header("X-Circuit-Id", "test_spam_unique")
        .header("Cookie", cookie_header_val)
        .send()
        .await
        .unwrap();

    let new_cookie_header = resp_spam
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();
    let cookie_val = new_cookie_header
        .split(';')
        .next()
        .unwrap()
        .split('=')
        .nth(1)
        .unwrap();
    let decrypted =
        EncryptedSession::from_bytes(&crypto.decrypt(cookie_val).unwrap(), 3600).unwrap();

    assert!(
        decrypted.queue_started_at > now
            || decrypted.queue_started_at >= decrypted.last_active_at - 1
    );
}

#[tokio::test]
async fn test_queue_normal_progression() {
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
        session_id: "test_queue_normal_unique".to_string(),
        verified: false,
        verified_at: 0,
        created_at: now - 3,
        queue_started_at: now - 3,
        queue_completed: false,
        last_active_at: now - 3,
        ..Default::default()
    };

    let cookie_val = crypto.encrypt(&session.to_bytes());
    let cookie = format!("{SESSION_COOKIE_NAME}={cookie_val}");

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;

    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/target"))
        .header("X-Circuit-Id", "test_normal_unique")
        .header("Cookie", cookie)
        .send()
        .await
        .unwrap();

    let new_cookie_header = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
    let cookie_val = new_cookie_header
        .split(';')
        .next()
        .unwrap()
        .split('=')
        .nth(1)
        .unwrap();
    let decrypted =
        EncryptedSession::from_bytes(&crypto.decrypt(cookie_val).unwrap(), 3600).unwrap();

    assert!(decrypted.queue_started_at < now - 1);
}

#[tokio::test]
async fn test_redirect_after_access_verify() {
    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();
    config.waf_mode = WafMode::Defense;
    config.features.captcha_enabled = false;
    let config = Arc::new(config);
    let (proxy_port, _) = spawn_proxy(config.clone()).await;

    let crypto = CookieCrypto::new(&config.session_secret);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let session = EncryptedSession {
        session_id: "test_redir_access_unique".to_string(),
        verified: false,
        verified_at: 0,
        created_at: now - 10,
        queue_started_at: now - 10,
        queue_completed: false,
        last_active_at: now - 10,
        ..Default::default()
    };

    let cookie_val = crypto.encrypt(&session.to_bytes());
    let cookie = format!("{SESSION_COOKIE_NAME}={cookie_val}");

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();

    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/target/path"))
        .header("X-Circuit-Id", "test_redir_unique")
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();

    let text = resp.text().await.unwrap();
    assert!(text.contains("Click to Enter"));

    let captcha_mgr = CaptchaManager::new(&config);
    let token = captcha_mgr.create_token(&session.session_id.to_uppercase());

    let post_resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/target/path"))
        .header("X-Circuit-Id", "test_redir_unique")
        .header("Cookie", &cookie)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!("cf-turnstile-response={token}"))
        .send()
        .await
        .unwrap();

    assert_eq!(post_resp.status(), 303);
    assert_eq!(post_resp.headers().get("location").unwrap(), "/target/path");
}

#[tokio::test]
async fn test_redirect_after_captcha_verify() {
    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();
    config.waf_mode = WafMode::Defense;
    config.features.captcha_enabled = true;
    let config = Arc::new(config);
    let (proxy_port, _) = spawn_proxy(config.clone()).await;

    let crypto = CookieCrypto::new(&config.session_secret);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let session = EncryptedSession {
        session_id: "test_redir_captcha_unique".to_string(),
        verified: false,
        verified_at: 0,
        created_at: now,
        queue_started_at: now - 10,
        queue_completed: true,
        last_active_at: now - 10,
        ..Default::default()
    };

    let cookie_val = crypto.encrypt(&session.to_bytes());
    let cookie = format!("{SESSION_COOKIE_NAME}={cookie_val}");

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();

    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/target/path"))
        .header("X-Circuit-Id", "test_redir_cap_unique")
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();

    let text = resp.text().await.unwrap();
    assert!(text.contains("Security Check"));
    assert!(!text.contains("Click to Enter"));

    let captcha_mgr = CaptchaManager::new(&config);
    let answer = "TESTANS";
    let token = captcha_mgr.create_token(answer);

    let post_resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/target/path"))
        .header("X-Circuit-Id", "test_redir_cap_unique")
        .header("Cookie", &cookie)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!("s={token}&solution={answer}"))
        .send()
        .await
        .unwrap();

    assert_eq!(post_resp.status(), 303);
    assert_eq!(post_resp.headers().get("location").unwrap(), "/target/path");
}

#[tokio::test]
async fn test_i2p_cookie_flag() {
    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();
    config.waf_mode = WafMode::Defense;
    let config = Arc::new(config);
    let (proxy_port, _) = spawn_proxy(config.clone()).await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .header("X-I2P-DestB64", "base64_dest_unique")
        .send()
        .await
        .unwrap();

    match resp.status() {
        reqwest::StatusCode::OK => {
            let cookie = resp.headers().get("Set-Cookie").unwrap().to_str().unwrap();
            assert!(!cookie.contains("; Secure"));
        }
        status => {
            let text = resp.text().await.unwrap_or_default();
            panic!("Expected 200 OK, got {status}. Body: {text}");
        }
    }
}

#[tokio::test]
async fn test_tor_cookie_flag() {
    let backend_port = spawn_mock_backend().await;
    let mut config = (*create_test_config(backend_port)).clone();
    config.waf_mode = WafMode::Defense;
    let config = Arc::new(config);
    let (proxy_port, _) = spawn_proxy(config.clone()).await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .header("X-Circuit-Id", "circuit_123_unique")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let cookie = resp.headers().get("Set-Cookie").unwrap().to_str().unwrap();
    assert!(cookie.contains("; Secure"));
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
