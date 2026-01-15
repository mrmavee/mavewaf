use mavewaf::config::{CaptchaStyle, Config, FeatureFlags, WafMode};
use mavewaf::core::middleware::{EncryptedSession, RateLimiter, SESSION_COOKIE_NAME};
use mavewaf::core::proxy::MaveProxy;
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
        session_id: "test_queue_spam".to_string(),
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
        .header("X-Circuit-Id", "test_spam")
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
        .header("X-Circuit-Id", "test_spam")
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
        session_id: "test_queue_normal".to_string(),
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
        .header("X-Circuit-Id", "test_normal")
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

    let _session = EncryptedSession {
        session_id: "test_redir_access".to_string(),
        verified: false,
        verified_at: 0,
        created_at: now,
        queue_started_at: now - 10,
        queue_completed: false,

        ..Default::default()
    };

    let session = EncryptedSession {
        session_id: "test_redir_access".to_string(),
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
        .header("X-Circuit-Id", "test_redir")
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
        .header("X-Circuit-Id", "test_redir")
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
        session_id: "test_redir_captcha".to_string(),
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
        .header("X-Circuit-Id", "test_redir_cap")
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
        .header("X-Circuit-Id", "test_redir_cap")
        .header("Cookie", &cookie)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!("s={token}&solution={answer}"))
        .send()
        .await
        .unwrap();

    assert_eq!(post_resp.status(), 303);
    assert_eq!(post_resp.headers().get("location").unwrap(), "/target/path");
}
