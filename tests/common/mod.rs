use mavewaf::config::{CaptchaStyle, Config, FeatureFlags, WafMode};
use mavewaf::core::middleware::RateLimiter;
use mavewaf::core::proxy::MaveProxy;
use mavewaf::features::webhook::WebhookNotifier;
use mavewaf::security::captcha::CaptchaManager;
use mavewaf::security::defense::DefenseMonitor;
use mavewaf::security::waf::WafEngine;
use pingora::proxy::http_proxy_service;
use pingora::server::Server;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub async fn spawn_mock_backend() -> u16 {
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

pub fn create_test_config(backend_port: u16) -> Arc<Config> {
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
        attack_churn_threshold: 30,
        attack_rps_threshold: 30,
        attack_rpc_threshold: 5,
        attack_defense_score: 2.0,
        attack_pow_score: 4.0,
        attack_pow_effort: 5,
        attack_recovery_secs: 300,
    })
}

pub async fn spawn_proxy(config: Arc<Config>) -> (u16, std::thread::JoinHandle<()>) {
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
