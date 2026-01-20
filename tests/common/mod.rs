use mavewaf::config::Config;
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
    let mut config = (*mavewaf::test_utils::create_test_config()).clone();
    config.listen_addr = "127.0.0.1:0".parse().unwrap();
    config.internal_addr = "127.0.0.1:0".parse().unwrap();
    config.backend_url = format!("http://127.0.0.1:{backend_port}");
    config.features.waf_body_scan_enabled = true;
    config.ssrf_allowed_hosts = vec!["127.0.0.1".to_string()];
    Arc::new(config)
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
