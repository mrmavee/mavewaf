//! `MaveWAF` - High-performance reverse proxy and WAF for hidden services.
//!
//! Copyright (C) 2026 Maverick
//! SPDX-License-Identifier: AGPL-3.0-only
//!
//! Initializes the application runtime, loads configuration, sets up logging,
//! and launches the Proxy and API services.

use mavewaf::{
    CaptchaManager, Config, DefenseMonitor, MaveProxy, ProxyProtocolConfig, RateLimiter,
    TorControl, WafEngine, WebhookNotifier, preload_templates, run_proxy_listener,
};

use pingora::proxy::http_proxy_service;
use pingora::server::Server;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

fn main() {
    dotenvy::dotenv().ok();

    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stdout());
    let log_format = std::env::var("LOG_FORMAT").unwrap_or_else(|_| "json".to_string());

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(non_blocking);

    if log_format.eq_ignore_ascii_case("pretty") {
        subscriber.init();
    } else {
        subscriber.json().init();
    }

    let config = Config::from_env();
    preload_templates();
    info!(
        listen_addr = %config.listen_addr,
        internal_addr = %config.internal_addr,
        backend_url = %config.backend_url,
        waf_mode = ?config.waf_mode,
        log_format = %config.log_format,
        "Server initialized"
    );

    let rate_limiter = RateLimiter::new(config.rate_limit_rps, config.rate_limit_burst);
    let session_rate_limiter = RateLimiter::new(
        config.rate_limit_session_rps,
        config.rate_limit_session_burst,
    );

    let defense_monitor = Arc::new(DefenseMonitor::new(config.clone()));
    let webhook_notifier = Arc::new(WebhookNotifier::new(&config));
    let captcha_manager = Arc::new(CaptchaManager::new(&config));
    captcha_manager.start_worker();
    let waf_engine = Arc::new(WafEngine::new(
        webhook_notifier.clone(),
        config.ssrf_allowed_hosts.clone(),
    ));

    let _tor_control = config
        .tor_control_addr
        .map(|addr| TorControl::new(addr, config.tor_control_password.clone()));

    let mut server = Server::new(None).expect("Failed to create Pingora server");
    server.bootstrap();

    let proxy = MaveProxy::new(
        config.clone(),
        rate_limiter,
        session_rate_limiter,
        defense_monitor,
        webhook_notifier,
        captcha_manager,
        waf_engine,
    );

    let mut proxy_service = http_proxy_service(&server.configuration, proxy);
    proxy_service.add_tcp(&config.internal_addr.to_string());
    server.add_service(proxy_service);

    let protocol_config = ProxyProtocolConfig {
        listen_addr: config.listen_addr,
        internal_addr: config.internal_addr,
        circuit_prefix: config.tor_circuit_prefix.clone(),
        concurrency_limit: config.concurrency_limit,
    };

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        rt.block_on(run_proxy_listener(protocol_config));
    });

    server.run_forever();
}
