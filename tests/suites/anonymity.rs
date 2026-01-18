use crate::common::{create_test_config, spawn_mock_backend, spawn_proxy};
use mavewaf::config::WafMode;
use std::sync::Arc;

#[tokio::test]
async fn test_i2p_circuit_header() {
    let backend_port = spawn_mock_backend().await;
    let config = create_test_config(backend_port);
    let (proxy_port, _) = spawn_proxy(config).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .header("X-I2P-DestB64", "base64_dest_unique")
        .send()
        .await
        .unwrap();

    let status = resp.status();
    assert!(status == 200 || status == 403);
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
