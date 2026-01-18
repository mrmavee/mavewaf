use crate::common::{create_test_config, spawn_mock_backend, spawn_proxy};

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
