use crate::common::{create_test_config, spawn_mock_backend, spawn_proxy};
use mavewaf::config::WafMode;
use mavewaf::core::middleware::{EncryptedSession, SESSION_COOKIE_NAME};
use mavewaf::security::captcha::CaptchaManager;
use mavewaf::security::crypto::CookieCrypto;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
