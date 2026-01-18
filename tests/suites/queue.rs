use crate::common::{create_test_config, spawn_mock_backend, spawn_proxy};
use mavewaf::config::WafMode;
use mavewaf::core::middleware::{EncryptedSession, SESSION_COOKIE_NAME};
use mavewaf::security::captcha::CaptchaManager;
use mavewaf::security::crypto::CookieCrypto;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
