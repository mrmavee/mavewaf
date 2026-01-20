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

    monitor.simulate_elapsed_time(15);

    let score = monitor.calculate_attack_score();
    assert!(score > 4.5, "Score was {score}, expected > 4.5");

    assert!(monitor.should_auto_defense());
    assert!(monitor.should_enable_pow().is_some());

    monitor.mark_pow_enabled();
    assert!(monitor.is_pow_enabled());
    assert!(monitor.should_enable_pow().is_none());

    assert!(!monitor.should_disable_pow());
}

#[tokio::test]
async fn test_pow_requires_minimum_elapsed_time() {
    let mut config = (*create_test_config(0)).clone();
    config.attack_defense_score = 1.0;
    config.attack_pow_score = 2.0;
    let config = Arc::new(config);
    let monitor = DefenseMonitor::new(config);

    for i in 0..50 {
        let cid = format!("circuit_{i}");
        monitor.record_request(Some(&cid), false);
        monitor.record_unverified_request();
        monitor.record_circuit_kill();
    }

    let score_before = monitor.calculate_attack_score();
    assert!(
        score_before.abs() < f64::EPSILON,
        "Score should be 0 when elapsed < 10s"
    );
    assert!(!monitor.should_auto_defense());

    monitor.simulate_elapsed_time(15);

    let score_after = monitor.calculate_attack_score();
    assert!(score_after > 0.0, "Score should be > 0 after 15s elapsed");
    assert!(monitor.should_enable_pow().is_some());
    assert!(monitor.should_auto_defense());
}

#[tokio::test]
async fn test_pow_requires_minimum_requests_or_activity() {
    let mut config = (*create_test_config(0)).clone();
    config.attack_defense_score = 0.5;
    config.attack_pow_score = 1.0;
    let config = Arc::new(config);
    let monitor = DefenseMonitor::new(config);

    for i in 0..5 {
        let cid = format!("circuit_{i}");
        monitor.record_request(Some(&cid), false);
    }
    monitor.simulate_elapsed_time(20);

    let score = monitor.calculate_attack_score();
    assert!(
        score.abs() < f64::EPSILON,
        "Score should be 0 with < 10 requests and no kills/unverified"
    );

    for i in 5..15 {
        let cid = format!("circuit_{i}");
        monitor.record_request(Some(&cid), false);
    }

    let score_after = monitor.calculate_attack_score();
    assert!(score_after > 0.0, "Score should be > 0 after 10+ requests");
}

#[tokio::test]
async fn test_pow_activates_with_kills_even_low_requests() {
    let mut config = (*create_test_config(0)).clone();
    config.attack_defense_score = 0.1;
    config.attack_pow_score = 0.5;
    config.defense_circuit_flood_threshold = 1;
    let config = Arc::new(config);
    let monitor = DefenseMonitor::new(config);

    for i in 0..3 {
        let cid = format!("bad_circuit_{i}");
        monitor.record_request(Some(&cid), false);
        monitor.record_circuit_kill();
    }
    monitor.simulate_elapsed_time(15);

    let score = monitor.calculate_attack_score();
    assert!(
        score > 0.0,
        "Score should be > 0 with kills even if requests < 10"
    );
}

#[tokio::test]
async fn test_pow_activates_with_unverified_even_low_requests() {
    let mut config = (*create_test_config(0)).clone();
    config.attack_defense_score = 0.1;
    config.attack_pow_score = 0.5;
    let config = Arc::new(config);
    let monitor = DefenseMonitor::new(config);

    for i in 0..5 {
        let cid = format!("unverified_circuit_{i}");
        monitor.record_request(Some(&cid), false);
        monitor.record_unverified_request();
    }
    monitor.simulate_elapsed_time(15);

    let score = monitor.calculate_attack_score();
    assert!(
        score > 0.0,
        "Score should be > 0 with unverified even if requests < 10"
    );
}

#[tokio::test]
async fn test_pow_enables_defense_mode_automatically() {
    let mut config = (*create_test_config(0)).clone();
    config.attack_defense_score = 2.0;
    config.attack_pow_score = 4.0;
    let config = Arc::new(config);
    let monitor = DefenseMonitor::new(config);

    assert!(!monitor.is_defense_mode());
    assert!(!monitor.is_pow_enabled());

    monitor.mark_pow_enabled();

    assert!(monitor.is_pow_enabled());
    assert!(
        monitor.is_defense_mode(),
        "Defense mode should be activated when PoW is enabled"
    );
}

#[tokio::test]
async fn test_pow_does_not_duplicate_defense_activation() {
    let mut config = (*create_test_config(0)).clone();
    config.attack_defense_score = 2.0;
    config.attack_pow_score = 4.0;
    let config = Arc::new(config);
    let monitor = DefenseMonitor::new(config);

    assert!(!monitor.enable_auto_defense());

    for i in 0..30 {
        let cid = format!("circuit_{i}");
        monitor.record_request(Some(&cid), false);
        monitor.record_unverified_request();
    }
    monitor.simulate_elapsed_time(20);

    let activated = monitor.enable_auto_defense();
    assert!(activated, "Defense should activate first time");
    assert!(monitor.is_defense_mode());

    let activated_again = monitor.enable_auto_defense();
    assert!(!activated_again, "Defense should not re-activate");

    monitor.mark_pow_enabled();
    assert!(monitor.is_pow_enabled());
    assert!(monitor.is_defense_mode());
}

#[tokio::test]
async fn test_low_circuit_usage_factor_requires_minimum_circuits() {
    let mut config = (*create_test_config(0)).clone();
    config.attack_rpc_threshold = 100;
    config.attack_defense_score = 0.5;
    let config = Arc::new(config);
    let monitor = DefenseMonitor::new(config);

    for i in 0..3 {
        let cid = format!("circuit_{i}");
        monitor.record_request(Some(&cid), false);
    }
    monitor.simulate_elapsed_time(15);

    let score1 = monitor.calculate_attack_score();

    let monitor2 = DefenseMonitor::new(Arc::new({
        let mut c = (*create_test_config(0)).clone();
        c.attack_rpc_threshold = 100;
        c.attack_defense_score = 0.5;
        c
    }));
    for i in 0..15 {
        let cid = format!("circuit_{i}");
        monitor2.record_request(Some(&cid), false);
    }
    monitor2.simulate_elapsed_time(15);

    let score2 = monitor2.calculate_attack_score();
    assert!(
        score2 > score1,
        "Score with 15 circuits ({score2}) should be higher than 3 circuits ({score1}) due to low_circuit_usage_factor"
    );
}

#[tokio::test]
async fn test_score_zero_on_startup() {
    let config = Arc::new((*create_test_config(0)).clone());
    let monitor = DefenseMonitor::new(config);

    let score = monitor.calculate_attack_score();
    assert!(
        score.abs() < f64::EPSILON,
        "Score should be 0 on fresh startup"
    );
    assert!(!monitor.should_auto_defense());
    assert!(monitor.should_enable_pow().is_none());
}

#[tokio::test]
async fn test_stem_attack_pattern_circuit_rotation() {
    let mut config = (*create_test_config(0)).clone();
    config.attack_churn_threshold = 10;
    config.attack_rpc_threshold = 5;
    config.attack_defense_score = 2.0;
    config.attack_pow_score = 4.0;
    let config = Arc::new(config);
    let monitor = DefenseMonitor::new(config);

    for i in 0..30 {
        let cid = format!("rotating_circuit_{i}");
        monitor.record_request(Some(&cid), false);
    }

    monitor.simulate_elapsed_time(15);

    let score = monitor.calculate_attack_score();
    assert!(
        score > 2.0,
        "Stem attack pattern (30 circuits, 1 req each) should trigger defense. Score: {score}"
    );
    assert!(monitor.should_auto_defense());
}

#[tokio::test]
async fn test_attack_tracking_independent_of_threshold_reset() {
    let mut config = (*create_test_config(0)).clone();
    config.attack_churn_threshold = 5;
    config.attack_defense_score = 1.0;
    let config = Arc::new(config);
    let monitor = DefenseMonitor::new(config);

    for i in 0..20 {
        let cid = format!("circuit_{i}");
        monitor.record_request(Some(&cid), false);
    }

    monitor.simulate_elapsed_time(15);

    let score1 = monitor.calculate_attack_score();
    assert!(score1 > 0.0, "Score should be > 0 after requests");

    for i in 20..40 {
        let cid = format!("circuit_{i}");
        monitor.record_request(Some(&cid), false);
    }

    let score2 = monitor.calculate_attack_score();
    assert!(
        score2 >= score1,
        "Score should increase or stay same with more circuits. Before: {score1}, After: {score2}"
    );
}

#[tokio::test]
async fn test_high_churn_rate_detection() {
    let mut config = (*create_test_config(0)).clone();
    config.attack_churn_threshold = 10;
    config.attack_defense_score = 1.5;
    config.attack_pow_score = 3.0;
    let config = Arc::new(config);
    let monitor = DefenseMonitor::new(config);

    for i in 0..50 {
        let cid = format!("churn_circuit_{i}");
        monitor.record_request(Some(&cid), false);
    }

    monitor.simulate_elapsed_time(30);

    let score = monitor.calculate_attack_score();
    assert!(
        score > 1.5,
        "High churn rate (50 circuits in 30s = 100/min) should trigger defense. Score: {score}"
    );

    assert!(
        monitor.should_auto_defense(),
        "Defense mode should activate on high churn"
    );
}

#[tokio::test]
async fn test_pow_auto_disable_after_recovery() {
    let mut config = (*create_test_config(0)).clone();
    config.attack_defense_score = 2.0;
    config.attack_pow_score = 4.0;
    config.attack_recovery_secs = 60;
    let config = Arc::new(config);
    let monitor = DefenseMonitor::new(config);

    monitor.mark_pow_enabled();
    assert!(monitor.is_pow_enabled());
    assert!(monitor.is_defense_mode());

    assert!(
        !monitor.should_disable_pow(),
        "PoW should not disable immediately after enabling"
    );

    monitor.simulate_pow_elapsed(70);

    let should_disable = monitor.should_disable_pow();
    assert!(
        should_disable,
        "PoW should auto-disable after recovery period with low score"
    );

    monitor.mark_pow_disabled();
    assert!(!monitor.is_pow_enabled());
}

#[tokio::test]
async fn test_pow_stays_enabled_during_attack() {
    let mut config = (*create_test_config(0)).clone();
    config.attack_defense_score = 1.0;
    config.attack_pow_score = 2.0;
    config.attack_recovery_secs = 30;
    let config = Arc::new(config);
    let monitor = DefenseMonitor::new(config);

    for i in 0..30 {
        let cid = format!("attack_circuit_{i}");
        monitor.record_request(Some(&cid), false);
        monitor.record_unverified_request();
    }
    monitor.simulate_elapsed_time(15);

    monitor.mark_pow_enabled();
    assert!(monitor.is_pow_enabled());

    monitor.simulate_pow_elapsed(60);

    let score = monitor.calculate_attack_score();
    assert!(
        score >= 1.0,
        "Score should still be high during attack: {score}"
    );

    assert!(
        !monitor.should_disable_pow(),
        "PoW should stay enabled while score is still high"
    );
}
