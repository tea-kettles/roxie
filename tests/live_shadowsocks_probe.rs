use std::sync::Arc;
use std::time::Duration;

use roxie::config::ShadowsocksConfig;
use roxie::transport::Proxy;
use tokio::task::JoinSet;
use tokio::time::timeout;
use url::Url;

// cargo test --test live_shadowsocks_probe -- --ignored

const DEFAULT_SERVER: &str = "100.82.255.88";
const DEFAULT_PORT: u16 = 25565;
const DEFAULT_PASSWORD: &str = "password123";
const DEFAULT_TARGET: &str = "http://httpbin.org/ip";
const DEFAULT_EXPECTED_IP: &str = "75.187.247.92";
const METHOD_PROBE_TIMEOUT_SECS: u64 = 20;
const CHACHA_METHOD: &str = "chacha20-ietf-poly1305";

#[cfg(feature = "shadowsocks")]
const CANDIDATE_METHODS: &[&str] = &[
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
];

#[tokio::test]
#[ignore]
#[cfg(feature = "shadowsocks")]
async fn probe_shadowsocks_method_and_cancel_others() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_test_writer()
        .try_init();

    let server = std::env::var("SS_SERVER").unwrap_or_else(|_| DEFAULT_SERVER.to_string());
    let port = std::env::var("SS_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT);
    let password = std::env::var("SS_PASSWORD").unwrap_or_else(|_| DEFAULT_PASSWORD.to_string());
    let target_raw = std::env::var("SS_TARGET").unwrap_or_else(|_| DEFAULT_TARGET.to_string());
    let expected_ip =
        std::env::var("SS_EXPECTED_IP").unwrap_or_else(|_| DEFAULT_EXPECTED_IP.to_string());
    let target = Arc::new(Url::parse(&target_raw).expect("failed to parse SS_TARGET"));

    tracing::info!(
        server = %server,
        port = port,
        target = %target,
        expected_ip = %expected_ip,
        candidates = ?CANDIDATE_METHODS,
        "starting concurrent shadowsocks method probe"
    );

    let mut tasks = JoinSet::new();

    for method in CANDIDATE_METHODS {
        let host = server.clone();
        let pass = password.clone();
        let target = Arc::clone(&target);
        let method = (*method).to_string();

        tasks.spawn(async move {
            let config = ShadowsocksConfig::new().set_method(method.clone());
            let proxy = Proxy::Shadowsocks {
                host,
                port,
                password: pass,
                config: Arc::new(config),
            };

            let result = timeout(Duration::from_secs(METHOD_PROBE_TIMEOUT_SECS), async {
                proxy.get(&target).await
            })
            .await;

            match result {
                Ok(Ok(body)) => Ok((method, body)),
                Ok(Err(e)) => Err(format!("{} failed: {}", method, e)),
                Err(_) => Err(format!(
                    "{} timed out after {}s",
                    method, METHOD_PROBE_TIMEOUT_SECS
                )),
            }
        });
    }

    let mut winner: Option<(String, String)> = None;
    let mut failures: Vec<String> = Vec::new();

    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Ok((method, body))) => {
                if !body.contains(&expected_ip) {
                    failures.push(format!(
                        "{} connected, but response body did not contain expected ip {}. body preview: {}",
                        method,
                        expected_ip,
                        body.chars().take(200).collect::<String>()
                    ));
                    continue;
                }
                winner = Some((method, body));
                tasks.abort_all();
                break;
            }
            Ok(Err(err)) => failures.push(err),
            Err(join_err) => failures.push(format!("task join error: {}", join_err)),
        }
    }

    if let Some((method, body)) = winner {
        tracing::info!(
            method = %method,
            body_preview = %body.chars().take(160).collect::<String>(),
            "detected working shadowsocks method; aborted remaining probes"
        );
    } else {
        panic!(
            "no candidate method succeeded. failures: {}",
            failures.join(" | ")
        );
    }
}

#[tokio::test]
#[ignore]
#[cfg(feature = "shadowsocks")]
async fn shadowsocks_chacha20_ietf_poly1305_connects_and_matches_expected_ip() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_test_writer()
        .try_init();

    let server = std::env::var("SS_SERVER").unwrap_or_else(|_| DEFAULT_SERVER.to_string());
    let port = std::env::var("SS_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT);
    let password = std::env::var("SS_PASSWORD").unwrap_or_else(|_| DEFAULT_PASSWORD.to_string());
    let target_raw = std::env::var("SS_TARGET").unwrap_or_else(|_| DEFAULT_TARGET.to_string());
    let expected_ip =
        std::env::var("SS_EXPECTED_IP").unwrap_or_else(|_| DEFAULT_EXPECTED_IP.to_string());

    let target = Url::parse(&target_raw).expect("failed to parse SS_TARGET");
    let config = ShadowsocksConfig::new().set_method(CHACHA_METHOD);
    let proxy = Proxy::Shadowsocks {
        host: server,
        port,
        password,
        config: Arc::new(config),
    };

    let body = timeout(Duration::from_secs(METHOD_PROBE_TIMEOUT_SECS), async {
        proxy.get(&target).await
    })
    .await
    .expect("chacha20 method timed out")
    .expect("chacha20 method failed");

    assert!(
        body.contains(&expected_ip),
        "response did not contain expected ip {}. body preview: {}",
        expected_ip,
        body.chars().take(200).collect::<String>()
    );
}
