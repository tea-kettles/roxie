use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use roxie::config::ShadowsocksConfig;
use roxie::transport::Proxy;
use tokio::sync::Mutex;
use tokio::time::timeout;
use url::Url;

// cargo test --test live_shadowsocks_stress -- --ignored --nocapture

const DEFAULT_SERVER: &str = "100.82.255.88";
const DEFAULT_PORT: u16 = 25565;
const DEFAULT_PASSWORD: &str = "password123";
const DEFAULT_METHOD: &str = "chacha20-ietf-poly1305";
const DEFAULT_TARGET: &str = "http://httpbin.org/ip";
const DEFAULT_EXPECTED_IP: &str = "75.187.247.92";

const DEFAULT_TOTAL_REQUESTS: usize = 1000;
const DEFAULT_CONCURRENCY: usize = 100;
const DEFAULT_TIMEOUT_SECS: u64 = 20;
const DEFAULT_MIN_SUCCESS_RATE: f64 = 0.95;

#[tokio::test]
#[ignore]
#[cfg(feature = "shadowsocks")]
async fn shadowsocks_stress_test_production_gate() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let server = std::env::var("SS_SERVER").unwrap_or_else(|_| DEFAULT_SERVER.to_string());
    let port = std::env::var("SS_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT);
    let password = std::env::var("SS_PASSWORD").unwrap_or_else(|_| DEFAULT_PASSWORD.to_string());
    let method = std::env::var("SS_METHOD").unwrap_or_else(|_| DEFAULT_METHOD.to_string());
    let target_raw = std::env::var("SS_TARGET").unwrap_or_else(|_| DEFAULT_TARGET.to_string());
    let expected_ip =
        std::env::var("SS_EXPECTED_IP").unwrap_or_else(|_| DEFAULT_EXPECTED_IP.to_string());

    let total_requests = std::env::var("SS_STRESS_TOTAL")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_TOTAL_REQUESTS);
    let concurrency = std::env::var("SS_STRESS_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_CONCURRENCY);
    let request_timeout_secs = std::env::var("SS_STRESS_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_TIMEOUT_SECS);
    let min_success_rate = std::env::var("SS_STRESS_MIN_SUCCESS")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(DEFAULT_MIN_SUCCESS_RATE);
    let p95_budget_ms = std::env::var("SS_STRESS_P95_MS")
        .ok()
        .and_then(|v| v.parse::<u128>().ok());

    let target = Arc::new(Url::parse(&target_raw).expect("failed to parse SS_TARGET"));
    let config = Arc::new(ShadowsocksConfig::new().set_method(method.clone()));
    let proxy = Arc::new(Proxy::Shadowsocks {
        host: server,
        port,
        password,
        config,
    });

    tracing::info!(
        method = %method,
        target = %target,
        total_requests,
        concurrency,
        timeout_secs = request_timeout_secs,
        min_success_rate,
        expected_ip = %expected_ip,
        "starting shadowsocks stress test"
    );

    let next_index = Arc::new(AtomicUsize::new(0));
    let success_count = Arc::new(AtomicUsize::new(0));
    let failure_count = Arc::new(AtomicUsize::new(0));
    let latency_ms = Arc::new(Mutex::new(Vec::<u128>::with_capacity(total_requests)));

    let test_start = Instant::now();
    let mut handles = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let next_index = Arc::clone(&next_index);
        let success_count = Arc::clone(&success_count);
        let failure_count = Arc::clone(&failure_count);
        let latency_ms = Arc::clone(&latency_ms);
        let proxy = Arc::clone(&proxy);
        let target = Arc::clone(&target);
        let expected_ip = expected_ip.clone();

        let handle = tokio::spawn(async move {
            loop {
                let idx = next_index.fetch_add(1, Ordering::Relaxed);
                if idx >= total_requests {
                    break;
                }

                let req_start = Instant::now();
                let res = timeout(Duration::from_secs(request_timeout_secs), async {
                    proxy.get(&target).await
                })
                .await;
                let elapsed_ms = req_start.elapsed().as_millis();

                match res {
                    Ok(Ok(body)) if body.contains(&expected_ip) => {
                        success_count.fetch_add(1, Ordering::Relaxed);
                        latency_ms.lock().await.push(elapsed_ms);
                    }
                    _ => {
                        failure_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.await.expect("stress worker task panicked");
    }

    let total_elapsed = test_start.elapsed();
    let successes = success_count.load(Ordering::Relaxed);
    let failures = failure_count.load(Ordering::Relaxed);
    let attempted = successes + failures;

    assert_eq!(
        attempted, total_requests,
        "attempt count mismatch: attempted={}, expected={}",
        attempted, total_requests
    );

    let success_rate = successes as f64 / total_requests as f64;
    let rps = total_requests as f64 / total_elapsed.as_secs_f64();

    let mut latencies = latency_ms.lock().await;
    latencies.sort_unstable();
    let p50 = percentile(&latencies, 0.50).unwrap_or(0);
    let p95 = percentile(&latencies, 0.95).unwrap_or(0);
    let p99 = percentile(&latencies, 0.99).unwrap_or(0);

    tracing::info!(
        total_requests,
        successes,
        failures,
        success_rate = format!("{:.4}", success_rate),
        elapsed_secs = format!("{:.2}", total_elapsed.as_secs_f64()),
        rps = format!("{:.2}", rps),
        p50_ms = p50,
        p95_ms = p95,
        p99_ms = p99,
        "shadowsocks stress test finished"
    );

    assert!(
        success_rate >= min_success_rate,
        "success rate {:.4} is below required {:.4}",
        success_rate,
        min_success_rate
    );

    if let Some(budget) = p95_budget_ms {
        assert!(
            p95 <= budget,
            "p95 latency {}ms exceeds budget {}ms",
            p95,
            budget
        );
    }
}

fn percentile(sorted: &[u128], p: f64) -> Option<u128> {
    if sorted.is_empty() {
        return None;
    }

    let p = p.clamp(0.0, 1.0);
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted.get(idx).copied()
}
