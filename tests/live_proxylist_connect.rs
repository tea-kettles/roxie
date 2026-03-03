use std::fs;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use roxie::config::BaseProxyConfig;
use roxie::transport::ProxyList;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing_subscriber;
use url::Url;

// cargo test --test proxylist_connect -- --ignored

#[tokio::test]
#[ignore]
async fn proxylist_connects_to_google() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .init();
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let proxies_path = format!("{}/tests/proxies.json", manifest_dir);
    let proxies_json = fs::read_to_string(&proxies_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", proxies_path, e));

    let list = ProxyList::from_array(&proxies_json)
        .unwrap_or_else(|e| panic!("failed to parse proxies.json: {}", e));
    assert!(!list.is_empty(), "proxies.json contained no proxies");

    let target =
        Arc::new(Url::parse("https://www.google.com").expect("failed to parse target URL"));

    let semaphore = Arc::new(Semaphore::new(200));

    let success_count = Arc::new(AtomicUsize::new(0));
    let failure_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(list.len());

    for proxy in list.iter().cloned() {
        let permit_semaphore = semaphore.clone();
        let target = target.clone();
        let success_count = success_count.clone();
        let failure_count = failure_count.clone();

        let handle = tokio::spawn(async move {
            // Limit concurrency
            let _permit = permit_semaphore.acquire().await.unwrap();

            let result = timeout(Duration::from_secs(20), proxy.connect(&target)).await;

            match result {
                Ok(Ok(_stream)) => {
                    success_count.fetch_add(1, Ordering::Relaxed);
                }
                Ok(Err(_)) | Err(_) => {
                    failure_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        handles.push(handle);
    }

    // Global bound for the entire test
    let join_result = timeout(Duration::from_secs(120), async {
        for handle in handles {
            let _ = handle.await;
        }
    })
    .await;

    assert!(join_result.is_ok(), "test exceeded global timeout");

    let successes = success_count.load(Ordering::Relaxed);
    let failures = failure_count.load(Ordering::Relaxed);

    assert!(
        successes > 0,
        "no proxies succeeded (failures: {})",
        failures
    );
}

use rand::seq::IteratorRandom;
use rand::thread_rng;

#[tokio::test]
#[ignore]
async fn proxy_single_random_connect_trace_logging() {
    // Trace-level logging to inspect connector internals
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_test_writer()
        .try_init();

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let proxies_path = format!("{}/tests/proxies.json", manifest_dir);
    let proxies_json = fs::read_to_string(&proxies_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", proxies_path, e));

    let list = ProxyList::from_array(&proxies_json)
        .unwrap_or_else(|e| panic!("failed to parse proxies.json: {}", e));
    assert!(!list.is_empty(), "proxies.json contained no proxies");

    // Pick a single random proxy
    let proxy = list
        .iter()
        .choose(&mut thread_rng())
        .expect("proxy list unexpectedly empty")
        .clone();

    let target = Url::parse("https://www.google.com").expect("failed to parse target URL");

    tracing::info!(
        proxy_scheme = %proxy.get_scheme(),
        proxy_addr = %proxy.get_host(),
        "testing single proxy with trace logging"
    );

    let result = timeout(Duration::from_secs(20), proxy.connect(&target)).await;

    match result {
        Ok(Ok(_stream)) => {
            tracing::info!("single proxy connection succeeded");
        }
        Ok(Err(err)) => {
            tracing::info!(
                error = %err,
                "single proxy connection failed (expected in many cases)"
            );
        }
        Err(_) => {
            tracing::info!("single proxy connection timed out");
        }
    }

    // This test is about observability, not success.
    // It should never fail unless something panics internally.
    assert!(true);
}

// cargo test --test live_proxylist_connect proxylist_autotls_trace -- --ignored

#[tokio::test]
#[ignore]
async fn proxylist_autotls_trace() {
    // Trace-level logging to see autotls behavior
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_test_writer()
        .try_init();

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let proxies_path = format!("{}/tests/proxies.json", manifest_dir);
    let proxies_json = fs::read_to_string(&proxies_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", proxies_path, e));

    // Create base config with autotls enabled
    let mut base_config = BaseProxyConfig::new();
    base_config.set_auto_tls(true);
    base_config.set_handshake_timeout(Duration::from_secs(15));
    base_config.set_phase_timeout(Duration::from_secs(5));
    base_config.set_tcp_nodelay(true);

    tracing::info!(
        auto_tls = base_config.is_auto_tls(),
        handshake_timeout = ?base_config.get_handshake_timeout(),
        "created base config with autotls enabled"
    );

    // Parse and apply config to all proxies
    let list = ProxyList::from_array(&proxies_json)
        .unwrap_or_else(|e| panic!("failed to parse proxies.json: {}", e))
        .config(base_config);

    assert!(!list.is_empty(), "proxies.json contained no proxies");
    tracing::info!(proxy_count = list.len(), "loaded and configured proxies");

    let target =
        Arc::new(Url::parse("https://www.google.com").expect("failed to parse target URL"));

    let semaphore = Arc::new(Semaphore::new(200));
    let success_count = Arc::new(AtomicUsize::new(0));
    let failure_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(list.len());

    for proxy in list.iter().cloned() {
        let permit_semaphore = semaphore.clone();
        let target = target.clone();
        let success_count = success_count.clone();
        let failure_count = failure_count.clone();

        let handle = tokio::spawn(async move {
            let _permit = permit_semaphore.acquire().await.unwrap();

            tracing::trace!(
                proxy_scheme = %proxy.get_scheme(),
                proxy_host = %proxy.get_host(),
                proxy_port = proxy.get_port(),
                "attempting connection with autotls"
            );

            let result = timeout(Duration::from_secs(20), proxy.connect(&target)).await;

            match result {
                Ok(Ok(_stream)) => {
                    tracing::debug!(
                        proxy_scheme = %proxy.get_scheme(),
                        proxy_addr = %format!("{}:{}", proxy.get_host(), proxy.get_port()),
                        "connection succeeded with autotls"
                    );
                    success_count.fetch_add(1, Ordering::Relaxed);
                }
                Ok(Err(e)) => {
                    tracing::trace!(
                        proxy_scheme = %proxy.get_scheme(),
                        proxy_addr = %format!("{}:{}", proxy.get_host(), proxy.get_port()),
                        error = %e,
                        "connection failed"
                    );
                    failure_count.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    tracing::trace!(
                        proxy_scheme = %proxy.get_scheme(),
                        proxy_addr = %format!("{}:{}", proxy.get_host(), proxy.get_port()),
                        "connection timed out"
                    );
                    failure_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        handles.push(handle);
    }

    let join_result = timeout(Duration::from_secs(120), async {
        for handle in handles {
            let _ = handle.await;
        }
    })
    .await;

    assert!(join_result.is_ok(), "test exceeded global timeout");

    let successes = success_count.load(Ordering::Relaxed);
    let failures = failure_count.load(Ordering::Relaxed);

    tracing::info!(
        successes = successes,
        failures = failures,
        total = successes + failures,
        "autotls test completed"
    );

    assert!(
        successes > 0,
        "no proxies succeeded with autotls (failures: {})",
        failures
    );
}
