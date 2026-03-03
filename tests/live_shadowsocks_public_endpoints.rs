use std::fs;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use roxie::transport::ProxyList;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use url::Url;

// cargo test --test live_shadowsocks_public_endpoints -- --ignored --nocapture

const PROXY_FILE: &str = "ss_proxies.json";
const TARGET_URL: &str = "http://httpbin.org/ip";
const PER_PROXY_TIMEOUT_SECS: u64 = 20;
const GLOBAL_TIMEOUT_SECS: u64 = 180;

#[tokio::test]
#[ignore]
#[cfg(feature = "shadowsocks")]
async fn public_shadowsocks_endpoints_have_at_least_one_success() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let proxies_path = format!("{}/{}", manifest_dir, PROXY_FILE);
    let proxies_json = fs::read_to_string(&proxies_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", proxies_path, e));

    let list = ProxyList::from_array(&proxies_json)
        .unwrap_or_else(|e| panic!("failed to parse {}: {}", PROXY_FILE, e));
    assert!(!list.is_empty(), "{} contained no proxies", PROXY_FILE);

    let target = Arc::new(Url::parse(TARGET_URL).expect("failed to parse target URL"));
    let direct_origin_ips = fetch_direct_origin_ips(TARGET_URL)
        .await
        .unwrap_or_default();
    let direct_origin_ip = direct_origin_ips.first().cloned().unwrap_or_default();
    println!(
        "BASELINE: direct (non-proxy) origin IP(s) from {} => {:?}",
        TARGET_URL, direct_origin_ips
    );

    let success_count = Arc::new(AtomicUsize::new(0));
    let failure_count = Arc::new(AtomicUsize::new(0));
    let correct_ip_count = Arc::new(AtomicUsize::new(0));
    let own_ip_match_count = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(list.len());

    for proxy in list.iter().cloned() {
        let target = Arc::clone(&target);
        let success_count = Arc::clone(&success_count);
        let failure_count = Arc::clone(&failure_count);
        let correct_ip_count = Arc::clone(&correct_ip_count);
        let own_ip_match_count = Arc::clone(&own_ip_match_count);
        let direct_origin_ip = direct_origin_ip.clone();

        let handle = tokio::spawn(async move {
            let result = timeout(Duration::from_secs(PER_PROXY_TIMEOUT_SECS), async {
                proxy.get(&target).await
            })
            .await;

            match result {
                Ok(Ok(body)) => {
                    let origin_ips = extract_origin_ips(&body);
                    let expected_ips = resolve_expected_ips(proxy.get_host(), proxy.get_port()).await;
                    let is_correct = origin_ips.iter().any(|ip| expected_ips.contains(ip));
                    let is_own_ip = !direct_origin_ip.is_empty()
                        && origin_ips.iter().any(|ip| ip == &direct_origin_ip);

                    tracing::info!(
                        host = %proxy.get_host(),
                        port = proxy.get_port(),
                        scheme = %proxy.get_scheme(),
                        is_correct_ip = is_correct,
                        is_own_ip = is_own_ip,
                        origin_ips = ?origin_ips,
                        expected_ips = ?expected_ips,
                        body_preview = %body.chars().take(120).collect::<String>(),
                        "public shadowsocks endpoint succeeded"
                    );
                    success_count.fetch_add(1, Ordering::Relaxed);
                    if is_correct {
                        correct_ip_count.fetch_add(1, Ordering::Relaxed);
                    }
                    if is_own_ip {
                        own_ip_match_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Ok(Err(err)) => {
                    tracing::info!(
                        host = %proxy.get_host(),
                        port = proxy.get_port(),
                        scheme = %proxy.get_scheme(),
                        error = %err,
                        "public shadowsocks endpoint failed"
                    );
                    failure_count.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    tracing::info!(
                        host = %proxy.get_host(),
                        port = proxy.get_port(),
                        scheme = %proxy.get_scheme(),
                        timeout_secs = PER_PROXY_TIMEOUT_SECS,
                        "public shadowsocks endpoint timed out"
                    );
                    failure_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        handles.push(handle);
    }

    timeout(Duration::from_secs(GLOBAL_TIMEOUT_SECS), async {
        for handle in handles {
            let _ = handle.await;
        }
    })
    .await
    .expect("global timeout reached while testing public shadowsocks endpoints");

    let successes = success_count.load(Ordering::Relaxed);
    let failures = failure_count.load(Ordering::Relaxed);
    let correct_ips = correct_ip_count.load(Ordering::Relaxed);
    let own_ip_matches = own_ip_match_count.load(Ordering::Relaxed);

    tracing::info!(
        total = successes + failures,
        successes,
        failures,
        correct_ip_matches = correct_ips,
        own_ip_matches = own_ip_matches,
        direct_origin_ip = %direct_origin_ip,
        "public shadowsocks endpoint test complete"
    );
    println!(
        "SUMMARY: direct origin ip = {}, worked successfully = {} / {}, failed = {}, correct IP matches = {}, returned own IP = {}",
        if direct_origin_ip.is_empty() {
            "<unavailable>"
        } else {
            &direct_origin_ip
        },
        successes,
        successes + failures,
        failures,
        correct_ips,
        own_ip_matches
    );

    assert!(
        successes > 0,
        "no public shadowsocks endpoint succeeded (failures: {})",
        failures
    );
}

async fn fetch_direct_origin_ips(target_url: &str) -> Result<Vec<String>, String> {
    let target = Url::parse(target_url).map_err(|e| format!("invalid target url: {}", e))?;
    let host = target
        .host_str()
        .ok_or_else(|| "target url missing host".to_string())?;
    let port = target
        .port_or_known_default()
        .ok_or_else(|| "target url missing port".to_string())?;
    let mut path = target.path().to_string();
    if path.is_empty() {
        path = "/".to_string();
    }
    if let Some(q) = target.query() {
        path.push('?');
        path.push_str(q);
    }

    let addr = format!("{}:{}", host, port);
    let mut stream = timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("direct TCP connect to {} timed out", addr))?
        .map_err(|e| format!("direct TCP connect to {} failed: {}", addr, e))?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: roxie-direct-ip-check\r\n\r\n",
        path, host
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("direct request write failed: {}", e))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|e| format!("direct response read failed: {}", e))?;

    let response_text = String::from_utf8_lossy(&response);
    let body = if let Some(idx) = response_text.find("\r\n\r\n") {
        &response_text[idx + 4..]
    } else {
        &response_text
    };

    Ok(extract_origin_ips(body))
}

fn extract_origin_ips(body: &str) -> Vec<String> {
    let parsed = serde_json::from_str::<Value>(body);
    let origin = match parsed
        .ok()
        .and_then(|v| v.get("origin").and_then(|v| v.as_str()).map(|s| s.to_string()))
    {
        Some(v) => v,
        None => return Vec::new(),
    };

    origin
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

async fn resolve_expected_ips(host: &str, port: u16) -> Vec<String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![ip.to_string()];
    }

    let mut ips = Vec::new();
    if let Ok(addrs) = tokio::net::lookup_host((host, port)).await {
        for addr in addrs {
            let ip = addr.ip().to_string();
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
    ips
}
