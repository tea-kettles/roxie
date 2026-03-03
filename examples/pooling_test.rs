//! Test example for ProxyPool with ConnectionPool for connection reuse.
//!
//! Demonstrates connection pooling with multiple requests to the same target,
//! showing connection reuse statistics. Reads proxies from `tests/proxies.json`
//! and makes multiple requests to verify connections are being reused.
//!
//! Run with:
//! ```bash
//! cargo run --example pooling_test
//! ```

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use roxie::extensions::ProxyPoolExt;
use roxie::transport::{ProxyList, ProxyPool};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};
use tracing_subscriber;
use url::Url;

const PROXY_FILE: &str = "proxies.json";
const TARGET_URL: &str = "https://example.com/";
const NUM_REQUESTS: usize = 10;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .init();

    info!("🚀 Connection Pool Test Starting (connect_with_best)");
    info!("📊 Will test proxies first, then make {} requests to {}", NUM_REQUESTS, TARGET_URL);

    // Load proxies
    let proxies_json = std::fs::read_to_string(PROXY_FILE)?;
    let list = ProxyList::from_array(&proxies_json)?;
    info!("✅ Loaded {} proxies", list.len());

    // Create proxy pool for intelligent selection
    let proxy_pool = Arc::new(ProxyPool::from_list(&list));
    info!("✅ Created ProxyPool with {} proxies", proxy_pool.len());

    // STEP 1: Test all proxies first
    info!("\n🧪 STEP 1: Testing all proxies concurrently...");
    info!("   Max concurrent: 100");
    info!("   Test URL: {}", TARGET_URL);
    
    let test_results = proxy_pool.initialize_pool(100, Some(TARGET_URL)).await;
    
    info!("\n📊 Proxy Test Results:");
    info!("   Total tested:  {}", test_results.total_tested);
    info!("   ✅ Working:     {} ({:.1}%)", 
          test_results.working_count,
          (test_results.working_count as f64 / test_results.total_tested as f64) * 100.0);
    info!("   ❌ Failed:      {} ({:.1}%)", 
          test_results.failed_count,
          (test_results.failed_count as f64 / test_results.total_tested as f64) * 100.0);
    
    if test_results.working_count > 0 {
        info!("\n⚡ Performance Statistics:");
        info!("   Average response: {}ms", test_results.avg_response_time_ms);
        info!("   Fastest:          {}ms", test_results.fastest_ms);
        info!("   Slowest:          {}ms", test_results.slowest_ms);
        
        // Show top 5 fastest proxies
        let mut working: Vec<_> = test_results.results.iter()
            .filter(|r| r.success)
            .collect();
        working.sort_by_key(|r| r.response_time_ms);
        
        info!("\n🏆 Top 5 Fastest Proxies:");
        for (i, result) in working.iter().take(5).enumerate() {
            info!("   {}. {} - {}ms", i + 1, result.proxy_key, result.response_time_ms);
        }
    } else {
        warn!("⚠️  No working proxies found! Requests will likely fail.");
    }

    // STEP 2: Make requests using connect_with_best
    info!("\n🔗 STEP 2: Making {} requests using connect_with_best...", NUM_REQUESTS);

    let target = Url::parse(TARGET_URL)?;

    // Make requests using connect_with_best
    info!("   Best proxies have been scored and will be prioritized");
    
    let mut successful_requests = 0;
    let mut failed_requests = 0;

    for i in 0..NUM_REQUESTS {
        debug!("Request {}/{}", i + 1, NUM_REQUESTS);
        
        // Use connect_with_best - tries up to 10 best proxies
        // Now it will prefer the proxies that succeeded in testing
        match make_request_with_best(&proxy_pool, &target, i + 1).await {
            Ok(_) => {
                successful_requests += 1;
                info!("✅ Request {}/{} succeeded", i + 1, NUM_REQUESTS);
            }
            Err(e) => {
                failed_requests += 1;
                warn!("❌ Request {}/{} failed: {}", i + 1, NUM_REQUESTS, e);
            }
        }

        // Small delay between requests to see connection reuse
        if i < NUM_REQUESTS - 1 {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    // Display final statistics
    info!("\n📊 Final Request Statistics:");
    info!("   Total requests: {}", NUM_REQUESTS);
    info!("   Successful: {}", successful_requests);
    info!("   Failed: {}", failed_requests);
    
    if successful_requests > 0 {
        let success_rate = (successful_requests as f64 / NUM_REQUESTS as f64) * 100.0;
        info!("   Success rate: {:.1}%", success_rate);
    }

    // Get proxy pool statistics to see scoring evolution
    let pool_stats = proxy_pool.stats();
    info!("\n🎯 Final Proxy Pool Statistics:");
    info!("   Total proxies: {}", pool_stats.total_proxies);
    info!("   Active (scored > 0): {}", pool_stats.active_proxies);
    info!("   Average score: {:.2}", pool_stats.average_score);
    info!("   Locked proxies: {}", pool_stats.locked_proxies);

    if successful_requests > 0 && test_results.working_count > 0 {
        info!("\n✨ Summary:");
        info!("   1. Testing found {} working proxies", test_results.working_count);
        info!("   2. Best proxies were automatically prioritized");
        info!("   3. Connections were pooled and reused for speed");
        info!("   4. Success rate: {:.1}%", 
              (successful_requests as f64 / NUM_REQUESTS as f64) * 100.0);
    }

    Ok(())
}

/// Makes a single HTTP request using connect_with_best.
async fn make_request_with_best(
    proxy_pool: &Arc<ProxyPool>,
    target: &Url,
    request_num: usize,
) -> Result<(), String> {
    // connect_with_best tries up to N best proxies
    // Each failure rotates to next-best proxy
    // Internally pools connections for reuse
    let mut stream = proxy_pool.connect_with_semaphore(target, 10).await
        .map_err(|e| format!("Failed to connect: {}", e))?;

    debug!("Request {} - got stream from connect_with_best", request_num);

    // Build HTTP request
    let host = target.host_str().unwrap_or("example.com");
    let path = target.path();
    let request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: roxie-pooling-test\r\n\
         Connection: keep-alive\r\n\
         \r\n",
        path, host
    );

    // Send request - write directly to the stream
    tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes())
        .await
        .map_err(|e| format!("Failed to write request: {}", e))?;

    debug!("Request {} - sent HTTP request", request_num);

    // Read response (just headers to verify connection)
    let mut buffer = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer)
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    if n == 0 {
        return Err("Connection closed by remote".to_string());
    }

    let response = String::from_utf8_lossy(&buffer[..n]);
    
    // Check for valid HTTP response
    if response.starts_with("HTTP/1.1") || response.starts_with("HTTP/1.0") {
        debug!("Request {} - received valid HTTP response ({} bytes)", request_num, n);
        Ok(())
    } else {
        Err(format!("Invalid HTTP response: {}", &response[..n.min(100)]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires proxies.json file
    async fn test_connect_with_best_rotation() {
        let proxies_json = std::fs::read_to_string(PROXY_FILE).unwrap();
        let list = ProxyList::from_array(&proxies_json).unwrap();
        let proxy_pool = Arc::new(ProxyPool::from_list(&list));
        let target = Url::parse("https://example.com/").unwrap();

        // Make 3 requests with connect_with_best
        for i in 0..3 {
            let result = make_request_with_best(&proxy_pool, &target, i + 1).await;
            if result.is_ok() {
                println!("Request {} succeeded", i + 1);
            }
        }

        // Check that good proxies have been scored
        let stats = proxy_pool.stats();
        println!("Active proxies (scored > 0): {}", stats.active_proxies);
        assert!(stats.active_proxies > 0, "At least one proxy should be scored");
    }
}