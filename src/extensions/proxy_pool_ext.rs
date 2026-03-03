//! Extensions for [`ProxyPool`].
//!
//! Provides intelligence-driven connection strategies that leverage
//! historical performance data to minimize latency.

use std::sync::Arc;
use std::time::Instant;

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Semaphore;
use tracing::{debug, trace, warn};
use url::Url;

use crate::errors::ProxyError;
use crate::transport::{ProxyPool, ProxyStream};

/* Types */

/// Result of testing a single proxy.
#[derive(Debug, Clone)]
pub struct ProxyTestResult {
    pub proxy_key: String,
    pub success: bool,
    pub response_time_ms: u64,
    pub error: Option<String>,
}

/// Results from testing all proxies in a pool.
#[derive(Debug, Clone)]
pub struct ProxyTestResults {
    pub total_tested: usize,
    pub working_count: usize,
    pub failed_count: usize,
    pub avg_response_time_ms: u64,
    pub fastest_ms: u64,
    pub slowest_ms: u64,
    pub results: Vec<ProxyTestResult>,
}

/* Trait Definition */

#[allow(async_fn_in_trait)]
pub trait ProxyPoolExt {
    /// Connects using a scored race of the top X proxies.
    ///
    /// This method fetches the highest-ranked proxies from the pool and attempts
    /// to connect through them concurrently up to the semaphore limit.
    /// If the top-tier proxies fail, it continues down the ranked list.
    async fn connect_with_semaphore(
        self: &Arc<Self>,
        target: &Url,
        semaphore_permits: usize,
    ) -> Result<ProxyStream, ProxyError>;

    /// Tests all proxies concurrently to establish baseline scores for the pool.
    async fn initialize_pool(
        self: &Arc<Self>,
        max_concurrent: usize,
        test_url: Option<&str>,
    ) -> ProxyTestResults;
}

/* Implementations */

impl ProxyPoolExt for ProxyPool {
    async fn connect_with_semaphore(
        self: &Arc<Self>,
        target: &Url,
        semaphore_permits: usize,
    ) -> Result<ProxyStream, ProxyError> {
        let start = Instant::now();
        
        // Create a semaphore with the given limit
        let semaphore = Arc::new(Semaphore::new(semaphore_permits));

        // 1. Get ALL proxies sorted by score (Best to Worst)
        // We assume the pool has been initialized or has internal scoring.
        let mut candidates = self.top(self.len());
        
        if candidates.is_empty() {
            return Err(ProxyError::InvalidConfiguration { 
                reason: "Proxy pool is empty".to_string() 
            });
        }

        let mut race = FuturesUnordered::new();
        let mut last_error = None;
        let total_candidates = candidates.len();

        trace!(
            target_url = %target, 
            pool_size = total_candidates, 
            "starting scored race connection"
        );

        // 2. The Logic: Maintain a "moving window" of concurrent attempts based on ranking
        loop {
            // Fill the race buffer up to the semaphore's available permits
            while race.len() < semaphore.available_permits() && !candidates.is_empty() {
                let (proxy, _) = candidates.remove(0); // Take the best available
                let target_clone = target.clone();
                let sem_clone = Arc::clone(&semaphore);
                let pool_ref = Arc::clone(self);

                race.push(async move {
                    let _permit = sem_clone.acquire().await.ok()?;
                    let attempt_start = Instant::now();
                    
                    let res = proxy.connect(&target_clone).await;
                    
                    // Update the pool based on real-time race results
                    match &res {
                        Ok(_) => pool_ref.record_success(proxy, attempt_start.elapsed()),
                        Err(_) => pool_ref.record_failure(proxy),
                    }
                    
                    Some((proxy, res))
                });
            }

            // 3. Wait for the first success among the current racy batch
            if race.is_empty() {
                break;
            }

            if let Some(Some((proxy, result))) = race.next().await {
                match result {
                    Ok(stream) => {
                        debug!(
                            proxy = %proxy.get_host(),
                            elapsed_ms = start.elapsed().as_millis(),
                            "race winner found among top-ranked proxies"
                        );
                        return Ok(stream);
                    }
                    Err(e) => {
                        last_error = Some(e);
                        // Continue loop to push more candidates into the race
                    }
                }
            }
        }

        Err(ProxyError::InvalidConfiguration {
            reason: format!(
                "All {} ranked proxies failed. Last error: {:?}", 
                total_candidates, 
                last_error
            ),
        })
    }

    async fn initialize_pool(
        self: &Arc<Self>,
        max_concurrent: usize,
        test_url: Option<&str>,
    ) -> ProxyTestResults {
        let target_url = test_url.unwrap_or("https://www.google.com");
        
        let target = match Url::parse(target_url) {
            Ok(url) => url,
            Err(e) => {
                warn!("Invalid test URL '{}': {}", target_url, e);
                return ProxyTestResults {
                    total_tested: 0,
                    working_count: 0,
                    failed_count: 0,
                    avg_response_time_ms: 0,
                    fastest_ms: 0,
                    slowest_ms: 0,
                    results: vec![],
                };
            }
        };

        debug!(target_url = %target, total_proxies = self.len(), max_concurrent, "starting pool initialization");

        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        
        // Collect all proxies from the pool to test them
        let mut proxies = Vec::new();
        for _ in 0..self.len() {
            if let Some(proxy) = self.sample(self.len()) {
                self.unlock(proxy);
                proxies.push(proxy);
                if proxies.len() >= self.len() {
                    break;
                }
            }
        }

        let mut futures = proxies
            .into_iter()
            .map(|proxy| {
                let sem = Arc::clone(&semaphore);
                let target = target.clone();
                let pool = Arc::clone(self);
                let proxy_key = format!(
                    "{}://{}:{}",
                    proxy.get_scheme(),
                    proxy.get_host(),
                    proxy.get_port()
                );

                async move {
                    let _permit = sem.acquire().await.ok()?;
                    let test_start = Instant::now();
                    
                    match proxy.connect(&target).await {
                        Ok(_) => {
                            let elapsed = test_start.elapsed();
                            // Record success directly to the pool to establish initial ranking
                            pool.record_success(proxy, elapsed);

                            Some(ProxyTestResult {
                                proxy_key,
                                success: true,
                                response_time_ms: elapsed.as_millis() as u64,
                                error: None,
                            })
                        }
                        Err(e) => {
                            pool.record_failure(proxy);
                            Some(ProxyTestResult {
                                proxy_key,
                                success: false,
                                response_time_ms: 0,
                                error: Some(e.to_string()),
                            })
                        }
                    }
                }
            })
            .collect::<FuturesUnordered<_>>();

        let mut results = Vec::new();
        while let Some(result) = futures.next().await {
            if let Some(r) = result {
                results.push(r);
            }
        }

        // Calculate statistics
        let total_tested = results.len();
        let working_count = results.iter().filter(|r| r.success).count();
        let failed_count = total_tested - working_count;

        let working_times: Vec<u64> = results
            .iter()
            .filter(|r| r.success)
            .map(|r| r.response_time_ms)
            .collect();

        let (avg_response_time_ms, fastest_ms, slowest_ms) = if !working_times.is_empty() {
            let sum: u64 = working_times.iter().sum();
            let avg = sum / working_times.len() as u64;
            let fastest = *working_times.iter().min().unwrap_or(&0);
            let slowest = *working_times.iter().max().unwrap_or(&0);
            (avg, fastest, slowest)
        } else {
            (0, 0, 0)
        };

        debug!(total_tested, working_count, "pool initialization complete");

        ProxyTestResults {
            total_tested,
            working_count,
            failed_count,
            avg_response_time_ms,
            fastest_ms,
            slowest_ms,
            results,
        }
    }
}