//! Extensions for [`ProxyList`].
//!
//! Provides opt-in helper methods for different proxy connection strategies:
//! - Random selection with single attempt
//! - Sequential iteration until success
//! - Concurrent attempts with semaphore-limited parallelism

use std::sync::Arc;
use std::time::Instant;

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Semaphore;
use tracing::{debug, trace};
use url::Url;

use crate::errors::ProxyError;
use crate::transport::{ProxyList, ProxyStream};

/* Types */

/// Extension helpers for [`ProxyList`].
///
/// Provides three connection strategies with semaphore-based rate limiting:
/// - [`ProxyListExt::connect_random`]: Single random proxy attempt
/// - [`ProxyListExt::connect_with_iteration`]: Sequential attempts until success
/// - [`ProxyListExt::connect_with_semaphore`]: Concurrent attempts, first success wins
#[allow(async_fn_in_trait)]
pub trait ProxyListExt {
    /// Returns a new list with all proxies of `protocol` removed.
    ///
    /// Protocol matching is ASCII case-insensitive.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use roxie::extensions::ProxyListExt;
    /// use roxie::transport::ProxyList;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let list = ProxyList::from_lines(
    ///     "http://proxy1.com:8080\nsocks5://proxy2.com:1080"
    /// )?;
    ///
    /// let pruned = list.purge("http");
    /// assert_eq!(pruned.len(), 1);
    /// # Ok(())
    /// # }
    /// ```
    fn purge(&self, protocol: &str) -> ProxyList;

    /// Attempts connection through a single random proxy.
    ///
    /// Acquires a semaphore permit, selects a random proxy, and attempts
    /// a single connection. Returns `Ok(None)` when the list is empty.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use roxie::transport::ProxyList;
    /// use roxie::extensions::ProxyListExt;
    /// use tokio::sync::Semaphore;
    /// use url::Url;
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let list = ProxyList::from_lines("http://proxy.com:8080")?;
    /// let semaphore = Arc::new(Semaphore::new(10));
    /// let target = Url::parse("https://example.com")?;
    ///
    /// match list.connect_random(&target, &semaphore).await? {
    ///     Some(stream) => println!("Connected!"),
    ///     None => println!("List was empty"),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    async fn connect_random(
        &self,
        target: &Url,
        semaphore: &Arc<Semaphore>,
    ) -> Result<Option<ProxyStream>, ProxyError>;

    /// Iterates through proxies sequentially until one succeeds.
    ///
    /// Tries each proxy in order, returning the first successful connection.
    /// Each attempt acquires a semaphore permit before connecting.
    /// Returns `Ok(None)` when the list is empty.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use roxie::transport::ProxyList;
    /// use roxie::extensions::ProxyListExt;
    /// use tokio::sync::Semaphore;
    /// use url::Url;
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let list = ProxyList::from_lines(
    ///     "http://proxy1.com:8080\nhttp://proxy2.com:8080"
    /// )?;
    /// let semaphore = Arc::new(Semaphore::new(1));
    /// let target = Url::parse("https://example.com")?;
    ///
    /// // Try proxies one by one until success
    /// match list.connect_with_iteration(&target, &semaphore).await? {
    ///     Some(stream) => println!("Connected via first working proxy"),
    ///     None => println!("All proxies failed or list was empty"),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    async fn connect_with_iteration(
        &self,
        target: &Url,
        semaphore: &Arc<Semaphore>,
    ) -> Result<Option<ProxyStream>, ProxyError>;

    /// Attempts connection through all proxies concurrently, returning first success.
    ///
    /// Uses `FuturesUnordered` for efficient concurrent racing with minimal overhead.
    /// Each future acquires a semaphore permit before connecting, naturally limiting
    /// parallelism to the semaphore's permit count. Returns the first successful
    /// connection and cancels remaining attempts.
    ///
    /// Returns `Ok(None)` when the list is empty. If all proxies fail, returns
    /// the last error observed.
    ///
    /// # Performance Characteristics
    ///
    /// - Memory: O(active futures) instead of O(total proxies)
    /// - No task spawning overhead - uses lazy futures
    /// - Natural backpressure from semaphore
    /// - Optimal for large proxy lists (1000+)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use roxie::transport::ProxyList;
    /// use roxie::extensions::ProxyListExt;
    /// use tokio::sync::Semaphore;
    /// use url::Url;
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let list = ProxyList::from_lines(
    ///     "http://proxy1.com:8080\nhttp://proxy2.com:8080\nhttp://proxy3.com:8080"
    /// )?;
    /// let semaphore = Arc::new(Semaphore::new(5)); // Max 5 concurrent attempts
    /// let target = Url::parse("https://example.com")?;
    ///
    /// // Race all proxies, return first success
    /// match list.connect_with_semaphore(&target, &semaphore).await? {
    ///     Some(stream) => println!("Connected via fastest proxy"),
    ///     None => println!("All proxies failed or list was empty"),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    async fn connect_with_semaphore(
        &self,
        target: &Url,
        semaphore: &Arc<Semaphore>,
    ) -> Result<Option<ProxyStream>, ProxyError>;
}

/* Implementations */

impl ProxyListExt for ProxyList {
    fn purge(&self, protocol: &str) -> ProxyList {
        let start = Instant::now();

        let filtered = self
            .iter()
            .filter(|proxy| !proxy.get_scheme().eq_ignore_ascii_case(protocol))
            .cloned()
            .collect::<Vec<_>>();

        trace!(
            protocol = protocol,
            before = self.len(),
            after = filtered.len(),
            removed = self.len().saturating_sub(filtered.len()),
            elapsed_ms = start.elapsed().as_millis(),
            "purged proxies by protocol"
        );

        ProxyList::from_proxies(filtered)
    }

    async fn connect_random(
        &self,
        target: &Url,
        semaphore: &Arc<Semaphore>,
    ) -> Result<Option<ProxyStream>, ProxyError> {
        let start = Instant::now();

        trace!(
            target_url = %target,
            proxy_count = self.len(),
            "attempting connection through random proxy"
        );

        if self.is_empty() {
            trace!(
                elapsed_ms = start.elapsed().as_millis(),
                "proxy list is empty"
            );
            return Ok(None);
        }

        trace!("acquiring semaphore permit");
        let _permit = semaphore
            .acquire()
            .await
            .map_err(|_| ProxyError::InvalidConfiguration {
                reason: "semaphore closed (connection pool shutdown)".to_string(),
            })?;

        trace!(
            elapsed_ms = start.elapsed().as_millis(),
            "semaphore permit acquired"
        );

        let proxy = self.random().expect("list not empty (checked above)");

        debug!(
            proxy_scheme = %proxy.get_scheme(),
            proxy_host = %proxy.get_host(),
            proxy_port = proxy.get_port(),
            target_url = %target,
            "connecting via random proxy"
        );

        let result = proxy.connect(target).await;

        match &result {
            Ok(_) => {
                trace!(
                    proxy_host = %proxy.get_host(),
                    proxy_port = proxy.get_port(),
                    elapsed_ms = start.elapsed().as_millis(),
                    "connection successful"
                );
            }
            Err(e) => {
                trace!(
                    proxy_host = %proxy.get_host(),
                    proxy_port = proxy.get_port(),
                    error = %e,
                    elapsed_ms = start.elapsed().as_millis(),
                    "connection failed"
                );
            }
        }

        result.map(Some)
    }

    async fn connect_with_iteration(
        &self,
        target: &Url,
        semaphore: &Arc<Semaphore>,
    ) -> Result<Option<ProxyStream>, ProxyError> {
        let start = Instant::now();

        trace!(
            target_url = %target,
            proxy_count = self.len(),
            "attempting sequential connection through proxy list"
        );

        if self.is_empty() {
            trace!(
                elapsed_ms = start.elapsed().as_millis(),
                "proxy list is empty"
            );
            return Ok(None);
        }

        let mut last_error: Option<ProxyError> = None;

        for (index, proxy) in self.iter().enumerate() {
            trace!(
                proxy_index = index,
                proxy_host = %proxy.get_host(),
                proxy_port = proxy.get_port(),
                "acquiring semaphore permit for proxy"
            );

            let _permit =
                semaphore
                    .acquire()
                    .await
                    .map_err(|_| ProxyError::InvalidConfiguration {
                        reason: "semaphore closed (connection pool shutdown)".to_string(),
                    })?;

            trace!(
                proxy_index = index,
                "semaphore permit acquired, attempting connection"
            );

            debug!(
                proxy_index = index,
                proxy_scheme = %proxy.get_scheme(),
                proxy_host = %proxy.get_host(),
                proxy_port = proxy.get_port(),
                target_url = %target,
                "attempting connection via proxy"
            );

            match proxy.connect(target).await {
                Ok(stream) => {
                    debug!(
                        proxy_index = index,
                        proxy_host = %proxy.get_host(),
                        proxy_port = proxy.get_port(),
                        elapsed_ms = start.elapsed().as_millis(),
                        "connection successful"
                    );
                    return Ok(Some(stream));
                }
                Err(e) => {
                    trace!(
                        proxy_index = index,
                        proxy_host = %proxy.get_host(),
                        proxy_port = proxy.get_port(),
                        error = %e,
                        "connection failed, trying next proxy"
                    );
                    last_error = Some(e);
                }
            }
        }

        trace!(
            proxies_tried = self.len(),
            elapsed_ms = start.elapsed().as_millis(),
            "all proxies failed"
        );

        match last_error {
            Some(err) => Err(err),
            None => Ok(None),
        }
    }

    async fn connect_with_semaphore(
        &self,
        target: &Url,
        semaphore: &Arc<Semaphore>,
    ) -> Result<Option<ProxyStream>, ProxyError> {
        let start = Instant::now();

        trace!(
            target_url = %target,
            proxy_count = self.len(),
            max_concurrent = semaphore.available_permits(),
            "attempting concurrent connections (FuturesUnordered)"
        );

        if self.is_empty() {
            trace!(
                elapsed_ms = start.elapsed().as_millis(),
                "proxy list is empty"
            );
            return Ok(None);
        }

        // Use Arc to avoid cloning the URL for every future
        let target = Arc::new(target.clone());

        // Create lazy futures for each proxy (no task spawning overhead)
        let mut futures = self
            .iter()
            .cloned()
            .map(|proxy| {
                let target = Arc::clone(&target);
                let sem = Arc::clone(semaphore);

                // Lazy future - doesn't run until polled by FuturesUnordered
                async move {
                    // Acquire permit (naturally limits concurrency)
                    let _permit = match sem.acquire().await {
                        Ok(p) => p,
                        Err(_) => {
                            trace!(
                                proxy_host = %proxy.get_host(),
                                "semaphore closed, aborting"
                            );
                            return Err(ProxyError::InvalidConfiguration {
                                reason: "semaphore closed (pool shutdown)".to_string(),
                            });
                        }
                    };

                    trace!(
                        proxy_host = %proxy.get_host(),
                        proxy_port = proxy.get_port(),
                        "permit acquired, connecting"
                    );

                    // Attempt connection
                    let result = proxy.connect(&target).await;

                    match &result {
                        Ok(_) => {
                            trace!(
                                proxy_host = %proxy.get_host(),
                                proxy_port = proxy.get_port(),
                                "connection succeeded"
                            );
                        }
                        Err(e) => {
                            trace!(
                                proxy_host = %proxy.get_host(),
                                proxy_port = proxy.get_port(),
                                error = %e,
                                "connection failed"
                            );
                        }
                    }

                    result
                }
            })
            .collect::<FuturesUnordered<_>>();

        trace!(
            futures_count = self.len(),
            "futures created (lazy, not spawned)"
        );

        let mut last_error: Option<ProxyError> = None;
        let mut completed = 0;

        // Poll futures as they become ready - first success wins
        while let Some(result) = futures.next().await {
            completed += 1;

            match result {
                Ok(stream) => {
                    debug!(
                        completed = completed,
                        total = self.len(),
                        elapsed_ms = start.elapsed().as_millis(),
                        "first success - returning stream"
                    );

                    // Drop FuturesUnordered = automatic cancellation of remaining
                    return Ok(Some(stream));
                }
                Err(err) => {
                    trace!(
                        error = %err,
                        completed = completed,
                        "attempt failed"
                    );
                    last_error = Some(err);
                }
            }
        }

        trace!(
            completed = completed,
            elapsed_ms = start.elapsed().as_millis(),
            "all attempts completed without success"
        );

        match last_error {
            Some(err) => Err(err),
            None => Ok(None),
        }
    }
}

/* Tests */

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::Semaphore;
    use url::Url;

    use super::ProxyListExt;
    use crate::transport::ProxyList;

    #[tokio::test]
    async fn empty_list_connect_random_returns_none() {
        let list = ProxyList::from_lines("").unwrap();
        let sem = Arc::new(Semaphore::new(10));
        let target = Url::parse("https://example.com").unwrap();
        let result = list.connect_random(&target, &sem).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn empty_list_connect_with_iteration_returns_none() {
        let list = ProxyList::from_lines("").unwrap();
        let sem = Arc::new(Semaphore::new(10));
        let target = Url::parse("https://example.com").unwrap();
        let result = list.connect_with_iteration(&target, &sem).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn empty_list_connect_with_semaphore_returns_none() {
        let list = ProxyList::from_lines("").unwrap();
        let sem = Arc::new(Semaphore::new(10));
        let target = Url::parse("https://example.com").unwrap();
        let result = list.connect_with_semaphore(&target, &sem).await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    #[cfg(all(feature = "http", feature = "socks5"))]
    fn purge_removes_matching_protocol() {
        let list = ProxyList::from_lines(
            "http://proxy1.example.com:8080\nsocks5://proxy2.example.com:1080",
        )
        .expect("failed to parse test proxy list");

        let purged = list.purge("http");
        assert_eq!(purged.len(), 1);
        assert_eq!(purged.get(0).expect("missing proxy").get_scheme(), "socks5");
    }

    #[test]
    #[cfg(feature = "http")]
    fn purge_case_insensitive() {
        let list = ProxyList::from_lines("http://proxy1.example.com:8080").unwrap();
        let purged = list.purge("HTTP");
        assert_eq!(purged.len(), 0);
    }

    #[test]
    #[cfg(feature = "http")]
    fn purge_no_match_leaves_list_intact() {
        let list = ProxyList::from_lines("http://proxy1.example.com:8080").unwrap();
        let purged = list.purge("socks5");
        assert_eq!(purged.len(), 1);
    }

    #[test]
    #[cfg(all(feature = "http", feature = "socks4", feature = "socks5"))]
    fn purge_removes_only_matching_protocol_from_mixed_list() {
        let list = ProxyList::from_lines(
            "http://proxy1.com:8080\nsocks4://proxy2.com:1080\nsocks5://proxy3.com:1080\nhttp://proxy4.com:8080",
        )
        .unwrap();
        assert_eq!(list.len(), 4);

        let purged = list.purge("http");
        assert_eq!(purged.len(), 2);
        for proxy in purged.iter() {
            assert_ne!(proxy.get_scheme(), "http");
        }
    }

    #[test]
    #[cfg(all(feature = "http", feature = "socks5"))]
    fn purge_all_of_one_protocol_leaves_others() {
        let list = ProxyList::from_lines(
            "http://proxy1.com:8080\nhttp://proxy2.com:8080\nsocks5://proxy3.com:1080",
        )
        .unwrap();

        let purged = list.purge("http");
        assert_eq!(purged.len(), 1);
        assert_eq!(purged.get(0).unwrap().get_scheme(), "socks5");
    }

    #[test]
    #[cfg(feature = "http")]
    fn purge_all_proxies_of_only_protocol_gives_empty_list() {
        let list = ProxyList::from_lines("http://proxy1.com:8080\nhttp://proxy2.com:8080").unwrap();
        let purged = list.purge("http");
        assert!(purged.is_empty());
    }

    #[test]
    fn purge_from_empty_list_stays_empty() {
        let list = ProxyList::from_lines("").unwrap();
        let purged = list.purge("http");
        assert!(purged.is_empty());
    }

    #[test]
    #[cfg(feature = "http")]
    fn purge_is_idempotent() {
        let list =
            ProxyList::from_lines("http://proxy1.com:8080\nhttp://proxy2.com:8080").unwrap();
        let purged_once = list.purge("socks5");
        let purged_twice = purged_once.purge("socks5");
        assert_eq!(purged_twice.len(), 2);
    }

    #[test]
    #[cfg(feature = "socks4")]
    fn purge_socks4a_does_not_remove_socks4() {
        let list = ProxyList::from_lines(
            "socks4://proxy1.com:1080\nsocks4a://proxy2.com:1080",
        )
        .unwrap();
        let purged = list.purge("socks4a");
        assert_eq!(purged.len(), 1);
        assert_eq!(purged.get(0).unwrap().get_scheme(), "socks4");
    }

    #[test]
    #[cfg(feature = "socks5")]
    fn purge_socks5h_does_not_remove_socks5() {
        let list = ProxyList::from_lines(
            "socks5://proxy1.com:1080\nsocks5h://proxy2.com:1080",
        )
        .unwrap();
        let purged = list.purge("socks5h");
        assert_eq!(purged.len(), 1);
        assert_eq!(purged.get(0).unwrap().get_scheme(), "socks5");
    }
}
