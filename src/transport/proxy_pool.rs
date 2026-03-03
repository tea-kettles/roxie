//! Smart proxy pool with performance tracking.
//!
//! Provides intelligent proxy selection based on historical performance
//! with exponential decay scoring and locking mechanisms.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use rand::{seq::index::sample, thread_rng};
use tracing::{debug, trace};

use crate::transport::{Proxy, ProxyList};

/* Constants */

const SCORE_TIME_PENALTY_FACTOR: f64 = 0.2;
const MIN_SCORE_GAIN: f64 = 0.2;
const SCORE_DECAY_LAMBDA: f64 = 0.1;
const SECONDS_PER_HOUR: f64 = 3600.0;
const DEFAULT_SELECTION_SIZE: usize = 5;

/* Types */

/// Smart proxy pool with performance scoring and selection algorithms.
///
/// # Examples
///
/// ```
/// use roxie::transport::{ProxyList, ProxyPool};
/// use std::time::Duration;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let lines = "http://proxy1.com:8080\nhttp://proxy2.com:8080";
/// let list = ProxyList::from_lines(lines)?;
/// let pool = ProxyPool::from_list(&list);
///
/// // Select best proxy from sample
/// if let Some(proxy) = pool.quick() {
///     // Use proxy...
///     pool.record_success(proxy, Duration::from_millis(150));
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ProxyPool {
    proxies: Arc<Vec<Proxy>>,
    scores: Arc<Vec<RwLock<ProxyScore>>>,
    proxy_index_map: Arc<HashMap<Proxy, usize>>,
}

/// Statistics for the proxy pool.
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_proxies: usize,
    pub scored_proxies: usize,
    pub active_proxies: usize,
    pub locked_proxies: usize,
    pub average_score: f64,
}

#[derive(Debug, Clone, Copy)]
struct ProxyScore {
    score: f64,
    last_used: Option<Instant>,
    locked: bool,
}

/* Implementations */

impl ProxyScore {
    fn new() -> Self {
        Self {
            score: 0.0,
            last_used: None,
            locked: false,
        }
    }

    fn record_success(&mut self, response_time: Duration) {
        let time_penalty = response_time.as_secs_f64() * SCORE_TIME_PENALTY_FACTOR;
        let score_gain = (1.0 - time_penalty).max(MIN_SCORE_GAIN);

        self.score += score_gain;
        self.last_used = Some(Instant::now());
        self.locked = false;
    }

    fn record_failure(&mut self) {
        self.score = 0.0;
        self.last_used = Some(Instant::now());
        self.locked = false;
    }

    fn get_decayed_score(&self) -> f64 {
        if self.locked {
            return f64::NEG_INFINITY;
        }

        match self.last_used {
            Some(last_used) => {
                let elapsed = last_used.elapsed().as_secs_f64() / SECONDS_PER_HOUR;
                let decay_factor = (-SCORE_DECAY_LAMBDA * elapsed).exp();
                self.score * decay_factor
            }
            None => self.score,
        }
    }

    fn lock(&mut self) {
        self.locked = true;
    }

    fn unlock(&mut self) {
        self.locked = false;
    }
}

impl ProxyPool {
    /// Creates a ProxyPool from a ProxyList.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::{ProxyList, ProxyPool};
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let lines = "http://proxy1.com:8080\nhttp://proxy2.com:8080";
    /// let list = ProxyList::from_lines(lines)?;
    /// let pool = ProxyPool::from_list(&list);
    /// assert_eq!(pool.len(), 2);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_list(proxy_list: &ProxyList) -> Self {
        trace!(proxy_count = proxy_list.len(), "creating pool");

        let proxies: Vec<Proxy> = proxy_list.iter().cloned().collect();
        let proxies = Arc::new(proxies);

        let scores = Arc::new(
            (0..proxies.len())
                .map(|_| RwLock::new(ProxyScore::new()))
                .collect(),
        );

        let proxy_index_map = Arc::new(
            proxies
                .iter()
                .enumerate()
                .map(|(i, proxy)| (proxy.clone(), i))
                .collect(),
        );

        trace!(proxy_count = proxies.len(), "pool created");

        ProxyPool {
            proxies,
            scores,
            proxy_index_map,
        }
    }

    /// Creates a ProxyPool from newline-separated proxy URLs.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyPool;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let lines = "http://proxy1.com:8080\nhttp://proxy2.com:8080";
    /// let pool = ProxyPool::from_lines(lines)?;
    /// assert_eq!(pool.len(), 2);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_lines(lines_str: &str) -> Result<Self, crate::errors::ParseError> {
        let proxy_list = ProxyList::from_lines(lines_str)?;
        Ok(Self::from_list(&proxy_list))
    }

    /// Creates a ProxyPool from JSON array of proxy URL strings.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyPool;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let array = r#"["http://proxy1.com:8080", "http://proxy2.com:8080"]"#;
    /// let pool = ProxyPool::from_array(array)?;
    /// assert_eq!(pool.len(), 2);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_array(json_str: &str) -> Result<Self, crate::errors::ParseError> {
        let proxy_list = ProxyList::from_array(json_str)?;
        Ok(Self::from_list(&proxy_list))
    }

    /// Creates a ProxyPool from structured JSON format.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyPool;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let json = r#"{
    ///     "proxies": [
    ///         {"protocol": "http", "host": "proxy.com", "port": 8080}
    ///     ]
    /// }"#;
    /// let pool = ProxyPool::from_json(json)?;
    /// assert_eq!(pool.len(), 1);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_json(json_str: &str) -> Result<Self, crate::errors::ParseError> {
        let proxy_list = ProxyList::from_json(json_str)?;
        Ok(Self::from_list(&proxy_list))
    }

    /// Gets the top N proxies by score.
    ///
    /// Returns a vector of tuples containing references to proxies and their
    /// decayed scores, sorted from highest to lowest score.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyPool;
    /// use std::time::Duration;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let lines = "http://proxy1.com:8080\nhttp://proxy2.com:8080\nhttp://proxy3.com:8080";
    /// let pool = ProxyPool::from_lines(lines)?;
    /// 
    /// // Record some successes to generate scores
    /// if let Some(proxy) = pool.quick() {
    ///     pool.unlock(proxy);
    ///     pool.record_success(proxy, Duration::from_millis(100));
    /// }
    ///
    /// // Get top 2 proxies
    /// let top_proxies = pool.top(2);
    /// for (proxy, score) in top_proxies {
    ///     println!("Proxy: {}:{}, Score: {}", 
    ///         proxy.get_host(), proxy.get_port(), score);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn top(&self, n: usize) -> Vec<(&Proxy, f64)> {
        let mut proxy_scores: Vec<(&Proxy, f64)> = self
            .proxies
            .iter()
            .enumerate()
            .map(|(i, proxy)| {
                let score = self.scores[i].read().get_decayed_score();
                (proxy, score)
            })
            .collect();

        // Sort by score in descending order
        proxy_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        proxy_scores.into_iter().take(n).collect()
    }

    /// Gets best proxy by scanning all available proxies.
    ///
    /// This performs an exhaustive search for the highest-scored proxy.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyPool;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let lines = "http://proxy1.com:8080\nhttp://proxy2.com:8080";
    /// let pool = ProxyPool::from_lines(lines)?;
    /// if let Some(proxy) = pool.best() {
    ///     println!("Best proxy: {}:{}", proxy.get_host(), proxy.get_port());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn best(&self) -> Option<&Proxy> {
        self.sample(self.proxies.len())
    }

    /// Gets best proxy from 5 random candidates (fast selection).
    ///
    /// This is faster than `best()` for large pools while still providing
    /// good selection quality.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyPool;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let lines = "http://proxy1.com:8080\nhttp://proxy2.com:8080";
    /// let pool = ProxyPool::from_lines(lines)?;
    /// if let Some(proxy) = pool.quick() {
    ///     println!("Quick proxy: {}:{}", proxy.get_host(), proxy.get_port());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn quick(&self) -> Option<&Proxy> {
        self.sample(DEFAULT_SELECTION_SIZE)
    }

    /// Gets best proxy from N random candidates.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyPool;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let lines = "http://proxy1.com:8080\nhttp://proxy2.com:8080\nhttp://proxy3.com:8080";
    /// let pool = ProxyPool::from_lines(lines)?;
    /// // Sample 2 proxies and pick the best
    /// if let Some(proxy) = pool.sample(2) {
    ///     println!("Sampled proxy: {}:{}", proxy.get_host(), proxy.get_port());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn sample(&self, selection_size: usize) -> Option<&Proxy> {
        if self.proxies.is_empty() {
            return None;
        }

        let mut rng = thread_rng();
        let n = self.proxies.len();
        let count = selection_size.min(n);

        let mut best_idx = None;
        let mut best_score = f64::NEG_INFINITY;

        for i in sample(&mut rng, n, count).into_iter() {
            let score = self.scores[i].read().get_decayed_score();
            if score > best_score {
                best_score = score;
                best_idx = Some(i);
            }
        }

        if let Some(index) = best_idx {
            self.scores[index].write().lock();
            self.proxies.get(index)
        } else {
            None
        }
    }

    /// Returns the total number of proxies in the pool.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyPool;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let lines = "http://proxy1.com:8080\nhttp://proxy2.com:8080";
    /// let pool = ProxyPool::from_lines(lines)?;
    /// assert_eq!(pool.len(), 2);
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn len(&self) -> usize {
        self.proxies.len()
    }

    /// Returns true if the pool contains no proxies.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    /// Records successful connection with response time.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyPool;
    /// use std::time::Duration;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let lines = "http://proxy.com:8080";
    /// let pool = ProxyPool::from_lines(lines)?;
    /// let proxy = pool.quick().unwrap();
    ///
    /// // After successful use
    /// pool.record_success(proxy, Duration::from_millis(150));
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn record_success(&self, proxy: &Proxy, response_time: Duration) {
        if let Some(&index) = self.proxy_index_map.get(proxy) {
            self.scores[index].write().record_success(response_time);
            debug!(
                proxy_host = proxy.get_host(),
                proxy_port = proxy.get_port(),
                response_time_ms = response_time.as_millis() as u64,
                "recorded successful connection"
            );
        }
    }

    /// Records failed connection.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyPool;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let lines = "http://proxy.com:8080";
    /// let pool = ProxyPool::from_lines(lines)?;
    /// let proxy = pool.quick().unwrap();
    ///
    /// // After failed connection
    /// pool.record_failure(proxy);
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn record_failure(&self, proxy: &Proxy) {
        if let Some(&index) = self.proxy_index_map.get(proxy) {
            self.scores[index].write().record_failure();
            trace!(
                proxy_host = proxy.get_host(),
                proxy_port = proxy.get_port(),
                "recorded failed connection"
            );
        }
    }

    /// Gets current score for a proxy.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyPool;
    /// use std::time::Duration;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let lines = "http://proxy.com:8080";
    /// let pool = ProxyPool::from_lines(lines)?;
    /// let proxy = pool.quick().unwrap();
    ///
    /// pool.record_success(proxy, Duration::from_millis(100));
    /// let score = pool.get_score(proxy);
    /// assert!(score > 0.0);
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn get_score(&self, proxy: &Proxy) -> f64 {
        self.proxy_index_map
            .get(proxy)
            .map(|&index| self.scores[index].read().get_decayed_score())
            .unwrap_or(0.0)
    }

    /// Gets all proxy scores as a map.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyPool;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let lines = "http://proxy1.com:8080\nhttp://proxy2.com:8080";
    /// let pool = ProxyPool::from_lines(lines)?;
    /// let scores = pool.get_all_scores();
    /// assert_eq!(scores.len(), 2);
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_all_scores(&self) -> HashMap<String, f64> {
        self.proxies
            .iter()
            .enumerate()
            .map(|(i, proxy)| {
                let key = format!(
                    "{}://{}:{}",
                    proxy.get_scheme(),
                    proxy.get_host(),
                    proxy.get_port()
                );
                let score = self.scores[i].read().get_decayed_score();
                (key, score)
            })
            .collect()
    }

    /// Resets all scores to 0 and unlocks all proxies.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyPool;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let lines = "http://proxy.com:8080";
    /// let pool = ProxyPool::from_lines(lines)?;
    /// pool.reset_scores();
    /// # Ok(())
    /// # }
    /// ```
    pub fn reset_scores(&self) {
        for score_lock in self.scores.iter() {
            *score_lock.write() = ProxyScore::new();
        }
        trace!("all scores reset");
    }

    /// Gets pool statistics.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyPool;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let lines = "http://proxy.com:8080";
    /// let pool = ProxyPool::from_lines(lines)?;
    /// let stats = pool.stats();
    /// assert_eq!(stats.total_proxies, 1);
    /// # Ok(())
    /// # }
    /// ```
    pub fn stats(&self) -> PoolStats {
        let mut total_score = 0.0;
        let mut active_count = 0;
        let mut locked_count = 0;

        for score_lock in self.scores.iter() {
            let score = score_lock.read();
            let decayed = score.get_decayed_score();
            total_score += decayed;
            if decayed > 0.0 {
                active_count += 1;
            }
            if score.locked {
                locked_count += 1;
            }
        }

        let scored_proxies = self.proxies.len();

        PoolStats {
            total_proxies: self.proxies.len(),
            scored_proxies,
            active_proxies: active_count,
            locked_proxies: locked_count,
            average_score: if scored_proxies > 0 {
                total_score / scored_proxies as f64
            } else {
                0.0
            },
        }
    }

    /// Locks a proxy manually.
    ///
    /// Locked proxies will not be selected until unlocked.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyPool;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let lines = "http://proxy.com:8080";
    /// let pool = ProxyPool::from_lines(lines)?;
    /// let proxy = pool.quick().unwrap();
    /// pool.lock(proxy);
    /// # Ok(())
    /// # }
    /// ```
    pub fn lock(&self, proxy: &Proxy) {
        if let Some(&index) = self.proxy_index_map.get(proxy) {
            self.scores[index].write().lock();
            trace!(
                proxy_host = proxy.get_host(),
                proxy_port = proxy.get_port(),
                "proxy locked"
            );
        }
    }

    /// Unlocks a proxy manually.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyPool;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let lines = "http://proxy.com:8080";
    /// let pool = ProxyPool::from_lines(lines)?;
    /// let proxy = pool.quick().unwrap();
    /// pool.lock(proxy);
    /// pool.unlock(proxy);
    /// # Ok(())
    /// # }
    /// ```
    pub fn unlock(&self, proxy: &Proxy) {
        if let Some(&index) = self.proxy_index_map.get(proxy) {
            self.scores[index].write().unlock();
            trace!(
                proxy_host = proxy.get_host(),
                proxy_port = proxy.get_port(),
                "proxy unlocked"
            );
        }
    }
}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "http")]
    fn from_list_creates_pool() {
        let lines = "http://proxy1.com:8080\nhttp://proxy2.com:8080";
        let list = ProxyList::from_lines(lines).unwrap();
        let pool = ProxyPool::from_list(&list);
        assert_eq!(pool.len(), 2);
    }

    #[test]
    #[cfg(feature = "http")]
    fn from_lines_creates_pool() {
        let lines = "http://proxy1.com:8080\nhttp://proxy2.com:8080";
        let pool = ProxyPool::from_lines(lines).unwrap();
        assert_eq!(pool.len(), 2);
    }

    #[test]
    #[cfg(feature = "http")]
    fn quick_returns_proxy() {
        let lines = "http://proxy.com:8080";
        let pool = ProxyPool::from_lines(lines).unwrap();
        assert!(pool.quick().is_some());
    }

    #[test]
    #[cfg(feature = "http")]
    fn best_returns_proxy() {
        let lines = "http://proxy.com:8080";
        let pool = ProxyPool::from_lines(lines).unwrap();
        assert!(pool.best().is_some());
    }

    #[test]
    #[cfg(feature = "http")]
    fn record_success_updates_score() {
        let lines = "http://proxy.com:8080";
        let pool = ProxyPool::from_lines(lines).unwrap();
        let proxy = pool.quick().unwrap();

        pool.unlock(proxy); // Unlock after selection
        let score_before = pool.get_score(proxy);

        pool.record_success(proxy, Duration::from_millis(100));
        let score_after = pool.get_score(proxy);

        assert!(score_after > score_before);
    }

    #[test]
    #[cfg(feature = "http")]
    fn record_failure_resets_score() {
        let lines = "http://proxy.com:8080";
        let pool = ProxyPool::from_lines(lines).unwrap();
        let proxy = pool.quick().unwrap();

        pool.unlock(proxy);
        pool.record_success(proxy, Duration::from_millis(100));
        pool.record_failure(proxy);

        let score = pool.get_score(proxy);
        assert_eq!(score, 0.0);
    }

    #[test]
    #[cfg(feature = "http")]
    fn stats_returns_correct_info() {
        let lines = "http://proxy.com:8080";
        let pool = ProxyPool::from_lines(lines).unwrap();
        let stats = pool.stats();
        assert_eq!(stats.total_proxies, 1);
    }

    #[test]
    #[cfg(feature = "http")]
    fn lock_prevents_selection() {
        let lines = "http://proxy.com:8080";
        let pool = ProxyPool::from_lines(lines).unwrap();
        let proxy = pool.quick().unwrap();

        pool.lock(proxy);
        let score = pool.get_score(proxy);
        assert_eq!(score, f64::NEG_INFINITY);
    }

    #[test]
    #[cfg(feature = "http")]
    fn unlock_allows_selection() {
        let lines = "http://proxy.com:8080";
        let pool = ProxyPool::from_lines(lines).unwrap();
        let proxy = pool.quick().unwrap();

        pool.lock(proxy);
        pool.unlock(proxy);
        let score = pool.get_score(proxy);
        assert_ne!(score, f64::NEG_INFINITY);
    }

    #[test]
    #[cfg(feature = "http")]
    fn reset_scores_clears_all() {
        let lines = "http://proxy.com:8080";
        let pool = ProxyPool::from_lines(lines).unwrap();
        let proxy = pool.quick().unwrap();

        pool.unlock(proxy);
        pool.record_success(proxy, Duration::from_millis(100));
        pool.reset_scores();

        let score = pool.get_score(proxy);
        assert_eq!(score, 0.0);
    }
}
