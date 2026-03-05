//! Connection pool with stream reuse and lifecycle management.
//!
//! Maintains pools of established connections (TCP + TLS) per proxy,
//! enabling connection reuse to avoid repeated handshakes. Integrates
//! with ProxyPool for intelligent proxy selection based on performance.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tracing::{debug, trace, warn};
use url::Url;

use crate::errors::ProxyError;
use crate::transport::{Proxy, ProxyPool, ProxyStream};

/* Constants */

const DEFAULT_MAX_IDLE_PER_PROXY: usize = 10;
const DEFAULT_MAX_CONNECTIONS_PER_PROXY: usize = 50;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const DEFAULT_CONNECTION_LIFETIME: Duration = Duration::from_secs(300);

/* Types */

/// A pooled connection with metadata for lifecycle management.
struct PooledConnection {
    stream: ProxyStream,
    proxy: Proxy,
    created_at: Instant,
    last_used: Instant,
    use_count: usize,
}

/// Per-proxy connection pool with limits and lifecycle management.
struct ProxyConnections {
    idle: Vec<PooledConnection>,
    active_count: usize,
    max_idle: usize,
    max_connections: usize,
}

/// Connection pool that maintains reusable streams per proxy.
///
/// Integrates with ProxyPool for selection and scoring while handling
/// the actual connection lifecycle, reuse, and cleanup.
///
/// # Examples
///
/// ```no_run
/// use roxie::transport::{ConnectionPool, ProxyPool, ProxyList};
/// use roxie::config::BaseProxyConfig;
/// use std::sync::Arc;
/// use std::time::Duration;
/// use url::Url;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let proxies_json = r#"["http://proxy1.com:8080", "http://proxy2.com:8080"]"#;
/// let list = ProxyList::from_array(proxies_json)?;
/// let proxy_pool = Arc::new(ProxyPool::from_list(&list));
///
/// let conn_pool = ConnectionPool::new(proxy_pool)
///     .with_max_idle_per_proxy(10)
///     .with_max_connections_per_proxy(50)
///     .with_idle_timeout(Duration::from_secs(90));
///
/// let target = Url::parse("https://example.com")?;
/// let mut stream = conn_pool.get(&target).await?;
///
/// // Use stream for HTTP request...
/// // Connection automatically returned to pool on drop
/// # Ok(())
/// # }
/// ```
pub struct ConnectionPool {
    proxy_pool: Arc<ProxyPool>,
    connections: Arc<RwLock<HashMap<ProxyKey, ProxyConnections>>>,
    max_idle_per_proxy: usize,
    max_connections_per_proxy: usize,
    idle_timeout: Duration,
    connection_lifetime: Duration,
}

/// Statistics for the connection pool.
#[derive(Debug, Clone)]
pub struct ConnectionPoolStats {
    pub total_proxies: usize,
    pub total_idle_connections: usize,
    pub total_active_connections: usize,
    pub total_connections: usize,
    pub proxy_stats: Vec<ProxyStats>,
}

/// Per-proxy connection statistics.
#[derive(Debug, Clone)]
pub struct ProxyStats {
    pub proxy_key: String,
    pub idle_count: usize,
    pub active_count: usize,
    pub total_count: usize,
}

/// Typed errors returned by [`ConnectionPool::get`].
#[derive(Debug, thiserror::Error)]
pub enum ConnectionPoolError {
    /// No proxies were available from the backing [`ProxyPool`].
    #[error("no proxies available")]
    NoProxiesAvailable,

    /// Per-proxy connection limit was reached for the computed key.
    #[error("connection limit reached for proxy {proxy_key}")]
    ConnectionLimitReached { proxy_key: String },

    /// Proxy connection attempt failed.
    #[error("failed to connect through proxy {proxy_key}: {source}")]
    ConnectFailed {
        proxy_key: String,
        #[source]
        source: ProxyError,
    },
}

/// Unique identifier for a proxy+target combination.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProxyKey {
    proxy_host: String,
    proxy_port: u16,
    target_host: String,
    target_port: u16,
    use_tls: bool,
}

/// A connection guard that returns the connection to the pool on drop.
pub struct PooledStream {
    stream: Option<ProxyStream>,
    proxy: Proxy,
    key: ProxyKey,
    pool: Arc<RwLock<HashMap<ProxyKey, ProxyConnections>>>,
    proxy_pool: Arc<ProxyPool>,
    start_time: Instant,
}

/* Implementations */

impl ProxyKey {
    fn new(proxy: &Proxy, target: &Url) -> Self {
        let target_host = target.host_str().unwrap_or("").to_string();
        let target_port = target.port_or_known_default().unwrap_or(80);
        let use_tls = target.scheme() == "https";

        Self {
            proxy_host: proxy.get_host().to_string(),
            proxy_port: proxy.get_port(),
            target_host,
            target_port,
            use_tls,
        }
    }

    fn to_string(&self) -> String {
        format!(
            "{}:{} -> {}:{} (tls={})",
            self.proxy_host, self.proxy_port, self.target_host, self.target_port, self.use_tls
        )
    }
}

impl PooledConnection {
    fn new(stream: ProxyStream, proxy: Proxy) -> Self {
        let now = Instant::now();
        Self {
            stream,
            proxy,
            created_at: now,
            last_used: now,
            use_count: 0,
        }
    }

    fn is_expired(&self, idle_timeout: Duration, lifetime: Duration) -> bool {
        let idle_expired = self.last_used.elapsed() > idle_timeout;
        let lifetime_expired = self.created_at.elapsed() > lifetime;
        idle_expired || lifetime_expired
    }

    fn mark_used(&mut self) {
        self.last_used = Instant::now();
        self.use_count += 1;
    }
}

impl ProxyConnections {
    fn new(max_idle: usize, max_connections: usize) -> Self {
        Self {
            idle: Vec::new(),
            active_count: 0,
            max_idle,
            max_connections,
        }
    }

    fn can_create_new(&self) -> bool {
        (self.idle.len() + self.active_count) < self.max_connections
    }

    fn take_idle(&mut self) -> Option<PooledConnection> {
        self.idle.pop().map(|mut conn| {
            conn.mark_used();
            self.active_count += 1;
            conn
        })
    }

    fn return_connection(&mut self, conn: PooledConnection) {
        self.active_count = self.active_count.saturating_sub(1);
        
        if self.idle.len() < self.max_idle {
            self.idle.push(conn);
        } else {
            trace!("connection pool full, dropping connection");
        }
    }

    fn cleanup_expired(&mut self, idle_timeout: Duration, lifetime: Duration) {
        let before = self.idle.len();
        self.idle.retain(|conn| !conn.is_expired(idle_timeout, lifetime));
        let removed = before - self.idle.len();
        
        if removed > 0 {
            trace!(removed, "cleaned up expired connections");
        }
    }
}

impl ConnectionPool {
    /// Creates a new connection pool with the given proxy pool.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use roxie::transport::{ConnectionPool, ProxyPool, ProxyList};
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let list = ProxyList::from_lines("http://proxy.com:8080")?;
    /// let proxy_pool = Arc::new(ProxyPool::from_list(&list));
    /// let conn_pool = ConnectionPool::new(proxy_pool);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(proxy_pool: Arc<ProxyPool>) -> Self {
        Self {
            proxy_pool,
            connections: Arc::new(RwLock::new(HashMap::new())),
            max_idle_per_proxy: DEFAULT_MAX_IDLE_PER_PROXY,
            max_connections_per_proxy: DEFAULT_MAX_CONNECTIONS_PER_PROXY,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            connection_lifetime: DEFAULT_CONNECTION_LIFETIME,
        }
    }

    /// Sets the maximum number of idle connections per proxy.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use roxie::transport::{ConnectionPool, ProxyPool, ProxyList};
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let list = ProxyList::from_lines("http://proxy.com:8080")?;
    /// let proxy_pool = Arc::new(ProxyPool::from_list(&list));
    /// let conn_pool = ConnectionPool::new(proxy_pool)
    ///     .with_max_idle_per_proxy(20);
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_max_idle_per_proxy(mut self, max: usize) -> Self {
        self.max_idle_per_proxy = max;
        self
    }

    /// Sets the maximum total connections per proxy.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use roxie::transport::{ConnectionPool, ProxyPool, ProxyList};
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let list = ProxyList::from_lines("http://proxy.com:8080")?;
    /// let proxy_pool = Arc::new(ProxyPool::from_list(&list));
    /// let conn_pool = ConnectionPool::new(proxy_pool)
    ///     .with_max_connections_per_proxy(100);
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_max_connections_per_proxy(mut self, max: usize) -> Self {
        self.max_connections_per_proxy = max;
        self
    }

    /// Sets the idle timeout for connections.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use roxie::transport::{ConnectionPool, ProxyPool, ProxyList};
    /// use std::sync::Arc;
    /// use std::time::Duration;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let list = ProxyList::from_lines("http://proxy.com:8080")?;
    /// let proxy_pool = Arc::new(ProxyPool::from_list(&list));
    /// let conn_pool = ConnectionPool::new(proxy_pool)
    ///     .with_idle_timeout(Duration::from_secs(120));
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Sets the maximum lifetime for connections.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use roxie::transport::{ConnectionPool, ProxyPool, ProxyList};
    /// use std::sync::Arc;
    /// use std::time::Duration;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let list = ProxyList::from_lines("http://proxy.com:8080")?;
    /// let proxy_pool = Arc::new(ProxyPool::from_list(&list));
    /// let conn_pool = ConnectionPool::new(proxy_pool)
    ///     .with_connection_lifetime(Duration::from_secs(600));
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_connection_lifetime(mut self, lifetime: Duration) -> Self {
        self.connection_lifetime = lifetime;
        self
    }

    /// Gets a connection to the target, reusing an existing one if available.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use roxie::transport::{ConnectionPool, ProxyPool, ProxyList};
    /// use std::sync::Arc;
    /// use url::Url;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let list = ProxyList::from_lines("http://proxy.com:8080")?;
    /// let proxy_pool = Arc::new(ProxyPool::from_list(&list));
    /// let conn_pool = ConnectionPool::new(proxy_pool);
    ///
    /// let target = Url::parse("https://example.com")?;
    /// let stream = conn_pool.get(&target).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get(&self, target: &Url) -> Result<PooledStream, ConnectionPoolError> {
        // Select best proxy from the pool
        let proxy = self.proxy_pool.quick()
            .ok_or(ConnectionPoolError::NoProxiesAvailable)?
            .clone();

        let key = ProxyKey::new(&proxy, target);

        // Try to get an idle connection first
        let existing = {
            let mut pools = self.connections.write();
            let proxy_conns = pools
                .entry(key.clone())
                .or_insert_with(|| ProxyConnections::new(
                    self.max_idle_per_proxy,
                    self.max_connections_per_proxy,
                ));

            // Cleanup expired connections
            proxy_conns.cleanup_expired(self.idle_timeout, self.connection_lifetime);

            proxy_conns.take_idle()
        };

        if let Some(conn) = existing {
            trace!(
                proxy_key = %key.to_string(),
                use_count = conn.use_count,
                age_secs = conn.created_at.elapsed().as_secs(),
                "reusing pooled connection"
            );

            self.proxy_pool.unlock(&proxy);
            
            return Ok(PooledStream {
                stream: Some(conn.stream),
                proxy: conn.proxy,
                key,
                pool: self.connections.clone(),
                proxy_pool: self.proxy_pool.clone(),
                start_time: Instant::now(),
            });
        }

        // Check if we can create a new connection
        let can_create = {
            let pools = self.connections.read();
            pools.get(&key)
                .map(|p| p.can_create_new())
                .unwrap_or(true)
        };

        if !can_create {
            self.proxy_pool.unlock(&proxy);
            return Err(ConnectionPoolError::ConnectionLimitReached {
                proxy_key: key.to_string(),
            });
        }

        // Create new connection
        trace!(
            proxy_key = %key.to_string(),
            "creating new connection"
        );

        let start = Instant::now();
        
        match proxy.connect(target).await {
            Ok(stream) => {
                let elapsed = start.elapsed();
                
                // Update active count
                {
                    let mut pools = self.connections.write();
                    let proxy_conns = pools
                        .entry(key.clone())
                        .or_insert_with(|| ProxyConnections::new(
                            self.max_idle_per_proxy,
                            self.max_connections_per_proxy,
                        ));
                    proxy_conns.active_count += 1;
                }

                debug!(
                    proxy_key = %key.to_string(),
                    elapsed_ms = elapsed.as_millis() as u64,
                    "new connection established"
                );

                // Record success in proxy pool
                self.proxy_pool.record_success(&proxy, elapsed);
                self.proxy_pool.unlock(&proxy);

                Ok(PooledStream {
                    stream: Some(stream),
                    proxy,
                    key,
                    pool: self.connections.clone(),
                    proxy_pool: self.proxy_pool.clone(),
                    start_time: Instant::now(),
                })
            }
            Err(e) => {
                // Record failure in proxy pool
                self.proxy_pool.record_failure(&proxy);
                self.proxy_pool.unlock(&proxy);

                warn!(
                    proxy_key = %key.to_string(),
                    error = %e,
                    "connection failed"
                );

                Err(ConnectionPoolError::ConnectFailed {
                    proxy_key: key.to_string(),
                    source: e,
                })
            }
        }
    }

    /// Gets statistics about the connection pool.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use roxie::transport::{ConnectionPool, ProxyPool, ProxyList};
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let list = ProxyList::from_lines("http://proxy.com:8080")?;
    /// let proxy_pool = Arc::new(ProxyPool::from_list(&list));
    /// let conn_pool = ConnectionPool::new(proxy_pool);
    ///
    /// let stats = conn_pool.stats();
    /// println!("Total connections: {}", stats.total_connections);
    /// # Ok(())
    /// # }
    /// ```
    pub fn stats(&self) -> ConnectionPoolStats {
        let pools = self.connections.read();
        
        let mut total_idle = 0;
        let mut total_active = 0;
        let mut proxy_stats = Vec::new();

        for (key, conns) in pools.iter() {
            total_idle += conns.idle.len();
            total_active += conns.active_count;

            proxy_stats.push(ProxyStats {
                proxy_key: key.to_string(),
                idle_count: conns.idle.len(),
                active_count: conns.active_count,
                total_count: conns.idle.len() + conns.active_count,
            });
        }

        ConnectionPoolStats {
            total_proxies: pools.len(),
            total_idle_connections: total_idle,
            total_active_connections: total_active,
            total_connections: total_idle + total_active,
            proxy_stats,
        }
    }

    /// Clears all idle connections from the pool.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use roxie::transport::{ConnectionPool, ProxyPool, ProxyList};
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let list = ProxyList::from_lines("http://proxy.com:8080")?;
    /// let proxy_pool = Arc::new(ProxyPool::from_list(&list));
    /// let conn_pool = ConnectionPool::new(proxy_pool);
    ///
    /// conn_pool.clear();
    /// # Ok(())
    /// # }
    /// ```
    pub fn clear(&self) {
        let mut pools = self.connections.write();
        for (_, conns) in pools.iter_mut() {
            let cleared = conns.idle.len();
            conns.idle.clear();
            if cleared > 0 {
                debug!(cleared, "cleared idle connections");
            }
        }
    }
}

impl PooledStream {
    /// Gets a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut ProxyStream {
        self.stream.as_mut().expect("stream already taken")
    }

    /// Gets a reference to the underlying stream.
    pub fn get_ref(&self) -> &ProxyStream {
        self.stream.as_ref().expect("stream already taken")
    }

    /// Consumes the guard and returns the underlying stream.
    ///
    /// This prevents the connection from being returned to the pool.
    pub fn into_inner(mut self) -> ProxyStream {
        self.stream.take().expect("stream already taken")
    }
}

impl Drop for PooledStream {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            let elapsed = self.start_time.elapsed();
            
            // Record usage time in proxy pool for scoring
            self.proxy_pool.record_success(&self.proxy, elapsed);
            
            // Return connection to pool
            let conn = PooledConnection::new(stream, self.proxy.clone());
            
            let mut pools = self.pool.write();
            if let Some(proxy_conns) = pools.get_mut(&self.key) {
                proxy_conns.return_connection(conn);
                trace!(
                    proxy_key = %self.key.to_string(),
                    "connection returned to pool"
                );
            }
        }
    }
}

impl std::ops::Deref for PooledStream {
    type Target = ProxyStream;

    fn deref(&self) -> &Self::Target {
        self.stream.as_ref().expect("stream already taken")
    }
}

impl std::ops::DerefMut for PooledStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.stream.as_mut().expect("stream already taken")
    }
}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pooled_connection_expiry() {
        let proxy = create_test_proxy();
        let stream = create_test_stream();
        let mut conn = PooledConnection::new(stream, proxy);

        // Fresh connection should not be expired
        assert!(!conn.is_expired(Duration::from_secs(60), Duration::from_secs(300)));

        // Simulate old last_used time
        conn.last_used = Instant::now() - Duration::from_secs(120);
        assert!(conn.is_expired(Duration::from_secs(60), Duration::from_secs(300)));
    }

    #[cfg(feature = "http")]
    fn create_test_proxy() -> Proxy {
        use crate::config::HTTPConfig;
        Proxy::HTTP {
            host: "proxy.test".to_string(),
            port: 8080,
            config: Arc::new(HTTPConfig::new("proxy.test", 8080)),
        }
    }

    #[cfg(not(feature = "http"))]
    fn create_test_proxy() -> Proxy {
        panic!("No proxy protocols enabled for testing");
    }

    fn create_test_stream() -> ProxyStream {
        // Create a dummy TCP stream for testing
        // In real tests, you'd use a proper test setup
        use tokio::net::TcpStream;
        use std::net::{TcpListener};
        
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        
        let rt = tokio::runtime::Runtime::new().unwrap();
        let stream = rt.block_on(async {
            TcpStream::connect(addr).await.unwrap()
        });
        
        ProxyStream::from_tcp(stream)
    }
}
