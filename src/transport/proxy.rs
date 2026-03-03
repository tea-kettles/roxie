//! Proxy connection management.
//!
//! Provides the `Proxy` enum for connecting through various proxy protocols
//! with automatic protocol dispatch and optional TLS wrapping.
//!
//! # Examples
//!
//! Basic proxy connection:
//! ```no_run
//! use roxie::transport::Proxy;
//! use roxie::config::SOCKS5Config;
//! use std::sync::Arc;
//! use url::Url;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Arc::new(SOCKS5Config::new("localhost", 1080));
//! let proxy = Proxy::SOCKS5 {
//!     host: "localhost".to_string(),
//!     port: 1080,
//!     config,
//! };
//!
//! let target = Url::parse("https://example.com")?;
//! let stream = proxy.connect(&target).await?;
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, instrument, trace};
use url::Url;

use crate::config::*;
use crate::errors::ProxyError;
use crate::protocols;
use crate::transport::ProxyStream;

/* Types */

/// Self-contained proxy connection unit with embedded configuration.
///
/// Each variant represents a different proxy protocol with its own
/// configuration and connection requirements.
///
/// # Examples
///
/// ```
/// use roxie::transport::Proxy;
/// use roxie::config::HTTPConfig;
/// use std::sync::Arc;
///
/// let proxy = Proxy::HTTP {
///     host: "proxy.example.com".to_string(),
///     port: 8080,
///     config: Arc::new(
///         HTTPConfig::new("proxy.example.com", 8080)
///             .set_username("user")
///             .set_password("pass"),
///     ),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Proxy {
    /// HTTP CONNECT proxy.
    #[cfg(feature = "http")]
    HTTP {
        host: String,
        port: u16,
        config: Arc<HTTPConfig>,
    },

    /// HTTPS CONNECT proxy (HTTP over TLS).
    #[cfg(feature = "http")]
    HTTPS {
        host: String,
        port: u16,
        config: Arc<HTTPConfig>,
    },

    /// SOCKS4 proxy.
    #[cfg(feature = "socks4")]
    SOCKS4 {
        host: String,
        port: u16,
        config: Arc<SOCKS4Config>,
    },

    /// SOCKS4A proxy (with remote DNS resolution).
    #[cfg(feature = "socks4")]
    SOCKS4A {
        host: String,
        port: u16,
        config: Arc<SOCKS4Config>,
    },

    /// SOCKS5 proxy.
    #[cfg(feature = "socks5")]
    SOCKS5 {
        host: String,
        port: u16,
        config: Arc<SOCKS5Config>,
    },

    /// SOCKS5H proxy (with remote DNS resolution).
    #[cfg(feature = "socks5")]
    SOCKS5H {
        host: String,
        port: u16,
        config: Arc<SOCKS5Config>,
    },

    /// Tor SOCKS proxy with optional control port configuration.
    #[cfg(feature = "tor")]
    Tor {
        host: String,
        port: u16,
        config: Arc<TorConfig>,
    },

    /// Shadowsocks encrypted proxy.
    #[cfg(feature = "shadowsocks")]
    Shadowsocks {
        host: String,
        port: u16,
        password: String,
        config: Arc<ShadowsocksConfig>,
    },
}

/* Implementations */

impl Proxy {
    /// Establishes connection through proxy to destination.
    ///
    /// Returns a ready-to-use stream tunneled through the proxy.
    /// The stream may be TLS-wrapped if the destination is HTTPS.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use roxie::transport::Proxy;
    /// use roxie::config::SOCKS5Config;
    /// use std::sync::Arc;
    /// use url::Url;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Arc::new(SOCKS5Config::new("localhost", 1080));
    /// let proxy = Proxy::SOCKS5 {
    ///     host: "localhost".to_string(),
    ///     port: 1080,
    ///     config,
    /// };
    ///
    /// let target = Url::parse("https://example.com")?;
    /// let stream = proxy.connect(&target).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(
        level = "debug",
        skip(self, destination),
        fields(
            proxy = %format!("{}:{}", self.get_host(), self.get_port()),   // "187.216.144.170:5678"
        )
    )]
    pub async fn connect(&self, destination: &Url) -> Result<ProxyStream, ProxyError> {
        let start = Instant::now();

        trace!(
            proxy_scheme = self.get_scheme(),
            proxy_host = self.get_host(),
            proxy_port = self.get_port(),
            target_url = %destination,
            "establishing connection through proxy"
        );

        let result = self.connect_inner(destination).await;
        let elapsed = start.elapsed();

        match &result {
            Ok(_) => {
                debug!(
                    proxy_scheme = self.get_scheme(),
                    elapsed_ms = elapsed.as_millis() as u64,
                    "connection established successfully"
                );
            }
            Err(e) => {
                trace!(
                    proxy_scheme = self.get_scheme(),
                    elapsed_ms = elapsed.as_millis() as u64,
                    error = %e,
                    "connection failed"
                );
            }
        }

        result
    }

    async fn connect_inner(&self, destination: &Url) -> Result<ProxyStream, ProxyError> {
        match self {
            #[cfg(feature = "http")]
            Proxy::HTTP { host, port, config } | Proxy::HTTPS { host, port, config } => {
                self.connect_http(host, *port, config, destination).await
            }

            #[cfg(feature = "socks4")]
            Proxy::SOCKS4 { host, port, config } | Proxy::SOCKS4A { host, port, config } => {
                self.connect_socks4(host, *port, config, destination).await
            }

            #[cfg(feature = "socks5")]
            Proxy::SOCKS5 { host, port, config } | Proxy::SOCKS5H { host, port, config } => {
                self.connect_socks5(host, *port, config, destination).await
            }

            #[cfg(feature = "tor")]
            Proxy::Tor { host, port, config } => {
                self.connect_tor(host, *port, config, destination).await
            }

            #[cfg(feature = "shadowsocks")]
            Proxy::Shadowsocks {
                host,
                port,
                password,
                config,
            } => {
                self.connect_shadowsocks(host, *port, password, config, destination)
                    .await
            }

            #[allow(unreachable_patterns)]
            _ => Err(ProxyError::UnsupportedProtocol {
                scheme: self.get_scheme().to_string(),
            }),
        }
    }

    #[cfg(feature = "http")]
    async fn connect_http(
        &self,
        host: &str,
        port: u16,
        config: &HTTPConfig,
        destination: &Url,
    ) -> Result<ProxyStream, ProxyError> {
        let proxy_addr = format!("{}:{}", host, port);
        let mut stream =
            TcpStream::connect(&proxy_addr)
                .await
                .map_err(|e| ProxyError::ConnectionFailed {
                    host: host.to_string(),
                    port,
                    source: e,
                })?;

        trace!(
            proxy_addr = proxy_addr,
            "TCP connected, starting HTTP handshake"
        );

        protocols::http::establish_http(&mut stream, destination, config).await?;

        trace!(proxy_addr = proxy_addr, "HTTP handshake complete");

        // Check if autotls is enabled and destination uses HTTPS
        let base_config = config.get_base_config();
        if base_config.is_auto_tls() && destination.scheme() == "https" {
            trace!(
                proxy_addr = proxy_addr,
                target_host = destination.host_str(),
                "autotls enabled, establishing TLS connection"
            );

            let target_host = destination
                .host_str()
                .ok_or(ProxyError::MissingTargetHost)?;

            // Reuse caller-provided TLS settings when available; otherwise start from defaults
            let tls_config = base_config.get_tls_config().cloned().unwrap_or_else(|| {
                crate::config::TLSConfig::new()
                    .set_handshake_timeout(base_config.get_handshake_timeout())
            });

            let tls_stream =
                crate::transport::tls::establish_tls(stream, target_host, &tls_config).await?;

            trace!(
                proxy_addr = proxy_addr,
                target_host = target_host,
                "TLS handshake complete"
            );

            Ok(ProxyStream::Tls(Box::new(tls_stream)))
        } else {
            Ok(ProxyStream::Tcp(stream))
        }
    }

    #[cfg(feature = "socks4")]
    async fn connect_socks4(
        &self,
        host: &str,
        port: u16,
        config: &SOCKS4Config,
        destination: &Url,
    ) -> Result<ProxyStream, ProxyError> {
        let proxy_addr = format!("{}:{}", host, port);
        let mut stream =
            TcpStream::connect(&proxy_addr)
                .await
                .map_err(|e| ProxyError::ConnectionFailed {
                    host: host.to_string(),
                    port,
                    source: e,
                })?;

        trace!(
            proxy_addr = proxy_addr,
            "TCP connected, starting SOCKS4 handshake"
        );

        protocols::socks4::establish_socks4(&mut stream, destination, config).await?;

        trace!(proxy_addr = proxy_addr, "SOCKS4 handshake complete");

        // Check if autotls is enabled and destination uses HTTPS
        let base_config = config.get_base_config();
        if base_config.is_auto_tls() && destination.scheme() == "https" {
            trace!(
                proxy_addr = proxy_addr,
                target_host = destination.host_str(),
                "autotls enabled, establishing TLS connection"
            );

            let target_host = destination
                .host_str()
                .ok_or(ProxyError::MissingTargetHost)?;

            // Reuse caller-provided TLS settings when available; otherwise start from defaults
            let tls_config = base_config.get_tls_config().cloned().unwrap_or_else(|| {
                crate::config::TLSConfig::new()
                    .set_handshake_timeout(base_config.get_handshake_timeout())
            });

            let tls_stream =
                crate::transport::tls::establish_tls(stream, target_host, &tls_config).await?;

            trace!(
                proxy_addr = proxy_addr,
                target_host = target_host,
                "TLS handshake complete"
            );

            Ok(ProxyStream::Tls(Box::new(tls_stream)))
        } else {
            Ok(ProxyStream::Tcp(stream))
        }
    }

    #[cfg(feature = "socks5")]
    async fn connect_socks5(
        &self,
        host: &str,
        port: u16,
        config: &SOCKS5Config,
        destination: &Url,
    ) -> Result<ProxyStream, ProxyError> {
        let proxy_addr = format!("{}:{}", host, port);
        let mut stream =
            TcpStream::connect(&proxy_addr)
                .await
                .map_err(|e| ProxyError::ConnectionFailed {
                    host: host.to_string(),
                    port,
                    source: e,
                })?;

        trace!(
            proxy_addr = proxy_addr,
            "TCP connected, starting SOCKS5 handshake"
        );

        protocols::socks5::establish_socks5(&mut stream, destination, config).await?;

        trace!(proxy_addr = proxy_addr, "SOCKS5 handshake complete");

        // Check if autotls is enabled and destination uses HTTPS
        let base_config = config.get_base_config();
        if base_config.is_auto_tls() && destination.scheme() == "https" {
            trace!(
                proxy_addr = proxy_addr,
                target_host = destination.host_str(),
                "autotls enabled, establishing TLS connection"
            );

            let target_host = destination
                .host_str()
                .ok_or(ProxyError::MissingTargetHost)?;

            // Reuse caller-provided TLS settings when available; otherwise start from defaults
            let tls_config = base_config.get_tls_config().cloned().unwrap_or_else(|| {
                crate::config::TLSConfig::new()
                    .set_handshake_timeout(base_config.get_handshake_timeout())
            });

            let tls_stream =
                crate::transport::tls::establish_tls(stream, target_host, &tls_config).await?;

            trace!(
                proxy_addr = proxy_addr,
                target_host = target_host,
                "TLS handshake complete"
            );

            Ok(ProxyStream::Tls(Box::new(tls_stream)))
        } else {
            Ok(ProxyStream::Tcp(stream))
        }
    }

    #[cfg(feature = "tor")]
    async fn connect_tor(
        &self,
        host: &str,
        port: u16,
        config: &TorConfig,
        destination: &Url,
    ) -> Result<ProxyStream, ProxyError> {
        let proxy_addr = format!("{}:{}", host, port);
        let mut stream =
            TcpStream::connect(&proxy_addr)
                .await
                .map_err(|e| ProxyError::ConnectionFailed {
                    host: host.to_string(),
                    port,
                    source: e,
                })?;

        trace!(
            proxy_addr = proxy_addr,
            "TCP connected, starting tor handshake"
        );

        let apply_config = config.has_control_config();
        protocols::tor::establish_tor(&mut stream, destination, config, apply_config).await?;

        trace!(proxy_addr = proxy_addr, "tor handshake complete");

        // Check if autotls is enabled and destination uses HTTPS
        let base_config = config.get_base_config();
        if base_config.is_auto_tls() && destination.scheme() == "https" {
            trace!(
                proxy_addr = proxy_addr,
                target_host = destination.host_str(),
                "autotls enabled, establishing TLS connection"
            );

            let target_host = destination
                .host_str()
                .ok_or(ProxyError::MissingTargetHost)?;

            // Reuse caller-provided TLS settings when available; otherwise start from defaults
            let tls_config = base_config.get_tls_config().cloned().unwrap_or_else(|| {
                crate::config::TLSConfig::new()
                    .set_handshake_timeout(base_config.get_handshake_timeout())
            });

            let tls_stream =
                crate::transport::tls::establish_tls(stream, target_host, &tls_config).await?;

            trace!(
                proxy_addr = proxy_addr,
                target_host = target_host,
                "TLS handshake complete"
            );

            Ok(ProxyStream::Tls(Box::new(tls_stream)))
        } else {
            Ok(ProxyStream::Tcp(stream))
        }
    }

    #[cfg(feature = "shadowsocks")]
    async fn connect_shadowsocks(
        &self,
        host: &str,
        port: u16,
        password: &str,
        config: &ShadowsocksConfig,
        destination: &Url,
    ) -> Result<ProxyStream, ProxyError> {
        let proxy_addr = format!("{}:{}", host, port);
        let mut stream =
            TcpStream::connect(&proxy_addr)
                .await
                .map_err(|e| ProxyError::ConnectionFailed {
                    host: host.to_string(),
                    port,
                    source: e,
                })?;

        trace!(
            proxy_addr = proxy_addr,
            "TCP connected, starting shadowsocks handshake"
        );

        let (cipher, nonce, master_key, method) = protocols::shadowsocks::establish_shadowsocks(
            &mut stream,
            destination,
            password,
            config,
        )
        .await?;

        trace!(proxy_addr = proxy_addr, "shadowsocks handshake complete");

        Ok(ProxyStream::from_shadowsocks(
            stream, cipher, nonce, master_key, method,
        ))
    }

    /// Returns the proxy host.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::Proxy;
    /// use roxie::config::SOCKS5Config;
    /// use std::sync::Arc;
    ///
    /// let proxy = Proxy::SOCKS5 {
    ///     host: "localhost".to_string(),
    ///     port: 1080,
    ///     config: Arc::new(SOCKS5Config::new("localhost", 1080)),
    /// };
    ///
    /// assert_eq!(proxy.get_host(), "localhost");
    /// ```
    pub fn get_host(&self) -> &str {
        match self {
            #[cfg(feature = "http")]
            Proxy::HTTP { host, .. } | Proxy::HTTPS { host, .. } => host,
            #[cfg(feature = "socks4")]
            Proxy::SOCKS4 { host, .. } | Proxy::SOCKS4A { host, .. } => host,
            #[cfg(feature = "socks5")]
            Proxy::SOCKS5 { host, .. } | Proxy::SOCKS5H { host, .. } => host,
            #[cfg(feature = "tor")]
            Proxy::Tor { host, .. } => host,
            #[cfg(feature = "shadowsocks")]
            Proxy::Shadowsocks { host, .. } => host,
        }
    }

    /// Returns the proxy port.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::Proxy;
    /// use roxie::config::SOCKS5Config;
    /// use std::sync::Arc;
    ///
    /// let proxy = Proxy::SOCKS5 {
    ///     host: "localhost".to_string(),
    ///     port: 1080,
    ///     config: Arc::new(SOCKS5Config::new("localhost", 1080)),
    /// };
    ///
    /// assert_eq!(proxy.get_port(), 1080);
    /// ```
    pub fn get_port(&self) -> u16 {
        match self {
            #[cfg(feature = "http")]
            Proxy::HTTP { port, .. } | Proxy::HTTPS { port, .. } => *port,
            #[cfg(feature = "socks4")]
            Proxy::SOCKS4 { port, .. } | Proxy::SOCKS4A { port, .. } => *port,
            #[cfg(feature = "socks5")]
            Proxy::SOCKS5 { port, .. } | Proxy::SOCKS5H { port, .. } => *port,
            #[cfg(feature = "tor")]
            Proxy::Tor { port, .. } => *port,
            #[cfg(feature = "shadowsocks")]
            Proxy::Shadowsocks { port, .. } => *port,
        }
    }

    /// Returns the scheme of the proxy as a static string.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::Proxy;
    /// use roxie::config::SOCKS5Config;
    /// use std::sync::Arc;
    ///
    /// let proxy = Proxy::SOCKS5 {
    ///     host: "localhost".to_string(),
    ///     port: 1080,
    ///     config: Arc::new(SOCKS5Config::new("localhost", 1080)),
    /// };
    ///
    /// assert_eq!(proxy.get_scheme(), "socks5");
    /// ```
    pub fn get_scheme(&self) -> &'static str {
        match self {
            #[cfg(feature = "http")]
            Proxy::HTTP { .. } => "http",
            #[cfg(feature = "http")]
            Proxy::HTTPS { .. } => "https",
            #[cfg(feature = "socks4")]
            Proxy::SOCKS4 { .. } => "socks4",
            #[cfg(feature = "socks4")]
            Proxy::SOCKS4A { .. } => "socks4a",
            #[cfg(feature = "socks5")]
            Proxy::SOCKS5 { .. } => "socks5",
            #[cfg(feature = "socks5")]
            Proxy::SOCKS5H { .. } => "socks5h",
            #[cfg(feature = "tor")]
            Proxy::Tor { .. } => "tor",
            #[cfg(feature = "shadowsocks")]
            Proxy::Shadowsocks { .. } => "shadowsocks",
        }
    }

    /// Convenience helper to perform a simple HTTP GET through this proxy.
    ///
    /// The response body is returned as UTF-8 (lossy) and the underlying
    /// stream is closed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use roxie::transport::Proxy;
    /// use roxie::config::SOCKS5Config;
    /// use std::sync::Arc;
    /// use url::Url;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let proxy = Proxy::SOCKS5 {
    ///     host: "localhost".to_string(),
    ///     port: 1080,
    ///     config: Arc::new(SOCKS5Config::new("localhost", 1080)),
    /// };
    ///
    /// let target = Url::parse("http://example.com")?;
    /// let response = proxy.get(&target).await?;
    /// println!("Response: {}", response);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get(&self, destination: &Url) -> Result<String, ProxyError> {
        let mut stream = self.connect(destination).await?;

        let host = destination
            .host_str()
            .ok_or(ProxyError::MissingTargetHost)?;
        let mut path = destination.path().to_string();
        if path.is_empty() {
            path = "/".to_string();
        }
        if let Some(q) = destination.query() {
            path.push('?');
            path.push_str(q);
        }

        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            path, host
        );

        stream.write_all(request.as_bytes()).await?;

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;

        let body = if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            &buf[pos + 4..]
        } else {
            &buf[..]
        };

        Ok(String::from_utf8_lossy(body).to_string())
    }

    /// INTERNAL: Apply shared base configuration to this proxy.
    ///
    /// This is intentionally not public - users should apply config at the
    /// collection level via `ProxyList::config()` or `ProxyPool::config()`.
    /// For detailed per-proxy customization, export to JSON and re-import.
    ///
    /// Creates a new proxy instance with the same connection details but
    /// with the provided base configuration merged into its protocol-specific
    /// config.
    pub(crate) fn with_base_config(self, base: Arc<BaseProxyConfig>) -> Self {
        match self {
            #[cfg(feature = "http")]
            Proxy::HTTP { host, port, config } => {
                let mut new_config = (*config).clone();
                new_config.set_base_arc(base.clone());
                Proxy::HTTP {
                    host,
                    port,
                    config: Arc::new(new_config),
                }
            }

            #[cfg(feature = "http")]
            Proxy::HTTPS { host, port, config } => {
                let mut new_config = (*config).clone();
                new_config.set_base_arc(base.clone());
                Proxy::HTTPS {
                    host,
                    port,
                    config: Arc::new(new_config),
                }
            }

            #[cfg(feature = "socks4")]
            Proxy::SOCKS4 { host, port, config } => {
                let mut new_config = (*config).clone();
                new_config.set_base_arc(base.clone());
                Proxy::SOCKS4 {
                    host,
                    port,
                    config: Arc::new(new_config),
                }
            }

            #[cfg(feature = "socks4")]
            Proxy::SOCKS4A { host, port, config } => {
                let mut new_config = (*config).clone();
                new_config.set_base_arc(base.clone());
                Proxy::SOCKS4A {
                    host,
                    port,
                    config: Arc::new(new_config),
                }
            }

            #[cfg(feature = "socks5")]
            Proxy::SOCKS5 { host, port, config } => {
                let mut new_config = (*config).clone();
                new_config.set_base_arc(base.clone());
                Proxy::SOCKS5 {
                    host,
                    port,
                    config: Arc::new(new_config),
                }
            }

            #[cfg(feature = "socks5")]
            Proxy::SOCKS5H { host, port, config } => {
                let mut new_config = (*config).clone();
                new_config.set_base_arc(base.clone());
                Proxy::SOCKS5H {
                    host,
                    port,
                    config: Arc::new(new_config),
                }
            }

            #[cfg(feature = "tor")]
            Proxy::Tor { host, port, config } => {
                let mut new_config = (*config).clone();
                new_config.set_base_arc(base.clone());
                Proxy::Tor {
                    host,
                    port,
                    config: Arc::new(new_config),
                }
            }

            #[cfg(feature = "shadowsocks")]
            Proxy::Shadowsocks {
                host,
                port,
                password,
                config,
            } => {
                let mut new_config = (*config).clone();
                new_config.set_base_arc(base.clone());
                Proxy::Shadowsocks {
                    host,
                    port,
                    password,
                    config: Arc::new(new_config),
                }
            }

            #[allow(unreachable_patterns)]
            _ => self,
        }
    }
}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "http")]
    fn proxy_host_returns_host() {
        let proxy = Proxy::HTTP {
            host: "proxy.com".to_string(),
            port: 8080,
            config: Arc::new(HTTPConfig::new("", 0)),
        };
        assert_eq!(proxy.get_host(), "proxy.com");
    }

    #[test]
    #[cfg(feature = "http")]
    fn proxy_port_returns_port() {
        let proxy = Proxy::HTTP {
            host: "proxy.com".to_string(),
            port: 8080,
            config: Arc::new(HTTPConfig::new("", 0)),
        };
        assert_eq!(proxy.get_port(), 8080);
    }

    #[test]
    #[cfg(feature = "http")]
    fn proxy_scheme_returns_scheme() {
        let proxy = Proxy::HTTP {
            host: "proxy.com".to_string(),
            port: 8080,
            config: Arc::new(HTTPConfig::new("", 0)),
        };
        assert_eq!(proxy.get_scheme(), "http");
    }

    #[test]
    #[cfg(feature = "socks5")]
    fn socks5_proxy_accessors() {
        let proxy = Proxy::SOCKS5 {
            host: "localhost".to_string(),
            port: 1080,
            config: Arc::new(SOCKS5Config::new("", 1080)),
        };
        assert_eq!(proxy.get_host(), "localhost");
        assert_eq!(proxy.get_port(), 1080);
        assert_eq!(proxy.get_scheme(), "socks5");
    }
}
