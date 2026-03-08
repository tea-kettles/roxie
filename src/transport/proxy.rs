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

    /// Hysteria2 QUIC-based proxy.
    #[cfg(feature = "hysteria2")]
    Hysteria2 {
        host: String,
        port: u16,
        password: String,
        config: Arc<Hysteria2Config>,
    },

    /// Trojan TLS-based proxy.
    ///
    /// Traffic is disguised as HTTPS by establishing TLS directly to the proxy server
    /// and prefixing each TCP stream with a SHA-224 password hash header.
    #[cfg(feature = "trojan")]
    Trojan {
        host: String,
        port: u16,
        password: String,
        config: Arc<TrojanConfig>,
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

            #[cfg(feature = "hysteria2")]
            Proxy::Hysteria2 {
                host,
                port,
                password,
                config,
            } => {
                self.connect_hysteria2(host, *port, password, config, destination)
                    .await
            }

            #[cfg(feature = "trojan")]
            Proxy::Trojan {
                host,
                port,
                password,
                config,
            } => {
                self.connect_trojan(host, *port, password, config, destination)
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

        Self::wrap_tls_if_needed(stream, &proxy_addr, destination, config.get_base_config()).await
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

        Self::wrap_tls_if_needed(stream, &proxy_addr, destination, config.get_base_config()).await
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

        Self::wrap_tls_if_needed(stream, &proxy_addr, destination, config.get_base_config()).await
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

        Self::wrap_tls_if_needed(stream, &proxy_addr, destination, config.get_base_config()).await
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

        let ss_stream = crate::transport::streams::ShadowsocksStream::new(
            stream, cipher, nonce, master_key, method,
        );

        #[cfg(feature = "tls")]
        if config.get_base_config().is_auto_tls() && destination.scheme() == "https" {
            let target_host = destination.host_str().ok_or(ProxyError::MissingTargetHost)?;
            let tls_config = config
                .get_base_config()
                .get_tls_config()
                .cloned()
                .unwrap_or_else(|| {
                    crate::config::TLSConfig::new()
                        .set_handshake_timeout(config.get_base_config().get_handshake_timeout())
                });

            trace!(
                proxy_addr = proxy_addr,
                target_host = target_host,
                "autotls enabled, wrapping shadowsocks in TLS"
            );

            let tls_stream =
                crate::transport::tls::establish_tls(ss_stream, target_host, &tls_config).await?;

            trace!(
                proxy_addr = proxy_addr,
                target_host = target_host,
                "TLS handshake complete over shadowsocks"
            );

            return Ok(ProxyStream::from_tls_shadowsocks(tls_stream));
        }

        Ok(ProxyStream::from_shadowsocks_stream(ss_stream))
    }

    #[cfg(feature = "hysteria2")]
    async fn connect_hysteria2(
        &self,
        host: &str,
        port: u16,
        password: &str,
        config: &Hysteria2Config,
        destination: &Url,
    ) -> Result<ProxyStream, ProxyError> {
        trace!(
            proxy_host = host,
            proxy_port = port,
            target_url = %destination,
            "starting Hysteria2 connection"
        );

        let (send, recv, conn) =
            protocols::hysteria2::establish_hysteria2(host, port, password, config, destination)
                .await?;

        trace!(
            proxy_host = host,
            proxy_port = port,
            "Hysteria2 stream established"
        );

        let hy2_stream = crate::transport::streams::Hysteria2TcpStream::new(send, recv, conn);

        #[cfg(feature = "tls")]
        if config.get_base_config().is_auto_tls() && destination.scheme() == "https" {
            let target_host = destination.host_str().ok_or(ProxyError::MissingTargetHost)?;
            let tls_config = config
                .get_base_config()
                .get_tls_config()
                .cloned()
                .unwrap_or_else(|| {
                    crate::config::TLSConfig::new()
                        .set_handshake_timeout(config.get_base_config().get_handshake_timeout())
                });

            trace!(
                proxy_host = host,
                proxy_port = port,
                target_host = target_host,
                "autotls enabled, wrapping hysteria2 in TLS"
            );

            let tls_stream =
                crate::transport::tls::establish_tls(hy2_stream, target_host, &tls_config).await?;

            trace!(
                proxy_host = host,
                proxy_port = port,
                target_host = target_host,
                "TLS handshake complete over hysteria2"
            );

            return Ok(ProxyStream::from_tls_hysteria2(tls_stream));
        }

        Ok(ProxyStream::from_hysteria2_stream(hy2_stream))
    }

    #[cfg(feature = "trojan")]
    async fn connect_trojan(
        &self,
        host: &str,
        port: u16,
        password: &str,
        config: &TrojanConfig,
        destination: &Url,
    ) -> Result<ProxyStream, ProxyError> {
        use crate::config::TLSConfig;
        use crate::errors::TrojanError;
        use crate::transport::tls::establish_tls;
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use tokio_tungstenite::tungstenite::http::header::{HOST, HeaderName, HeaderValue};

        let timeout_dur = config.get_connection_timeout();
        let result = tokio::time::timeout(timeout_dur, async {
            let proxy_addr = format!("{}:{}", host, port);
            let tcp = TcpStream::connect(&proxy_addr)
                .await
                .map_err(|e| ProxyError::ConnectionFailed {
                    host: host.to_string(),
                    port,
                    source: e,
                })?;

            trace!(proxy_addr = proxy_addr, "TCP connected, starting Trojan TLS handshake");

            // Build TLS config from TrojanConfig fields.
            let sni = config.get_sni().unwrap_or(host);
            let mut tls_config = TLSConfig::new()
                .set_handshake_timeout(config.get_base_config().get_handshake_timeout())
                .set_danger_accept_invalid_certs(config.is_skip_cert_verify());

            // WebSocket requires HTTP/1.1; force that ALPN so CDN/Cloudflare servers don't
            // negotiate h2, which would break the HTTP Upgrade handshake.
            if config.is_ws_enabled() {
                tls_config = tls_config.set_alpn(vec![b"http/1.1".to_vec()]);
            } else {
                // Parse comma-separated ALPN strings into wire-format byte vecs.
                let alpn_protos: Vec<Vec<u8>> = config
                    .get_alpn()
                    .split(',')
                    .map(|s| s.trim().as_bytes().to_vec())
                    .filter(|b| !b.is_empty())
                    .collect();
                if !alpn_protos.is_empty() {
                    tls_config = tls_config.set_alpn(alpn_protos);
                }
            }

            let mut tls_stream = establish_tls(tcp, sni, &tls_config)
                .await
                .map_err(|e| TrojanError::TlsHandshakeFailed {
                    host: host.to_string(),
                    source: std::io::Error::other(e.to_string()),
                })?;

            trace!(proxy_addr = proxy_addr, "TLS handshake complete");

            // WebSocket transport path.
            if config.is_ws_enabled() {
                use crate::transport::streams::WsStream;

                let ws_host = config.get_ws_host().unwrap_or(sni);
                let ws_path = config.get_ws_path();
                let ws_url = format!("ws://{}{}", ws_host, ws_path);

                trace!(
                    proxy_addr = proxy_addr,
                    ws_url = ws_url,
                    "upgrading to WebSocket"
                );

                let mut request = ws_url
                    .clone()
                    .into_client_request()
                    .map_err(|e| ProxyError::InvalidConfiguration {
                        reason: format!("invalid trojan ws url '{}': {}", ws_url, e),
                    })?;

                // Ensure Host header tracks ws_host overrides.
                let host_header = HeaderValue::from_str(ws_host).map_err(|e| {
                    ProxyError::InvalidConfiguration {
                        reason: format!("invalid trojan ws host header '{}': {}", ws_host, e),
                    }
                })?;
                request.headers_mut().insert(HOST, host_header);

                if let Some(raw_headers) = config.get_ws_headers() {
                    for pair in raw_headers
                        .split(';')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        let (name, value) =
                            pair.split_once(':')
                                .ok_or_else(|| ProxyError::InvalidConfiguration {
                                    reason: format!(
                                        "invalid trojan ws header '{}', expected 'Name: Value'",
                                        pair
                                    ),
                                })?;

                        let name = HeaderName::from_bytes(name.trim().as_bytes()).map_err(|e| {
                            ProxyError::InvalidConfiguration {
                                reason: format!("invalid trojan ws header name '{}': {}", name, e),
                            }
                        })?;

                        let value = HeaderValue::from_str(value.trim()).map_err(|e| {
                            ProxyError::InvalidConfiguration {
                                reason: format!(
                                    "invalid trojan ws header value for '{}': {}",
                                    name, e
                                ),
                            }
                        })?;

                        request.headers_mut().insert(name, value);
                    }
                }

                let (ws, _) =
                    tokio_tungstenite::client_async(request, tls_stream)
                        .await
                        .map_err(|e| TrojanError::Io {
                            source: std::io::Error::other(e.to_string()),
                        })?;

                let mut ws_stream = WsStream::new(ws);

                trace!(
                    proxy_addr = proxy_addr,
                    "WebSocket upgrade complete, sending Trojan header"
                );

                protocols::trojan::establish_trojan(&mut ws_stream, destination, password).await?;

                trace!(proxy_addr = proxy_addr, "Trojan header sent via WebSocket");

                return Ok(ProxyStream::from_trojan_ws(ws_stream));
            }

            // Plain TLS path.
            trace!(proxy_addr = proxy_addr, "sending Trojan header");

            protocols::trojan::establish_trojan(&mut tls_stream, destination, password).await?;

            trace!(proxy_addr = proxy_addr, "Trojan header sent");

            // If auto_tls is enabled and target is HTTPS, wrap in a second TLS layer.
            if config.get_base_config().is_auto_tls() && destination.scheme() == "https" {
                let target_host = destination.host_str().ok_or(ProxyError::MissingTargetHost)?;
                let inner_tls_config = config
                    .get_base_config()
                    .get_tls_config()
                    .cloned()
                    .unwrap_or_else(|| {
                        TLSConfig::new()
                            .set_handshake_timeout(config.get_base_config().get_handshake_timeout())
                    });

                trace!(
                    proxy_addr = proxy_addr,
                    target_host = target_host,
                    "auto_tls: wrapping Trojan tunnel in second TLS for HTTPS target"
                );

                let target_tls = establish_tls(tls_stream, target_host, &inner_tls_config).await?;

                trace!(target_host = target_host, "second TLS handshake complete");

                return Ok(ProxyStream::from_tls_trojan(target_tls));
            }

            Ok(ProxyStream::Tls(Box::new(tls_stream)))
        })
        .await;

        match result {
            Ok(v) => v,
            Err(_) => Err(ProxyError::ConnectionTimeout {
                host: host.to_string(),
                port,
                timeout_ms: timeout_dur.as_millis() as u64,
            }),
        }
    }

    /// Wraps a connected TCP stream in TLS when auto_tls is enabled and the destination is HTTPS.
    ///
    /// Returns [`ProxyStream::Tls`] when TLS is applied, or [`ProxyStream::Tcp`] otherwise.
    async fn wrap_tls_if_needed(
        stream: TcpStream,
        proxy_addr: &str,
        destination: &Url,
        base_config: &BaseProxyConfig,
    ) -> Result<ProxyStream, ProxyError> {
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
            #[cfg(feature = "hysteria2")]
            Proxy::Hysteria2 { host, .. } => host,
            #[cfg(feature = "trojan")]
            Proxy::Trojan { host, .. } => host,
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
            #[cfg(feature = "hysteria2")]
            Proxy::Hysteria2 { port, .. } => *port,
            #[cfg(feature = "trojan")]
            Proxy::Trojan { port, .. } => *port,
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
            #[cfg(feature = "hysteria2")]
            Proxy::Hysteria2 { .. } => "hysteria2",
            #[cfg(feature = "trojan")]
            Proxy::Trojan { .. } => "trojan",
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

            #[cfg(feature = "hysteria2")]
            Proxy::Hysteria2 {
                host,
                port,
                password,
                config,
            } => {
                let mut new_config = (*config).clone();
                new_config.set_base_arc(base.clone());
                Proxy::Hysteria2 {
                    host,
                    port,
                    password,
                    config: Arc::new(new_config),
                }
            }

            #[cfg(feature = "trojan")]
            Proxy::Trojan {
                host,
                port,
                password,
                config,
            } => {
                let mut new_config = (*config).clone();
                new_config.set_base_arc(base.clone());
                Proxy::Trojan {
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

    #[test]
    #[cfg(feature = "http")]
    fn https_proxy_scheme() {
        let proxy = Proxy::HTTPS {
            host: "proxy.com".to_string(),
            port: 8443,
            config: Arc::new(HTTPConfig::new("proxy.com", 8443)),
        };
        assert_eq!(proxy.get_scheme(), "https");
        assert_eq!(proxy.get_host(), "proxy.com");
        assert_eq!(proxy.get_port(), 8443);
    }

    #[test]
    #[cfg(feature = "socks4")]
    fn socks4_proxy_accessors() {
        let proxy = Proxy::SOCKS4 {
            host: "proxy.com".to_string(),
            port: 1080,
            config: Arc::new(SOCKS4Config::new("proxy.com", 1080)),
        };
        assert_eq!(proxy.get_host(), "proxy.com");
        assert_eq!(proxy.get_port(), 1080);
        assert_eq!(proxy.get_scheme(), "socks4");
    }

    #[test]
    #[cfg(feature = "socks4")]
    fn socks4a_proxy_accessors() {
        let proxy = Proxy::SOCKS4A {
            host: "proxy.com".to_string(),
            port: 1080,
            config: Arc::new(SOCKS4Config::new("proxy.com", 1080)),
        };
        assert_eq!(proxy.get_host(), "proxy.com");
        assert_eq!(proxy.get_port(), 1080);
        assert_eq!(proxy.get_scheme(), "socks4a");
    }

    #[test]
    #[cfg(feature = "socks5")]
    fn socks5h_proxy_accessors() {
        let proxy = Proxy::SOCKS5H {
            host: "proxy.com".to_string(),
            port: 1080,
            config: Arc::new(SOCKS5Config::new("proxy.com", 1080)),
        };
        assert_eq!(proxy.get_host(), "proxy.com");
        assert_eq!(proxy.get_port(), 1080);
        assert_eq!(proxy.get_scheme(), "socks5h");
    }

    #[test]
    #[cfg(feature = "tor")]
    fn tor_proxy_accessors() {
        let proxy = Proxy::Tor {
            host: "127.0.0.1".to_string(),
            port: 9050,
            config: Arc::new(TorConfig::new()),
        };
        assert_eq!(proxy.get_host(), "127.0.0.1");
        assert_eq!(proxy.get_port(), 9050);
        assert_eq!(proxy.get_scheme(), "tor");
    }

    #[test]
    #[cfg(feature = "shadowsocks")]
    fn shadowsocks_proxy_accessors() {
        let proxy = Proxy::Shadowsocks {
            host: "proxy.com".to_string(),
            port: 8388,
            password: "secret".to_string(),
            config: Arc::new(ShadowsocksConfig::new()),
        };
        assert_eq!(proxy.get_host(), "proxy.com");
        assert_eq!(proxy.get_port(), 8388);
        assert_eq!(proxy.get_scheme(), "shadowsocks");
    }

    #[test]
    #[cfg(feature = "hysteria2")]
    fn hysteria2_proxy_accessors() {
        let proxy = Proxy::Hysteria2 {
            host: "proxy.com".to_string(),
            port: 443,
            password: "pass".to_string(),
            config: Arc::new(Hysteria2Config::new()),
        };
        assert_eq!(proxy.get_host(), "proxy.com");
        assert_eq!(proxy.get_port(), 443);
        assert_eq!(proxy.get_scheme(), "hysteria2");
    }

    #[test]
    #[cfg(feature = "http")]
    fn with_base_config_updates_handshake_timeout() {
        use std::time::Duration;
        let proxy = Proxy::HTTP {
            host: "proxy.com".to_string(),
            port: 8080,
            config: Arc::new(HTTPConfig::new("proxy.com", 8080)),
        };
        let mut base = BaseProxyConfig::new();
        base.set_handshake_timeout(Duration::from_secs(42));
        let configured = proxy.with_base_config(Arc::new(base));
        match configured {
            Proxy::HTTP { config, .. } => {
                assert_eq!(
                    config.get_base_config().get_handshake_timeout(),
                    Duration::from_secs(42)
                );
            }
            _ => panic!("expected HTTP proxy"),
        }
    }

    #[test]
    #[cfg(feature = "http")]
    fn with_base_config_preserves_host_and_port() {
        let proxy = Proxy::HTTP {
            host: "proxy.com".to_string(),
            port: 8080,
            config: Arc::new(HTTPConfig::new("proxy.com", 8080)),
        };
        let base = BaseProxyConfig::new();
        let configured = proxy.with_base_config(Arc::new(base));
        assert_eq!(configured.get_host(), "proxy.com");
        assert_eq!(configured.get_port(), 8080);
    }

    #[test]
    #[cfg(feature = "socks5")]
    fn with_base_config_works_for_socks5() {
        let proxy = Proxy::SOCKS5 {
            host: "proxy.com".to_string(),
            port: 1080,
            config: Arc::new(SOCKS5Config::new("proxy.com", 1080)),
        };
        let mut base = BaseProxyConfig::new();
        base.set_tcp_nodelay(true);
        let configured = proxy.with_base_config(Arc::new(base));
        match configured {
            Proxy::SOCKS5 { config, .. } => {
                assert!(config.get_base_config().is_tcp_nodelay());
            }
            _ => panic!("expected SOCKS5 proxy"),
        }
    }
}
