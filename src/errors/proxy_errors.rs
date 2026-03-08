//! Proxy connection error types.
//!
//! High-level errors that can occur during proxy connection establishment and
//! protocol negotiation. This module provides the unified error type that wraps
//! all protocol-specific errors, making it the primary error type for proxy
//! operations.
//!
//! # Organization
//!
//! The `ProxyError` enum includes:
//! * Generic connection and configuration errors
//! * Protocol-specific errors (wrapped transparently)
//! * URL validation errors
//!
//! # Examples
//!
//! Connection timeout:
//!
//! ```
//! use roxie::errors::ProxyError;
//!
//! let err = ProxyError::ConnectionTimeout {
//!     host: "proxy.example.com".to_string(),
//!     port: 1080,
//!     timeout_ms: 5000,
//! };
//!
//! assert!(err.to_string().contains("timed out"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::io;

#[cfg(feature = "http")]
use crate::errors::HTTPError;
#[cfg(feature = "hysteria2")]
use crate::errors::Hysteria2Error;
#[cfg(feature = "socks4")]
use crate::errors::SOCKS4Error;
#[cfg(feature = "socks5")]
use crate::errors::SOCKS5Error;
#[cfg(feature = "shadowsocks")]
use crate::errors::ShadowsocksError;
#[cfg(feature = "tls")]
use crate::errors::TLSError;
#[cfg(feature = "tor")]
use crate::errors::TorError;
#[cfg(feature = "trojan")]
use crate::errors::TrojanError;

/* Types */

/// High-level proxy connection errors.
///
/// This is the primary error type for all proxy operations. It includes both
/// generic errors (connection failures, configuration issues) and protocol-
/// specific errors (wrapped transparently via `#[error(transparent)]`).
///
/// Protocol-specific errors are only available when their corresponding features
/// are enabled (for example, `HTTPError` requires the `http` feature).
///
/// # Examples
///
/// Unsupported protocol:
///
/// ```
/// use roxie::errors::ProxyError;
///
/// let err = ProxyError::UnsupportedProtocol {
///     scheme: "ftp".to_string(),
/// };
///
/// assert!(err.to_string().contains("unsupported"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// Missing credentials:
///
/// ```
/// use roxie::errors::ProxyError;
///
/// let err = ProxyError::MissingCredentials {
///     protocol: "HTTP".to_string(),
/// };
///
/// assert!(err.to_string().contains("missing credentials"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /* Connection Errors */
    /// Failed to connect to proxy.
    ///
    /// The initial TCP connection to the proxy server failed. This could
    /// indicate network issues, wrong address, or the proxy server being down.
    #[error("failed to connect to proxy {host}:{port}: {source}")]
    ConnectionFailed {
        /// Proxy hostname or IP address.
        host: String,
        /// Proxy port number.
        port: u16,
        /// Underlying connection error.
        #[source]
        source: io::Error,
    },

    /// Connection to proxy timed out.
    ///
    /// The TCP connection attempt exceeded the configured timeout.
    #[error("connection to proxy {host}:{port} timed out after {timeout_ms} ms")]
    ConnectionTimeout {
        /// Proxy hostname or IP address.
        host: String,
        /// Proxy port number.
        port: u16,
        /// Configured timeout in milliseconds.
        timeout_ms: u64,
    },

    /* Protocol Errors */
    /// Unsupported proxy protocol.
    ///
    /// The URL scheme is not recognized as a supported proxy protocol.
    /// Supported protocols depend on which features are enabled.
    #[error("unsupported proxy protocol: '{scheme}'")]
    UnsupportedProtocol {
        /// URL scheme that was not recognized.
        scheme: String,
    },

    /// Protocol handshake failed.
    ///
    /// The proxy handshake failed for reasons not covered by protocol-specific
    /// errors. This is a generic catch-all for unusual handshake failures.
    #[error("protocol handshake failed for {scheme}: {reason}")]
    ProtocolHandshakeFailed {
        /// Protocol scheme.
        scheme: String,
        /// Reason for handshake failure.
        reason: String,
    },

    /* Configuration Errors */
    /// Invalid proxy configuration.
    ///
    /// The proxy configuration is invalid or contains contradictory settings.
    #[error("invalid proxy configuration: {reason}")]
    InvalidConfiguration {
        /// Reason the configuration is invalid.
        reason: String,
    },

    /// Missing credentials for authenticated proxy.
    ///
    /// The proxy requires authentication but no credentials were provided
    /// in the configuration.
    #[error("missing credentials for {protocol} proxy")]
    MissingCredentials {
        /// Protocol name (for example, "HTTP", "SOCKS5").
        protocol: String,
    },

    /// Invalid auto_tls configuration.
    ///
    /// The automatic TLS configuration is invalid or cannot be applied.
    #[error("invalid auto_tls configuration: {reason}")]
    InvalidAutoTLSConfig {
        /// Reason the auto_tls config is invalid.
        reason: String,
    },

    /* Serialization Errors */
    /// JSON serialization failed.
    #[error("serialization error: {message}")]
    SerializationError {
        /// Serialization failure message.
        message: String,
    },

    /* URL Errors */
    /// Target URL missing host.
    ///
    /// The target URL that should be accessed through the proxy does not
    /// specify a hostname.
    #[error("target URL missing host")]
    MissingTargetHost,

    /// Target URL missing port.
    ///
    /// The target URL that should be accessed through the proxy does not
    /// specify a port number.
    #[error("target URL missing port")]
    MissingTargetPort,

    /// Invalid target URL.
    ///
    /// The target URL is malformed or contains invalid components.
    #[error("invalid target URL: {reason}")]
    InvalidTargetUrl {
        /// Reason the URL is invalid.
        reason: String,
    },

    /* Protocol-Specific Errors (Feature-Gated) */
    /// HTTP proxy error.
    ///
    /// Wraps all HTTP CONNECT proxy errors. Available when the `http` feature
    /// is enabled.
    #[cfg(feature = "http")]
    #[error(transparent)]
    HTTP(#[from] HTTPError),

    /// SOCKS4 proxy error.
    ///
    /// Wraps all SOCKS4/4A proxy errors. Available when the `socks4` feature
    /// is enabled.
    #[cfg(feature = "socks4")]
    #[error(transparent)]
    SOCKS4(#[from] SOCKS4Error),

    /// SOCKS5 proxy error.
    ///
    /// Wraps all SOCKS5 proxy errors. Available when the `socks5` feature
    /// is enabled.
    #[cfg(feature = "socks5")]
    #[error(transparent)]
    SOCKS5(#[from] SOCKS5Error),

    /// Shadowsocks proxy error.
    ///
    /// Wraps all Shadowsocks AEAD proxy errors. Available when the `shadowsocks`
    /// feature is enabled.
    #[cfg(feature = "shadowsocks")]
    #[error(transparent)]
    Shadowsocks(#[from] ShadowsocksError),

    /// TLS error.
    ///
    /// Wraps all TLS connection and certificate errors. Available when the
    /// `tls` feature is enabled.
    #[cfg(feature = "tls")]
    #[error(transparent)]
    TLS(#[from] TLSError),

    /// Tor proxy error.
    ///
    /// Wraps all Tor control and SOCKS errors. Available when the `tor`
    /// feature is enabled.
    #[cfg(feature = "tor")]
    #[error(transparent)]
    Tor(#[from] TorError),

    /// Hysteria2 proxy error.
    ///
    /// Wraps all Hysteria2 QUIC proxy errors. Available when the `hysteria2`
    /// feature is enabled.
    #[cfg(feature = "hysteria2")]
    #[error(transparent)]
    Hysteria2(#[from] Hysteria2Error),

    /// Trojan proxy error.
    ///
    /// Wraps all Trojan TLS proxy errors. Available when the `trojan`
    /// feature is enabled.
    #[cfg(feature = "trojan")]
    #[error(transparent)]
    Trojan(#[from] TrojanError),

    /* I/O Errors */
    /// Generic I/O error during proxy operation.
    ///
    /// An I/O error occurred that doesn't fit into more specific categories.
    /// The underlying I/O error is preserved in the error chain.
    #[error("I/O error during proxy operation: {source}")]
    Io {
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
}

/* From Implementations */

impl From<io::Error> for ProxyError {
    /// Convert io::Error to ProxyError.
    ///
    /// This allows using `?` operator with I/O operations in proxy code,
    /// automatically wrapping I/O errors as ProxyError::Io.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::errors::ProxyError;
    /// use std::io;
    ///
    /// fn example() -> Result<(), ProxyError> {
    ///     // I/O errors are automatically converted
    ///     let _ = std::fs::read("/nonexistent")?;
    ///     Ok(())
    /// }
    ///
    /// assert!(example().is_err());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn from(source: io::Error) -> Self {
        Self::Io { source }
    }
}
