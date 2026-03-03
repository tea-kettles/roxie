//! Error types for the roxie proxy library.
//!
//! This module organizes all error types by domain, providing rich, structured
//! error information following the "Five W pattern" (What, Where, Who, When, Why).
//! Each error carries enough context to understand exactly what went wrong without
//! needing to dig through logs.
//!
//! # Organization
//!
//! Errors are organized into separate modules by domain:
//!
//! * [`config_errors`] - Configuration validation errors
//! * [`EndpointError`] - DNS resolution and endpoint errors  
//! * [`ParseError`] - Proxy URL and JSON parsing errors
//! * [`ProxyError`] - High-level proxy connection errors
//!
//! ## Protocol-Specific Errors
//!
//! Each supported protocol has its own error module (feature-gated):
//!
//! * [`HTTPError`] - HTTP CONNECT proxy errors (feature: `http`)
//! * [`SOCKS4Error`] - SOCKS4/4A protocol errors (feature: `socks4`)
//! * [`SOCKS5Error`] - SOCKS5 protocol errors (feature: `socks5`)
//! * [`ShadowsocksError`] - Shadowsocks AEAD errors (feature: `shadowsocks`)
//! * [`TorError`] - Tor control and SOCKS errors (feature: `tor`)
//! * [`TLSError`] - TLS handshake and certificate errors (feature: `tls`)
//!
//! # Design Philosophy
//!
//! All errors in roxie follow these principles:
//!
//! * **Rich Context**: Every error answers the Five Ws
//! * **Actionable**: Errors tell you what to fix, not just what failed
//! * **No Secrets**: Errors never leak passwords, tokens, or keys
//! * **Source Chains**: Underlying errors are preserved with `#[source]`
//!
//! # Examples
//!
//! Errors carry detailed structured information:
//!
//! ```
//! use roxie::errors::ParseError;
//!
//! let err = ParseError::InvalidUrl {
//!     url: "not-a-url".to_string(),
//!     reason: "missing scheme".to_string(),
//! };
//!
//! // Rich error message with context
//! assert!(err.to_string().contains("not-a-url"));
//! assert!(err.to_string().contains("missing scheme"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

/* Core Error Modules */

pub mod config_errors;
mod endpoint_errors;
mod parse_errors;
mod proxy_errors;

/* Core Error Re-exports */

pub use endpoint_errors::EndpointError;
pub use parse_errors::ParseError;
pub use proxy_errors::ProxyError;

/* Protocol-Specific Error Modules */

#[cfg(feature = "http")]
mod http_errors;
#[cfg(feature = "hysteria2")]
mod hysteria2_errors;
#[cfg(feature = "shadowsocks")]
mod shadowsocks_errors;
#[cfg(feature = "socks4")]
mod socks4_errors;
#[cfg(feature = "socks5")]
mod socks5_errors;
#[cfg(feature = "tls")]
mod tls_errors;
#[cfg(feature = "tor")]
mod tor_errors;
#[cfg(feature = "trojan")]
mod trojan_errors;
#[cfg(feature = "vmess")]
mod vmess_errors;

/* Protocol-Specific Error Re-exports */

#[cfg(feature = "http")]
pub use http_errors::HTTPError;
#[cfg(feature = "hysteria2")]
pub use hysteria2_errors::Hysteria2Error;
#[cfg(feature = "shadowsocks")]
pub use shadowsocks_errors::ShadowsocksError;
#[cfg(feature = "socks4")]
pub use socks4_errors::SOCKS4Error;
#[cfg(feature = "socks5")]
pub use socks5_errors::SOCKS5Error;
#[cfg(feature = "tls")]
pub use tls_errors::TLSError;
#[cfg(feature = "tor")]
pub use tor_errors::TorError;
#[cfg(feature = "trojan")]
pub use trojan_errors::TrojanError;
#[cfg(feature = "vmess")]
pub use vmess_errors::VMessError;
