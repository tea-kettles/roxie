//! Configuration types for proxy connections.
//!
//! This module provides configuration structures for all supported proxy
//! protocols. Each protocol-specific config embeds a `BaseProxyConfig` that
//! contains shared settings like timeouts, DNS resolution, TCP options, and
//! automatic TLS for HTTPS targets.
//!
//! # Architecture
//!
//! The configuration system uses trait-based composition:
//!
//! * [`BaseProxyConfig`] - Shared configuration embedded in all protocol configs
//! * [`HasBaseProxyConfig`] - Trait for types that embed base configuration
//! * [`BaseProxyConfigBuilder`] - Fluent builder methods for base config
//!
//! Protocol-specific configs implement `HasBaseProxyConfig` and automatically
//! gain access to builder methods like `.set_handshake_timeout()`, `.set_tcp_nodelay()`,
//! and `.set_auto_tls()` through the blanket trait implementation.
//!
//! # Protocol Configurations
//!
//! Feature-gated protocol configs (enabled with corresponding features):
//!
//! * [`HTTPConfig`] - HTTP CONNECT proxy (feature: `http`)
//! * [`SOCKS4Config`] - SOCKS4/4A proxy (feature: `socks4`)
//! * [`SOCKS5Config`] - SOCKS5 proxy (feature: `socks5`)
//! * [`ShadowsocksConfig`] - Shadowsocks AEAD proxy (feature: `shadowsocks`)
//! * [`TorConfig`] - Tor control and circuit configuration (feature: `tor`)
//! * [`TLSConfig`] - TLS connection settings (feature: `tls`)
//!
//! # Examples
//!
//! Basic HTTP proxy configuration:
//!
//! ```
//! use roxie::config::{HTTPConfig, BaseProxyConfigBuilder};
//! use std::time::Duration;
//!
//! let config = HTTPConfig::new("proxy.example.com", 8080)
//!     .set_credentials("user", "pass")
//!     .set_handshake_timeout(Duration::from_secs(15))
//!     .set_tcp_nodelay(true);
//!
//! config.validate()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! SOCKS5 with custom timeouts:
//!
//! ```
//! use roxie::config::{SOCKS5Config, BaseProxyConfigBuilder};
//! use std::time::Duration;
//!
//! let config = SOCKS5Config::new("proxy.example.com", 1080)
//!     .set_credentials("user", "pass")
//!     .set_phase_timeout(Duration::from_secs(3))
//!     .set_resolve_locally(false);
//!
//! config.validate()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod proxy_config;

#[cfg(feature = "http")]
mod http_config;
#[cfg(feature = "hysteria2")]
mod hysteria2_config;
#[cfg(feature = "shadowsocks")]
mod shadowsocks_config;
#[cfg(feature = "socks4")]
mod socks4_config;
#[cfg(feature = "socks5")]
mod socks5_config;
#[cfg(feature = "tls")]
mod tls_config;
#[cfg(feature = "tor")]
mod tor_config;
#[cfg(feature = "trojan")]
mod trojan_config;
#[cfg(feature = "vmess")]
mod vmess_config;

#[cfg(feature = "http")]
pub use http_config::*;
#[cfg(feature = "hysteria2")]
pub use hysteria2_config::*;
pub use proxy_config::*;
#[cfg(feature = "shadowsocks")]
pub use shadowsocks_config::*;
#[cfg(feature = "socks4")]
pub use socks4_config::*;
#[cfg(feature = "socks5")]
pub use socks5_config::*;
#[cfg(feature = "tls")]
pub use tls_config::*;
#[cfg(feature = "tor")]
pub use tor_config::*;
#[cfg(feature = "trojan")]
pub use trojan_config::*;
#[cfg(feature = "vmess")]
pub use vmess_config::*;
