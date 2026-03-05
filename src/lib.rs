//! # roxie
//!
//! A modular, async Rust proxy library with the goal of being able to abstract down any remote proxy of any type into a single TCP-like IO stream.
//! Use cases include web scraping, performance testing, and building custom proxy clients and tools.
//! 
//! ## Supported Protocols
//!
//! | Protocol       | Feature flag    | Notes                                    |
//! |----------------|-----------------|------------------------------------------|
//! | HTTP CONNECT   | `http`          | With optional Basic auth                 |
//! | HTTPS CONNECT  | `http`          | HTTP over TLS                            |
//! | SOCKS4         | `socks4`        | With user ID support                     |
//! | SOCKS4A        | `socks4`        | Remote DNS resolution                    |
//! | SOCKS5         | `socks5`        | With username/password auth              |
//! | SOCKS5H        | `socks5`        | Remote DNS resolution                    |
//! | Tor            | `tor`           | SOCKS5 with `.onion` support             |
//! | Shadowsocks    | `shadowsocks`   | AEAD encryption (AES-GCM, ChaCha20)      |
//! | Hysteria2      | `hysteria2`     | QUIC/HTTP3 + optional Salamander obfs    |
//! | VMess          | `vmess`         | (stub, in development)                   |
//! | Trojan         | `trojan`        | (stub, in development)                   |
//!
//! ## Quick Start
//!
//! Add roxie to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! roxie = { version = "0.1", features = ["default"] }
//! ```
//!
//! ### Connect through a single proxy
//!
//! ```no_run
//! use roxie::Proxy;
//! use roxie::config::SOCKS5Config;
//! use std::sync::Arc;
//! use url::Url;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Arc::new(SOCKS5Config::new("proxy.example.com", 1080));
//! let proxy = Proxy::SOCKS5 {
//!     host: "proxy.example.com".to_string(),
//!     port: 1080,
//!     config,
//! };
//!
//! let target = Url::parse("https://httpbin.org/ip")?;
//! let mut stream = proxy.connect(&target).await?;
//! // stream implements AsyncRead + AsyncWrite
//! # Ok(())
//! # }
//! ```
//!
//! ### Build a proxy list from URLs and connect
//!
//! ```no_run
//! use roxie::{ProxyList, ProxyListExt};
//! use url::Url;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let list = ProxyList::from_lines(
//!     "http://proxy1.com:8080
//!     socks5://user:pass@proxy2.com:1080"
//! )?;
//!
//! let target = Url::parse("https://httpbin.org/ip")?;
//! let stream = list.connect_random(&target).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Parse from JSON
//!
//! ```no_run
//! use roxie::ProxyList;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Flat array of URL strings
//! let json = r#"["http://proxy1.com:8080", "socks5://proxy2.com:1080"]"#;
//! let list = ProxyList::from_array(json)?;
//!
//! // Grouped format
//! let grouped = r#"{"configs": [{"protocol": "socks5", "host": "proxy.com", "port": 1080}]}"#;
//! let list = ProxyList::from_json(grouped)?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Performance-aware pool with scoring
//!
//! ```no_run
//! use roxie::{ProxyList, ProxyPool};
//! use roxie::extensions::ProxyPoolExt;
//! use std::sync::Arc;
//! use std::time::Duration;
//! use url::Url;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let list = ProxyList::from_lines("http://a.com:8080\nhttp://b.com:8080")?;
//! let pool = Arc::new(ProxyPool::from_list(&list));
//!
//! let target = Url::parse("https://httpbin.org/ip")?;
//! let stream = pool.connect_with_semaphore(&target, 5).await?;
//!
//! // Feed results back so the pool learns from experience
//! if let Some(proxy) = pool.quick() {
//!     pool.record_success(proxy, Duration::from_millis(120));
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### Key Types
//!
//! * [`Proxy`] — The central connection primitive. Each variant holds its own
//!   configuration and is self-contained. Call [`Proxy::connect`] to get a
//!   [`ProxyStream`].
//!
//! * [`ProxyList`] — An immutable, cheaply-cloneable (`Arc`-backed) ordered
//!   collection of proxies. Parse from newline-delimited URLs, JSON arrays, or
//!   grouped JSON. Supports random selection and full iteration.
//!
//! * [`ProxyPool`] — A [`ProxyList`] with exponential-decay performance scoring.
//!   Call [`record_success`](ProxyPool::record_success) /
//!   [`record_failure`](ProxyPool::record_failure) after each attempt to improve
//!   future selections.
//!
//! * [`ProxyStream`] — A unified `AsyncRead + AsyncWrite` stream returned by
//!   every proxy connection. Transparently wraps TCP, TLS, Shadowsocks AEAD, and
//!   Hysteria2 QUIC streams.
//!
//! * [`ProxyListExt`] — Extension trait on [`ProxyList`] adding connection
//!   strategies: random, sequential iteration, and semaphore-limited concurrent
//!   racing.
//!
//! ## Feature Flags
//!
//! ```toml
//! [dependencies]
//! # Everything enabled (default)
//! roxie = { version = "0.1", features = ["default"] }
//!
//! # Minimal: only HTTP and SOCKS5 over plaintext
//! roxie = { version = "0.1", default-features = false, features = ["http", "socks5"] }
//!
//! # Add TLS support
//! roxie = { version = "0.1", default-features = false, features = ["http", "socks5", "tls"] }
//!
//! # Privacy-focused stack
//! roxie = { version = "0.1", default-features = false, features = ["tor", "shadowsocks", "tls"] }
//! ```
//!
//! | Flag            | Enables                                                   |
//! |-----------------|-----------------------------------------------------------|
//! | `http`          | HTTP/HTTPS CONNECT, Base64, URL parsing                   |
//! | `socks4`        | SOCKS4 and SOCKS4A                                        |
//! | `socks5`        | SOCKS5 and SOCKS5H                                        |
//! | `tls`           | TLS via `rustls` + `tokio-rustls`                         |
//! | `shadowsocks`   | Shadowsocks AEAD (AES-128/256-GCM, ChaCha20-Poly1305)     |
//! | `hysteria2`     | Hysteria2 over QUIC/HTTP3 (includes `tls`)                |
//! | `tor`           | Tor integration via local SOCKS5 (includes `socks5`)      |
//! | `vmess`         | VMess (stub)                                              |
//! | `trojan`        | Trojan (stub)                                             |
//! | `all`           | All of the above                                          |
//! | `default`       | Equivalent to `all`                                       |
//!
//! ## Error Handling
//!
//! All fallible operations return `Result<_, ProxyError>` or `Result<_, ParseError>`.
//! Error types are fully structured — every variant carries named fields describing
//! what failed, where, and why — following the "Five Ws" design principle. No
//! sensitive data (passwords, keys) is ever included in error messages.
//!
//! ```
//! use roxie::errors::{ParseError, ProxyError};
//!
//! let err = ParseError::InvalidUrl {
//!     url: "not-a-url".to_string(),
//!     reason: "missing scheme".to_string(),
//! };
//!
//! assert!(err.to_string().contains("not-a-url"));
//! assert!(err.to_string().contains("missing scheme"));
//! ```
//!
//! ## Configuration
//!
//! Every proxy variant stores an `Arc`-wrapped config struct. All configs share a
//! common [`config::BaseProxyConfig`] through the [`config::HasBaseProxyConfig`]
//! trait, exposing builder methods like:
//!
//! * `set_handshake_timeout(Duration)` — Time allowed for the proxy handshake
//! * `set_phase_timeout(Duration)` — Per-phase read/write timeout (SOCKS5)
//! * `set_tcp_nodelay(bool)` — Disable Nagle's algorithm
//! * `set_auto_tls(bool)` — Automatically wrap connection in TLS for `https://` targets
//! * `set_resolve_locally(bool)` — DNS resolved client-side (SOCKS4) or server-side (SOCKS4A)
//!
//! ```
//! use roxie::config::{HTTPConfig, BaseProxyConfigBuilder};
//! use std::time::Duration;
//!
//! let config = HTTPConfig::new("proxy.example.com", 8080)
//!     .set_credentials("user", "secret")
//!     .set_handshake_timeout(Duration::from_secs(10))
//!     .set_tcp_nodelay(true)
//!     .set_auto_tls(true);
//!
//! config.validate()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Parsing Proxies
//!
//! The [`utils`] module exposes two primary parsers:
//!
//! * [`utils::parse_proxy_url`] — Parse a single proxy URL string into a [`Proxy`]
//! * [`utils::parse_proxy_json`] — Parse a single proxy from a JSON object
//! * [`utils::parse_proxy_list_json`] — Parse a batch from the grouped JSON format
//!
//! URL schemes recognised: `http`, `https`, `socks4`, `socks4a`, `socks5`, `socks5h`,
//! `tor`, `ss` / `shadowsocks`, `hysteria2` / `hy2`.
//!
//! ```
//! use roxie::utils::parse_proxy_url;
//!
//! // Returns Ok(Some(proxy)) on success, Ok(None) for unknown schemes
//! let proxy = parse_proxy_url("socks5://user:pass@proxy.com:1080")?;
//! assert!(proxy.is_some());
//!
//! let unknown = parse_proxy_url("vmess://opaque-base64-blob")?;
//! assert!(unknown.is_none()); // unsupported scheme → None, not an error
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod config;
pub mod errors;
pub mod extensions;
pub mod protocols;
pub mod transport;
pub mod utils;

// Re-export commonly used types for convenience
pub use extensions::ProxyListExt;
pub use transport::{Endpoint, PoolStats, Proxy, ProxyList, ProxyPool, ProxyStream};
