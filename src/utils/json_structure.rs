//! JSON structure definitions for proxy configuration parsing.
//!
//! This module defines the expected JSON format for each proxy type.
//! These structures serve as the schema reference for parsing proxy
//! configurations from JSON files or strings.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/* Base Configuration Structures */

/// TLS client configuration for JSON serialization.
///
/// Corresponds to the `TLSConfig` enum in the main configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TLSConfigJson {
    /// Use system defaults with optional ALPN protocols
    Default {
        /// ALPN protocols as strings (e.g., "h2", "http/1.1")
        #[serde(skip_serializing_if = "Option::is_none")]
        alpn: Option<Vec<String>>,
    },
    /// Skip certificate validation (dangerous, testing only)
    DangerAcceptInvalidCerts,
}

impl Default for TLSConfigJson {
    fn default() -> Self {
        TLSConfigJson::Default { alpn: None }
    }
}

/// Common configuration options shared across basic proxy protocols.
///
/// Used by: HTTP, HTTPS, SOCKS4, SOCKS4A, SOCKS5, SOCKS5H
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyConfigJson {
    /// Timeout for the complete handshake sequence (seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake_timeout: Option<u64>,

    /// Timeout for individual protocol phases (seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase_timeout: Option<u64>,

    /// Whether to resolve target addresses locally before connecting
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolve_locally: Option<bool>,

    /// Enable TCP_NODELAY for the connection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_nodelay: Option<bool>,

    /// TCP keep-alive interval (seconds), null to disable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_alive: Option<u64>,

    /// Enable automatic TLS for HTTPS targets
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_tls: Option<bool>,

    /// TLS configuration settings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_config: Option<TLSConfigJson>,
}

impl Default for ProxyConfigJson {
    fn default() -> Self {
        Self {
            handshake_timeout: Some(10),
            phase_timeout: Some(5),
            resolve_locally: Some(false),
            tcp_nodelay: Some(true),
            keep_alive: Some(60),
            auto_tls: Some(true),
            tls_config: None,
        }
    }
}

impl ProxyConfigJson {
    /// Returns the handshake timeout as a `Duration`.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::utils::json_structure::ProxyConfigJson;
    /// use std::time::Duration;
    ///
    /// let config = ProxyConfigJson { handshake_timeout: Some(5), ..ProxyConfigJson::default() };
    /// assert_eq!(config.handshake_timeout_duration(), Duration::from_secs(5));
    /// ```
    pub fn handshake_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.handshake_timeout.unwrap_or(10))
    }

    /// Returns the per-phase timeout as a `Duration`.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::utils::json_structure::ProxyConfigJson;
    /// use std::time::Duration;
    ///
    /// let config = ProxyConfigJson { phase_timeout: Some(3), ..ProxyConfigJson::default() };
    /// assert_eq!(config.phase_timeout_duration(), Duration::from_secs(3));
    /// ```
    pub fn phase_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.phase_timeout.unwrap_or(5))
    }

    /// Returns the TCP keep-alive interval as a `Duration`, if configured.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::utils::json_structure::ProxyConfigJson;
    /// use std::time::Duration;
    ///
    /// let config = ProxyConfigJson { keep_alive: Some(30), ..ProxyConfigJson::default() };
    /// assert_eq!(config.keep_alive_duration(), Some(Duration::from_secs(30)));
    /// ```
    pub fn keep_alive_duration(&self) -> Option<Duration> {
        self.keep_alive.map(Duration::from_secs)
    }
}

/// Configuration for Shadowsocks proxies.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ShadowsocksConfigJson {
    /// Encryption method (e.g., "aes-256-gcm", "chacha20-poly1305")
    pub method: String,

    /// Optional plugin for obfuscation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,

    /// Plugin options/arguments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_opts: Option<String>,

    /// Connection timeout (seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_timeout: Option<u64>,

    /// Enable UDP relay support
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_relay: Option<bool>,

    /// Enable TCP Fast Open
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_fast_open: Option<bool>,
}

impl Default for ShadowsocksConfigJson {
    fn default() -> Self {
        Self {
            method: "aes-256-gcm".to_string(),
            connection_timeout: Some(10),
            plugin: None,
            plugin_opts: None,
            udp_relay: Some(false),
            tcp_fast_open: Some(false),
        }
    }
}

impl ShadowsocksConfigJson {
    /// Returns the connection timeout as a `Duration`.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::utils::json_structure::ShadowsocksConfigJson;
    /// use std::time::Duration;
    ///
    /// let config = ShadowsocksConfigJson { connection_timeout: Some(12), ..ShadowsocksConfigJson::default() };
    /// assert_eq!(config.connection_timeout_duration(), Duration::from_secs(12));
    /// ```
    pub fn connection_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.connection_timeout.unwrap_or(10))
    }
}

/// Configuration for Hysteria2 proxies.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Hysteria2ConfigJson {
    /// Upload bandwidth limit (Mbps)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up_mbps: Option<u32>,

    /// Download bandwidth limit (Mbps)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub down_mbps: Option<u32>,

    /// Congestion control algorithm (e.g., "bbr", "cubic")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub congestion_control: Option<String>,

    /// SNI for TLS handshake
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,

    /// Skip certificate verification (insecure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,

    /// ALPN protocol negotiation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,

    /// Connection timeout (seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_timeout: Option<u64>,

    /// Idle timeout (seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_timeout: Option<u64>,
}

impl Default for Hysteria2ConfigJson {
    fn default() -> Self {
        Self {
            up_mbps: Some(0),
            down_mbps: Some(0),
            congestion_control: Some("bbr".to_string()),
            sni: None,
            skip_cert_verify: Some(false),
            alpn: Some("h3".to_string()),
            connection_timeout: Some(10),
            idle_timeout: Some(60),
        }
    }
}

impl Hysteria2ConfigJson {
    /// Returns the connection timeout as a `Duration`.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::utils::json_structure::Hysteria2ConfigJson;
    /// use std::time::Duration;
    ///
    /// let config = Hysteria2ConfigJson { connection_timeout: Some(15), ..Hysteria2ConfigJson::default() };
    /// assert_eq!(config.connection_timeout_duration(), Duration::from_secs(15));
    /// ```
    pub fn connection_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.connection_timeout.unwrap_or(10))
    }

    /// Returns the idle timeout as a `Duration`.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::utils::json_structure::Hysteria2ConfigJson;
    /// use std::time::Duration;
    ///
    /// let config = Hysteria2ConfigJson { idle_timeout: Some(90), ..Hysteria2ConfigJson::default() };
    /// assert_eq!(config.idle_timeout_duration(), Duration::from_secs(90));
    /// ```
    pub fn idle_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.idle_timeout.unwrap_or(60))
    }
}

/// Configuration for Tor proxies.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TorConfigJson {
    /// Control port host
    pub control_host: String,

    /// Control port number
    pub control_port: u16,

    /// Control port authentication password
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_password: Option<String>,

    /// Exit node selection (e.g., "{us}", "{de,fr}")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_nodes: Option<String>,

    /// Exit nodes to exclude (e.g., "{ru,cn}")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_exit_nodes: Option<String>,

    /// Enforce strict node selection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strict_nodes: Option<bool>,

    /// Use bridge relays
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_bridges: Option<bool>,

    /// Bridge relay configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bridges: Option<String>,
}

impl Default for TorConfigJson {
    fn default() -> Self {
        Self {
            control_host: "127.0.0.1".to_string(),
            control_port: 9051,
            control_password: None,
            exit_nodes: None,
            exclude_exit_nodes: None,
            strict_nodes: Some(false),
            use_bridges: Some(false),
            bridges: None,
        }
    }
}

/// Configuration for VMess proxies.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VMessConfigJson {
    /// Alter ID for additional security
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alter_id: Option<u16>,

    /// Security encryption method (e.g., "auto", "aes-128-gcm", "chacha20-poly1305")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,

    /// Network transport (e.g., "tcp", "ws", "h2", "grpc")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    /// Enable TLS
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_enabled: Option<bool>,

    /// TLS server name for SNI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_server_name: Option<String>,

    /// Allow insecure TLS (skip certificate verification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_allow_insecure: Option<bool>,

    /// WebSocket path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_path: Option<String>,

    /// WebSocket headers
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_headers: Option<String>,

    /// HTTP/2 host
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h2_host: Option<String>,

    /// HTTP/2 path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h2_path: Option<String>,

    /// Connection timeout (seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_timeout: Option<u64>,
}

impl Default for VMessConfigJson {
    fn default() -> Self {
        Self {
            alter_id: Some(0),
            security: Some("auto".to_string()),
            network: Some("tcp".to_string()),
            tls_enabled: Some(false),
            tls_server_name: None,
            tls_allow_insecure: Some(false),
            ws_path: Some("/".to_string()),
            ws_headers: None,
            h2_host: None,
            h2_path: Some("/".to_string()),
            connection_timeout: Some(10),
        }
    }
}

impl VMessConfigJson {
    /// Returns the connection timeout as a `Duration`.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::utils::json_structure::VMessConfigJson;
    /// use std::time::Duration;
    ///
    /// let config = VMessConfigJson { connection_timeout: Some(18), ..VMessConfigJson::default() };
    /// assert_eq!(config.connection_timeout_duration(), Duration::from_secs(18));
    /// ```
    pub fn connection_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.connection_timeout.unwrap_or(10))
    }
}

/// Configuration for Trojan proxies.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TrojanConfigJson {
    /// SNI for TLS handshake
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,

    /// Skip certificate verification (insecure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,

    /// ALPN protocol negotiation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,

    /// Enable WebSocket transport
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_enabled: Option<bool>,

    /// WebSocket path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_path: Option<String>,

    /// WebSocket headers
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_headers: Option<String>,

    /// Connection timeout (seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_timeout: Option<u64>,
}

impl Default for TrojanConfigJson {
    fn default() -> Self {
        Self {
            sni: None,
            skip_cert_verify: Some(false),
            alpn: Some("h2,http/1.1".to_string()),
            ws_enabled: Some(false),
            ws_path: Some("/".to_string()),
            ws_headers: None,
            connection_timeout: Some(10),
        }
    }
}

impl TrojanConfigJson {
    /// Returns the connection timeout as a `Duration`.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::utils::json_structure::TrojanConfigJson;
    /// use std::time::Duration;
    ///
    /// let config = TrojanConfigJson { connection_timeout: Some(22), ..TrojanConfigJson::default() };
    /// assert_eq!(config.connection_timeout_duration(), Duration::from_secs(22));
    /// ```
    pub fn connection_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.connection_timeout.unwrap_or(10))
    }
}

/* Proxy Type Definitions */

/// HTTP proxy configuration.
///
/// # JSON Format
///
/// ```json
/// {
///   "protocol": "http",
///   "host": "proxy.example.com",
///   "port": 8080,
///   "username": "optional-user",
///   "password": "optional-pass",
///   "base": {
///     "handshake_timeout": 10,
///     "phase_timeout": 5,
///     "resolve_locally": false,
///     "tcp_nodelay": true,
///     "keep_alive": 60,
///     "auto_tls": true,
///     "tls_config": null
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProxyJson {
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<ProxyConfigJson>,
}

/// HTTPS proxy configuration.
///
/// # JSON Format
///
/// ```json
/// {
///   "protocol": "https",
///   "host": "proxy.example.com",
///   "port": 443,
///   "username": "optional-user",
///   "password": "optional-pass",
///   "base": {
///     "handshake_timeout": 10,
///     "phase_timeout": 5,
///     "resolve_locally": false,
///     "tcp_nodelay": true,
///     "keep_alive": 60,
///     "auto_tls": true,
///     "tls_config": {
///       "type": "default",
///       "alpn": ["h2", "http/1.1"]
///     }
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpsProxyJson {
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<ProxyConfigJson>,
}

/// SOCKS4 proxy configuration.
///
/// # JSON Format
///
/// ```json
/// {
///   "protocol": "socks4",
///   "host": "proxy.example.com",
///   "port": 1080,
///   "user_id": "optional-user-id",
///   "base": {
///     "handshake_timeout": 10,
///     "phase_timeout": 5,
///     "resolve_locally": false,
///     "tcp_nodelay": true,
///     "keep_alive": 60,
///     "auto_tls": true,
///     "tls_config": null
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks4ProxyJson {
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<ProxyConfigJson>,
}

/// SOCKS4A proxy configuration.
///
/// # JSON Format
///
/// ```json
/// {
///   "protocol": "socks4a",
///   "host": "proxy.example.com",
///   "port": 1080,
///   "user_id": "optional-user-id",
///   "base": {
///     "handshake_timeout": 10,
///     "phase_timeout": 5,
///     "resolve_locally": false,
///     "tcp_nodelay": true,
///     "keep_alive": 60,
///     "auto_tls": true,
///     "tls_config": null
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks4aProxyJson {
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<ProxyConfigJson>,
}

/// SOCKS5 proxy configuration.
///
/// # JSON Format
///
/// ```json
/// {
///   "protocol": "socks5",
///   "host": "proxy.example.com",
///   "port": 1080,
///   "username": "optional-user",
///   "password": "optional-pass",
///   "base": {
///     "handshake_timeout": 10,
///     "phase_timeout": 5,
///     "resolve_locally": false,
///     "tcp_nodelay": true,
///     "keep_alive": 60,
///     "auto_tls": true,
///     "tls_config": null
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5ProxyJson {
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<ProxyConfigJson>,
}

/// SOCKS5H proxy configuration (remote DNS resolution).
///
/// # JSON Format
///
/// ```json
/// {
///   "protocol": "socks5h",
///   "host": "proxy.example.com",
///   "port": 1080,
///   "username": "optional-user",
///   "password": "optional-pass",
///   "base": {
///     "handshake_timeout": 10,
///     "phase_timeout": 5,
///     "resolve_locally": false,
///     "tcp_nodelay": true,
///     "keep_alive": 60,
///     "auto_tls": true,
///     "tls_config": null
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5hProxyJson {
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<ProxyConfigJson>,
}

/// Shadowsocks proxy configuration.
///
/// # JSON Format
///
/// ```json
/// {
///   "protocol": "shadowsocks",
///   "host": "proxy.example.com",
///   "port": 8388,
///   "password": "secret-password",
///   "base": {
///     "handshake_timeout": 10,
///     "phase_timeout": 5,
///     "resolve_locally": false,
///     "tcp_nodelay": true,
///     "keep_alive": 60,
///     "auto_tls": true,
///     "tls_config": null
///   },
///   "config": {
///     "method": "aes-256-gcm",
///     "plugin": null,
///     "plugin_opts": null,
///     "connection_timeout": 10,
///     "udp_relay": false,
///     "tcp_fast_open": false
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksProxyJson {
    pub host: String,
    pub port: u16,
    pub password: String,
    /// Base proxy options shared across protocols.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<ProxyConfigJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<ShadowsocksConfigJson>,
}

/// Hysteria2 proxy configuration.
///
/// # JSON Format
///
/// ```json
/// {
///   "protocol": "hysteria2",
///   "host": "proxy.example.com",
///   "port": 443,
///   "password": "secret-password",
///   "base": {
///     "handshake_timeout": 10,
///     "phase_timeout": 5,
///     "resolve_locally": false,
///     "tcp_nodelay": true,
///     "keep_alive": 60,
///     "auto_tls": true,
///     "tls_config": null
///   },
///   "config": {
///     "up_mbps": 0,
///     "down_mbps": 0,
///     "congestion_control": "bbr",
///     "sni": "example.com",
///     "skip_cert_verify": false,
///     "alpn": "h3",
///     "connection_timeout": 10,
///     "idle_timeout": 60
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hysteria2ProxyJson {
    pub host: String,
    pub port: u16,
    pub password: String,
    /// Base proxy options shared across protocols.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<ProxyConfigJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<Hysteria2ConfigJson>,
}

/// Tor proxy configuration.
///
/// # JSON Format
///
/// ```json
/// {
///   "protocol": "tor",
///   "host": "127.0.0.1",
///   "port": 9050,
///   "base": {
///     "handshake_timeout": 10,
///     "phase_timeout": 5,
///     "resolve_locally": false,
///     "tcp_nodelay": true,
///     "keep_alive": 60,
///     "auto_tls": true,
///     "tls_config": null
///   },
///   "config": {
///     "control_host": "127.0.0.1",
///     "control_port": 9051,
///     "control_password": "optional-control-pass",
///     "exit_nodes": "{us}",
///     "exclude_exit_nodes": "{ru}",
///     "strict_nodes": true,
///     "use_bridges": false,
///     "bridges": null
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorProxyJson {
    pub host: String,
    pub port: u16,
    /// Base proxy options shared across protocols.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<ProxyConfigJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<TorConfigJson>,
}

/// VMess proxy configuration.
///
/// # JSON Format
///
/// ```json
/// {
///   "protocol": "vmess",
///   "host": "proxy.example.com",
///   "port": 443,
///   "uuid": "vmess-uuid",
///   "base": {
///     "handshake_timeout": 10,
///     "phase_timeout": 5,
///     "resolve_locally": false,
///     "tcp_nodelay": true,
///     "keep_alive": 60,
///     "auto_tls": true,
///     "tls_config": null
///   },
///   "config": {
///     "alter_id": 0,
///     "security": "auto",
///     "network": "tcp",
///     "tls_enabled": true,
///     "tls_server_name": "example.com",
///     "tls_allow_insecure": false,
///     "ws_path": "/ws",
///     "ws_headers": "Host: example.com",
///     "h2_host": "example.com",
///     "h2_path": "/h2",
///     "connection_timeout": 10
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VMessProxyJson {
    pub host: String,
    pub port: u16,
    pub uuid: String,
    /// Base proxy options shared across protocols.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<ProxyConfigJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<VMessConfigJson>,
}

/// Trojan proxy configuration.
///
/// # JSON Format
///
/// ```json
/// {
///   "protocol": "trojan",
///   "host": "proxy.example.com",
///   "port": 443,
///   "password": "trojan-password",
///   "base": {
///     "handshake_timeout": 10,
///     "phase_timeout": 5,
///     "resolve_locally": false,
///     "tcp_nodelay": true,
///     "keep_alive": 60,
///     "auto_tls": true,
///     "tls_config": null
///   },
///   "config": {
///     "sni": "example.com",
///     "skip_cert_verify": false,
///     "alpn": "h2,http/1.1",
///     "ws_enabled": false,
///     "ws_path": "/ws",
///     "ws_headers": "Host: example.com",
///     "connection_timeout": 10
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrojanProxyJson {
    pub host: String,
    pub port: u16,
    pub password: String,
    /// Base proxy options shared across protocols.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<ProxyConfigJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<TrojanConfigJson>,
}

/* Root Proxy Structure */

/// Root proxy configuration with protocol discriminator.
///
/// This is the top-level structure for parsing proxy JSON.
/// The `protocol` field determines which proxy type to parse.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum ProxyJson {
    #[cfg(feature = "http")]
    Http(HttpProxyJson),

    #[cfg(feature = "http")]
    Https(HttpsProxyJson),

    #[cfg(feature = "socks4")]
    Socks4(Socks4ProxyJson),

    #[cfg(feature = "socks4")]
    Socks4a(Socks4aProxyJson),

    #[cfg(feature = "socks5")]
    Socks5(Socks5ProxyJson),

    #[cfg(feature = "socks5")]
    Socks5h(Socks5hProxyJson),

    #[cfg(feature = "shadowsocks")]
    Shadowsocks(ShadowsocksProxyJson),

    #[cfg(feature = "hysteria2")]
    Hysteria2(Hysteria2ProxyJson),

    #[cfg(feature = "tor")]
    Tor(TorProxyJson),

    #[cfg(feature = "vmess")]
    Vmess(VMessProxyJson),

    #[cfg(feature = "trojan")]
    Trojan(TrojanProxyJson),
}

/* Grouped Proxy List Structures */

/// Root structure for grouped proxy list JSON format.
///
/// Groups proxies that share the same base configuration together,
/// reducing duplication and enabling efficient Arc-based config sharing.
///
/// # JSON Format
///
/// ```json
/// {
///   "configs": [
///     {
///       "base": {
///         "handshake_timeout": 10,
///         "phase_timeout": 5,
///         "resolve_locally": false,
///         "tcp_nodelay": true,
///         "keep_alive": 60,
///         "auto_tls": true
///       },
///       "proxies": [
///         { "protocol": "http", "host": "proxy1.com", "port": 8080 },
///         { "protocol": "socks5", "host": "proxy2.com", "port": 1080 }
///       ]
///     }
///   ]
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyListJson {
    pub configs: Vec<ProxyGroupJson>,
}

/// A group of proxies sharing the same base configuration.
///
/// This structure enables efficient memory usage by storing the base
/// configuration once and sharing it via Arc across all proxies in the group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyGroupJson {
    pub base: ProxyConfigJson,
    pub proxies: Vec<ProxyJson>,
}

impl ProxyListJson {
    /// Creates a new empty proxy list.
    pub fn new() -> Self {
        Self {
            configs: Vec::new(),
        }
    }

    /// Adds a proxy group to the list.
    pub fn add_group(&mut self, group: ProxyGroupJson) {
        self.configs.push(group);
    }
}

impl Default for ProxyListJson {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyGroupJson {
    /// Creates a new proxy group with the specified base configuration.
    pub fn new(base: ProxyConfigJson) -> Self {
        Self {
            base,
            proxies: Vec::new(),
        }
    }

    /// Adds a proxy to this group.
    pub fn add_proxy(&mut self, proxy: ProxyJson) {
        self.proxies.push(proxy);
    }
}

/* TESTS */

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    /* TLSConfigJson tests */

    #[test]
    fn tls_config_json_default_impl_is_default_variant() {
        let tls = TLSConfigJson::default();
        match tls {
            TLSConfigJson::Default { alpn } => {
                assert!(alpn.is_none());
            }
            _ => panic!("Expected TLSConfigJson::Default from Default impl"),
        }
    }

    #[test]
    fn tls_config_json_default_variant_roundtrip_without_alpn() {
        let value = json!({
            "type": "default"
        });

        let tls: TLSConfigJson = serde_json::from_value(value.clone()).unwrap();
        match &tls {
            TLSConfigJson::Default { alpn } => {
                assert!(alpn.is_none());
            }
            _ => panic!("Expected Default variant"),
        }

        let serialized = serde_json::to_value(tls).unwrap();
        assert_eq!(serialized.get("type").unwrap(), "default");
        assert!(serialized.get("alpn").is_none());
    }

    #[test]
    fn tls_config_json_default_variant_with_alpn_roundtrip() {
        let value = json!({
            "type": "default",
            "alpn": ["h2", "http/1.1"]
        });

        let tls: TLSConfigJson = serde_json::from_value(value.clone()).unwrap();
        match &tls {
            TLSConfigJson::Default { alpn } => {
                let alpn = alpn.as_ref().expect("ALPN should be Some");
                assert_eq!(alpn, &vec!["h2".to_string(), "http/1.1".to_string()]);
            }
            _ => panic!("Expected Default variant"),
        }

        let serialized = serde_json::to_value(&tls).unwrap();
        assert_eq!(serialized, value);
    }

    #[test]
    fn tls_config_json_danger_accept_invalid_certs_roundtrip() {
        let value = json!({
            "type": "danger_accept_invalid_certs"
        });

        let tls: TLSConfigJson = serde_json::from_value(value.clone()).unwrap();
        match tls {
            TLSConfigJson::DangerAcceptInvalidCerts => {}
            _ => panic!("Expected DangerAcceptInvalidCerts variant"),
        }

        let serialized = serde_json::to_value(&tls).unwrap();
        assert_eq!(serialized, value);
    }

    #[test]
    fn tls_config_json_rejects_unknown_type() {
        let value = json!({
            "type": "unknown_tls_type"
        });

        let res: Result<TLSConfigJson, _> = serde_json::from_value(value);
        assert!(res.is_err());
    }

    /* ProxyConfigJson tests */

    #[test]
    fn proxy_config_json_default_values() {
        let cfg = ProxyConfigJson::default();
        assert_eq!(cfg.handshake_timeout, Some(10));
        assert_eq!(cfg.phase_timeout, Some(5));
        assert_eq!(cfg.resolve_locally, Some(false));
        assert_eq!(cfg.tcp_nodelay, Some(true));
        assert_eq!(cfg.keep_alive, Some(60));
        assert_eq!(cfg.auto_tls, Some(true));
        assert!(cfg.tls_config.is_none());
    }

    #[test]
    fn proxy_config_json_duration_helpers_use_values_or_defaults() {
        let cfg_custom = ProxyConfigJson {
            handshake_timeout: Some(7),
            phase_timeout: Some(3),
            keep_alive: Some(30),
            ..ProxyConfigJson::default()
        };

        assert_eq!(
            cfg_custom.handshake_timeout_duration(),
            Duration::from_secs(7)
        );
        assert_eq!(cfg_custom.phase_timeout_duration(), Duration::from_secs(3));
        assert_eq!(
            cfg_custom.keep_alive_duration(),
            Some(Duration::from_secs(30))
        );

        let cfg_none = ProxyConfigJson {
            handshake_timeout: None,
            phase_timeout: None,
            keep_alive: None,
            ..ProxyConfigJson::default()
        };

        assert_eq!(
            cfg_none.handshake_timeout_duration(),
            Duration::from_secs(10)
        );
        assert_eq!(cfg_none.phase_timeout_duration(), Duration::from_secs(5));
        assert!(cfg_none.keep_alive_duration().is_none());
    }

    #[test]
    fn proxy_config_json_roundtrip_with_tls_config() {
        let tls = TLSConfigJson::Default {
            alpn: Some(vec!["h2".into(), "http/1.1".into()]),
        };
        let cfg = ProxyConfigJson {
            handshake_timeout: Some(12),
            phase_timeout: Some(6),
            resolve_locally: Some(true),
            tcp_nodelay: Some(false),
            keep_alive: Some(120),
            auto_tls: Some(true),
            tls_config: Some(tls),
        };

        let value = serde_json::to_value(&cfg).unwrap();
        let parsed: ProxyConfigJson = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(parsed.handshake_timeout, Some(12));
        assert_eq!(parsed.phase_timeout, Some(6));
        assert_eq!(parsed.resolve_locally, Some(true));
        assert_eq!(parsed.tcp_nodelay, Some(false));
        assert_eq!(parsed.keep_alive, Some(120));
        assert_eq!(parsed.auto_tls, Some(true));
        assert!(parsed.tls_config.is_some());

        // Confirm ALPN content
        let tls = parsed.tls_config.as_ref().unwrap();
        match tls {
            TLSConfigJson::Default { alpn } => {
                let alpn = alpn.as_ref().unwrap();
                assert_eq!(*alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
            }
            _ => panic!("Expected Default TLS config"),
        }

        // Roundtrip again
        let roundtrip_value = serde_json::to_value(parsed).unwrap();
        assert_eq!(value, roundtrip_value);
    }

    #[test]
    fn proxy_config_json_rejects_invalid_types_for_timeouts() {
        // handshake_timeout as negative integer
        let value = json!({
            "handshake_timeout": -1,
            "phase_timeout": 5u64
        });

        let res: Result<ProxyConfigJson, _> = serde_json::from_value(value);
        assert!(res.is_err());
    }

    /* ShadowsocksConfigJson tests */

    #[test]
    fn shadowsocks_config_json_default_values_and_duration() {
        let cfg = ShadowsocksConfigJson::default();
        assert_eq!(cfg.method, "aes-256-gcm");
        assert_eq!(cfg.connection_timeout, Some(10));
        assert!(cfg.plugin.is_none());
        assert!(cfg.plugin_opts.is_none());
        assert_eq!(cfg.udp_relay, Some(false));
        assert_eq!(cfg.tcp_fast_open, Some(false));

        assert_eq!(cfg.connection_timeout_duration(), Duration::from_secs(10));
    }

    #[test]
    fn shadowsocks_config_json_custom_connection_timeout() {
        let cfg = ShadowsocksConfigJson {
            connection_timeout: Some(20),
            ..ShadowsocksConfigJson::default()
        };
        assert_eq!(cfg.connection_timeout_duration(), Duration::from_secs(20));
    }

    /* Hysteria2ConfigJson tests */

    #[test]
    fn hysteria2_config_json_default_values_and_durations() {
        let cfg = Hysteria2ConfigJson::default();
        assert_eq!(cfg.up_mbps, Some(0));
        assert_eq!(cfg.down_mbps, Some(0));
        assert_eq!(cfg.congestion_control, Some("bbr".to_string()));
        assert!(cfg.sni.is_none());
        assert_eq!(cfg.skip_cert_verify, Some(false));
        assert_eq!(cfg.alpn, Some("h3".to_string()));
        assert_eq!(cfg.connection_timeout, Some(10));
        assert_eq!(cfg.idle_timeout, Some(60));

        assert_eq!(cfg.connection_timeout_duration(), Duration::from_secs(10));
        assert_eq!(cfg.idle_timeout_duration(), Duration::from_secs(60));
    }

    #[test]
    fn hysteria2_config_json_custom_durations() {
        let cfg = Hysteria2ConfigJson {
            connection_timeout: Some(15),
            idle_timeout: Some(90),
            ..Hysteria2ConfigJson::default()
        };

        assert_eq!(cfg.connection_timeout_duration(), Duration::from_secs(15));
        assert_eq!(cfg.idle_timeout_duration(), Duration::from_secs(90));
    }

    /* TorConfigJson tests */

    #[test]
    fn tor_config_json_default_values() {
        let cfg = TorConfigJson::default();
        assert_eq!(cfg.control_host, "127.0.0.1");
        assert_eq!(cfg.control_port, 9051);
        assert!(cfg.control_password.is_none());
        assert!(cfg.exit_nodes.is_none());
        assert!(cfg.exclude_exit_nodes.is_none());
        assert_eq!(cfg.strict_nodes, Some(false));
        assert_eq!(cfg.use_bridges, Some(false));
        assert!(cfg.bridges.is_none());
    }

    /* VMessConfigJson tests */

    #[test]
    fn vmess_config_json_default_values_and_duration() {
        let cfg = VMessConfigJson::default();
        assert_eq!(cfg.alter_id, Some(0));
        assert_eq!(cfg.security, Some("auto".to_string()));
        assert_eq!(cfg.network, Some("tcp".to_string()));
        assert_eq!(cfg.tls_enabled, Some(false));
        assert!(cfg.tls_server_name.is_none());
        assert_eq!(cfg.tls_allow_insecure, Some(false));
        assert_eq!(cfg.ws_path, Some("/".to_string()));
        assert!(cfg.ws_headers.is_none());
        assert!(cfg.h2_host.is_none());
        assert_eq!(cfg.h2_path, Some("/".to_string()));
        assert_eq!(cfg.connection_timeout, Some(10));

        assert_eq!(cfg.connection_timeout_duration(), Duration::from_secs(10));
    }

    #[test]
    fn vmess_config_json_custom_connection_timeout() {
        let cfg = VMessConfigJson {
            connection_timeout: Some(18),
            ..VMessConfigJson::default()
        };

        assert_eq!(cfg.connection_timeout_duration(), Duration::from_secs(18));
    }

    /* TrojanConfigJson tests */

    #[test]
    fn trojan_config_json_default_values_and_duration() {
        let cfg = TrojanConfigJson::default();
        assert!(cfg.sni.is_none());
        assert_eq!(cfg.skip_cert_verify, Some(false));
        assert_eq!(cfg.alpn, Some("h2,http/1.1".to_string()));
        assert_eq!(cfg.ws_enabled, Some(false));
        assert_eq!(cfg.ws_path, Some("/".to_string()));
        assert!(cfg.ws_headers.is_none());
        assert_eq!(cfg.connection_timeout, Some(10));

        assert_eq!(cfg.connection_timeout_duration(), Duration::from_secs(10));
    }

    #[test]
    fn trojan_config_json_custom_connection_timeout() {
        let cfg = TrojanConfigJson {
            connection_timeout: Some(22),
            ..TrojanConfigJson::default()
        };

        assert_eq!(cfg.connection_timeout_duration(), Duration::from_secs(22));
    }

    /* Individual proxy JSON structs (without ProxyJson root) */

    #[test]
    fn http_proxy_json_minimal_deserializes_and_defaults_base() {
        let value = json!({
            "host": "proxy.example.com",
            "port": 8080
        });

        let http: HttpProxyJson = serde_json::from_value(value).unwrap();
        assert_eq!(http.host, "proxy.example.com");
        assert_eq!(http.port, 8080);
        assert!(http.username.is_none());
        assert!(http.password.is_none());
        assert!(http.base.is_none());

        // Caller can apply defaults for base if needed
        let base = http.base.unwrap_or_default();
        assert_eq!(base.handshake_timeout, Some(10));
    }

    #[test]
    fn http_proxy_json_full_roundtrip_with_base() {
        let value = json!({
            "host": "proxy.example.com",
            "port": 8080,
            "username": "user",
            "password": "pass",
            "base": {
                "handshake_timeout": 20,
                "phase_timeout": 10,
                "resolve_locally": true,
                "tcp_nodelay": false,
                "keep_alive": 120,
                "auto_tls": false,
                "tls_config": {
                    "type": "default",
                    "alpn": ["h2"]
                }
            }
        });

        let http: HttpProxyJson = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(http.host, "proxy.example.com");
        assert_eq!(http.port, 8080);
        assert_eq!(http.username.as_deref(), Some("user"));
        assert_eq!(http.password.as_deref(), Some("pass"));

        let base = http.base.as_ref().unwrap();
        assert_eq!(base.handshake_timeout, Some(20));
        assert_eq!(base.phase_timeout, Some(10));
        assert_eq!(base.resolve_locally, Some(true));
        assert_eq!(base.tcp_nodelay, Some(false));
        assert_eq!(base.keep_alive, Some(120));
        assert_eq!(base.auto_tls, Some(false));
        assert!(base.tls_config.is_some());

        let serialized = serde_json::to_value(&http).unwrap();
        assert_eq!(serialized, value);
    }

    #[test]
    fn socks5_proxy_json_with_credentials_and_base_roundtrip() {
        let value = json!({
            "host": "proxy.example.com",
            "port": 1080,
            "username": "user",
            "password": "pass",
            "base": {
                "handshake_timeout": 5,
                "phase_timeout": 2,
                "resolve_locally": false,
                "tcp_nodelay": true,
                "keep_alive": 60,
                "auto_tls": true
            }
        });

        let s5: Socks5ProxyJson = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(s5.host, "proxy.example.com");
        assert_eq!(s5.port, 1080);
        assert_eq!(s5.username.as_deref(), Some("user"));
        assert_eq!(s5.password.as_deref(), Some("pass"));

        let base = s5.base.as_ref().unwrap();
        assert_eq!(base.handshake_timeout, Some(5));
        assert_eq!(base.phase_timeout, Some(2));
        assert_eq!(base.resolve_locally, Some(false));
        assert_eq!(base.tcp_nodelay, Some(true));
        assert_eq!(base.keep_alive, Some(60));
        assert_eq!(base.auto_tls, Some(true));

        let serialized = serde_json::to_value(&s5).unwrap();
        assert_eq!(serialized, value);
    }

    #[test]
    fn socks4_proxy_json_with_user_id_roundtrip() {
        let value = json!({
            "host": "proxy.example.com",
            "port": 1080,
            "user_id": "some-id"
        });

        let s4: Socks4ProxyJson = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(s4.host, "proxy.example.com");
        assert_eq!(s4.port, 1080);
        assert_eq!(s4.user_id.as_deref(), Some("some-id"));

        let serialized = serde_json::to_value(&s4).unwrap();
        assert_eq!(serialized, value);
    }

    #[test]
    fn socks4a_proxy_json_with_user_id_roundtrip() {
        let value = json!({
            "host": "proxy.example.com",
            "port": 1080,
            "user_id": "some-id"
        });

        let s4a: Socks4aProxyJson = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(s4a.host, "proxy.example.com");
        assert_eq!(s4a.port, 1080);
        assert_eq!(s4a.user_id.as_deref(), Some("some-id"));

        let serialized = serde_json::to_value(&s4a).unwrap();
        assert_eq!(serialized, value);
    }

    #[test]
    fn socks5h_proxy_json_roundtrip() {
        let value = json!({
            "host": "proxy.example.com",
            "port": 1080,
            "username": "user",
            "password": "pass"
        });

        let s5h: Socks5hProxyJson = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(s5h.host, "proxy.example.com");
        assert_eq!(s5h.port, 1080);
        assert_eq!(s5h.username.as_deref(), Some("user"));
        assert_eq!(s5h.password.as_deref(), Some("pass"));

        let serialized = serde_json::to_value(&s5h).unwrap();
        assert_eq!(serialized, value);
    }

    #[test]
    fn shadowsocks_proxy_json_full_roundtrip() {
        let value = json!({
            "host": "proxy.example.com",
            "port": 8388,
            "password": "secret",
            "base": {
                "handshake_timeout": 10,
                "phase_timeout": 5
            },
            "config": {
                "method": "chacha20-poly1305",
                "plugin": "obfs-local",
                "plugin_opts": "obfs=http;obfs-host=example.com",
                "connection_timeout": 12,
                "udp_relay": true,
                "tcp_fast_open": true
            }
        });

        let ss: ShadowsocksProxyJson = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(ss.host, "proxy.example.com");
        assert_eq!(ss.port, 8388);
        assert_eq!(ss.password, "secret");

        let cfg = ss.config.as_ref().unwrap();
        assert_eq!(cfg.method, "chacha20-poly1305");
        assert_eq!(cfg.plugin.as_deref(), Some("obfs-local"));
        assert_eq!(
            cfg.plugin_opts.as_deref(),
            Some("obfs=http;obfs-host=example.com")
        );
        assert_eq!(cfg.connection_timeout, Some(12));
        assert_eq!(cfg.connection_timeout_duration(), Duration::from_secs(12));
        assert_eq!(cfg.udp_relay, Some(true));
        assert_eq!(cfg.tcp_fast_open, Some(true));

        let base = ss.base.as_ref().unwrap();
        assert_eq!(base.handshake_timeout, Some(10));
        assert_eq!(base.phase_timeout, Some(5));
        assert_eq!(base.resolve_locally, Some(false));
        assert_eq!(base.tcp_nodelay, Some(true));
        assert_eq!(base.keep_alive, Some(60));
        assert_eq!(base.auto_tls, Some(true));

        let serialized = serde_json::to_value(&ss).unwrap();
        let expected = json!({
            "host": "proxy.example.com",
            "port": 8388,
            "password": "secret",
            "base": {
                "handshake_timeout": 10,
                "phase_timeout": 5,
                "resolve_locally": false,
                "tcp_nodelay": true,
                "keep_alive": 60,
                "auto_tls": true
            },
            "config": {
                "method": "chacha20-poly1305",
                "plugin": "obfs-local",
                "plugin_opts": "obfs=http;obfs-host=example.com",
                "connection_timeout": 12,
                "udp_relay": true,
                "tcp_fast_open": true
            }
        });
        assert_eq!(serialized, expected);
    }

    #[test]
    fn hysteria2_proxy_json_full_roundtrip() {
        let value = json!({
            "host": "proxy.example.com",
            "port": 443,
            "password": "secret",
            "base": {
                "handshake_timeout": 10,
                "phase_timeout": 5
            },
            "config": {
                "up_mbps": 10,
                "down_mbps": 100,
                "congestion_control": "cubic",
                "sni": "example.com",
                "skip_cert_verify": true,
                "alpn": "h3",
                "connection_timeout": 15,
                "idle_timeout": 120
            }
        });

        let hy: Hysteria2ProxyJson = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(hy.host, "proxy.example.com");
        assert_eq!(hy.port, 443);
        assert_eq!(hy.password, "secret");

        let cfg = hy.config.as_ref().unwrap();
        assert_eq!(cfg.up_mbps, Some(10));
        assert_eq!(cfg.down_mbps, Some(100));
        assert_eq!(cfg.congestion_control.as_deref(), Some("cubic"));
        assert_eq!(cfg.sni.as_deref(), Some("example.com"));
        assert_eq!(cfg.skip_cert_verify, Some(true));
        assert_eq!(cfg.alpn.as_deref(), Some("h3"));
        assert_eq!(cfg.connection_timeout, Some(15));
        assert_eq!(cfg.idle_timeout, Some(120));

        let base = hy.base.as_ref().unwrap();
        assert_eq!(base.handshake_timeout, Some(10));
        assert_eq!(base.phase_timeout, Some(5));
        assert_eq!(base.resolve_locally, Some(false));
        assert_eq!(base.tcp_nodelay, Some(true));
        assert_eq!(base.keep_alive, Some(60));
        assert_eq!(base.auto_tls, Some(true));

        let serialized = serde_json::to_value(&hy).unwrap();
        let expected = json!({
            "host": "proxy.example.com",
            "port": 443,
            "password": "secret",
            "base": {
                "handshake_timeout": 10,
                "phase_timeout": 5,
                "resolve_locally": false,
                "tcp_nodelay": true,
                "keep_alive": 60,
                "auto_tls": true
            },
            "config": {
                "up_mbps": 10,
                "down_mbps": 100,
                "congestion_control": "cubic",
                "sni": "example.com",
                "skip_cert_verify": true,
                "alpn": "h3",
                "connection_timeout": 15,
                "idle_timeout": 120
            }
        });
        assert_eq!(serialized, expected);
    }

    #[test]
    fn tor_proxy_json_full_roundtrip() {
        let value = json!({
            "host": "127.0.0.1",
            "port": 9050,
            "base": {
                "handshake_timeout": 12,
                "phase_timeout": 6,
                "resolve_locally": false,
                "tcp_nodelay": true,
                "keep_alive": 60,
                "auto_tls": true
            },
            "config": {
                "control_host": "127.0.0.1",
                "control_port": 9051,
                "control_password": "ctrl-pass",
                "exit_nodes": "{us}",
                "exclude_exit_nodes": "{ru}",
                "strict_nodes": true,
                "use_bridges": true,
                "bridges": "bridge config"
            }
        });

        let tor: TorProxyJson = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(tor.host, "127.0.0.1");
        assert_eq!(tor.port, 9050);
        let base = tor.base.as_ref().unwrap();
        assert_eq!(base.handshake_timeout, Some(12));
        assert_eq!(base.phase_timeout, Some(6));
        assert_eq!(base.resolve_locally, Some(false));
        assert_eq!(base.tcp_nodelay, Some(true));
        assert_eq!(base.keep_alive, Some(60));
        assert_eq!(base.auto_tls, Some(true));

        let cfg = tor.config.as_ref().unwrap();
        assert_eq!(cfg.control_host, "127.0.0.1");
        assert_eq!(cfg.control_port, 9051);
        assert_eq!(cfg.control_password.as_deref(), Some("ctrl-pass"));
        assert_eq!(cfg.exit_nodes.as_deref(), Some("{us}"));
        assert_eq!(cfg.exclude_exit_nodes.as_deref(), Some("{ru}"));
        assert_eq!(cfg.strict_nodes, Some(true));
        assert_eq!(cfg.use_bridges, Some(true));
        assert_eq!(cfg.bridges.as_deref(), Some("bridge config"));

        let serialized = serde_json::to_value(&tor).unwrap();
        assert_eq!(serialized, value);
    }

    #[test]
    fn vmess_proxy_json_full_roundtrip() {
        let value = json!({
            "host": "proxy.example.com",
            "port": 443,
            "uuid": "vmess-uuid",
            "base": {
                "handshake_timeout": 10,
                "phase_timeout": 5
            },
            "config": {
                "alter_id": 0,
                "security": "auto",
                "network": "ws",
                "tls_enabled": true,
                "tls_server_name": "example.com",
                "tls_allow_insecure": false,
                "ws_path": "/ws",
                "ws_headers": "Host: example.com",
                "h2_host": "example.com",
                "h2_path": "/h2",
                "connection_timeout": 10
            }
        });

        let vm: VMessProxyJson = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(vm.host, "proxy.example.com");
        assert_eq!(vm.port, 443);
        assert_eq!(vm.uuid, "vmess-uuid");

        let cfg = vm.config.as_ref().unwrap();
        assert_eq!(cfg.alter_id, Some(0));
        assert_eq!(cfg.security.as_deref(), Some("auto"));
        assert_eq!(cfg.network.as_deref(), Some("ws"));
        assert_eq!(cfg.tls_enabled, Some(true));
        assert_eq!(cfg.tls_server_name.as_deref(), Some("example.com"));
        assert_eq!(cfg.tls_allow_insecure, Some(false));
        assert_eq!(cfg.ws_path.as_deref(), Some("/ws"));
        assert_eq!(cfg.ws_headers.as_deref(), Some("Host: example.com"));
        assert_eq!(cfg.h2_host.as_deref(), Some("example.com"));
        assert_eq!(cfg.h2_path.as_deref(), Some("/h2"));
        assert_eq!(cfg.connection_timeout, Some(10));

        let base = vm.base.as_ref().unwrap();
        assert_eq!(base.handshake_timeout, Some(10));
        assert_eq!(base.phase_timeout, Some(5));
        assert_eq!(base.resolve_locally, Some(false));
        assert_eq!(base.tcp_nodelay, Some(true));
        assert_eq!(base.keep_alive, Some(60));
        assert_eq!(base.auto_tls, Some(true));

        let serialized = serde_json::to_value(&vm).unwrap();
        let expected = json!({
            "host": "proxy.example.com",
            "port": 443,
            "uuid": "vmess-uuid",
            "base": {
                "handshake_timeout": 10,
                "phase_timeout": 5,
                "resolve_locally": false,
                "tcp_nodelay": true,
                "keep_alive": 60,
                "auto_tls": true
            },
            "config": {
                "alter_id": 0,
                "security": "auto",
                "network": "ws",
                "tls_enabled": true,
                "tls_server_name": "example.com",
                "tls_allow_insecure": false,
                "ws_path": "/ws",
                "ws_headers": "Host: example.com",
                "h2_host": "example.com",
                "h2_path": "/h2",
                "connection_timeout": 10
            }
        });
        assert_eq!(serialized, expected);
    }

    #[test]
    fn trojan_proxy_json_full_roundtrip() {
        let value = json!({
            "host": "proxy.example.com",
            "port": 443,
            "password": "trojan-password",
            "base": {
                "handshake_timeout": 10,
                "phase_timeout": 5
            },
            "config": {
                "sni": "example.com",
                "skip_cert_verify": false,
                "alpn": "h2,http/1.1",
                "ws_enabled": true,
                "ws_path": "/ws",
                "ws_headers": "Host: example.com",
                "connection_timeout": 10
            }
        });

        let tr: TrojanProxyJson = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(tr.host, "proxy.example.com");
        assert_eq!(tr.port, 443);
        assert_eq!(tr.password, "trojan-password");

        let cfg = tr.config.as_ref().unwrap();
        assert_eq!(cfg.sni.as_deref(), Some("example.com"));
        assert_eq!(cfg.skip_cert_verify, Some(false));
        assert_eq!(cfg.alpn.as_deref(), Some("h2,http/1.1"));
        assert_eq!(cfg.ws_enabled, Some(true));
        assert_eq!(cfg.ws_path.as_deref(), Some("/ws"));
        assert_eq!(cfg.ws_headers.as_deref(), Some("Host: example.com"));
        assert_eq!(cfg.connection_timeout, Some(10));

        let base = tr.base.as_ref().unwrap();
        assert_eq!(base.handshake_timeout, Some(10));
        assert_eq!(base.phase_timeout, Some(5));
        assert_eq!(base.resolve_locally, Some(false));
        assert_eq!(base.tcp_nodelay, Some(true));
        assert_eq!(base.keep_alive, Some(60));
        assert_eq!(base.auto_tls, Some(true));

        let serialized = serde_json::to_value(&tr).unwrap();
        let expected = json!({
            "host": "proxy.example.com",
            "port": 443,
            "password": "trojan-password",
            "base": {
                "handshake_timeout": 10,
                "phase_timeout": 5,
                "resolve_locally": false,
                "tcp_nodelay": true,
                "keep_alive": 60,
                "auto_tls": true
            },
            "config": {
                "sni": "example.com",
                "skip_cert_verify": false,
                "alpn": "h2,http/1.1",
                "ws_enabled": true,
                "ws_path": "/ws",
                "ws_headers": "Host: example.com",
                "connection_timeout": 10
            }
        });
        assert_eq!(serialized, expected);
    }

    /* Root ProxyJson tests */

    #[cfg(feature = "http")]
    #[test]
    fn proxy_json_http_variant_roundtrip() {
        let value = json!({
            "protocol": "http",
            "host": "proxy.example.com",
            "port": 8080,
            "username": "user",
            "password": "pass"
        });

        let proxy: ProxyJson = serde_json::from_value(value.clone()).unwrap();
        match &proxy {
            ProxyJson::Http(http) => {
                assert_eq!(http.host, "proxy.example.com");
                assert_eq!(http.port, 8080);
                assert_eq!(http.username.as_deref(), Some("user"));
                assert_eq!(http.password.as_deref(), Some("pass"));
            }
            _ => panic!("Expected Http variant"),
        }

        let serialized = serde_json::to_value(&proxy).unwrap();
        assert_eq!(serialized, value);
    }

    #[cfg(feature = "http")]
    #[test]
    fn proxy_json_https_variant_roundtrip() {
        let input = json!({
            "protocol": "https",
            "host": "proxy.example.com",
            "port": 443,
            "username": "user",
            "password": "pass",
            "base": {
                "handshake_timeout": 10,
                "phase_timeout": 5,
                "tls_config": {
                    "type": "default",
                    "alpn": ["h2", "http/1.1"]
                }
            }
        });

        let expected = json!({
            "protocol": "https",
            "host": "proxy.example.com",
            "port": 443,
            "username": "user",
            "password": "pass",
            "base": {
                // explicit defaults are preserved on export
                "auto_tls": true,
                "tcp_nodelay": true,
                "resolve_locally": false,
                "keep_alive": 60,

                "handshake_timeout": 10,
                "phase_timeout": 5,

                "tls_config": {
                    "type": "default",
                    "alpn": ["h2", "http/1.1"]
                }
            }
        });

        let proxy: ProxyJson = serde_json::from_value(input).unwrap();

        match &proxy {
            ProxyJson::Https(https) => {
                assert_eq!(https.host, "proxy.example.com");
                assert_eq!(https.port, 443);
                assert_eq!(https.username.as_deref(), Some("user"));
                assert_eq!(https.password.as_deref(), Some("pass"));
                assert!(https.base.is_some());
            }
            _ => panic!("Expected Https variant"),
        }

        let serialized = serde_json::to_value(&proxy).unwrap();
        assert_eq!(serialized, expected);
    }

    #[cfg(feature = "socks4")]
    #[test]
    fn proxy_json_socks4_variant_roundtrip() {
        let value = json!({
            "protocol": "socks4",
            "host": "proxy.example.com",
            "port": 1080,
            "user_id": "user-id"
        });

        let proxy: ProxyJson = serde_json::from_value(value.clone()).unwrap();
        match &proxy {
            ProxyJson::Socks4(s4) => {
                assert_eq!(s4.host, "proxy.example.com");
                assert_eq!(s4.port, 1080);
                assert_eq!(s4.user_id.as_deref(), Some("user-id"));
            }
            _ => panic!("Expected Socks4 variant"),
        }

        let serialized = serde_json::to_value(&proxy).unwrap();
        assert_eq!(serialized, value);
    }

    #[cfg(feature = "socks4")]
    #[test]
    fn proxy_json_socks4a_variant_roundtrip() {
        let value = json!({
            "protocol": "socks4a",
            "host": "proxy.example.com",
            "port": 1080,
            "user_id": "user-id"
        });

        let proxy: ProxyJson = serde_json::from_value(value.clone()).unwrap();
        match &proxy {
            ProxyJson::Socks4a(s4a) => {
                assert_eq!(s4a.host, "proxy.example.com");
                assert_eq!(s4a.port, 1080);
                assert_eq!(s4a.user_id.as_deref(), Some("user-id"));
            }
            _ => panic!("Expected Socks4a variant"),
        }

        let serialized = serde_json::to_value(&proxy).unwrap();
        assert_eq!(serialized, value);
    }

    #[cfg(feature = "socks5")]
    #[test]
    fn proxy_json_socks5_variant_roundtrip() {
        let value = json!({
            "protocol": "socks5",
            "host": "proxy.example.com",
            "port": 1080,
            "username": "user",
            "password": "pass"
        });

        let proxy: ProxyJson = serde_json::from_value(value.clone()).unwrap();
        match &proxy {
            ProxyJson::Socks5(s5) => {
                assert_eq!(s5.host, "proxy.example.com");
                assert_eq!(s5.port, 1080);
                assert_eq!(s5.username.as_deref(), Some("user"));
                assert_eq!(s5.password.as_deref(), Some("pass"));
            }
            _ => panic!("Expected Socks5 variant"),
        }

        let serialized = serde_json::to_value(&proxy).unwrap();
        assert_eq!(serialized, value);
    }

    #[cfg(feature = "socks5")]
    #[test]
    fn proxy_json_socks5h_variant_roundtrip() {
        let value = json!({
            "protocol": "socks5h",
            "host": "proxy.example.com",
            "port": 1080,
            "username": "user",
            "password": "pass"
        });

        let proxy: ProxyJson = serde_json::from_value(value.clone()).unwrap();
        match &proxy {
            ProxyJson::Socks5h(s5h) => {
                assert_eq!(s5h.host, "proxy.example.com");
                assert_eq!(s5h.port, 1080);
                assert_eq!(s5h.username.as_deref(), Some("user"));
                assert_eq!(s5h.password.as_deref(), Some("pass"));
            }
            _ => panic!("Expected Socks5h variant"),
        }

        let serialized = serde_json::to_value(&proxy).unwrap();
        assert_eq!(serialized, value);
    }

    #[cfg(feature = "shadowsocks")]
    #[test]
    fn proxy_json_shadowsocks_variant_roundtrip() {
        let value = json!({
            "protocol": "shadowsocks",
            "host": "proxy.example.com",
            "port": 8388,
            "password": "secret"
        });

        let proxy: ProxyJson = serde_json::from_value(value.clone()).unwrap();
        match &proxy {
            ProxyJson::Shadowsocks(ss) => {
                assert_eq!(ss.host, "proxy.example.com");
                assert_eq!(ss.port, 8388);
                assert_eq!(ss.password, "secret");
            }
            _ => panic!("Expected Shadowsocks variant"),
        }

        let serialized = serde_json::to_value(&proxy).unwrap();
        assert_eq!(serialized, value);
    }

    #[cfg(feature = "hysteria2")]
    #[test]
    fn proxy_json_hysteria2_variant_roundtrip() {
        let value = json!({
            "protocol": "hysteria2",
            "host": "proxy.example.com",
            "port": 443,
            "password": "secret"
        });

        let proxy: ProxyJson = serde_json::from_value(value.clone()).unwrap();
        match &proxy {
            ProxyJson::Hysteria2(hy) => {
                assert_eq!(hy.host, "proxy.example.com");
                assert_eq!(hy.port, 443);
                assert_eq!(hy.password, "secret");
            }
            _ => panic!("Expected Hysteria2 variant"),
        }

        let serialized = serde_json::to_value(&proxy).unwrap();
        assert_eq!(serialized, value);
    }

    #[cfg(feature = "tor")]
    #[test]
    fn proxy_json_tor_variant_roundtrip() {
        let value = json!({
            "protocol": "tor",
            "host": "127.0.0.1",
            "port": 9050
        });

        let proxy: ProxyJson = serde_json::from_value(value.clone()).unwrap();
        match &proxy {
            ProxyJson::Tor(tor) => {
                assert_eq!(tor.host, "127.0.0.1");
                assert_eq!(tor.port, 9050);
            }
            _ => panic!("Expected Tor variant"),
        }

        let serialized = serde_json::to_value(&proxy).unwrap();
        assert_eq!(serialized, value);
    }

    #[cfg(feature = "vmess")]
    #[test]
    fn proxy_json_vmess_variant_roundtrip() {
        let value = json!({
            "protocol": "vmess",
            "host": "proxy.example.com",
            "port": 443,
            "uuid": "vmess-uuid"
        });

        let proxy: ProxyJson = serde_json::from_value(value.clone()).unwrap();
        match &proxy {
            ProxyJson::Vmess(vm) => {
                assert_eq!(vm.host, "proxy.example.com");
                assert_eq!(vm.port, 443);
                assert_eq!(vm.uuid, "vmess-uuid");
            }
            _ => panic!("Expected Vmess variant"),
        }

        let serialized = serde_json::to_value(&proxy).unwrap();
        assert_eq!(serialized, value);
    }

    #[cfg(feature = "trojan")]
    #[test]
    fn proxy_json_trojan_variant_roundtrip() {
        let value = json!({
            "protocol": "trojan",
            "host": "proxy.example.com",
            "port": 443,
            "password": "trojan-password"
        });

        let proxy: ProxyJson = serde_json::from_value(value.clone()).unwrap();
        match &proxy {
            ProxyJson::Trojan(tr) => {
                assert_eq!(tr.host, "proxy.example.com");
                assert_eq!(tr.port, 443);
                assert_eq!(tr.password, "trojan-password");
            }
            _ => panic!("Expected Trojan variant"),
        }

        let serialized = serde_json::to_value(&proxy).unwrap();
        assert_eq!(serialized, value);
    }

    /* Negative tests on ProxyJson root */

    #[test]
    fn proxy_json_rejects_unknown_protocol() {
        let value = json!({
            "protocol": "unknown_protocol",
            "host": "proxy.example.com",
            "port": 8080
        });

        let res: Result<ProxyJson, _> = serde_json::from_value(value);
        assert!(res.is_err());
    }

    #[test]
    fn proxy_json_rejects_missing_protocol() {
        let value = json!({
            "host": "proxy.example.com",
            "port": 8080
        });

        let res: Result<ProxyJson, _> = serde_json::from_value(value);
        assert!(res.is_err());
    }

    #[cfg(feature = "http")]
    #[test]
    fn proxy_json_http_rejects_missing_required_fields() {
        // Missing host
        let value = json!({
            "protocol": "http",
            "port": 8080
        });
        let res: Result<ProxyJson, _> = serde_json::from_value(value);
        assert!(res.is_err());

        // Missing port
        let value = json!({
            "protocol": "http",
            "host": "proxy.example.com"
        });
        let res: Result<ProxyJson, _> = serde_json::from_value(value);
        assert!(res.is_err());
    }

    #[cfg(feature = "http")]
    #[test]
    fn proxy_json_http_rejects_invalid_port_type() {
        let value = json!({
            "protocol": "http",
            "host": "proxy.example.com",
            "port": "not-a-number"
        });

        let res: Result<ProxyJson, _> = serde_json::from_value(value);
        assert!(res.is_err());
    }
}
