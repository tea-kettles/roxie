//! VMess proxy configuration.
//!
//! Defines configuration for VMess proxy connections (V2Ray protocol),
//! including security, transport, and TLS related options, plus shared
//! proxy timeouts and TLS via `BaseProxyConfig`.

use std::sync::Arc;
use std::time::Duration;

use crate::config::proxy_config::{BaseProxyConfig, HasBaseProxyConfig};
use crate::errors::config_errors::ConfigError;

/* Types */

/// Configuration for VMess proxy connections (V2Ray protocol).
///
/// Models security, transport, and protocol specific options while
/// delegating generic proxy settings such as timeouts and TLS to the
/// embedded `BaseProxyConfig`.
///
/// ## Security options
///
/// * `"auto"` (default)
/// * `"aes-128-gcm"`
/// * `"chacha20-poly1305"`
/// * `"none"`
///
/// ## Network transport options
///
/// * `"tcp"` (default)
/// * `"ws"` or `"websocket"`
/// * `"h2"` or `"http2"`
/// * `"quic"`
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use roxie::config::VMessConfig;
/// use roxie::config::BaseProxyConfigBuilder;
///
/// let config = VMessConfig::new()
///     .set_alter_id(16)
///     .set_security("aes-128-gcm")
///     .set_network("ws")
///     .set_tls_enabled(true)
///     .set_tls_server_name("example.com")
///     .set_tls_allow_insecure(false)
///     .set_ws_path("/ws")
///     .set_ws_headers("User-Agent: test-client")
///     .set_h2_host("h2.example.com")
///     .set_h2_path("/h2")
///     .set_connection_timeout(Duration::from_secs(15))
///     .set_handshake_timeout(Duration::from_secs(20));
///
/// config.validate()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VMessConfig {
    // Base proxy configuration shared with all protocols.
    base: Arc<BaseProxyConfig>,
    // Alter ID for additional security.
    alter_id: u16,
    // Security or encryption method.
    security: String,
    // Network transport name.
    network: String,
    // Whether TLS is enabled for this VMess transport.
    tls_enabled: bool,
    // Server name for SNI when TLS is enabled.
    tls_server_name: Option<String>,
    // Whether to allow insecure TLS (skip verification) for VMess.
    tls_allow_insecure: bool,
    // WebSocket path (if `network` is ws or websocket).
    ws_path: String,
    // WebSocket headers (for example "key1:value1;key2:value2").
    ws_headers: Option<String>,
    // HTTP/2 host list (comma separated).
    h2_host: Option<String>,
    // HTTP/2 path.
    h2_path: String,
    // Connection timeout when establishing the VMess tunnel.
    connection_timeout: Duration,
}

/* Implementations */

impl VMessConfig {
    /// Creates a new `VMessConfig` with sensible defaults.
    ///
    /// Defaults:
    /// * `alter_id`: `0`
    /// * `security`: `"auto"`
    /// * `network`: `"tcp"`
    /// * `tls_enabled`: `false`
    /// * `tls_server_name`: `None`
    /// * `tls_allow_insecure`: `false`
    /// * `ws_path`: `"/"`
    /// * `ws_headers`: `None`
    /// * `h2_host`: `None`
    /// * `h2_path`: `"/"`
    /// * `connection_timeout`: `10` seconds
    /// * `base`: `BaseProxyConfig::new()`
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::VMessConfig;
    ///
    /// let config = VMessConfig::new();
    /// assert_eq!(config.get_security(), "auto");
    /// assert_eq!(config.get_network(), "tcp");
    /// ```
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseProxyConfig::new()),
            alter_id: 0,
            security: "auto".to_string(),
            network: "tcp".to_string(),
            tls_enabled: false,
            tls_server_name: None,
            tls_allow_insecure: false,
            ws_path: "/".to_string(),
            ws_headers: None,
            h2_host: None,
            h2_path: "/".to_string(),
            connection_timeout: Duration::from_secs(10),
        }
    }

    /// Sets the alter ID used by VMess for additional security.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::VMessConfig;
    ///
    /// let config = VMessConfig::new()
    ///     .set_alter_id(8);
    ///
    /// assert_eq!(config.get_alter_id(), 8);
    /// ```
    pub fn set_alter_id(mut self, alter_id: u16) -> Self {
        self.alter_id = alter_id;
        self
    }

    /// Sets the VMess security method.
    ///
    /// Valid values are `"auto"`, `"aes-128-gcm"`, `"chacha20-poly1305"`,
    /// and `"none"`. Validation is performed in [`VMessConfig::validate`].
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::VMessConfig;
    ///
    /// let config = VMessConfig::new()
    ///     .set_security("chacha20-poly1305");
    ///
    /// assert_eq!(config.get_security(), "chacha20-poly1305");
    /// ```
    pub fn set_security(mut self, security: impl Into<String>) -> Self {
        self.security = security.into();
        self
    }

    /// Sets the VMess network transport.
    ///
    /// Valid values (case insensitive) are `"tcp"`, `"ws"` or `"websocket"`,
    /// `"h2"` or `"http2"`, and `"quic"`.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::VMessConfig;
    ///
    /// let config = VMessConfig::new()
    ///     .set_network("ws");
    ///
    /// assert_eq!(config.get_network(), "ws");
    /// ```
    pub fn set_network(mut self, network: impl Into<String>) -> Self {
        self.network = network.into();
        self
    }

    /// Enables or disables TLS for VMess.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::VMessConfig;
    ///
    /// let config = VMessConfig::new()
    ///     .set_tls_enabled(true)
    ///     .set_tls_server_name("example.com")
    ///     .set_tls_allow_insecure(false);
    ///
    /// assert!(config.is_tls_enabled());
    /// assert_eq!(config.get_tls_server_name(), Some("example.com"));
    /// assert!(!config.is_tls_allow_insecure());
    /// ```
    pub fn set_tls_enabled(mut self, enabled: bool) -> Self {
        self.tls_enabled = enabled;
        self
    }

    /// Sets the TLS server name (SNI) for VMess.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::VMessConfig;
    ///
    /// let config = VMessConfig::new()
    ///     .set_tls_server_name("example.com");
    ///
    /// assert_eq!(config.get_tls_server_name(), Some("example.com"));
    /// ```
    pub fn set_tls_server_name(mut self, server_name: impl Into<String>) -> Self {
        self.tls_server_name = Some(server_name.into());
        self
    }

    /// Clears the TLS server name.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::VMessConfig;
    ///
    /// let config = VMessConfig::new()
    ///     .set_tls_server_name("example.com")
    ///     .clear_tls_server_name();
    ///
    /// assert!(config.get_tls_server_name().is_none());
    /// ```
    pub fn clear_tls_server_name(mut self) -> Self {
        self.tls_server_name = None;
        self
    }

    /// Enables or disables insecure TLS for VMess.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::VMessConfig;
    ///
    /// let config = VMessConfig::new()
    ///     .set_tls_allow_insecure(true);
    ///
    /// assert!(config.is_tls_allow_insecure());
    /// ```
    pub fn set_tls_allow_insecure(mut self, allow_insecure: bool) -> Self {
        self.tls_allow_insecure = allow_insecure;
        self
    }

    /// Sets the WebSocket path used when `network` is ws.
    ///
    /// Headers are formatted as `"key1:value1;key2:value2"`.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::VMessConfig;
    ///
    /// let config = VMessConfig::new()
    ///     .set_ws_path("/ws")
    ///     .set_ws_headers("User-Agent: test-client");
    ///
    /// assert_eq!(config.get_ws_path(), "/ws");
    /// assert_eq!(config.get_ws_headers(), Some("User-Agent: test-client"));
    /// ```
    pub fn set_ws_path(mut self, path: impl Into<String>) -> Self {
        self.ws_path = path.into();
        self
    }

    /// Sets the WebSocket headers used when `network` is ws.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::VMessConfig;
    ///
    /// let config = VMessConfig::new()
    ///     .set_ws_headers("User-Agent: test-client");
    ///
    /// assert_eq!(config.get_ws_headers(), Some("User-Agent: test-client"));
    /// ```
    pub fn set_ws_headers(mut self, headers: impl Into<String>) -> Self {
        self.ws_headers = Some(headers.into());
        self
    }

    /// Clears the WebSocket headers.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::VMessConfig;
    ///
    /// let config = VMessConfig::new()
    ///     .set_ws_headers("User-Agent: test-client")
    ///     .clear_ws_headers();
    ///
    /// assert!(config.get_ws_headers().is_none());
    /// ```
    pub fn clear_ws_headers(mut self) -> Self {
        self.ws_headers = None;
        self
    }

    /// Sets the HTTP 2 host list when `network` is h2 or http2.
    ///
    /// `host` is a comma separated list, `path` is the HTTP 2 path.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::VMessConfig;
    ///
    /// let config = VMessConfig::new()
    ///     .set_h2_host("h2.example.com")
    ///     .set_h2_path("/h2");
    ///
    /// assert_eq!(config.get_h2_host(), Some("h2.example.com"));
    /// assert_eq!(config.get_h2_path(), "/h2");
    /// ```
    pub fn set_h2_host(mut self, host: impl Into<String>) -> Self {
        self.h2_host = Some(host.into());
        self
    }

    /// Clears the HTTP 2 host list.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::VMessConfig;
    ///
    /// let config = VMessConfig::new()
    ///     .set_h2_host("h2.example.com")
    ///     .clear_h2_host();
    ///
    /// assert!(config.get_h2_host().is_none());
    /// ```
    pub fn clear_h2_host(mut self) -> Self {
        self.h2_host = None;
        self
    }

    /// Sets the HTTP 2 path when `network` is h2 or http2.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::VMessConfig;
    ///
    /// let config = VMessConfig::new()
    ///     .set_h2_path("/h2");
    ///
    /// assert_eq!(config.get_h2_path(), "/h2");
    /// ```
    pub fn set_h2_path(mut self, path: impl Into<String>) -> Self {
        self.h2_path = path.into();
        self
    }

    /// Sets the connection timeout for establishing VMess tunnels.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use roxie::config::VMessConfig;
    ///
    /// let config = VMessConfig::new()
    ///     .set_connection_timeout(Duration::from_secs(30));
    ///
    /// assert_eq!(config.get_connection_timeout(), Duration::from_secs(30));
    /// ```
    pub fn set_connection_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = timeout;
        self
    }

    /// Returns the configured alter ID.
    pub fn get_alter_id(&self) -> u16 {
        self.alter_id
    }

    /// Returns the configured security method.
    pub fn get_security(&self) -> &str {
        &self.security
    }

    /// Returns the configured network transport.
    pub fn get_network(&self) -> &str {
        &self.network
    }

    /// Returns whether TLS is enabled for VMess.
    pub fn is_tls_enabled(&self) -> bool {
        self.tls_enabled
    }

    /// Returns the configured TLS server name for SNI, if any.
    pub fn get_tls_server_name(&self) -> Option<&str> {
        self.tls_server_name.as_deref()
    }

    /// Returns whether insecure TLS is allowed.
    pub fn is_tls_allow_insecure(&self) -> bool {
        self.tls_allow_insecure
    }

    /// Returns the configured WebSocket path.
    pub fn get_ws_path(&self) -> &str {
        &self.ws_path
    }

    /// Returns the configured WebSocket headers, if any.
    pub fn get_ws_headers(&self) -> Option<&str> {
        self.ws_headers.as_deref()
    }

    /// Returns the configured HTTP 2 host list, if any.
    pub fn get_h2_host(&self) -> Option<&str> {
        self.h2_host.as_deref()
    }

    /// Returns the configured HTTP 2 path.
    pub fn get_h2_path(&self) -> &str {
        &self.h2_path
    }

    /// Returns the configured connection timeout.
    pub fn get_connection_timeout(&self) -> Duration {
        self.connection_timeout
    }

    /// Returns a shared reference to the embedded base proxy configuration.
    pub fn get_base(&self) -> &BaseProxyConfig {
        &self.base
    }

    /// Validate the configuration.
    ///
    /// Ensures the security and network fields are valid and that the embedded
    /// base proxy configuration passes its own validation.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::VMessConfig;
    ///
    /// let config = VMessConfig::new()
    ///     .set_security("auto")
    ///     .set_network("tcp");
    ///
    /// config.validate()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.base.validate()?;

        let valid_security = ["auto", "aes-128-gcm", "chacha20-poly1305", "none"];
        if !valid_security.contains(&self.security.as_str()) {
            return Err(ConfigError::InvalidValue {
                field: "security".to_string(),
                value: self.security.clone(),
                expected: "\"auto\", \"aes-128-gcm\", \"chacha20-poly1305\", or \"none\""
                    .to_string(),
            });
        }

        let network_normalized = self.network.to_lowercase();
        let valid_networks = ["tcp", "ws", "websocket", "h2", "http2", "quic"];
        if !valid_networks.contains(&network_normalized.as_str()) {
            return Err(ConfigError::InvalidValue {
                field: "network".to_string(),
                value: self.network.clone(),
                expected: "\"tcp\", \"ws\"/\"websocket\", \"h2\"/\"http2\", or \"quic\""
                    .to_string(),
            });
        }

        Ok(())
    }
}

impl Default for VMessConfig {
    /// Creates the default VMess configuration.
    ///
    /// Uses `"auto"` security, `"tcp"` network, and conservative timeouts.
    fn default() -> Self {
        Self::new()
    }
}

/// Wire `VMessConfig` into the shared base config trait.
///
/// This provides base config builder methods like `.set_handshake_timeout()`,
/// `.set_phase_timeout()`, `.set_auto_tls()`, and others via `BaseProxyConfigBuilder`.
impl HasBaseProxyConfig for VMessConfig {
    /// Access the shared base proxy configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use roxie::config::{VMessConfig, HasBaseProxyConfig, BaseProxyConfigBuilder};
    ///
    /// let config = VMessConfig::new()
    ///     .set_handshake_timeout(Duration::from_secs(18));
    ///
    /// assert_eq!(config.get_base_config().get_handshake_timeout(), Duration::from_secs(18));
    /// ```
    fn get_base_config(&self) -> &BaseProxyConfig {
        &self.base
    }

    /// Mutably access the shared base proxy configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use roxie::config::{VMessConfig, HasBaseProxyConfig};
    ///
    /// let mut config = VMessConfig::new();
    /// config.get_base_config_mut().set_handshake_timeout(Duration::from_secs(6));
    ///
    /// assert_eq!(config.get_base_config().get_handshake_timeout(), Duration::from_secs(6));
    /// ```
    fn get_base_config_mut(&mut self) -> &mut BaseProxyConfig {
        Arc::make_mut(&mut self.base)
    }
}

impl VMessConfig {
    #[allow(dead_code)]
    pub(crate) fn set_base_arc(&mut self, base: Arc<BaseProxyConfig>) {
        self.base = base;
    }
}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::proxy_config::BaseProxyConfigBuilder;

    #[test]
    fn vmess_config_defaults() {
        let config = VMessConfig::default();
        assert_eq!(config.get_alter_id(), 0);
        assert_eq!(config.get_security(), "auto");
        assert_eq!(config.get_network(), "tcp");
        assert!(!config.is_tls_enabled());
        assert!(config.get_tls_server_name().is_none());
        assert!(!config.is_tls_allow_insecure());
        assert_eq!(config.get_ws_path(), "/");
        assert!(config.get_ws_headers().is_none());
        assert!(config.get_h2_host().is_none());
        assert_eq!(config.get_h2_path(), "/");
        assert_eq!(config.get_connection_timeout(), Duration::from_secs(10));
    }

    #[test]
    fn vmess_config_builder_chain() {
        let config = VMessConfig::new()
            .set_alter_id(32)
            .set_security("aes-128-gcm")
            .set_network("ws")
            .set_tls_enabled(true)
            .set_tls_server_name("example.com")
            .set_tls_allow_insecure(true)
            .set_ws_path("/ws")
            .set_ws_headers("User-Agent: test")
            .set_h2_host("h2.example.com")
            .set_h2_path("/h2")
            .set_connection_timeout(Duration::from_secs(25))
            .set_handshake_timeout(Duration::from_secs(15))
            .set_tcp_nodelay(false)
            .set_auto_tls(false);

        assert_eq!(config.get_alter_id(), 32);
        assert_eq!(config.get_security(), "aes-128-gcm");
        assert_eq!(config.get_network(), "ws");
        assert!(config.is_tls_enabled());
        assert_eq!(config.get_tls_server_name(), Some("example.com"));
        assert!(config.is_tls_allow_insecure());
        assert_eq!(config.get_ws_path(), "/ws");
        assert_eq!(config.get_ws_headers(), Some("User-Agent: test"));
        assert_eq!(config.get_h2_host(), Some("h2.example.com"));
        assert_eq!(config.get_h2_path(), "/h2");
        assert_eq!(config.get_connection_timeout(), Duration::from_secs(25));
    }

    #[test]
    fn vmess_config_validation() {
        let valid = VMessConfig::new()
            .set_security("chacha20-poly1305")
            .set_network("quic");
        assert!(valid.validate().is_ok());

        let invalid_security = VMessConfig::new()
            .set_security("totally-unknown")
            .set_network("tcp");
        assert!(invalid_security.validate().is_err());

        let invalid_network = VMessConfig::new()
            .set_security("auto")
            .set_network("something-weird");
        assert!(invalid_network.validate().is_err());
    }
}
