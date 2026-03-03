//! Shadowsocks proxy configuration.
//!
//! Defines configuration for Shadowsocks proxy connections, including
//! cipher/transport settings and shared proxy timeouts/TLS via `BaseProxyConfig`.

use std::sync::Arc;
use std::time::Duration;

use crate::config::proxy_config::{BaseProxyConfig, HasBaseProxyConfig};
use crate::errors::config_errors::ConfigError;

/* Types */

/// Configuration for Shadowsocks proxy connections.
///
/// Supports cipher selection, optional plugin integration, and transport
/// flags such as UDP relay and TCP fast open. Shared proxy settings like
/// timeouts and TLS options are delegated to the embedded `BaseProxyConfig`
/// via the `HasBaseProxyConfig` trait.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use roxie::config::ShadowsocksConfig;
/// use roxie::config::BaseProxyConfigBuilder;
///
/// let config = ShadowsocksConfig::new()
///     .set_method("aes-256-gcm")
///     .set_udp_relay(true)
///     .set_tcp_fast_open(true)
///     .set_connection_timeout(Duration::from_secs(15))
///     .set_handshake_timeout(Duration::from_secs(20));
///
/// config.validate()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ShadowsocksConfig {
    // Base proxy configuration shared with all protocols.
    base: Arc<BaseProxyConfig>,
    // Encryption method (for example "aes-256-gcm").
    method: String,
    // Optional plugin name (for example "v2ray-plugin", "obfs-local").
    plugin: Option<String>,
    // Optional plugin options (semicolon separated key=value pairs).
    plugin_opts: Option<String>,
    // Connection timeout for establishing the initial Shadowsocks tunnel.
    connection_timeout: Duration,
    // Whether to enable UDP relay support.
    udp_relay: bool,
    // Whether to enable TCP fast open.
    tcp_fast_open: bool,
}

/* Implementations */

impl ShadowsocksConfig {
    /// Creates a new `ShadowsocksConfig` with sensible defaults.
    ///
    /// Defaults:
    /// * `method`: `"aes-256-gcm"`
    /// * `plugin`: `None`
    /// * `plugin_opts`: `None`
    /// * `connection_timeout`: `10` seconds
    /// * `udp_relay`: `false`
    /// * `tcp_fast_open`: `false`
    /// * `base`: `BaseProxyConfig::new()`
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::ShadowsocksConfig;
    ///
    /// let config = ShadowsocksConfig::new();
    /// assert_eq!(config.get_method(), "aes-256-gcm");
    /// ```
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseProxyConfig::new()),
            method: "aes-256-gcm".to_string(),
            plugin: None,
            plugin_opts: None,
            connection_timeout: Duration::from_secs(10),
            udp_relay: false,
            tcp_fast_open: false,
        }
    }

    /// Sets the encryption method.
    ///
    /// Valid methods typically include:
    /// * `aes-128-gcm`
    /// * `aes-256-gcm`
    /// * `chacha20-ietf-poly1305`
    /// * `xchacha20-ietf-poly1305`
    /// * `aes-128-cfb`
    /// * `aes-192-cfb`
    /// * `aes-256-cfb`
    /// * `rc4-md5` (not recommended)
    ///
    /// Validation is performed by [`ShadowsocksConfig::validate`].
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::ShadowsocksConfig;
    ///
    /// let config = ShadowsocksConfig::new()
    ///     .set_method("chacha20-ietf-poly1305");
    ///
    /// assert_eq!(config.get_method(), "chacha20-ietf-poly1305");
    /// ```
    pub fn set_method(mut self, method: impl Into<String>) -> Self {
        self.method = method.into();
        self
    }

    /// Sets the plugin name.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::ShadowsocksConfig;
    ///
    /// let config = ShadowsocksConfig::new()
    ///     .set_plugin("v2ray-plugin")
    ///     .set_plugin_opts("mode=websocket;host=example.com");
    ///
    /// assert_eq!(config.get_plugin(), Some("v2ray-plugin"));
    /// assert_eq!(config.get_plugin_opts(), Some("mode=websocket;host=example.com"));
    /// ```
    pub fn set_plugin(mut self, plugin: impl Into<String>) -> Self {
        self.plugin = Some(plugin.into());
        self
    }

    /// Clears the plugin and any associated options.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::ShadowsocksConfig;
    ///
    /// let config = ShadowsocksConfig::new()
    ///     .set_plugin("v2ray-plugin")
    ///     .clear_plugin();
    ///
    /// assert!(config.get_plugin().is_none());
    /// assert!(config.get_plugin_opts().is_none());
    /// ```
    pub fn clear_plugin(mut self) -> Self {
        self.plugin = None;
        self.plugin_opts = None;
        self
    }

    /// Sets the plugin options (semicolon separated key=value pairs).
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::ShadowsocksConfig;
    ///
    /// let config = ShadowsocksConfig::new()
    ///     .set_plugin_opts("mode=websocket");
    ///
    /// assert_eq!(config.get_plugin_opts(), Some("mode=websocket"));
    /// ```
    pub fn set_plugin_opts(mut self, opts: impl Into<String>) -> Self {
        self.plugin_opts = Some(opts.into());
        self
    }

    /// Clears the plugin options.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::ShadowsocksConfig;
    ///
    /// let config = ShadowsocksConfig::new()
    ///     .set_plugin_opts("mode=websocket")
    ///     .clear_plugin_opts();
    ///
    /// assert!(config.get_plugin_opts().is_none());
    /// ```
    pub fn clear_plugin_opts(mut self) -> Self {
        self.plugin_opts = None;
        self
    }

    /// Sets the connection timeout used when establishing the Shadowsocks tunnel.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use roxie::config::ShadowsocksConfig;
    ///
    /// let config = ShadowsocksConfig::new()
    ///     .set_connection_timeout(Duration::from_secs(30));
    ///
    /// assert_eq!(config.get_connection_timeout(), Duration::from_secs(30));
    /// ```
    pub fn set_connection_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = timeout;
        self
    }

    /// Enables or disables UDP relay support.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::ShadowsocksConfig;
    ///
    /// let config = ShadowsocksConfig::new()
    ///     .set_udp_relay(true);
    ///
    /// assert!(config.is_udp_relay());
    /// ```
    pub fn set_udp_relay(mut self, enable: bool) -> Self {
        self.udp_relay = enable;
        self
    }

    /// Enables or disables TCP fast open.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::ShadowsocksConfig;
    ///
    /// let config = ShadowsocksConfig::new()
    ///     .set_tcp_fast_open(true);
    ///
    /// assert!(config.is_tcp_fast_open());
    /// ```
    pub fn set_tcp_fast_open(mut self, enable: bool) -> Self {
        self.tcp_fast_open = enable;
        self
    }

    /// Returns the configured encryption method.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::ShadowsocksConfig;
    ///
    /// let config = ShadowsocksConfig::new()
    ///     .set_method("aes-128-gcm");
    ///
    /// assert_eq!(config.get_method(), "aes-128-gcm");
    /// ```
    pub fn get_method(&self) -> &str {
        &self.method
    }

    /// Returns the configured plugin name, if any.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::ShadowsocksConfig;
    ///
    /// let config = ShadowsocksConfig::new()
    ///     .set_plugin("v2ray-plugin");
    ///
    /// assert_eq!(config.get_plugin(), Some("v2ray-plugin"));
    /// ```
    pub fn get_plugin(&self) -> Option<&str> {
        self.plugin.as_deref()
    }

    /// Returns the configured plugin options, if any.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::ShadowsocksConfig;
    ///
    /// let config = ShadowsocksConfig::new()
    ///     .set_plugin("v2ray-plugin")
    ///     .set_plugin_opts("mode=websocket");
    ///
    /// assert_eq!(config.get_plugin_opts(), Some("mode=websocket"));
    /// ```
    pub fn get_plugin_opts(&self) -> Option<&str> {
        self.plugin_opts.as_deref()
    }

    /// Returns the configured connection timeout.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use roxie::config::ShadowsocksConfig;
    ///
    /// let config = ShadowsocksConfig::new();
    /// assert_eq!(config.get_connection_timeout(), Duration::from_secs(10));
    /// ```
    pub fn get_connection_timeout(&self) -> Duration {
        self.connection_timeout
    }

    /// Returns whether UDP relay support is enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::ShadowsocksConfig;
    ///
    /// let config = ShadowsocksConfig::new();
    /// assert!(!config.is_udp_relay());
    /// ```
    pub fn is_udp_relay(&self) -> bool {
        self.udp_relay
    }

    /// Returns whether TCP fast open is enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::ShadowsocksConfig;
    ///
    /// let config = ShadowsocksConfig::new();
    /// assert!(!config.is_tcp_fast_open());
    /// ```
    pub fn is_tcp_fast_open(&self) -> bool {
        self.tcp_fast_open
    }

    /// Returns a shared reference to the embedded base proxy configuration.
    ///
    /// This is primarily intended for internal callers and tests that need to
    /// inspect timeout or TLS settings.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use roxie::config::ShadowsocksConfig;
    /// use roxie::config::BaseProxyConfigBuilder;
    ///
    /// let config = ShadowsocksConfig::new()
    ///     .set_handshake_timeout(Duration::from_secs(20));
    ///
    /// assert_eq!(config.get_base().get_handshake_timeout(), Duration::from_secs(20));
    /// ```
    pub fn get_base(&self) -> &BaseProxyConfig {
        &self.base
    }

    /// Validate the configuration.
    ///
    /// Ensures that the selected cipher method is known and that the base
    /// configuration passes its own validation.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::ShadowsocksConfig;
    ///
    /// let config = ShadowsocksConfig::new()
    ///     .set_method("aes-256-gcm");
    ///
    /// config.validate()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.base.validate()?;

        let valid_methods = [
            "aes-128-gcm",
            "aes-256-gcm",
            "chacha20-ietf-poly1305",
            "xchacha20-ietf-poly1305",
            "aes-128-cfb",
            "aes-192-cfb",
            "aes-256-cfb",
            "rc4-md5",
        ];

        if !valid_methods.contains(&self.method.as_str()) {
            return Err(ConfigError::InvalidValue {
                field: "method".to_string(),
                value: self.method.clone(),
                expected: valid_methods.join(", "),
            });
        }

        Ok(())
    }
}

impl Default for ShadowsocksConfig {
    /// Creates the default Shadowsocks configuration.
    ///
    /// Uses `"aes-256-gcm"` as the cipher and a 10 second connection timeout.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::ShadowsocksConfig;
    ///
    /// let config = ShadowsocksConfig::default();
    /// assert_eq!(config.get_method(), "aes-256-gcm");
    /// ```
    fn default() -> Self {
        Self::new()
    }
}

/// Wire `ShadowsocksConfig` into the shared base config trait.
///
/// This provides all the base config builder methods like
/// `.set_handshake_timeout()`, `.set_phase_timeout()`, `.set_auto_tls()`, and others
/// via `BaseProxyConfigBuilder`.
impl HasBaseProxyConfig for ShadowsocksConfig {
    /// Access the shared base proxy configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use roxie::config::{ShadowsocksConfig, HasBaseProxyConfig, BaseProxyConfigBuilder};
    ///
    /// let config = ShadowsocksConfig::new()
    ///     .set_handshake_timeout(Duration::from_secs(25));
    ///
    /// assert_eq!(config.get_base_config().get_handshake_timeout(), Duration::from_secs(25));
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
    /// use roxie::config::{ShadowsocksConfig, HasBaseProxyConfig};
    ///
    /// let mut config = ShadowsocksConfig::new();
    /// config.get_base_config_mut().set_handshake_timeout(Duration::from_secs(5));
    ///
    /// assert_eq!(config.get_base_config().get_handshake_timeout(), Duration::from_secs(5));
    /// ```
    fn get_base_config_mut(&mut self) -> &mut BaseProxyConfig {
        Arc::make_mut(&mut self.base)
    }
}

impl ShadowsocksConfig {
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
    fn shadowsocks_config_defaults() {
        let config = ShadowsocksConfig::default();
        assert_eq!(config.get_method(), "aes-256-gcm");
        assert!(config.get_plugin().is_none());
        assert!(config.get_plugin_opts().is_none());
        assert_eq!(config.get_connection_timeout(), Duration::from_secs(10));
        assert!(!config.is_udp_relay());
        assert!(!config.is_tcp_fast_open());
        assert_eq!(
            config.get_base().get_handshake_timeout(),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn shadowsocks_config_builder_chain() {
        let config = ShadowsocksConfig::new()
            .set_method("chacha20-ietf-poly1305")
            .set_plugin("v2ray-plugin")
            .set_plugin_opts("mode=websocket")
            .set_connection_timeout(Duration::from_secs(30))
            .set_udp_relay(true)
            .set_tcp_fast_open(true)
            .set_handshake_timeout(Duration::from_secs(15))
            .set_tcp_nodelay(false)
            .set_auto_tls(false);

        assert_eq!(config.get_method(), "chacha20-ietf-poly1305");
        assert_eq!(config.get_plugin(), Some("v2ray-plugin"));
        assert_eq!(config.get_plugin_opts(), Some("mode=websocket"));
        assert_eq!(config.get_connection_timeout(), Duration::from_secs(30));
        assert!(config.is_udp_relay());
        assert!(config.is_tcp_fast_open());
        assert_eq!(
            config.get_base().get_handshake_timeout(),
            Duration::from_secs(15)
        );
        assert!(!config.get_base().is_tcp_nodelay());
        assert!(!config.get_base().is_auto_tls());
    }

    #[test]
    fn shadowsocks_config_validation() {
        let valid = ShadowsocksConfig::new().set_method("aes-128-gcm");
        assert!(valid.validate().is_ok());

        let invalid = ShadowsocksConfig::new().set_method("totally-unknown-cipher");
        assert!(invalid.validate().is_err());
    }
}
