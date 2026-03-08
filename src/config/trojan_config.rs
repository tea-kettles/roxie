//! Trojan proxy configuration.
//!
//! Defines configuration for Trojan proxy connections, including SNI,
//! TLS verification behavior, optional WebSocket transport, and shared
//! proxy timeouts and TLS via `BaseProxyConfig`.

use std::sync::Arc;
use std::time::Duration;

use crate::config::proxy_config::{BaseProxyConfig, HasBaseProxyConfig};
use crate::errors::config_errors::ConfigError;

/* Types */

/// Configuration for Trojan proxy connections.
///
/// Trojan disguises proxy traffic as HTTPS and can optionally use
/// WebSocket transport. This configuration models the TLS facing
/// parameters and WebSocket options while delegating generic proxy
/// settings such as timeouts and TLS to the embedded `BaseProxyConfig`.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use roxie::config::TrojanConfig;
/// use roxie::config::BaseProxyConfigBuilder;
///
/// let config = TrojanConfig::new()
///     .set_sni("example.com")
///     .set_skip_cert_verify(false)
///     .set_alpn("h2,http/1.1")
///     .set_ws_enabled(true)
///     .set_ws_path("/ws")
///     .set_ws_headers("User-Agent: trojan-client")
///     .set_connection_timeout(Duration::from_secs(15))
///     .set_handshake_timeout(Duration::from_secs(20));
///
/// config.validate()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrojanConfig {
    // Base proxy configuration shared with all protocols.
    base: Arc<BaseProxyConfig>,
    // Server name for SNI.
    sni: Option<String>,
    // Whether to skip certificate verification.
    skip_cert_verify: bool,
    // ALPN protocols (comma separated, for example "h2,http/1.1").
    alpn: String,
    // Whether WebSocket transport is enabled.
    ws_enabled: bool,
    // WebSocket path.
    ws_path: String,
    // WebSocket Host header override (for CDN fronting; defaults to SNI or proxy host).
    ws_host: Option<String>,
    // WebSocket headers (for example "key1:value1;key2:value2").
    ws_headers: Option<String>,
    // Connection timeout when establishing the Trojan tunnel.
    connection_timeout: Duration,
}

/* Implementations */

impl TrojanConfig {
    /// Creates a new `TrojanConfig` with sensible defaults.
    ///
    /// Defaults:
    /// * `sni`: `None`
    /// * `skip_cert_verify`: `false`
    /// * `alpn`: `"h2,http/1.1"`
    /// * `ws_enabled`: `false`
    /// * `ws_path`: `"/"`
    /// * `ws_headers`: `None`
    /// * `connection_timeout`: `10` seconds
    /// * `base`: `BaseProxyConfig::new()`
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TrojanConfig;
    ///
    /// let config = TrojanConfig::new();
    /// assert_eq!(config.get_alpn(), "h2,http/1.1");
    /// ```
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseProxyConfig::new()),
            sni: None,
            skip_cert_verify: false,
            alpn: "h2,http/1.1".to_string(),
            ws_enabled: false,
            ws_path: "/".to_string(),
            ws_host: None,
            ws_headers: None,
            connection_timeout: Duration::from_secs(10),
        }
    }

    /// Sets the SNI (Server Name Indication) to present during TLS.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TrojanConfig;
    ///
    /// let config = TrojanConfig::new()
    ///     .set_sni("example.com");
    ///
    /// assert_eq!(config.get_sni(), Some("example.com"));
    /// ```
    pub fn set_sni(mut self, sni: impl Into<String>) -> Self {
        self.sni = Some(sni.into());
        self
    }

    /// Clears the configured SNI value.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TrojanConfig;
    ///
    /// let config = TrojanConfig::new()
    ///     .set_sni("example.com")
    ///     .clear_sni();
    ///
    /// assert!(config.get_sni().is_none());
    /// ```
    pub fn clear_sni(mut self) -> Self {
        self.sni = None;
        self
    }

    /// Enables or disables skipping certificate verification.
    ///
    /// Skipping certificate verification is not recommended outside of
    /// controlled testing scenarios.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TrojanConfig;
    ///
    /// let config = TrojanConfig::new()
    ///     .set_skip_cert_verify(true);
    ///
    /// assert!(config.is_skip_cert_verify());
    /// ```
    pub fn set_skip_cert_verify(mut self, skip: bool) -> Self {
        self.skip_cert_verify = skip;
        self
    }

    /// Sets ALPN protocols (comma separated, for example "h2,http/1.1").
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TrojanConfig;
    ///
    /// let config = TrojanConfig::new()
    ///     .set_alpn("h2");
    ///
    /// assert_eq!(config.get_alpn(), "h2");
    /// ```
    pub fn set_alpn(mut self, protocols: impl Into<String>) -> Self {
        self.alpn = protocols.into();
        self
    }

    /// Enables or disables WebSocket transport.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TrojanConfig;
    ///
    /// let config = TrojanConfig::new()
    ///     .set_ws_enabled(true);
    ///
    /// assert!(config.is_ws_enabled());
    /// ```
    pub fn set_ws_enabled(mut self, enabled: bool) -> Self {
        self.ws_enabled = enabled;
        self
    }

    /// Sets the WebSocket path.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TrojanConfig;
    ///
    /// let config = TrojanConfig::new()
    ///     .set_ws_path("/ws");
    ///
    /// assert_eq!(config.get_ws_path(), "/ws");
    /// ```
    pub fn set_ws_path(mut self, path: impl Into<String>) -> Self {
        self.ws_path = path.into();
        self
    }

    /// Sets the WebSocket Host header used in the HTTP upgrade request.
    ///
    /// Useful for CDN fronting where the Host header differs from the proxy IP.
    pub fn set_ws_host(mut self, host: impl Into<String>) -> Self {
        self.ws_host = Some(host.into());
        self
    }

    /// Clears the WebSocket Host header override.
    pub fn clear_ws_host(mut self) -> Self {
        self.ws_host = None;
        self
    }

    /// Sets the WebSocket headers.
    ///
    /// Headers are formatted as `"key1:value1;key2:value2"`.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TrojanConfig;
    ///
    /// let config = TrojanConfig::new()
    ///     .set_ws_headers("User-Agent: trojan-client");
    ///
    /// assert_eq!(config.get_ws_headers(), Some("User-Agent: trojan-client"));
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
    /// use roxie::config::TrojanConfig;
    ///
    /// let config = TrojanConfig::new()
    ///     .set_ws_headers("User-Agent: trojan-client")
    ///     .clear_ws_headers();
    ///
    /// assert!(config.get_ws_headers().is_none());
    /// ```
    pub fn clear_ws_headers(mut self) -> Self {
        self.ws_headers = None;
        self
    }

    /// Sets the connection timeout for establishing Trojan tunnels.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use roxie::config::TrojanConfig;
    ///
    /// let config = TrojanConfig::new()
    ///     .set_connection_timeout(Duration::from_secs(30));
    ///
    /// assert_eq!(config.get_connection_timeout(), Duration::from_secs(30));
    /// ```
    pub fn set_connection_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = timeout;
        self
    }

    /// Returns the configured SNI, if any.
    pub fn get_sni(&self) -> Option<&str> {
        self.sni.as_deref()
    }

    /// Returns whether certificate verification is skipped.
    pub fn is_skip_cert_verify(&self) -> bool {
        self.skip_cert_verify
    }

    /// Returns the configured ALPN string.
    pub fn get_alpn(&self) -> &str {
        &self.alpn
    }

    /// Returns whether WebSocket transport is enabled.
    pub fn is_ws_enabled(&self) -> bool {
        self.ws_enabled
    }

    /// Returns the configured WebSocket path.
    pub fn get_ws_path(&self) -> &str {
        &self.ws_path
    }

    /// Returns the configured WebSocket Host header override, if any.
    pub fn get_ws_host(&self) -> Option<&str> {
        self.ws_host.as_deref()
    }

    /// Returns the configured WebSocket headers, if any.
    pub fn get_ws_headers(&self) -> Option<&str> {
        self.ws_headers.as_deref()
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
    /// Currently this validates only the embedded base proxy configuration.
    /// Additional protocol specific checks can be added as needed.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TrojanConfig;
    ///
    /// let config = TrojanConfig::new()
    ///     .set_alpn("h2,http/1.1");
    ///
    /// config.validate()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.base.validate()?;
        Ok(())
    }
}

impl Default for TrojanConfig {
    /// Creates the default Trojan configuration.
    ///
    /// Uses `"h2,http/1.1"` for ALPN, no SNI, and conservative timeouts.
    fn default() -> Self {
        Self::new()
    }
}

/// Wire `TrojanConfig` into the shared base config trait.
///
/// This provides base config builder methods like `.set_handshake_timeout()`,
/// `.set_phase_timeout()`, `.set_auto_tls()`, and others via `BaseProxyConfigBuilder`.
impl HasBaseProxyConfig for TrojanConfig {
    /// Access the shared base proxy configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use roxie::config::{TrojanConfig, HasBaseProxyConfig, BaseProxyConfigBuilder};
    ///
    /// let config = TrojanConfig::new()
    ///     .set_handshake_timeout(Duration::from_secs(12));
    ///
    /// assert_eq!(config.get_base_config().get_handshake_timeout(), Duration::from_secs(12));
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
    /// use roxie::config::{TrojanConfig, HasBaseProxyConfig};
    ///
    /// let mut config = TrojanConfig::new();
    /// config.get_base_config_mut().set_handshake_timeout(Duration::from_secs(8));
    ///
    /// assert_eq!(config.get_base_config().get_handshake_timeout(), Duration::from_secs(8));
    /// ```
    fn get_base_config_mut(&mut self) -> &mut BaseProxyConfig {
        Arc::make_mut(&mut self.base)
    }
}

impl TrojanConfig {
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
    fn trojan_config_defaults() {
        let config = TrojanConfig::default();
        assert!(config.get_sni().is_none());
        assert!(!config.is_skip_cert_verify());
        assert_eq!(config.get_alpn(), "h2,http/1.1");
        assert!(!config.is_ws_enabled());
        assert_eq!(config.get_ws_path(), "/");
        assert!(config.get_ws_headers().is_none());
        assert_eq!(config.get_connection_timeout(), Duration::from_secs(10));
    }

    #[test]
    fn trojan_config_builder_chain() {
        let config = TrojanConfig::new()
            .set_sni("example.com")
            .set_skip_cert_verify(true)
            .set_alpn("h2")
            .set_ws_enabled(true)
            .set_ws_path("/ws")
            .set_ws_headers("User-Agent: trojan-client")
            .set_connection_timeout(Duration::from_secs(25))
            .set_handshake_timeout(Duration::from_secs(15))
            .set_tcp_nodelay(false)
            .set_auto_tls(false);

        assert_eq!(config.get_sni(), Some("example.com"));
        assert!(config.is_skip_cert_verify());
        assert_eq!(config.get_alpn(), "h2");
        assert!(config.is_ws_enabled());
        assert_eq!(config.get_ws_path(), "/ws");
        assert_eq!(config.get_ws_headers(), Some("User-Agent: trojan-client"));
        assert_eq!(config.get_connection_timeout(), Duration::from_secs(25));
    }

    #[test]
    fn trojan_config_validation() {
        let config = TrojanConfig::new().set_alpn("h2,http/1.1");
        assert!(config.validate().is_ok());
    }
}
