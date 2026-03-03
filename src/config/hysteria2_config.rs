//! Hysteria2 proxy configuration.
//!
//! Defines configuration for Hysteria2 proxy connections, including
//! congestion control, bandwidth hints, TLS like options, and shared
//! proxy timeouts/TLS via `BaseProxyConfig`.

use std::sync::Arc;
use std::time::Duration;

use crate::config::proxy_config::{BaseProxyConfig, HasBaseProxyConfig};
use crate::errors::config_errors::ConfigError;

/* Types */

/// Configuration for Hysteria2 proxy connections.
///
/// Hysteria2 is a QUIC based proxy protocol optimized for lossy networks.
/// This configuration models congestion control, bandwidth hints, and
/// TLS related parameters, while delegating generic proxy settings such
/// as timeouts and TLS to the embedded `BaseProxyConfig`.
///
/// ## Congestion control options
///
/// * `"bbr"` (default, recommended)
/// * `"cubic"`
/// * `"newreno"`
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use roxie::config::Hysteria2Config;
/// use roxie::config::BaseProxyConfigBuilder;
///
/// let config = Hysteria2Config::new()
///     .set_bandwidth(10, 50)
///     .set_congestion_control("bbr")
///     .set_sni("example.com")
///     .set_alpn("h3")
///     .set_connection_timeout(Duration::from_secs(15))
///     .set_idle_timeout(Duration::from_secs(120))
///     .set_handshake_timeout(Duration::from_secs(20));
///
/// config.validate()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Hysteria2Config {
    // Base proxy configuration shared with all protocols.
    base: Arc<BaseProxyConfig>,
    // Upload bandwidth in Mbps (0 means auto).
    up_mbps: u32,
    // Download bandwidth in Mbps (0 means auto).
    down_mbps: u32,
    // QUIC congestion control algorithm.
    congestion_control: String,
    // Server name for SNI.
    sni: Option<String>,
    // Whether to skip certificate verification.
    skip_cert_verify: bool,
    // ALPN protocols (comma separated, for example "h3").
    alpn: String,
    // Connection timeout when establishing the tunnel.
    connection_timeout: Duration,
    // Idle timeout before closing inactive connections.
    idle_timeout: Duration,
}

/* Implementations */

impl Hysteria2Config {
    /// Creates a new `Hysteria2Config` with sensible defaults.
    ///
    /// Defaults:
    /// * `up_mbps`: `0` (auto)
    /// * `down_mbps`: `0` (auto)
    /// * `congestion_control`: `"bbr"`
    /// * `sni`: `None`
    /// * `skip_cert_verify`: `false`
    /// * `alpn`: `"h3"`
    /// * `connection_timeout`: `10` seconds
    /// * `idle_timeout`: `60` seconds
    /// * `base`: `BaseProxyConfig::new()`
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::Hysteria2Config;
    ///
    /// let config = Hysteria2Config::new();
    /// assert_eq!(config.get_congestion_control(), "bbr");
    /// ```
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseProxyConfig::new()),
            up_mbps: 0,
            down_mbps: 0,
            congestion_control: "bbr".to_string(),
            sni: None,
            skip_cert_verify: false,
            alpn: "h3".to_string(),
            connection_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(60),
        }
    }

    /// Sets upload and download bandwidth hints in Mbps.
    ///
    /// Passing `0` for either value signals automatic detection.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::Hysteria2Config;
    ///
    /// let config = Hysteria2Config::new()
    ///     .set_bandwidth(10, 50);
    ///
    /// assert_eq!(config.get_up_mbps(), 10);
    /// assert_eq!(config.get_down_mbps(), 50);
    /// ```
    pub fn set_bandwidth(mut self, up_mbps: u32, down_mbps: u32) -> Self {
        self.up_mbps = up_mbps;
        self.down_mbps = down_mbps;
        self
    }

    /// Sets the congestion control algorithm.
    ///
    /// Valid values are `"bbr"`, `"cubic"`, and `"newreno"`. Validation
    /// is performed by [`Hysteria2Config::validate`].
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::Hysteria2Config;
    ///
    /// let config = Hysteria2Config::new()
    ///     .set_congestion_control("cubic");
    ///
    /// assert_eq!(config.get_congestion_control(), "cubic");
    /// ```
    pub fn set_congestion_control(mut self, cc: impl Into<String>) -> Self {
        self.congestion_control = cc.into();
        self
    }

    /// Sets the SNI (Server Name Indication) to present during TLS.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::Hysteria2Config;
    ///
    /// let config = Hysteria2Config::new()
    ///     .set_sni("example.com");
    ///
    /// assert_eq!(config.get_sni(), Some("example.com"));
    /// ```
    pub fn set_sni(mut self, sni: impl Into<String>) -> Self {
        self.sni = Some(sni.into());
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
    /// use roxie::config::Hysteria2Config;
    ///
    /// let config = Hysteria2Config::new()
    ///     .set_skip_cert_verify(true);
    ///
    /// assert!(config.is_skip_cert_verify());
    /// ```
    pub fn set_skip_cert_verify(mut self, skip: bool) -> Self {
        self.skip_cert_verify = skip;
        self
    }

    /// Sets ALPN protocols (comma separated, for example `"h3"`).
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::Hysteria2Config;
    ///
    /// let config = Hysteria2Config::new()
    ///     .set_alpn("h3,h3-29");
    ///
    /// assert_eq!(config.get_alpn(), "h3,h3-29");
    /// ```
    pub fn set_alpn(mut self, protocols: impl Into<String>) -> Self {
        self.alpn = protocols.into();
        self
    }

    /// Sets the connection timeout used when establishing the Hysteria2 tunnel.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use roxie::config::Hysteria2Config;
    ///
    /// let config = Hysteria2Config::new()
    ///     .set_connection_timeout(Duration::from_secs(30));
    ///
    /// assert_eq!(config.get_connection_timeout(), Duration::from_secs(30));
    /// ```
    pub fn set_connection_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = timeout;
        self
    }

    /// Sets the idle timeout before closing inactive connections.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use roxie::config::Hysteria2Config;
    ///
    /// let config = Hysteria2Config::new()
    ///     .set_idle_timeout(Duration::from_secs(90));
    ///
    /// assert_eq!(config.get_idle_timeout(), Duration::from_secs(90));
    /// ```
    pub fn set_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Clears the configured SNI value.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::Hysteria2Config;
    ///
    /// let config = Hysteria2Config::new()
    ///     .set_sni("example.com")
    ///     .clear_sni();
    ///
    /// assert!(config.get_sni().is_none());
    /// ```
    pub fn clear_sni(mut self) -> Self {
        self.sni = None;
        self
    }

    /// Clears the configured ALPN value.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::Hysteria2Config;
    ///
    /// let config = Hysteria2Config::new()
    ///     .set_alpn("h3,h3-29")
    ///     .clear_alpn();
    ///
    /// assert_eq!(config.get_alpn(), "h3");
    /// ```
    pub fn clear_alpn(mut self) -> Self {
        self.alpn = "h3".to_string();
        self
    }

    /// Returns the configured upload bandwidth in Mbps.
    pub fn get_up_mbps(&self) -> u32 {
        self.up_mbps
    }

    /// Returns the configured download bandwidth in Mbps.
    pub fn get_down_mbps(&self) -> u32 {
        self.down_mbps
    }

    /// Returns the configured congestion control algorithm.
    pub fn get_congestion_control(&self) -> &str {
        &self.congestion_control
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

    /// Returns the configured connection timeout.
    pub fn get_connection_timeout(&self) -> Duration {
        self.connection_timeout
    }

    /// Returns the configured idle timeout.
    pub fn get_idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Returns a shared reference to the embedded base proxy configuration.
    ///
    /// This is primarily intended for internal callers and tests that need to
    /// inspect timeout or TLS settings.
    pub fn get_base(&self) -> &BaseProxyConfig {
        &self.base
    }

    /// Validate the configuration.
    ///
    /// Ensures that the congestion control algorithm is recognized and that
    /// the embedded base proxy configuration passes its own validation.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::Hysteria2Config;
    ///
    /// let config = Hysteria2Config::new()
    ///     .set_congestion_control("bbr");
    ///
    /// config.validate()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.base.validate()?;

        let cc_normalized = self.congestion_control.to_lowercase();
        let valid = ["bbr", "cubic", "newreno"];

        if !valid.contains(&cc_normalized.as_str()) {
            return Err(ConfigError::InvalidValue {
                field: "congestion_control".to_string(),
                value: self.congestion_control.clone(),
                expected: "\"bbr\", \"cubic\", or \"newreno\"".to_string(),
            });
        }

        Ok(())
    }
}

impl Default for Hysteria2Config {
    /// Creates the default Hysteria2 configuration.
    ///
    /// Uses `"bbr"` for congestion control, auto bandwidth hints, and
    /// conservative timeout values.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::Hysteria2Config;
    ///
    /// let config = Hysteria2Config::default();
    /// assert_eq!(config.get_congestion_control(), "bbr");
    /// ```
    fn default() -> Self {
        Self::new()
    }
}

/// Wire `Hysteria2Config` into the shared base config trait.
///
/// This provides all the base config builder methods like
/// `.set_handshake_timeout()`, `.set_phase_timeout()`, `.set_auto_tls()`, and others
/// via `BaseProxyConfigBuilder`.
impl HasBaseProxyConfig for Hysteria2Config {
    /// Access the shared base proxy configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use roxie::config::{Hysteria2Config, HasBaseProxyConfig, BaseProxyConfigBuilder};
    ///
    /// let config = Hysteria2Config::new()
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
    /// use roxie::config::{Hysteria2Config, HasBaseProxyConfig};
    ///
    /// let mut config = Hysteria2Config::new();
    /// config.get_base_config_mut().set_handshake_timeout(Duration::from_secs(5));
    ///
    /// assert_eq!(config.get_base_config().get_handshake_timeout(), Duration::from_secs(5));
    /// ```
    fn get_base_config_mut(&mut self) -> &mut BaseProxyConfig {
        Arc::make_mut(&mut self.base)
    }
}

impl Hysteria2Config {
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
    fn hysteria2_config_defaults() {
        let config = Hysteria2Config::default();
        assert_eq!(config.get_up_mbps(), 0);
        assert_eq!(config.get_down_mbps(), 0);
        assert_eq!(config.get_congestion_control(), "bbr");
        assert!(config.get_sni().is_none());
        assert!(!config.is_skip_cert_verify());
        assert_eq!(config.get_alpn(), "h3");
        assert_eq!(config.get_connection_timeout(), Duration::from_secs(10));
        assert_eq!(config.get_idle_timeout(), Duration::from_secs(60));
        assert_eq!(
            config.get_base().get_handshake_timeout(),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn hysteria2_config_builder_chain() {
        let config = Hysteria2Config::new()
            .set_bandwidth(10, 20)
            .set_congestion_control("newreno")
            .set_sni("example.com")
            .set_skip_cert_verify(true)
            .set_alpn("h3,h3-29")
            .set_connection_timeout(Duration::from_secs(30))
            .set_idle_timeout(Duration::from_secs(90))
            .set_handshake_timeout(Duration::from_secs(15))
            .set_tcp_nodelay(false)
            .set_auto_tls(false);

        assert_eq!(config.get_up_mbps(), 10);
        assert_eq!(config.get_down_mbps(), 20);
        assert_eq!(config.get_congestion_control(), "newreno");
        assert_eq!(config.get_sni(), Some("example.com"));
        assert!(config.is_skip_cert_verify());
        assert_eq!(config.get_alpn(), "h3,h3-29");
        assert_eq!(config.get_connection_timeout(), Duration::from_secs(30));
        assert_eq!(config.get_idle_timeout(), Duration::from_secs(90));
        assert_eq!(
            config.get_base().get_handshake_timeout(),
            Duration::from_secs(15)
        );
        assert!(!config.get_base().is_tcp_nodelay());
        assert!(!config.get_base().is_auto_tls());
    }

    #[test]
    fn hysteria2_config_validation() {
        let valid = Hysteria2Config::new().set_congestion_control("cubic");
        assert!(valid.validate().is_ok());

        let invalid = Hysteria2Config::new().set_congestion_control("totally-unknown-cc");
        assert!(invalid.validate().is_err());
    }
}
