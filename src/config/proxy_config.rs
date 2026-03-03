//! Shared base proxy configuration.
//!
//! This module provides cross-cutting configuration that applies to all proxy
//! protocols, including timeouts, DNS resolution behavior, and TCP options.
//! The configuration is designed to be embedded in protocol-specific configs
//! via the `HasBaseProxyConfig` trait.

use std::time::Duration;

use crate::config::TLSConfig;
use crate::errors::config_errors::ConfigError;

/// Base config used by all proxy protocols.
///
/// Holds cross-cutting configuration like timeouts and DNS behavior that apply
/// regardless of the specific proxy protocol being used. Protocol-specific
/// configs embed this via `HasBaseProxyConfig`.
///
/// # Examples
///
/// ```
/// use roxie::config::BaseProxyConfig;
/// use std::time::Duration;
///
/// let mut config = BaseProxyConfig::new();
/// config.set_handshake_timeout(Duration::from_secs(15));
/// config.set_tcp_nodelay(true);
/// config.set_auto_tls(true);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BaseProxyConfig {
    handshake_timeout: Duration,
    phase_timeout: Duration,
    resolve_locally: bool,
    tcp_nodelay: bool,
    keep_alive: Option<Duration>,
    auto_tls: bool,
    tls_config: Option<TLSConfig>,
}

/* Implementations */

impl BaseProxyConfig {
    /// Creates a new `BaseProxyConfig` with sensible defaults.
    ///
    /// Default values:
    /// - `handshake_timeout`: 10 seconds
    /// - `phase_timeout`: 5 seconds
    /// - `resolve_locally`: false
    /// - `tcp_nodelay`: true
    /// - `keep_alive`: 60 seconds
    /// - `auto_tls`: true
    /// - `tls_config`: None
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::BaseProxyConfig;
    ///
    /// let config = BaseProxyConfig::new();
    /// assert!(config.is_tcp_nodelay());
    /// assert!(config.is_auto_tls());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(10),
            phase_timeout: Duration::from_secs(5),
            resolve_locally: false,
            tcp_nodelay: true,
            keep_alive: Some(Duration::from_secs(60)),
            auto_tls: true,
            tls_config: None,
        }
    }

    /// Sets the total handshake timeout.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::BaseProxyConfig;
    /// use std::time::Duration;
    ///
    /// let mut config = BaseProxyConfig::new();
    /// config.set_handshake_timeout(Duration::from_secs(15));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn set_handshake_timeout(&mut self, timeout: Duration) {
        self.handshake_timeout = timeout;
    }

    /// Sets the per-phase timeout used for greeting, auth, and connect steps.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::BaseProxyConfig;
    /// use std::time::Duration;
    ///
    /// let mut config = BaseProxyConfig::new();
    /// config.set_phase_timeout(Duration::from_secs(3));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn set_phase_timeout(&mut self, timeout: Duration) {
        self.phase_timeout = timeout;
    }

    /// Controls whether DNS is resolved locally instead of by the proxy.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::BaseProxyConfig;
    ///
    /// let mut config = BaseProxyConfig::new();
    /// config.set_resolve_locally(true);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn set_resolve_locally(&mut self, resolve: bool) {
        self.resolve_locally = resolve;
    }

    /// Enables or disables the TCP_NODELAY socket option.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::BaseProxyConfig;
    ///
    /// let mut config = BaseProxyConfig::new();
    /// config.set_tcp_nodelay(false);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn set_tcp_nodelay(&mut self, nodelay: bool) {
        self.tcp_nodelay = nodelay;
    }

    /// Sets the TCP keep-alive duration.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::BaseProxyConfig;
    /// use std::time::Duration;
    ///
    /// let mut config = BaseProxyConfig::new();
    /// config.set_keep_alive(Duration::from_secs(30));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn set_keep_alive(&mut self, duration: Duration) {
        self.keep_alive = Some(duration);
    }

    /// Enables or disables automatic TLS for HTTPS targets.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::BaseProxyConfig;
    ///
    /// let mut config = BaseProxyConfig::new();
    /// config.set_auto_tls(false);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn set_auto_tls(&mut self, enabled: bool) {
        self.auto_tls = enabled;
    }

    /// Clears the TCP keep-alive duration.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::BaseProxyConfig;
    ///
    /// let mut config = BaseProxyConfig::new();
    /// config.clear_keep_alive();
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn clear_keep_alive(&mut self) {
        self.keep_alive = None;
    }

    /// Sets the TLS configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::{BaseProxyConfig, TLSConfig};
    ///
    /// let mut config = BaseProxyConfig::new();
    /// config.set_tls_config(TLSConfig::new());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn set_tls_config(&mut self, tls_config: TLSConfig) {
        self.tls_config = Some(tls_config);
    }

    /// Clears the TLS configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::BaseProxyConfig;
    ///
    /// let mut config = BaseProxyConfig::new();
    /// config.clear_tls_config();
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn clear_tls_config(&mut self) {
        self.tls_config = None;
    }

    /// Total handshake timeout.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::BaseProxyConfig;
    /// use std::time::Duration;
    ///
    /// let config = BaseProxyConfig::new();
    /// assert_eq!(config.get_handshake_timeout(), Duration::from_secs(10));
    /// ```
    pub fn get_handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    /// Per-phase timeout used for greeting, auth, and connect steps.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::BaseProxyConfig;
    /// use std::time::Duration;
    ///
    /// let config = BaseProxyConfig::new();
    /// assert_eq!(config.get_phase_timeout(), Duration::from_secs(5));
    /// ```
    pub fn get_phase_timeout(&self) -> Duration {
        self.phase_timeout
    }

    /// Whether DNS is resolved locally instead of by the proxy.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::BaseProxyConfig;
    ///
    /// let config = BaseProxyConfig::new();
    /// assert!(!config.is_resolve_locally());
    /// ```
    pub fn is_resolve_locally(&self) -> bool {
        self.resolve_locally
    }

    /// Whether the TCP_NODELAY socket option is enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::BaseProxyConfig;
    ///
    /// let config = BaseProxyConfig::new();
    /// assert!(config.is_tcp_nodelay());
    /// ```
    pub fn is_tcp_nodelay(&self) -> bool {
        self.tcp_nodelay
    }

    /// TCP keep-alive duration, if configured.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::BaseProxyConfig;
    /// use std::time::Duration;
    ///
    /// let config = BaseProxyConfig::new();
    /// assert_eq!(config.get_keep_alive(), Some(Duration::from_secs(60)));
    /// ```
    pub fn get_keep_alive(&self) -> Option<Duration> {
        self.keep_alive
    }

    /// Whether automatic TLS for HTTPS targets is enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::BaseProxyConfig;
    ///
    /// let config = BaseProxyConfig::new();
    /// assert!(config.is_auto_tls());
    /// ```
    pub fn is_auto_tls(&self) -> bool {
        self.auto_tls
    }

    /// Returns the configured TLS options, if any.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::BaseProxyConfig;
    ///
    /// let config = BaseProxyConfig::new();
    /// assert!(config.get_tls_config().is_none());
    /// ```
    pub fn get_tls_config(&self) -> Option<&TLSConfig> {
        self.tls_config.as_ref()
    }

    /// Validates the configuration for internal consistency.
    ///
    /// Ensures that all timeout durations are non-zero and that keep-alive
    /// duration (if configured) is also non-zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::BaseProxyConfig;
    ///
    /// let config = BaseProxyConfig::new();
    /// config.validate()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.handshake_timeout.is_zero() {
            return Err(ConfigError::InvalidValue {
                field: "handshake_timeout".to_string(),
                value: "0s".to_string(),
                expected: "non-zero duration".to_string(),
            });
        }

        if self.phase_timeout.is_zero() {
            return Err(ConfigError::InvalidValue {
                field: "phase_timeout".to_string(),
                value: "0s".to_string(),
                expected: "non-zero duration".to_string(),
            });
        }

        if let Some(keep_alive) = self.keep_alive {
            if keep_alive.is_zero() {
                return Err(ConfigError::InvalidValue {
                    field: "keep_alive".to_string(),
                    value: "0s".to_string(),
                    expected: "non-zero duration or None".to_string(),
                });
            }
        }

        Ok(())
    }
}

impl Default for BaseProxyConfig {
    fn default() -> Self {
        Self::new()
    }
}

/* Traits */

// Shared access and builder helpers for types that embed BaseProxyConfig.

/// Types that embed a `BaseProxyConfig`.
///
/// Implement this trait to gain access to the `BaseProxyConfigBuilder` methods
/// via the blanket implementation.
///
/// Implementors may keep the base config behind shared ownership (for example,
/// an `Arc<BaseProxyConfig>`). In that case, `get_base_config_mut` should use
/// copy-on-write semantics (e.g., `Arc::make_mut`) so callers still receive a
/// plain mutable reference without knowing about the internal sharing.
pub trait HasBaseProxyConfig {
    /// Returns an immutable reference to the embedded base config.
    fn get_base_config(&self) -> &BaseProxyConfig;

    /// Returns a mutable reference to the embedded base config.
    fn get_base_config_mut(&mut self) -> &mut BaseProxyConfig;
}

/// Builder-style helpers for any type that contains a `BaseProxyConfig`.
///
/// Implemented automatically for any `T` that implements `HasBaseProxyConfig`.
/// Provides fluent configuration methods that return `Self` for chaining.
///
/// # Examples
///
/// ```
/// # use roxie::config::{BaseProxyConfig, HasBaseProxyConfig, BaseProxyConfigBuilder};
/// # use std::time::Duration;
/// #
/// # struct MyConfig {
/// #     base: BaseProxyConfig,
/// # }
/// #
/// # impl HasBaseProxyConfig for MyConfig {
/// #     fn get_base_config(&self) -> &BaseProxyConfig { &self.base }
/// #     fn get_base_config_mut(&mut self) -> &mut BaseProxyConfig { &mut self.base }
/// # }
/// #
/// # impl MyConfig {
/// #     fn new() -> Self { Self { base: BaseProxyConfig::new() } }
/// # }
/// #
/// let config = MyConfig::new()
///     .set_handshake_timeout(Duration::from_secs(15))
///     .set_tcp_nodelay(true)
///     .set_auto_tls(true);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub trait BaseProxyConfigBuilder: HasBaseProxyConfig + Sized {
    /// Sets the total handshake timeout.
    fn set_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.get_base_config_mut().set_handshake_timeout(timeout);
        self
    }

    /// Sets the per-phase timeout used for greeting, auth, and connect steps.
    fn set_phase_timeout(mut self, timeout: Duration) -> Self {
        self.get_base_config_mut().set_phase_timeout(timeout);
        self
    }

    /// Controls whether DNS is resolved locally instead of by the proxy.
    fn set_resolve_locally(mut self, resolve: bool) -> Self {
        self.get_base_config_mut().set_resolve_locally(resolve);
        self
    }

    /// Enables or disables the TCP_NODELAY socket option.
    fn set_tcp_nodelay(mut self, nodelay: bool) -> Self {
        self.get_base_config_mut().set_tcp_nodelay(nodelay);
        self
    }

    /// Sets the TCP keep-alive duration.
    fn set_keep_alive(mut self, duration: Duration) -> Self {
        self.get_base_config_mut().set_keep_alive(duration);
        self
    }

    /// Enables or disables automatic TLS for HTTPS targets.
    fn set_auto_tls(mut self, enabled: bool) -> Self {
        self.get_base_config_mut().set_auto_tls(enabled);
        self
    }

    /// Sets the optional TLS configuration.
    fn set_tls_config(mut self, tls_config: TLSConfig) -> Self {
        self.get_base_config_mut().set_tls_config(tls_config);
        self
    }

    /// Clears the TCP keep-alive duration.
    fn clear_keep_alive(mut self) -> Self {
        self.get_base_config_mut().clear_keep_alive();
        self
    }

    /// Clears the TLS configuration.
    fn clear_tls_config(mut self) -> Self {
        self.get_base_config_mut().clear_tls_config();
        self
    }
}

// Blanket impl so every HasBaseProxyConfig gets the builder methods.
impl<T> BaseProxyConfigBuilder for T where T: HasBaseProxyConfig + Sized {}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_config_defaults() {
        let config = BaseProxyConfig::new();
        assert_eq!(config.get_handshake_timeout(), Duration::from_secs(10));
        assert_eq!(config.get_phase_timeout(), Duration::from_secs(5));
        assert!(!config.is_resolve_locally());
        assert!(config.is_tcp_nodelay());
        assert_eq!(config.get_keep_alive(), Some(Duration::from_secs(60)));
        assert!(config.is_auto_tls());
    }

    #[test]
    fn base_config_default_validates() {
        let config = BaseProxyConfig::new();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn base_config_setters_work() {
        let mut config = BaseProxyConfig::new();
        config.set_handshake_timeout(Duration::from_secs(20));
        config.set_phase_timeout(Duration::from_secs(3));
        config.set_resolve_locally(true);
        config.set_tcp_nodelay(false);
        config.set_keep_alive(Duration::from_secs(30));
        config.set_auto_tls(false);

        assert_eq!(config.get_handshake_timeout(), Duration::from_secs(20));
        assert_eq!(config.get_phase_timeout(), Duration::from_secs(3));
        assert!(config.is_resolve_locally());
        assert!(!config.is_tcp_nodelay());
        assert_eq!(config.get_keep_alive(), Some(Duration::from_secs(30)));
        assert!(!config.is_auto_tls());
    }

    #[test]
    fn validation_rejects_zero_handshake_timeout() {
        let mut config = BaseProxyConfig::new();
        config.set_handshake_timeout(Duration::ZERO);
        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("handshake_timeout"));
    }

    #[test]
    fn validation_rejects_zero_phase_timeout() {
        let mut config = BaseProxyConfig::new();
        config.set_phase_timeout(Duration::ZERO);
        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("phase_timeout"));
    }

    #[test]
    fn validation_rejects_zero_keep_alive() {
        let mut config = BaseProxyConfig::new();
        config.set_keep_alive(Duration::ZERO);
        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("keep_alive"));
    }

    #[test]
    fn validation_accepts_none_keep_alive() {
        let mut config = BaseProxyConfig::new();
        config.clear_keep_alive();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validation_accepts_valid_positive_durations() {
        let mut config = BaseProxyConfig::new();
        config.set_handshake_timeout(Duration::from_millis(1));
        config.set_phase_timeout(Duration::from_millis(1));
        config.set_keep_alive(Duration::from_millis(1));
        assert!(config.validate().is_ok());
    }
}
