//! SOCKS4/SOCKS4A proxy configuration.
//!
//! Defines configuration for SOCKS4 and SOCKS4A proxy connections, including
//! optional user ID and shared proxy timeouts/TLS via `BaseProxyConfig`.

use crate::config::proxy_config::{BaseProxyConfig, HasBaseProxyConfig};
use crate::errors::config_errors::ConfigError;
use std::sync::Arc;

/* Types */

/// Configuration for SOCKS4/SOCKS4A proxy connections.
///
/// Supports optional user ID (informational only, not authenticated) and delegates
/// common proxy settings like timeouts and TLS to the base configuration via the
/// `HasBaseProxyConfig` trait.
///
/// SOCKS4A (domain name support) is automatically used when `resolve_locally` is false
/// and the target is a domain name rather than an IP address.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use roxie::config::SOCKS4Config;
/// use roxie::config::BaseProxyConfigBuilder;
///
/// let config = SOCKS4Config::new("proxy.example.com", 1080)
///     .set_user_id("myuser")
///     .set_handshake_timeout(Duration::from_secs(15))
///     .set_resolve_locally(false); // Use SOCKS4A for domain names
///
/// config.validate()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SOCKS4Config {
    // Base proxy configuration shared with all protocols.
    base: Arc<BaseProxyConfig>,
    // Target SOCKS4 proxy host.
    host: String,
    // Target SOCKS4 proxy port.
    port: u16,
    // Optional user ID for SOCKS4 (informational only, not authenticated).
    user_id: Option<String>,
}

/* Implementations */

impl SOCKS4Config {
    /// Create a new SOCKS4 proxy configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::SOCKS4Config;
    ///
    /// let config = SOCKS4Config::new("proxy.example.com", 1080);
    /// config.validate().unwrap();
    /// ```
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            base: Arc::new(BaseProxyConfig::new()),
            host: host.into(),
            port,
            user_id: None,
        }
    }

    /// Set the proxy host.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::SOCKS4Config;
    ///
    /// let config = SOCKS4Config::new("old.example.com", 1080)
    ///     .set_host("new.example.com");
    ///
    /// config.validate().unwrap();
    /// ```
    pub fn set_host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into();
        self
    }

    /// Set the proxy port.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::SOCKS4Config;
    ///
    /// let config = SOCKS4Config::new("proxy.example.com", 1080)
    ///     .set_port(1081);
    ///
    /// config.validate().unwrap();
    /// ```
    pub fn set_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set the user ID for the proxy connection.
    ///
    /// Note: SOCKS4 user ID is informational only and provides no authentication.
    /// It is included in the connection request but not validated by most servers.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::SOCKS4Config;
    ///
    /// let config = SOCKS4Config::new("proxy.example.com", 1080)
    ///     .set_user_id("myuser");
    ///
    /// config.validate().unwrap();
    /// ```
    pub fn set_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Returns the configured proxy host.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::SOCKS4Config;
    ///
    /// let config = SOCKS4Config::new("proxy.example.com", 1080);
    /// assert_eq!(config.get_host(), "proxy.example.com");
    /// ```
    pub fn get_host(&self) -> &str {
        &self.host
    }

    /// Returns the configured proxy port.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::SOCKS4Config;
    ///
    /// let config = SOCKS4Config::new("proxy.example.com", 1080);
    /// assert_eq!(config.get_port(), 1080);
    /// ```
    pub fn get_port(&self) -> u16 {
        self.port
    }

    /// Returns the configured user ID, if any.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::SOCKS4Config;
    ///
    /// let config = SOCKS4Config::new("proxy.example.com", 1080).set_user_id("alice");
    /// assert_eq!(config.get_user_id(), Some("alice"));
    /// ```
    pub fn get_user_id(&self) -> Option<&str> {
        self.user_id.as_deref()
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
    /// use roxie::config::{SOCKS4Config, BaseProxyConfigBuilder};
    ///
    /// let config = SOCKS4Config::new("proxy.example.com", 1080)
    ///     .set_handshake_timeout(Duration::from_secs(20));
    ///
    /// assert_eq!(config.get_base().get_handshake_timeout(), Duration::from_secs(20));
    /// ```
    pub fn get_base(&self) -> &BaseProxyConfig {
        &self.base
    }

    /// Validate the configuration.
    ///
    /// Ensures host is not empty and port is in the valid range (1-65535).
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::SOCKS4Config;
    ///
    /// let config = SOCKS4Config::new("proxy.example.com", 1080)
    ///     .set_user_id("myuser");
    /// config.validate()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.base.validate()?;

        if self.port == 0 {
            return Err(ConfigError::InvalidValue {
                field: "port".to_string(),
                value: "0".to_string(),
                expected: "1-65535".to_string(),
            });
        }

        if self.host.is_empty() {
            return Err(ConfigError::MissingRequiredField {
                field: "host".to_string(),
            });
        }

        // Validate user_id if present
        if let Some(uid) = &self.user_id {
            if uid.len() > 255 {
                return Err(ConfigError::InvalidValue {
                    field: "user_id".to_string(),
                    value: format!("{} bytes", uid.len()),
                    expected: "maximum 255 bytes".to_string(),
                });
            }

            if uid.contains('\0') {
                return Err(ConfigError::InvalidValue {
                    field: "user_id".to_string(),
                    value: "contains null byte".to_string(),
                    expected: "no null bytes (would break SOCKS4 framing)".to_string(),
                });
            }
        }

        Ok(())
    }
}

impl Default for SOCKS4Config {
    /// Creates the default SOCKS4 proxy configuration (`localhost:1080`).
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::SOCKS4Config;
    ///
    /// let config = SOCKS4Config::default();
    /// assert_eq!(config.get_host(), "localhost");
    /// assert_eq!(config.get_port(), 1080);
    /// ```
    fn default() -> Self {
        Self::new("localhost", 1080)
    }
}

/// Wire SOCKS4Config into the shared base config trait.
///
/// This provides all the base config builder methods like `.set_handshake_timeout()`,
/// `.set_phase_timeout()`, `.set_resolve_locally()`, etc. via `BaseProxyConfigBuilder`.
impl HasBaseProxyConfig for SOCKS4Config {
    /// Access the shared base proxy configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use roxie::config::{SOCKS4Config, HasBaseProxyConfig, BaseProxyConfigBuilder};
    ///
    /// let config = SOCKS4Config::new("proxy.example.com", 1080)
    ///     .set_handshake_timeout(Duration::from_secs(20));
    ///
    /// assert_eq!(config.get_base_config().get_handshake_timeout(), Duration::from_secs(20));
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
    /// use roxie::config::{SOCKS4Config, HasBaseProxyConfig};
    ///
    /// let mut config = SOCKS4Config::new("proxy.example.com", 1080);
    /// config.get_base_config_mut().set_handshake_timeout(Duration::from_secs(5));
    ///
    /// assert_eq!(config.get_base_config().get_handshake_timeout(), Duration::from_secs(5));
    /// ```
    fn get_base_config_mut(&mut self) -> &mut BaseProxyConfig {
        Arc::make_mut(&mut self.base)
    }
}

impl SOCKS4Config {
    pub(crate) fn set_base_arc(&mut self, base: Arc<BaseProxyConfig>) {
        self.base = base;
    }
}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::proxy_config::BaseProxyConfigBuilder;
    use std::time::Duration;

    #[test]
    fn socks4_config_defaults() {
        let config = SOCKS4Config::default();
        assert_eq!(config.get_host(), "localhost");
        assert_eq!(config.get_port(), 1080);
        assert!(config.get_user_id().is_none());
        assert_eq!(
            config.get_base().get_handshake_timeout(),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn socks4_config_builder_chain() {
        let config = SOCKS4Config::new("proxy.example.com", 1080)
            .set_user_id("myuser")
            .set_handshake_timeout(Duration::from_secs(15))
            .set_tcp_nodelay(false)
            .set_resolve_locally(false);

        assert_eq!(config.get_host(), "proxy.example.com");
        assert_eq!(config.get_port(), 1080);
        assert_eq!(config.get_user_id(), Some("myuser"));
        assert_eq!(
            config.get_base().get_handshake_timeout(),
            Duration::from_secs(15)
        );
        assert!(!config.get_base().is_tcp_nodelay());
        assert!(!config.get_base().is_resolve_locally());
    }

    #[test]
    fn socks4_config_validation() {
        let valid = SOCKS4Config::new("proxy.com", 1080);
        assert!(valid.validate().is_ok());

        let invalid_port = SOCKS4Config::new("proxy.com", 0);
        assert!(invalid_port.validate().is_err());

        let invalid_host = SOCKS4Config::new("", 1080);
        assert!(invalid_host.validate().is_err());
    }

    #[test]
    fn socks4_config_user_id_too_long() {
        let long_user = "a".repeat(256);
        let config = SOCKS4Config::new("proxy.com", 1080).set_user_id(long_user);
        assert!(config.validate().is_err());
    }

    #[test]
    fn socks4_config_user_id_with_null_byte() {
        let config = SOCKS4Config::new("proxy.com", 1080).set_user_id("bad\0user");
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("null bytes"));
    }

    #[test]
    fn socks4_config_valid_user_id() {
        let config = SOCKS4Config::new("proxy.com", 1080).set_user_id("validuser123");
        assert!(config.validate().is_ok());
    }
}
