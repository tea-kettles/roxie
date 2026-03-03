//! HTTP proxy configuration.
//!
//! Defines configuration for HTTP CONNECT proxy connections, including
//! authentication credentials and shared proxy timeouts/TLS via `BaseProxyConfig`.

#[allow(unused_imports)]
use std::time::Duration; // For doc examples

use crate::config::proxy_config::{BaseProxyConfig, HasBaseProxyConfig};
use crate::errors::config_errors::ConfigError;
use std::sync::Arc;

/* Types */

/// Configuration for HTTP CONNECT proxy connections.
///
/// Supports basic authentication and delegates common proxy settings like
/// timeouts and TLS to the base configuration via the `HasBaseProxyConfig` trait.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use roxie::config::HTTPConfig;
/// use roxie::config::BaseProxyConfigBuilder;
///
/// let config = HTTPConfig::new("proxy.example.com", 3128)
///     .set_credentials("user", "pass")
///     .set_handshake_timeout(Duration::from_secs(15))
///     .set_tcp_nodelay(false);
///
/// config.validate()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HTTPConfig {
    // Base proxy configuration shared with all protocols.
    base: Arc<BaseProxyConfig>,
    // Target HTTP proxy host.
    host: String,
    // Target HTTP proxy port.
    port: u16,
    // Optional username for proxy authentication.
    username: Option<String>,
    // Optional password for proxy authentication.
    password: Option<String>,
}

/* Implementations */

impl HTTPConfig {
    /// Create a new HTTP proxy configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::HTTPConfig;
    /// use roxie::config::BaseProxyConfigBuilder;
    ///
    /// let config = HTTPConfig::new("proxy.example.com", 8080);
    /// config.validate().unwrap();
    /// ```
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            base: Arc::new(BaseProxyConfig::new()),
            host: host.into(),
            port,
            username: None,
            password: None,
        }
    }

    /// Set the proxy host.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::HTTPConfig;
    /// use roxie::config::BaseProxyConfigBuilder;
    ///
    /// let config = HTTPConfig::new("old.example.com", 8080)
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
    /// use roxie::config::HTTPConfig;
    /// use roxie::config::BaseProxyConfigBuilder;
    ///
    /// let config = HTTPConfig::new("proxy.example.com", 8080)
    ///     .set_port(3128);
    ///
    /// config.validate().unwrap();
    /// ```
    pub fn set_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set the username for proxy authentication.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::HTTPConfig;
    ///
    /// let config = HTTPConfig::new("proxy.example.com", 8080)
    ///     .set_username("user");
    ///
    /// config.validate().unwrap();
    /// ```
    pub fn set_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Set the password for proxy authentication.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::HTTPConfig;
    ///
    /// let config = HTTPConfig::new("proxy.example.com", 8080)
    ///     .set_password("pass");
    ///
    /// config.validate().unwrap();
    /// ```
    pub fn set_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Set both username and password in one call.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::HTTPConfig;
    ///
    /// let config = HTTPConfig::new("proxy.example.com", 8080)
    ///     .set_credentials("user", "pass");
    ///
    /// config.validate().unwrap();
    /// ```
    pub fn set_credentials(
        mut self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    /// Returns the configured proxy host.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::HTTPConfig;
    ///
    /// let config = HTTPConfig::new("proxy.example.com", 8080);
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
    /// use roxie::config::HTTPConfig;
    ///
    /// let config = HTTPConfig::new("proxy.example.com", 8080);
    /// assert_eq!(config.get_port(), 8080);
    /// ```
    pub fn get_port(&self) -> u16 {
        self.port
    }

    /// Returns the configured username, if any.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::HTTPConfig;
    ///
    /// let config = HTTPConfig::new("proxy.example.com", 8080).set_username("alice");
    /// assert_eq!(config.get_username(), Some("alice"));
    /// ```
    pub fn get_username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// Returns the configured password, if any.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::HTTPConfig;
    ///
    /// let config = HTTPConfig::new("proxy.example.com", 8080).set_password("secret");
    /// assert_eq!(config.get_password(), Some("secret"));
    /// ```
    pub fn get_password(&self) -> Option<&str> {
        self.password.as_deref()
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
    /// use roxie::config::{HTTPConfig, BaseProxyConfigBuilder};
    ///
    /// let config = HTTPConfig::new("proxy.example.com", 8080)
    ///     .set_handshake_timeout(Duration::from_secs(20));
    ///
    /// assert_eq!(config.get_base().get_handshake_timeout(), Duration::from_secs(20));
    /// ```
    pub fn get_base(&self) -> &BaseProxyConfig {
        &self.base
    }

    /// Validate the configuration.
    ///
    /// Ensures host is not empty and port is in the valid range (1 to 65535).
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::HTTPConfig;
    ///
    /// let config = HTTPConfig::new("proxy.example.com", 8080)
    ///     .set_credentials("user", "pass");
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

        Ok(())
    }
}

impl Default for HTTPConfig {
    /// Creates the default HTTP proxy configuration (`localhost:8080`).
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::HTTPConfig;
    ///
    /// let config = HTTPConfig::default();
    /// assert_eq!(config.get_host(), "localhost");
    /// assert_eq!(config.get_port(), 8080);
    /// ```
    fn default() -> Self {
        Self::new("localhost", 8080)
    }
}

/// Wire HTTPConfig into the shared base config trait.
///
/// This provides all the base config builder methods like `.set_handshake_timeout()`,
/// `.set_phase_timeout()`, `.set_auto_tls()`, and others via `BaseProxyConfigBuilder`.
impl HasBaseProxyConfig for HTTPConfig {
    /// Access the shared base proxy configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use roxie::config::{HTTPConfig, HasBaseProxyConfig, BaseProxyConfigBuilder};
    ///
    /// let config = HTTPConfig::new("proxy.example.com", 8080)
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
    /// use roxie::config::{HTTPConfig, HasBaseProxyConfig};
    ///
    /// let mut config = HTTPConfig::new("proxy.example.com", 8080);
    /// config.get_base_config_mut().set_handshake_timeout(Duration::from_secs(5));
    ///
    /// assert_eq!(config.get_base_config().get_handshake_timeout(), Duration::from_secs(5));
    /// ```
    fn get_base_config_mut(&mut self) -> &mut BaseProxyConfig {
        Arc::make_mut(&mut self.base)
    }
}

impl HTTPConfig {
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
    fn http_config_defaults() {
        let config = HTTPConfig::default();
        assert_eq!(config.get_host(), "localhost");
        assert_eq!(config.get_port(), 8080);
        assert!(config.get_username().is_none());
        assert!(config.get_password().is_none());
        assert_eq!(
            config.get_base().get_handshake_timeout(),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn http_config_builder_chain() {
        let config = HTTPConfig::new("proxy.example.com", 3128)
            .set_credentials("user", "pass")
            .set_handshake_timeout(Duration::from_secs(15))
            .set_tcp_nodelay(false)
            .set_auto_tls(false);

        assert_eq!(config.get_host(), "proxy.example.com");
        assert_eq!(config.get_port(), 3128);
        assert_eq!(config.get_username(), Some("user"));
        assert_eq!(config.get_password(), Some("pass"));
        assert_eq!(
            config.get_base().get_handshake_timeout(),
            Duration::from_secs(15)
        );
        assert!(!config.get_base().is_tcp_nodelay());
        assert!(!config.get_base().is_auto_tls());
    }

    #[test]
    fn http_config_validation() {
        let valid = HTTPConfig::new("proxy.com", 8080);
        assert!(valid.validate().is_ok());

        let invalid_port = HTTPConfig::new("proxy.com", 0);
        assert!(invalid_port.validate().is_err());

        let invalid_host = HTTPConfig::new("", 8080);
        assert!(invalid_host.validate().is_err());
    }
}
