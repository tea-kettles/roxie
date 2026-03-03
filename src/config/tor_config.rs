//! Tor proxy configuration.
//!
//! Defines configuration for Tor control and path selection, and wires in
//! shared proxy timeouts/TLS via `BaseProxyConfig`.

#[allow(unused_imports)]
use std::time::Duration; // For doc examples

use crate::config::proxy_config::{BaseProxyConfig, HasBaseProxyConfig};
use crate::errors::config_errors::ConfigError;
use std::sync::Arc;

/* Types */

/// Configuration for Tor proxy connections.
///
/// This type describes how to talk to the Tor control interface and how to
/// shape Tor's circuit behavior (exit nodes, StrictNodes, bridges). Shared
/// timeouts and TLS options live in the embedded `BaseProxyConfig`.
///
/// The SOCKS endpoint that applications connect to is modeled separately
/// at the `Proxy::TOR` layer.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use roxie::config::TorConfig;
/// use roxie::config::BaseProxyConfigBuilder;
///
/// let config = TorConfig::new()
///     .set_control_host("127.0.0.1")
///     .set_control_port(9051)
///     .set_strict_nodes(true)
///     .set_exit_nodes("{us}")
///     .set_handshake_timeout(Duration::from_secs(20));
///
/// config.validate()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TorConfig {
    /* Tor control settings */
    // Host for Tor control port.
    control_host: String,
    // Control port for managing Tor.
    control_port: u16,
    // Control port password (if configured; otherwise cookie auth is expected).
    control_password: Option<String>,
    // Control port cookie (hex-encoded; if automatic fetching fails).
    control_cookie: Option<String>,

    /* Path selection */
    // Exit nodes to prefer (country codes or fingerprints, for example "{us}").
    exit_nodes: Option<String>,
    // Exit nodes to exclude (country codes or fingerprints, for example "{cn},{ru}").
    exclude_exit_nodes: Option<String>,
    // Whether to enforce exit and entry choices strictly (Tor StrictNodes).
    strict_nodes: bool,

    /* Bridges and censorship resistance */
    // Enable bridges for censorship circumvention.
    use_bridges: bool,
    // Bridge addresses (newline separated if multiple).
    bridges: Option<String>,

    /* Shared base proxy configuration */
    base: Arc<BaseProxyConfig>,
}

/* Implementations */

impl TorConfig {
    /// Creates a new `TorConfig` with sensible defaults.
    ///
    /// Defaults:
    /// * `control_host`: `"127.0.0.1"`
    /// * `control_port`: `9051`
    /// * `strict_nodes`: `false`
    /// * `use_bridges`: `false`
    /// * `base`: `BaseProxyConfig::new()` (10 second handshake, etc)
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new();
    /// assert_eq!(config.get_control_host(), "127.0.0.1");
    /// assert_eq!(config.get_control_port(), 9051);
    /// ```
    pub fn new() -> Self {
        Self {
            control_host: "127.0.0.1".to_string(),
            control_port: 9051,
            control_password: None,
            control_cookie: None,
            exit_nodes: None,
            exclude_exit_nodes: None,
            strict_nodes: false,
            use_bridges: false,
            bridges: None,
            base: Arc::new(BaseProxyConfig::new()),
        }
    }

    /* Builder methods: control interface */

    /// Sets the Tor control host.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new()
    ///     .set_control_host("tor.example.com");
    ///
    /// assert_eq!(config.get_control_host(), "tor.example.com");
    /// ```
    pub fn set_control_host(mut self, host: impl Into<String>) -> Self {
        self.control_host = host.into();
        self
    }

    /// Sets the Tor control port.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new()
    ///     .set_control_port(9151);
    ///
    /// assert_eq!(config.get_control_port(), 9151);
    /// ```
    pub fn set_control_port(mut self, port: u16) -> Self {
        self.control_port = port;
        self
    }

    /// Sets the Tor control password.
    ///
    /// If omitted, cookie auth is expected.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new()
    ///     .set_control_password("secret");
    ///
    /// assert_eq!(config.get_control_password(), Some("secret"));
    /// ```
    pub fn set_control_password(mut self, password: impl Into<String>) -> Self {
        self.control_password = Some(password.into());
        self
    }

    /// Sets the Tor control cookie (hex-encoded).
    ///
    /// Normally the cookie is automatically fetched from the filesystem based on
    /// PROTOCOLINFO, but if that fails you can provide it manually here.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new()
    ///     .set_control_cookie("DEADBEEF01234567");
    ///
    /// assert_eq!(config.get_control_cookie(), Some("DEADBEEF01234567"));
    /// ```
    pub fn set_control_cookie(mut self, cookie: impl Into<String>) -> Self {
        self.control_cookie = Some(cookie.into());
        self
    }

    /* Builder methods: path selection */

    /// Sets exit nodes to prefer (comma separated country codes or fingerprints).
    ///
    /// The value is passed directly to Tor, for example `"{us}"` or `"{us},{ca}"`.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new()
    ///     .set_exit_nodes("{us}");
    ///
    /// assert_eq!(config.get_exit_nodes(), Some("{us}"));
    /// ```
    pub fn set_exit_nodes(mut self, nodes: impl Into<String>) -> Self {
        self.exit_nodes = Some(nodes.into());
        self
    }

    /// Sets exit nodes to exclude (comma separated country codes or fingerprints).
    ///
    /// The value is passed directly to Tor, for example `"{cn},{ru}"`.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new()
    ///     .set_exclude_exit_nodes("{cn},{ru}");
    ///
    /// assert_eq!(config.get_exclude_exit_nodes(), Some("{cn},{ru}"));
    /// ```
    pub fn set_exclude_exit_nodes(mut self, nodes: impl Into<String>) -> Self {
        self.exclude_exit_nodes = Some(nodes.into());
        self
    }

    /// Enables or disables strict node selection (Tor StrictNodes).
    ///
    /// When enabled, Tor will only use the configured exit and entry nodes.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new()
    ///     .set_strict_nodes(true);
    ///
    /// assert!(config.is_strict_nodes());
    /// ```
    pub fn set_strict_nodes(mut self, strict: bool) -> Self {
        self.strict_nodes = strict;
        self
    }

    /* Builder methods: bridges */

    /// Enables or disables the use of bridges.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new()
    ///     .set_use_bridges(true);
    ///
    /// assert!(config.is_use_bridges());
    /// ```
    pub fn set_use_bridges(mut self, use_bridges: bool) -> Self {
        self.use_bridges = use_bridges;
        self
    }

    /// Sets bridge addresses (newline separated if multiple).
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new()
    ///     .set_bridges("bridge1:443\nbridge2:443");
    ///
    /// assert!(config.get_bridges().unwrap().contains("bridge1:443"));
    /// ```
    pub fn set_bridges(mut self, bridges: impl Into<String>) -> Self {
        self.bridges = Some(bridges.into());
        self
    }

    /// Clears the control password.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new()
    ///     .set_control_password("secret")
    ///     .clear_control_password();
    ///
    /// assert!(config.get_control_password().is_none());
    /// ```
    pub fn clear_control_password(mut self) -> Self {
        self.control_password = None;
        self
    }

    /// Clears the control cookie.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new()
    ///     .set_control_cookie("DEADBEEF")
    ///     .clear_control_cookie();
    ///
    /// assert!(config.get_control_cookie().is_none());
    /// ```
    pub fn clear_control_cookie(mut self) -> Self {
        self.control_cookie = None;
        self
    }

    /// Clears the preferred exit nodes.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new()
    ///     .set_exit_nodes("{us}")
    ///     .clear_exit_nodes();
    ///
    /// assert!(config.get_exit_nodes().is_none());
    /// ```
    pub fn clear_exit_nodes(mut self) -> Self {
        self.exit_nodes = None;
        self
    }

    /// Clears the excluded exit nodes.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new()
    ///     .set_exclude_exit_nodes("{cn}")
    ///     .clear_exclude_exit_nodes();
    ///
    /// assert!(config.get_exclude_exit_nodes().is_none());
    /// ```
    pub fn clear_exclude_exit_nodes(mut self) -> Self {
        self.exclude_exit_nodes = None;
        self
    }

    /// Clears the configured bridges.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new()
    ///     .set_bridges("bridge1:443")
    ///     .clear_bridges();
    ///
    /// assert!(config.get_bridges().is_none());
    /// ```
    pub fn clear_bridges(mut self) -> Self {
        self.bridges = None;
        self
    }

    /* Accessors */

    /// Returns the configured control host.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new();
    /// assert_eq!(config.get_control_host(), "127.0.0.1");
    /// ```
    pub fn get_control_host(&self) -> &str {
        &self.control_host
    }

    /// Returns the configured control port.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new();
    /// assert_eq!(config.get_control_port(), 9051);
    /// ```
    pub fn get_control_port(&self) -> u16 {
        self.control_port
    }

    /// Returns the configured control password, if any.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new();
    /// assert!(config.get_control_password().is_none());
    /// ```
    pub fn get_control_password(&self) -> Option<&str> {
        self.control_password.as_deref()
    }

    /// Returns the configured control cookie (hex-encoded), if any.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new();
    /// assert!(config.get_control_cookie().is_none());
    /// ```
    pub fn get_control_cookie(&self) -> Option<&str> {
        self.control_cookie.as_deref()
    }

    /// Returns the configured preferred exit nodes, if any.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new();
    /// assert!(config.get_exit_nodes().is_none());
    /// ```
    pub fn get_exit_nodes(&self) -> Option<&str> {
        self.exit_nodes.as_deref()
    }

    /// Returns the configured excluded exit nodes, if any.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new();
    /// assert!(config.get_exclude_exit_nodes().is_none());
    /// ```
    pub fn get_exclude_exit_nodes(&self) -> Option<&str> {
        self.exclude_exit_nodes.as_deref()
    }

    /// Returns whether strict node selection is enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new();
    /// assert!(!config.is_strict_nodes());
    /// ```
    pub fn is_strict_nodes(&self) -> bool {
        self.strict_nodes
    }

    /// Returns whether bridges are enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new();
    /// assert!(!config.is_use_bridges());
    /// ```
    pub fn is_use_bridges(&self) -> bool {
        self.use_bridges
    }

    /// Returns the configured bridges string, if any.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new();
    /// assert!(config.get_bridges().is_none());
    /// ```
    pub fn get_bridges(&self) -> Option<&str> {
        self.bridges.as_deref()
    }

    /// Returns a reference to the embedded base proxy configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new();
    /// assert_eq!(config.get_base().get_handshake_timeout(), Duration::from_secs(10));
    /// ```
    pub fn get_base(&self) -> &BaseProxyConfig {
        &self.base
    }

    /// Returns true if any control or path selection overrides are configured.
    pub fn has_control_config(&self) -> bool {
        self.control_password.is_some()
            || self.control_cookie.is_some()
            || self.exit_nodes.is_some()
            || self.exclude_exit_nodes.is_some()
            || self.strict_nodes
            || self.use_bridges
            || self.bridges.is_some()
            || self.control_host != "127.0.0.1"
            || self.control_port != 9051
    }

    /// Validate the configuration.
    ///
    /// Ensures that the control port is in the valid range (1 to 65535) and
    /// that the control host is not empty. Additional global checks can be
    /// added to `BaseProxyConfig::validate`.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TorConfig;
    ///
    /// let config = TorConfig::new();
    /// config.validate()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.base.validate()?;

        if self.control_port == 0 {
            return Err(ConfigError::InvalidValue {
                field: "control_port".to_string(),
                value: "0".to_string(),
                expected: "1-65535".to_string(),
            });
        }

        if self.control_host.is_empty() {
            return Err(ConfigError::MissingRequiredField {
                field: "control_host".to_string(),
            });
        }

        Ok(())
    }
}

impl Default for TorConfig {
    fn default() -> Self {
        Self::new()
    }
}

/* Trait impls */

/// Wire TorConfig into the shared base config trait.
///
/// This provides all the base config builder methods like `.set_handshake_timeout()`,
/// `.set_phase_timeout()`, `.set_auto_tls()`, and others via `BaseProxyConfigBuilder`.
impl HasBaseProxyConfig for TorConfig {
    /// Access the shared base proxy configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use roxie::config::{TorConfig, HasBaseProxyConfig, BaseProxyConfigBuilder};
    ///
    /// let config = TorConfig::new()
    ///     .set_handshake_timeout(Duration::from_secs(15));
    ///
    /// assert_eq!(config.get_base_config().get_handshake_timeout(), Duration::from_secs(15));
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
    /// use roxie::config::{TorConfig, HasBaseProxyConfig};
    ///
    /// let mut config = TorConfig::new();
    /// config.get_base_config_mut().set_handshake_timeout(Duration::from_secs(5));
    ///
    /// assert_eq!(config.get_base_config().get_handshake_timeout(), Duration::from_secs(5));
    /// ```
    fn get_base_config_mut(&mut self) -> &mut BaseProxyConfig {
        Arc::make_mut(&mut self.base)
    }
}

impl TorConfig {
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
    fn tor_config_defaults() {
        let config = TorConfig::default();
        assert_eq!(config.get_control_host(), "127.0.0.1");
        assert_eq!(config.get_control_port(), 9051);
        assert!(config.get_control_password().is_none());
        assert!(config.get_exit_nodes().is_none());
        assert!(config.get_exclude_exit_nodes().is_none());
        assert!(!config.is_strict_nodes());
        assert!(!config.is_use_bridges());
        assert!(config.get_bridges().is_none());
        // Base defaults
        assert_eq!(
            config.get_base().get_handshake_timeout(),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn tor_config_builder_chain() {
        let config = TorConfig::new()
            .set_control_host("tor.example.com")
            .set_control_port(9151)
            .set_control_password("secret")
            .set_exit_nodes("{us}")
            .set_exclude_exit_nodes("{cn},{ru}")
            .set_strict_nodes(true)
            .set_use_bridges(true)
            .set_bridges("bridge1:443\nbridge2:443")
            .set_handshake_timeout(Duration::from_secs(20))
            .set_tcp_nodelay(false)
            .set_auto_tls(false);

        assert_eq!(config.get_control_host(), "tor.example.com");
        assert_eq!(config.get_control_port(), 9151);
        assert_eq!(config.get_control_password(), Some("secret"));
        assert_eq!(config.get_exit_nodes(), Some("{us}"));
        assert_eq!(config.get_exclude_exit_nodes(), Some("{cn},{ru}"));
        assert!(config.is_strict_nodes());
        assert!(config.is_use_bridges());
        assert!(config.get_bridges().unwrap().contains("bridge1:443"));
        assert_eq!(
            config.get_base().get_handshake_timeout(),
            Duration::from_secs(20)
        );
        assert!(!config.get_base().is_tcp_nodelay());
        assert!(!config.get_base().is_auto_tls());
    }

    #[test]
    fn tor_config_validation() {
        let valid = TorConfig::new();
        assert!(valid.validate().is_ok());

        let invalid_port = TorConfig::new().set_control_port(0);
        assert!(invalid_port.validate().is_err());

        let invalid_host = TorConfig::new().set_control_host("");
        assert!(invalid_host.validate().is_err());
    }
}
