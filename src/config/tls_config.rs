//! TLS configuration.
//!
//! Configuration options for TLS connections including ALPN and certificate validation.

use std::time::Duration;

/* Constants */

const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 10_000;

/* Types */

/// TLS configuration options.
///
/// Controls TLS handshake behavior, certificate validation, and protocol negotiation.
///
/// # Examples
///
/// Basic TLS with default settings:
/// ```
/// use roxie::config::TLSConfig;
///
/// let config = TLSConfig::new();
/// ```
///
/// With ALPN protocols:
/// ```
/// use roxie::config::TLSConfig;
///
/// let config = TLSConfig::new()
///     .set_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
/// ```
///
/// Dangerous mode (accepts invalid certificates):
/// ```
/// use roxie::config::TLSConfig;
///
/// let config = TLSConfig::new().set_danger_accept_invalid_certs(true);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TLSConfig {
    handshake_timeout: Duration,
    alpn_protocols: Vec<Vec<u8>>,
    danger_accept_invalid_certs: bool,
}

/* Implementations */

impl TLSConfig {
    /// Create a new TLS configuration with default settings.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TLSConfig;
    ///
    /// let config = TLSConfig::new();
    /// # assert_eq!(config.get_handshake_timeout().as_secs(), 10);
    /// ```
    pub fn new() -> Self {
        Self {
            handshake_timeout: Duration::from_millis(DEFAULT_HANDSHAKE_TIMEOUT_MS),
            alpn_protocols: Vec::new(),
            danger_accept_invalid_certs: false,
        }
    }

    /// Set the handshake timeout.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TLSConfig;
    /// use std::time::Duration;
    ///
    /// let config = TLSConfig::new()
    ///     .set_handshake_timeout(Duration::from_secs(5));
    /// # assert_eq!(config.get_handshake_timeout().as_secs(), 5);
    /// ```
    pub fn set_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Set ALPN protocols for negotiation.
    ///
    /// Protocols are in wire format (length-prefixed byte strings).
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TLSConfig;
    ///
    /// let config = TLSConfig::new()
    ///     .set_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    /// ```
    pub fn set_alpn(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Enable or disable certificate verification.
    ///
    /// **WARNING**: Setting this to `true` disables all certificate validation
    /// and is dangerous. Only use for testing or when you have another way
    /// to verify the server's identity.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TLSConfig;
    ///
    /// // Dangerous: accepts any certificate
    /// let config = TLSConfig::new()
    ///     .set_danger_accept_invalid_certs(true);
    /// ```
    pub fn set_danger_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.danger_accept_invalid_certs = accept;
        self
    }

    /// Get the handshake timeout.
    pub fn get_handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    /// Get the ALPN protocols.
    pub fn get_alpn_protocols(&self) -> &[Vec<u8>] {
        &self.alpn_protocols
    }

    /// Get the configured ALPN protocols, if any.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::config::TLSConfig;
    ///
    /// let config = TLSConfig::new().set_alpn(vec![b"h2".to_vec()]);
    /// assert!(config.get_alpn().is_some());
    /// ```
    pub fn get_alpn(&self) -> Option<&[Vec<u8>]> {
        if self.alpn_protocols.is_empty() {
            None
        } else {
            Some(&self.alpn_protocols)
        }
    }

    /// Check if invalid certificates are accepted.
    pub fn is_danger_accept_invalid_certs(&self) -> bool {
        self.danger_accept_invalid_certs
    }
}

impl Default for TLSConfig {
    fn default() -> Self {
        Self::new()
    }
}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_has_default_timeout() {
        let config = TLSConfig::new();
        assert_eq!(
            config.get_handshake_timeout().as_millis(),
            DEFAULT_HANDSHAKE_TIMEOUT_MS as u128
        );
    }

    #[test]
    fn new_has_no_alpn() {
        let config = TLSConfig::new();
        assert!(config.get_alpn_protocols().is_empty());
    }

    #[test]
    fn new_does_not_accept_invalid_certs() {
        let config = TLSConfig::new();
        assert!(!config.is_danger_accept_invalid_certs());
    }

    #[test]
    fn handshake_timeout_sets_value() {
        let config = TLSConfig::new().set_handshake_timeout(Duration::from_secs(5));
        assert_eq!(config.get_handshake_timeout().as_secs(), 5);
    }

    #[test]
    fn alpn_sets_protocols() {
        let protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let config = TLSConfig::new().set_alpn(protocols.clone());
        assert_eq!(config.get_alpn_protocols(), &protocols);
    }

    #[test]
    fn danger_accept_invalid_certs_enables() {
        let config = TLSConfig::new().set_danger_accept_invalid_certs(true);
        assert!(config.is_danger_accept_invalid_certs());
    }

    #[test]
    fn builder_pattern_chains() {
        let config = TLSConfig::new()
            .set_handshake_timeout(Duration::from_secs(3))
            .set_alpn(vec![b"h2".to_vec()])
            .set_danger_accept_invalid_certs(true);

        assert_eq!(config.get_handshake_timeout().as_secs(), 3);
        assert_eq!(config.get_alpn_protocols().len(), 1);
        assert!(config.is_danger_accept_invalid_certs());
    }
}
