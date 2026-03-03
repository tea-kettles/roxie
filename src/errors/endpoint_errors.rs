//! Endpoint resolution and DNS errors.
//!
//! Defines errors that can occur during endpoint parsing, IDNA encoding,
//! and DNS resolution operations. These errors provide detailed context
//! about which hostname failed to resolve and why.
//!
//! # Examples
//!
//! DNS resolution failure:
//!
//! ```
//! use roxie::errors::EndpointError;
//! use std::io;
//!
//! let err = EndpointError::DnsResolutionFailed {
//!     host: "nonexistent.example.com".to_string(),
//!     source: io::Error::new(io::ErrorKind::NotFound, "name not found"),
//! };
//!
//! assert!(err.to_string().contains("nonexistent.example.com"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::io;

/* Types */

/// Errors that can occur during endpoint operations.
///
/// Endpoint operations include DNS resolution, domain name validation,
/// and IDNA encoding. All errors provide the problematic hostname and
/// detailed context about what went wrong.
///
/// # Examples
///
/// DNS timeout with timing information:
///
/// ```
/// use roxie::errors::EndpointError;
///
/// let err = EndpointError::DnsResolutionTimeout {
///     host: "slow.example.com".to_string(),
///     elapsed_ms: 5100,
///     timeout_ms: 5000,
/// };
///
/// assert!(err.to_string().contains("timed out"));
/// assert!(err.to_string().contains("5100"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// DNS resolution failed.
    ///
    /// This error occurs when the DNS resolver returns an error for the given
    /// hostname. The underlying I/O error is preserved in the source chain,
    /// allowing callers to inspect the specific DNS failure reason.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::errors::EndpointError;
    /// use std::io;
    ///
    /// let err = EndpointError::DnsResolutionFailed {
    ///     host: "bad.example.com".to_string(),
    ///     source: io::Error::new(io::ErrorKind::NotFound, "not found"),
    /// };
    ///
    /// assert!(err.to_string().contains("DNS resolution failed"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[error("DNS resolution failed for '{host}': {source}")]
    DnsResolutionFailed {
        /// Hostname that failed to resolve.
        host: String,
        /// Underlying I/O error from the DNS resolver.
        #[source]
        source: io::Error,
    },

    /// DNS resolution timed out.
    ///
    /// This error occurs when DNS resolution takes longer than the configured
    /// timeout. The error includes both the elapsed time and the configured
    /// timeout for debugging.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::errors::EndpointError;
    ///
    /// let err = EndpointError::DnsResolutionTimeout {
    ///     host: "slow.example.com".to_string(),
    ///     elapsed_ms: 5100,
    ///     timeout_ms: 5000,
    /// };
    ///
    /// assert!(err.to_string().contains("timed out"));
    /// assert!(err.to_string().contains("after 5100ms"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[error("DNS resolution timed out for '{host}' after {elapsed_ms}ms (timeout: {timeout_ms}ms)")]
    DnsResolutionTimeout {
        /// Hostname that timed out.
        host: String,
        /// Time elapsed before timeout in milliseconds.
        elapsed_ms: u64,
        /// Configured timeout duration in milliseconds.
        timeout_ms: u64,
    },

    /// Domain name is invalid.
    ///
    /// This error occurs when a domain name fails validation (for example,
    /// contains invalid characters, exceeds length limits, or violates IDNA
    /// encoding rules).
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::errors::EndpointError;
    ///
    /// let err = EndpointError::InvalidDomainName {
    ///     domain: "invalid..domain".to_string(),
    /// };
    ///
    /// assert!(err.to_string().contains("invalid domain name"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[error("invalid domain name: '{domain}'")]
    InvalidDomainName {
        /// The invalid domain name.
        domain: String,
    },

    /// No addresses were returned from DNS.
    ///
    /// This error occurs when DNS resolution succeeds but returns zero
    /// addresses. This is distinct from DNS resolution failure - the name
    /// exists but has no A or AAAA records.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::errors::EndpointError;
    ///
    /// let err = EndpointError::NoAddressesFound {
    ///     host: "norecords.example.com".to_string(),
    /// };
    ///
    /// assert!(err.to_string().contains("no addresses"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[error("DNS resolution returned no addresses for '{host}'")]
    NoAddressesFound {
        /// Hostname that returned no addresses.
        host: String,
    },
}
