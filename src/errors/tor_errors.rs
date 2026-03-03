//! Tor proxy protocol errors.
//!
//! Defines error types specific to Tor proxy connections, including control port
//! communication errors, authentication failures, circuit configuration issues,
//! and SOCKS5 tunnel establishment errors.
//!
//! Tor support involves two components: control port for configuration and circuit
//! management, and SOCKS5 port for actual proxy connections. All errors provide
//! detailed context following the Five W pattern.
//!
//! # Examples
//!
//! Control port authentication failure:
//!
//! ```
//! use roxie::errors::TorError;
//!
//! let err = TorError::ControlPortAuthenticationFailed {
//!     host: "127.0.0.1".to_string(),
//!     port: 9051,
//!     reason: "invalid cookie".to_string(),
//! };
//!
//! assert!(err.to_string().contains("authentication failed"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::io;

/* Types */

/// Errors specific to Tor proxy operations.
///
/// Tor errors are organized into categories: control port connection and
/// authentication, control port command execution, circuit configuration,
/// and SOCKS5 tunnel establishment. The control port uses a text-based
/// protocol for managing Tor configuration and circuits.
///
/// # Control Port Protocol
///
/// Tor's control port responds with status codes:
/// * `250` - Success
/// * `451` - Resource exhausted
/// * `500-599` - Various error conditions
///
/// # Examples
///
/// Control port command failure:
///
/// ```
/// use roxie::errors::TorError;
///
/// let err = TorError::ControlPortCommandFailed {
///     host: "127.0.0.1".to_string(),
///     port: 9051,
///     command: "SETCONF ExitNodes={us}".to_string(),
///     reply: "552 Unrecognized option".to_string(),
/// };
///
/// assert!(err.to_string().contains("command failed"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, thiserror::Error)]
pub enum TorError {
    /* I/O and Connection Errors */
    /// IO error during Tor operations.
    ///
    /// Wraps I/O errors from SOCKS5 tunnel or control port operations.
    #[error("IO error during Tor operation with {proxy_addr}: {source}")]
    Io {
        /// Proxy address where error occurred (SOCKS5 endpoint).
        proxy_addr: String,
        /// Underlying IO error.
        #[source]
        source: io::Error,
    },

    /// Handshake timeout.
    ///
    /// The complete Tor handshake (control port config + SOCKS5 tunnel)
    /// exceeded the configured timeout.
    #[error(
        "Tor handshake with {proxy_addr} timed out after {elapsed_ms}ms \
         (timeout: {timeout_ms}ms)"
    )]
    HandshakeTimeout {
        /// Proxy address that timed out.
        proxy_addr: String,
        /// Time elapsed before timeout in milliseconds.
        elapsed_ms: u64,
        /// Configured timeout in milliseconds.
        timeout_ms: u64,
    },

    /// Phase timeout.
    ///
    /// A specific phase of Tor operations timed out.
    #[error(
        "Tor {phase} with {proxy_addr} timed out after {elapsed_ms}ms \
         (timeout: {timeout_ms}ms)"
    )]
    PhaseTimeout {
        /// Proxy address that timed out.
        proxy_addr: String,
        /// Phase that timed out.
        phase: String,
        /// Time elapsed before timeout in milliseconds.
        elapsed_ms: u64,
        /// Configured timeout in milliseconds.
        timeout_ms: u64,
    },

    /* Control Port Connection Errors */
    /// Control port connection failed.
    ///
    /// Failed to establish TCP connection to Tor's control port.
    #[error("failed to connect to Tor control port at {host}:{port}: {source}")]
    ControlPortConnectionFailed {
        /// Control port host.
        host: String,
        /// Control port port number.
        port: u16,
        /// Underlying IO error.
        #[source]
        source: io::Error,
    },

    /// Control port operation timeout.
    ///
    /// A control port operation (connect, auth, command) exceeded the timeout.
    #[error(
        "Tor control port operation at {host}:{port} timed out after {elapsed_ms}ms \
         (timeout: {timeout_ms}ms)"
    )]
    ControlPortTimeout {
        /// Control port host.
        host: String,
        /// Control port port number.
        port: u16,
        /// Time elapsed before timeout in milliseconds.
        elapsed_ms: u64,
        /// Configured timeout in milliseconds.
        timeout_ms: u64,
    },

    /* Control Port Authentication Errors */
    /// Control port authentication failed.
    ///
    /// Failed to authenticate with Tor's control port. This could indicate
    /// wrong password, invalid cookie, or unsupported authentication method.
    #[error("Tor control port authentication failed at {host}:{port}: {reason}")]
    ControlPortAuthenticationFailed {
        /// Control port host.
        host: String,
        /// Control port port number.
        port: u16,
        /// Reason for authentication failure.
        reason: String,
    },

    /// Control port cookie read failed.
    ///
    /// Failed to read the authentication cookie file from the filesystem.
    /// The cookie file is typically used when HASHEDPASSWORD authentication
    /// is not configured.
    #[error("failed to read Tor control cookie at {path}: {source}")]
    ControlPortCookieReadFailed {
        /// Path to the cookie file.
        path: String,
        /// Underlying IO error.
        #[source]
        source: io::Error,
    },

    /* Control Port Command Errors */
    /// Control port command failed.
    ///
    /// A command sent to the control port was rejected or failed. The reply
    /// contains the error message from Tor.
    #[error(
        "Tor control port command failed at {host}:{port}: command '{command}' returned: {reply}"
    )]
    ControlPortCommandFailed {
        /// Control port host.
        host: String,
        /// Control port port number.
        port: u16,
        /// Command that failed.
        command: String,
        /// Reply from Tor control port.
        reply: String,
    },

    /// Control port invalid reply.
    ///
    /// The control port sent a malformed or unexpected reply that could not
    /// be parsed.
    #[error("invalid reply from Tor control port at {host}:{port}: {reply}")]
    ControlPortInvalidReply {
        /// Control port host.
        host: String,
        /// Control port port number.
        port: u16,
        /// Invalid reply text.
        reply: String,
    },

    /// Control port connection closed unexpectedly.
    ///
    /// The control port closed the connection before completing an operation.
    /// This could indicate Tor crashed or the connection was reset.
    #[error("Tor control port connection at {host}:{port} closed unexpectedly")]
    ControlPortConnectionClosed {
        /// Control port host.
        host: String,
        /// Control port port number.
        port: u16,
    },

    /* Circuit Configuration Errors */
    /// Invalid exit nodes configuration.
    ///
    /// The exit nodes value is malformed or contains invalid country codes
    /// or fingerprints.
    #[error("invalid exit nodes configuration: {value}: {reason}")]
    InvalidExitNodes {
        /// Value that was provided.
        value: String,
        /// Reason the value is invalid.
        reason: String,
    },

    /// Invalid bridge configuration.
    ///
    /// The bridge configuration is malformed or contains invalid bridge
    /// descriptors.
    #[error("invalid bridge configuration: {reason}")]
    InvalidBridgeConfiguration {
        /// Reason the configuration is invalid.
        reason: String,
    },

    /// Configuration command failed.
    ///
    /// A SETCONF or similar configuration command was rejected by Tor.
    #[error("Tor configuration failed at {host}:{port}: {command} - {reason}")]
    ConfigurationFailed {
        /// Control port host.
        host: String,
        /// Control port port number.
        port: u16,
        /// Configuration command that failed.
        command: String,
        /// Reason for failure.
        reason: String,
    },

    /* Wrapped Protocol Errors */
    /// SOCKS5 error during tunnel establishment.
    ///
    /// An error occurred while establishing the SOCKS5 tunnel through Tor's
    /// SOCKS port. The underlying SOCKS5Error provides details.
    #[error("SOCKS5 error: {source}")]
    SOCKS5 {
        /// Underlying SOCKS5 error.
        #[source]
        source: crate::errors::SOCKS5Error,
    },

    /// Endpoint error during resolution.
    ///
    /// An error occurred while resolving the control port hostname.
    #[error("endpoint error: {source}")]
    Endpoint {
        /// Underlying endpoint resolution error.
        #[source]
        source: crate::errors::EndpointError,
    },
}

/* From Implementations */

impl From<crate::errors::SOCKS5Error> for TorError {
    /// Convert SOCKS5Error to TorError.
    ///
    /// This allows using `?` operator when calling SOCKS5 tunnel functions
    /// from Tor proxy code.
    fn from(source: crate::errors::SOCKS5Error) -> Self {
        Self::SOCKS5 { source }
    }
}

impl From<crate::errors::EndpointError> for TorError {
    /// Convert EndpointError to TorError.
    ///
    /// This allows using `?` operator when resolving the control port hostname.
    fn from(source: crate::errors::EndpointError) -> Self {
        Self::Endpoint { source }
    }
}
