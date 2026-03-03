//! TLS connection error types.
//!
//! Errors that can occur during TLS handshake, certificate validation, and
//! secure connection establishment. These errors provide detailed context about
//! TLS-specific failures including certificate issues, protocol version problems,
//! and configuration errors.
//!
//! # Examples
//!
//! Certificate verification failure:
//!
//! ```
//! use roxie::errors::TLSError;
//!
//! let err = TLSError::CertificateVerificationFailed {
//!     host: "untrusted.example.com".to_string(),
//!     reason: "self-signed certificate".to_string(),
//! };
//!
//! assert!(err.to_string().contains("certificate verification failed"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::io;

/* Types */

/// TLS connection errors.
///
/// Covers all aspects of TLS connection establishment including handshake,
/// certificate validation, protocol negotiation, and configuration issues.
/// All errors include the target hostname for context.
///
/// # Examples
///
/// Handshake timeout with phase information:
///
/// ```
/// use roxie::errors::TLSError;
///
/// let err = TLSError::HandshakeTimeout {
///     host: "slow.example.com".to_string(),
///     phase: "certificate_verification",
///     timeout_ms: 10000,
/// };
///
/// assert!(err.to_string().contains("timed out"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, thiserror::Error)]
pub enum TLSError {
    /* Connection Errors */
    /// TLS handshake failed.
    ///
    /// The TLS handshake process failed with an I/O error. This could indicate
    /// network issues, protocol incompatibility, or cipher suite mismatch.
    #[error("TLS handshake failed with {host}: {source}")]
    HandshakeFailed {
        /// Hostname where handshake failed.
        host: String,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// TLS handshake timeout.
    ///
    /// The TLS handshake exceeded the configured timeout during a specific phase.
    /// Common phases include "client_hello", "certificate_verification", and
    /// "key_exchange".
    #[error("TLS handshake with {host} timed out after {timeout_ms} ms during {phase}")]
    HandshakeTimeout {
        /// Hostname where timeout occurred.
        host: String,
        /// Phase where timeout occurred.
        phase: &'static str,
        /// Configured timeout in milliseconds.
        timeout_ms: u64,
    },

    /* Certificate Errors */
    /// Invalid server name for SNI.
    ///
    /// The hostname cannot be used for Server Name Indication (SNI). This
    /// typically means the hostname is malformed or contains invalid characters.
    #[error("invalid server name for SNI: '{host}'")]
    InvalidServerName {
        /// Invalid hostname.
        host: String,
    },

    /// Certificate verification failed.
    ///
    /// The server's TLS certificate could not be verified. This could indicate
    /// an expired certificate, hostname mismatch, self-signed certificate, or
    /// untrusted certificate authority.
    #[error("certificate verification failed for {host}: {reason}")]
    CertificateVerificationFailed {
        /// Hostname where verification failed.
        host: String,
        /// Specific reason for verification failure.
        reason: String,
    },

    /// Unsupported protocol version negotiated.
    ///
    /// The TLS version negotiated during handshake is not supported. This
    /// could indicate the server only supports very old (insecure) or very
    /// new (not yet implemented) TLS versions.
    #[error("unsupported protocol version negotiated with {host}: {version}")]
    UnsupportedProtocolVersion {
        /// Hostname with unsupported version.
        host: String,
        /// Version string (for example, "TLSv1.0", "TLSv1.3").
        version: String,
    },

    /* Configuration Errors */
    /// Invalid ALPN protocol.
    ///
    /// An Application-Layer Protocol Negotiation (ALPN) protocol string is
    /// malformed or contains invalid characters.
    #[error("invalid ALPN protocol: '{protocol}'")]
    InvalidALPNProtocol {
        /// Invalid ALPN protocol string.
        protocol: String,
    },

    /// TLS configuration error.
    ///
    /// General TLS configuration error, such as invalid cipher suite selection
    /// or contradictory security settings.
    #[error("TLS configuration error: {reason}")]
    ConfigurationError {
        /// Reason for configuration error.
        reason: String,
    },

    /// No root certificates configured.
    ///
    /// Certificate verification is enabled but no root certificate store is
    /// configured. At least one trusted root certificate is required to verify
    /// server certificates.
    #[error("no root certificates configured for verification")]
    NoRootCertificates,

    /* Protocol Errors */
    /// Unexpected TLS alert.
    ///
    /// The server sent an unexpected TLS alert message. Common alerts include
    /// "handshake_failure", "certificate_unknown", and "protocol_version".
    #[error("unexpected TLS alert from {host}: {alert}")]
    UnexpectedAlert {
        /// Hostname that sent alert.
        host: String,
        /// Alert message description.
        alert: String,
    },

    /// TLS protocol error.
    ///
    /// A protocol-level error occurred during a specific phase of the TLS
    /// handshake. This indicates a violation of TLS protocol rules.
    #[error("TLS protocol error with {host} during {phase}: {reason}")]
    ProtocolError {
        /// Hostname where error occurred.
        host: String,
        /// Phase where error occurred.
        phase: &'static str,
        /// Description of the protocol violation.
        reason: String,
    },

    /* I/O Errors */
    /// I/O error during TLS operation.
    ///
    /// An I/O error occurred after the TLS handshake completed, during
    /// encrypted data transfer.
    #[error("I/O error during TLS operation with {host}: {source}")]
    Io {
        /// Hostname where I/O error occurred.
        host: String,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
}
