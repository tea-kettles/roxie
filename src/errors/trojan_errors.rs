//! Trojan proxy protocol errors.

use std::io;

/* Types */

/// Errors that can occur during Trojan proxy operations.
///
/// The Trojan protocol runs over TLS, so errors include both TLS-level failures
/// and Trojan-specific handshake problems.
#[derive(Debug, thiserror::Error)]
pub enum TrojanError {
    /// TLS handshake with the Trojan proxy server failed.
    ///
    /// The TCP connection succeeded but the TLS layer could not be established.
    /// This usually indicates a certificate or SNI mismatch.
    #[error("TLS handshake with Trojan proxy {host} failed: {source}")]
    TlsHandshakeFailed {
        /// Proxy hostname.
        host: String,
        /// Underlying error.
        #[source]
        source: io::Error,
    },

    /// TLS handshake timed out before completing.
    #[error("TLS handshake with Trojan proxy {host} timed out after {timeout_ms} ms")]
    HandshakeTimeout {
        /// Proxy hostname.
        host: String,
        /// Configured timeout in milliseconds.
        timeout_ms: u64,
    },

    /// The destination address cannot be encoded in the Trojan header.
    ///
    /// Possible causes: missing host in the target URL, or a non-UTF-8 hostname.
    #[error("invalid destination address for Trojan: {reason}")]
    InvalidAddress {
        /// Why the address is invalid.
        reason: String,
    },

    /// Generic I/O error during the Trojan handshake.
    #[error("I/O error during Trojan handshake: {source}")]
    Io {
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
}

impl From<io::Error> for TrojanError {
    fn from(source: io::Error) -> Self {
        Self::Io { source }
    }
}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_handshake_failed_message() {
        let err = TrojanError::TlsHandshakeFailed {
            host: "proxy.example.com".to_string(),
            source: io::Error::other("connection reset"),
        };
        let msg = err.to_string();
        assert!(msg.contains("proxy.example.com"));
        assert!(msg.contains("connection reset"));
    }

    #[test]
    fn handshake_timeout_message() {
        let err = TrojanError::HandshakeTimeout {
            host: "proxy.example.com".to_string(),
            timeout_ms: 5000,
        };
        let msg = err.to_string();
        assert!(msg.contains("proxy.example.com"));
        assert!(msg.contains("5000"));
    }

    #[test]
    fn invalid_address_message() {
        let err = TrojanError::InvalidAddress {
            reason: "missing host".to_string(),
        };
        assert!(err.to_string().contains("missing host"));
    }

    #[test]
    fn from_io_error() {
        let io_err = io::Error::other("disk full");
        let err: TrojanError = io_err.into();
        assert!(matches!(err, TrojanError::Io { .. }));
        assert!(err.to_string().contains("disk full"));
    }
}
