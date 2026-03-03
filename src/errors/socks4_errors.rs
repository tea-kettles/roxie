//! SOCKS4 protocol errors.
//!
//! Defines error types specific to SOCKS4 and SOCKS4A proxy connections,
//! including connection failures, protocol version mismatches, identd-related
//! errors, and reply code interpretation.
//!
//! SOCKS4 is a simple proxy protocol that predates SOCKS5. SOCKS4A extends
//! it with domain name support. All errors provide detailed context following
//! the Five W pattern.
//!
//! # Examples
//!
//! Connection rejected by proxy:
//!
//! ```
//! use roxie::errors::SOCKS4Error;
//!
//! let err = SOCKS4Error::RequestRejected {
//!     proxy_addr: "proxy.example.com:1080".to_string(),
//! };
//!
//! assert!(err.to_string().contains("rejected"));
//! assert!(err.to_string().contains("0x5B"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::io;

/* Types */

/// Errors specific to SOCKS4/SOCKS4A protocol operations.
///
/// SOCKS4 errors cover the complete handshake lifecycle: connection, request
/// sending, reply parsing, and reply code interpretation. The protocol has
/// specific error codes (0x5A-0x5D) that are mapped to meaningful error variants.
///
/// # Reply Codes
///
/// SOCKS4 uses the following reply codes:
/// * `0x5A` - Request granted (success, not an error)
/// * `0x5B` - Request rejected or failed
/// * `0x5C` - Cannot connect to identd on the client
/// * `0x5D` - Different user IDs reported by client and identd
///
/// # Examples
///
/// Identd error with specific code:
///
/// ```
/// use roxie::errors::SOCKS4Error;
///
/// let err = SOCKS4Error::IdentdNotRunning {
///     proxy_addr: "proxy.example.com:1080".to_string(),
///};
///
/// assert!(err.to_string().contains("identd"));
/// assert!(err.to_string().contains("0x5C"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, thiserror::Error)]
pub enum SOCKS4Error {
    /* I/O and Connection Errors */
    /// IO error during SOCKS4 handshake.
    ///
    /// This error wraps underlying I/O errors that occur during any phase
    /// of the SOCKS4 handshake, preserving the error chain.
    #[error("IO error during SOCKS4 handshake with {proxy_addr}: {source}")]
    Io {
        /// Proxy address where the error occurred.
        proxy_addr: String,
        /// Underlying IO error.
        #[source]
        source: io::Error,
    },

    /// Handshake timeout.
    ///
    /// The complete SOCKS4 handshake exceeded the configured timeout.
    /// Includes timing information for debugging.
    #[error(
        "SOCKS4 handshake with {proxy_addr} timed out after {elapsed_ms}ms \
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
    /// A specific phase of the SOCKS4 handshake timed out. This is more
    /// specific than HandshakeTimeout and helps identify slow phases.
    #[error(
        "SOCKS4 {phase} with {proxy_addr} timed out after {elapsed_ms}ms \
         (timeout: {timeout_ms}ms)"
    )]
    PhaseTimeout {
        /// Proxy address that timed out.
        proxy_addr: String,
        /// Phase that timed out (for example, "request", "reply").
        phase: String,
        /// Time elapsed before timeout in milliseconds.
        elapsed_ms: u64,
        /// Configured timeout in milliseconds.
        timeout_ms: u64,
    },

    /* Protocol Validation Errors */
    /// Server does not support SOCKS4.
    ///
    /// The server's response does not match SOCKS4 protocol expectations.
    /// SOCKS4 replies must have version byte 0x00, anything else indicates
    /// a protocol mismatch.
    #[error(
        "protocol mismatch with {proxy_addr}: \
         expected SOCKS4 (reply version 0x00), but received {actual_description}"
    )]
    ProtocolMismatch {
        /// Proxy address with protocol mismatch.
        proxy_addr: String,
        /// Description of what was actually received.
        actual_description: String,
    },

    /// Invalid SOCKS4 reply version byte.
    ///
    /// The first byte of the SOCKS4 reply must be 0x00. Any other value
    /// indicates a protocol error or non-SOCKS4 server.
    #[error(
        "invalid SOCKS4 reply version from {proxy_addr}: \
         received 0x{received:02x}, expected 0x00"
    )]
    InvalidReplyVersion {
        /// Proxy address with invalid version.
        proxy_addr: String,
        /// Version byte that was received.
        received: u8,
    },

    /* SOCKS4 Reply Code Errors */
    /// SOCKS4 server rejected the connection request.
    ///
    /// Reply code 0x5B indicates the request was rejected or failed. This
    /// is the generic SOCKS4 failure code without specific reason.
    #[error("SOCKS4 connection request rejected by {proxy_addr} (code 0x5B)")]
    RequestRejected {
        /// Proxy address that rejected the request.
        proxy_addr: String,
    },

    /// SOCKS4 server reports identd not running.
    ///
    /// Reply code 0x5C indicates the client's identd service is not running
    /// or not reachable. Some SOCKS4 servers require identd for authentication.
    #[error(
        "SOCKS4 connection failed at {proxy_addr}: \
         client identd not running or not reachable (code 0x5C)"
    )]
    IdentdNotRunning {
        /// Proxy address that reported identd issue.
        proxy_addr: String,
    },

    /// SOCKS4 server reports identd mismatch.
    ///
    /// Reply code 0x5D indicates the user ID reported by the client differs
    /// from the user ID reported by identd. This is an authentication failure.
    #[error(
        "SOCKS4 connection failed at {proxy_addr}: \
         identd user ID mismatch (code 0x5D)"
    )]
    IdentdMismatch {
        /// Proxy address that reported identd mismatch.
        proxy_addr: String,
    },

    /// SOCKS4 server returned unknown error code.
    ///
    /// The reply code is not one of the standard SOCKS4 codes (0x5A-0x5D).
    /// This indicates either a protocol extension or corrupted data.
    #[error("SOCKS4 connection failed at {proxy_addr} with unknown error code 0x{code:02x}")]
    UnknownError {
        /// Proxy address that returned unknown code.
        proxy_addr: String,
        /// Unknown error code that was received.
        code: u8,
    },

    /* Target Validation Errors */
    /// Target URL has no host.
    ///
    /// The target URL does not specify a hostname or IP address to connect to.
    #[error("target URL has no host")]
    NoTargetHost,

    /// Target URL has no port.
    ///
    /// The target URL does not specify a port number to connect to.
    #[error("target URL has no port")]
    NoTargetPort,

    /// Target domain name is too long.
    ///
    /// SOCKS4A domain names are length-prefixed with a single byte, limiting
    /// them to 255 characters maximum.
    #[error("target domain name exceeds 255 bytes")]
    DomainTooLong,

    /// IPv6 addresses are not supported by SOCKS4.
    ///
    /// SOCKS4 predates IPv6 and only supports IPv4 addresses (4 bytes).
    /// SOCKS4A supports domain names which can resolve to IPv6, but direct
    /// IPv6 addresses cannot be used.
    #[error("SOCKS4 does not support IPv6 addresses")]
    IPv6NotSupported,

    /* User ID Validation Errors */
    /// Invalid user ID format.
    ///
    /// The SOCKS4 user ID contains invalid characters or violates protocol
    /// constraints (for example, null bytes which terminate the field).
    #[error("invalid SOCKS4 user ID: {reason}")]
    InvalidUserId {
        /// Reason the user ID is invalid.
        reason: String,
    },

    /* Wrapped Errors */
    /// Endpoint error during resolution.
    ///
    /// An error occurred while resolving the proxy or target hostname.
    #[error("endpoint error: {source}")]
    Endpoint {
        /// Underlying endpoint resolution error.
        #[source]
        source: crate::errors::EndpointError,
    },

    /// Early EOF - connection closed unexpectedly.
    ///
    /// The proxy closed the connection before sending the complete SOCKS4
    /// reply (which is exactly 8 bytes).
    #[error(
        "connection closed unexpectedly by {proxy_addr} during {phase}: \
         expected {expected_bytes} bytes, connection closed prematurely"
    )]
    EarlyEOF {
        /// Proxy address that closed unexpectedly.
        proxy_addr: String,
        /// Phase where EOF occurred.
        phase: String,
        /// Number of bytes that were expected.
        expected_bytes: usize,
    },
}

/* Helper Methods */

impl SOCKS4Error {
    /// Convert a SOCKS4 reply code to an appropriate error.
    ///
    /// This is an internal helper used by the SOCKS4 protocol implementation to
    /// interpret reply codes and create rich error variants. It maps SOCKS4 reply
    /// codes (0x5B, 0x5C, 0x5D) to specific error types with context.
    ///
    /// This method is not part of the public API. Errors are created automatically
    /// during SOCKS4 handshakes when the proxy returns error codes.
    ///
    /// # Panics
    ///
    /// Panics if called with 0x5A (success code). Callers should check for
    /// success before calling this function.
    pub(crate) fn from_reply_code(reply_code: u8, proxy_addr: String) -> Self {
        match reply_code {
            0x5A => {
                // This is success, not an error - caller should check before calling
                unreachable!("0x5A is success code, not an error")
            }
            0x5B => Self::RequestRejected { proxy_addr },
            0x5C => Self::IdentdNotRunning { proxy_addr },
            0x5D => Self::IdentdMismatch { proxy_addr },
            code => Self::UnknownError { proxy_addr, code },
        }
    }
}

/* From Implementations */

impl From<crate::errors::EndpointError> for SOCKS4Error {
    /// Convert EndpointError to SOCKS4Error.
    ///
    /// This allows using `?` operator when calling endpoint resolution
    /// functions from SOCKS4 proxy code.
    fn from(source: crate::errors::EndpointError) -> Self {
        Self::Endpoint { source }
    }
}
