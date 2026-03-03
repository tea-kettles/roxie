//! SOCKS5 protocol errors.
//!
//! Defines error types specific to SOCKS5 proxy connections, including
//! authentication failures, protocol version mismatches, method negotiation
//! errors, and server reply code interpretation.
//!
//! SOCKS5 is more complex than SOCKS4, supporting multiple authentication
//! methods and providing detailed error codes. All errors follow the Five W
//! pattern with rich context.
//!
//! # Examples
//!
//! Authentication method negotiation failure:
//!
//! ```
//! use roxie::errors::SOCKS5Error;
//!
//! let err = SOCKS5Error::NoAcceptableAuthMethod {
//!     proxy_addr: "proxy.example.com:1080".to_string(),
//! };
//!
//! assert!(err.to_string().contains("no acceptable"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::io;

/* Types */

/// Errors specific to SOCKS5 protocol operations.
///
/// SOCKS5 errors cover the complete handshake lifecycle: greeting, authentication
/// method negotiation, username/password authentication, connection request,
/// and reply parsing. The protocol defines specific error codes (0x00-0x08)
/// that are mapped to meaningful error variants.
///
/// # Protocol Flow
///
/// 1. **Greeting**: Client offers authentication methods -> Server selects one
/// 2. **Auth** (if required): Client sends credentials -> Server validates
/// 3. **Request**: Client requests connection -> Server attempts connection
/// 4. **Reply**: Server reports success or specific failure code
///
/// # Reply Codes
///
/// * `0x00` - Success (not an error)
/// * `0x01` - General SOCKS server failure
/// * `0x02` - Connection not allowed by ruleset
/// * `0x03` - Network unreachable
/// * `0x04` - Host unreachable
/// * `0x05` - Connection refused
/// * `0x06` - TTL expired
/// * `0x07` - Command not supported
/// * `0x08` - Address type not supported
///
/// # Examples
///
/// Connection refused by target:
///
/// ```
/// use roxie::errors::SOCKS5Error;
///
/// let err = SOCKS5Error::ConnectionFailed {
///     proxy_addr: "proxy.example.com:1080".to_string(),
///     reply_code: 0x05,
///     reason: "connection refused".to_string(),
/// };
///
/// assert!(err.to_string().contains("connection refused"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, thiserror::Error)]
pub enum SOCKS5Error {
    /* I/O and Connection Errors */
    /// IO error during SOCKS5 handshake.
    ///
    /// Wraps underlying I/O errors from any phase of the SOCKS5 handshake.
    #[error("IO error during SOCKS5 handshake with {proxy_addr}: {source}")]
    Io {
        /// Proxy address where the error occurred.
        proxy_addr: String,
        /// Underlying IO error.
        #[source]
        source: io::Error,
    },

    /// Handshake timeout.
    ///
    /// The entire SOCKS5 handshake exceeded the configured timeout. Includes
    /// the phase where timeout occurred for better debugging.
    #[error(
        "SOCKS5 handshake with {proxy_addr} timed out after {elapsed_ms}ms \
         (timeout: {timeout_ms}ms, phase: {phase})"
    )]
    HandshakeTimeout {
        /// Proxy address that timed out.
        proxy_addr: String,
        /// Time elapsed before timeout in milliseconds.
        elapsed_ms: u64,
        /// Configured timeout in milliseconds.
        timeout_ms: u64,
        /// Phase where timeout occurred.
        phase: String,
    },

    /// Phase timeout.
    ///
    /// A specific phase of the SOCKS5 handshake timed out.
    #[error(
        "SOCKS5 {phase} with {proxy_addr} timed out after {elapsed_ms}ms \
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

    /* Protocol Validation Errors */
    /// Server does not support SOCKS5.
    ///
    /// The server's response does not match SOCKS5 protocol. SOCKS5 messages
    /// must start with version byte 0x05.
    #[error(
        "protocol mismatch with {proxy_addr} during {phase}: \
         expected SOCKS5 (0x05), but received {actual_description}"
    )]
    ProtocolMismatch {
        /// Proxy address with protocol mismatch.
        proxy_addr: String,
        /// Phase where mismatch was detected.
        phase: String,
        /// Description of what was received.
        actual_description: String,
    },

    /// Invalid SOCKS5 version byte.
    ///
    /// A SOCKS5 message contained an invalid version byte (expected 0x05).
    #[error(
        "invalid SOCKS5 version from {proxy_addr}: \
         received 0x{received:02x}, expected 0x05"
    )]
    InvalidVersion {
        /// Proxy address with invalid version.
        proxy_addr: String,
        /// Version byte that was received.
        received: u8,
    },

    /* Authentication Method Errors */
    /// No acceptable authentication method.
    ///
    /// The server selected 0xFF, indicating none of the client's proposed
    /// authentication methods are acceptable. This usually means the server
    /// requires authentication but the client offered only "no auth".
    #[error("SOCKS5 server at {proxy_addr} reported no acceptable authentication methods")]
    NoAcceptableAuthMethod {
        /// Proxy address that rejected auth methods.
        proxy_addr: String,
    },

    /// Server requires authentication but none was provided.
    ///
    /// The server selected an authentication method other than 0x00 (no auth)
    /// but the client configuration doesn't include credentials.
    #[error("SOCKS5 server at {proxy_addr} requires authentication but none was provided")]
    AuthenticationRequired {
        /// Proxy address requiring authentication.
        proxy_addr: String,
    },

    /// Unsupported authentication method selected by server.
    ///
    /// The server selected an authentication method that the client doesn't
    /// support. Standard methods are 0x00 (no auth) and 0x02 (username/password).
    #[error(
        "SOCKS5 server at {proxy_addr} selected unsupported authentication method 0x{method:02x}"
    )]
    UnsupportedAuthMethod {
        /// Proxy address that selected unsupported method.
        proxy_addr: String,
        /// Authentication method byte.
        method: u8,
    },

    /* Username/Password Authentication Errors */
    /// Username/password authentication failed.
    ///
    /// The server rejected the provided credentials. The status byte is
    /// non-zero, indicating authentication failure.
    #[error(
        "SOCKS5 authentication failed at {proxy_addr}: \
         version=0x{version:02x}, status=0x{status:02x}"
    )]
    AuthenticationFailed {
        /// Proxy address where auth failed.
        proxy_addr: String,
        /// Authentication subnegotiation version byte.
        version: u8,
        /// Status byte (0x00 = success, non-zero = failure).
        status: u8,
    },

    /// Invalid credentials format.
    ///
    /// The provided credentials are malformed (for example, too long, contain
    /// invalid characters, or violate SOCKS5 constraints).
    #[error("invalid SOCKS5 credentials: {reason}")]
    InvalidCredentials {
        /// Reason the credentials are invalid.
        reason: String,
    },

    /* Connection Request Errors */
    /// SOCKS5 server returned an error reply.
    ///
    /// The server attempted the connection but it failed. The reply code
    /// indicates the specific failure reason (network unreachable, connection
    /// refused, etc).
    #[error("SOCKS5 connection failed at {proxy_addr}: {reason}")]
    ConnectionFailed {
        /// Proxy address that reported failure.
        proxy_addr: String,
        /// Reply code from server (0x01-0x08).
        reply_code: u8,
        /// Human-readable interpretation of reply code.
        reason: String,
    },

    /// Invalid address type in server response.
    ///
    /// The server's reply contained an address type that is not defined in
    /// SOCKS5. Valid types are 0x01 (IPv4), 0x03 (domain), 0x04 (IPv6).
    #[error("invalid address type 0x{atyp:02x} in SOCKS5 response from {proxy_addr}")]
    InvalidAddressType {
        /// Proxy address that sent invalid address type.
        proxy_addr: String,
        /// Address type byte that was received.
        atyp: u8,
    },

    /* Target Validation Errors */
    /// Target URL has no host.
    ///
    /// The target URL does not specify a hostname or IP address.
    #[error("target URL has no host")]
    NoTargetHost,

    /// Target URL has no port.
    ///
    /// The target URL does not specify a port number.
    #[error("target URL has no port")]
    NoTargetPort,

    /// Target domain name is too long.
    ///
    /// SOCKS5 domain names are length-prefixed with a single byte, limiting
    /// them to 255 characters maximum.
    #[error("target domain name exceeds 255 bytes")]
    DomainTooLong,

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
}

/* Helper Methods */

impl SOCKS5Error {
    /// Convert a SOCKS5 reply code to an appropriate error.
    ///
    /// This is an internal helper used by the SOCKS5 protocol implementation to
    /// interpret reply codes and create rich error variants. It maps SOCKS5 reply
    /// codes (0x00-0x08) to specific error types with human-readable messages.
    ///
    /// This method is not part of the public API. Errors are created automatically
    /// during SOCKS5 handshakes when the proxy returns error codes.
    pub(crate) fn from_reply_code(reply_code: u8, proxy_addr: String) -> Self {
        let reason = match reply_code {
            0x00 => "succeeded".to_string(),
            0x01 => "general SOCKS server failure".to_string(),
            0x02 => "connection not allowed by ruleset".to_string(),
            0x03 => "network unreachable".to_string(),
            0x04 => "host unreachable".to_string(),
            0x05 => "connection refused".to_string(),
            0x06 => "TTL expired".to_string(),
            0x07 => "command not supported".to_string(),
            0x08 => "address type not supported".to_string(),
            code => format!("unknown error code 0x{:02x}", code),
        };

        Self::ConnectionFailed {
            proxy_addr,
            reply_code,
            reason,
        }
    }
}

/* From Implementations */

impl From<crate::errors::EndpointError> for SOCKS5Error {
    /// Convert EndpointError to SOCKS5Error.
    ///
    /// This allows using `?` operator when calling endpoint resolution
    /// functions from SOCKS5 proxy code.
    fn from(source: crate::errors::EndpointError) -> Self {
        Self::Endpoint { source }
    }
}
