//! HTTP proxy protocol errors.
//!
//! Defines error types specific to HTTP CONNECT proxy connections, including
//! authentication failures, response parsing errors, header validation issues,
//! and tunnel establishment problems.
//!
//! All errors follow the Five W pattern, providing context about what operation
//! failed, which proxy was involved, when the failure occurred, and why.
//!
//! # Examples
//!
//! Authentication failure:
//!
//! ```
//! use roxie::errors::HTTPError;
//!
//! let err = HTTPError::AuthenticationFailed {
//!     proxy_addr: "proxy.example.com:8080".to_string(),
//! };
//!
//! assert!(err.to_string().contains("authentication failed"));
//! assert!(err.to_string().contains("proxy.example.com:8080"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::io;

/* Types */

/// Errors specific to HTTP CONNECT proxy operations.
///
/// HTTP CONNECT errors cover the entire lifecycle of establishing a tunnel
/// through an HTTP proxy: connection, authentication, CONNECT request/response
/// parsing, and header validation. All errors include the proxy address for
/// context and many include timing information for debugging timeouts.
///
/// # Examples
///
/// Timeout with detailed timing:
///
/// ```
/// use roxie::errors::HTTPError;
///
/// let err = HTTPError::HandshakeTimeout {
///     proxy_addr: "slow.proxy.com:8080".to_string(),
///     elapsed_ms: 10100,
///     timeout_ms: 10000,
/// };
///
/// assert!(err.to_string().contains("timed out"));
/// assert!(err.to_string().contains("10100ms"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, thiserror::Error)]
pub enum HTTPError {
    /* I/O and Connection Errors */
    /// IO error during HTTP handshake.
    ///
    /// This error wraps underlying I/O errors that occur during the HTTP
    /// CONNECT handshake, preserving the error chain for debugging.
    #[error("IO error during HTTP handshake with {proxy_addr}: {source}")]
    Io {
        /// Proxy address where the error occurred.
        proxy_addr: String,
        /// Underlying IO error.
        #[source]
        source: io::Error,
    },

    /// Handshake timeout.
    ///
    /// The entire HTTP CONNECT handshake (connect + auth + tunnel) exceeded
    /// the configured timeout. Includes both elapsed time and timeout for
    /// debugging.
    #[error(
        "HTTP handshake with {proxy_addr} timed out after {elapsed_ms}ms \
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
    /// A specific phase of the HTTP handshake (for example, "authentication",
    /// "connect request") timed out. This is more specific than HandshakeTimeout
    /// and helps identify which part of the handshake is slow.
    #[error(
        "HTTP {phase} with {proxy_addr} timed out after {elapsed_ms}ms \
         (timeout: {timeout_ms}ms)"
    )]
    PhaseTimeout {
        /// Proxy address that timed out.
        proxy_addr: String,
        /// Phase that timed out (for example, "authentication", "connect").
        phase: String,
        /// Time elapsed before timeout in milliseconds.
        elapsed_ms: u64,
        /// Configured timeout in milliseconds.
        timeout_ms: u64,
    },

    /* Protocol Mismatch Errors */
    /// Server does not support HTTP CONNECT.
    ///
    /// The server responded but doesn't appear to be an HTTP proxy supporting
    /// the CONNECT method. This might indicate connecting to a non-proxy HTTP
    /// server or a proxy that only supports GET/POST methods.
    #[error(
        "protocol mismatch with {proxy_addr}: \
         expected HTTP, but received {actual_description}"
    )]
    ProtocolMismatch {
        /// Proxy address that returned unexpected protocol.
        proxy_addr: String,
        /// Description of what was actually received.
        actual_description: String,
    },

    /// HTTP version not supported.
    ///
    /// The server returned an HTTP version that is not recognized or supported.
    /// Standard versions are "HTTP/1.0" and "HTTP/1.1".
    #[error("HTTP version not supported: '{version}'")]
    HTTPVersionNotSupported {
        /// Version string that was received.
        version: String,
    },

    /* Response Parsing Errors */
    /// HTTP response is empty.
    ///
    /// The proxy closed the connection without sending any HTTP response.
    /// This typically indicates a connection problem or proxy crash.
    #[error("HTTP response from {proxy_addr} is empty")]
    HTTPResponseEmpty {
        /// Proxy address that sent empty response.
        proxy_addr: String,
    },

    /// HTTP response headers incomplete.
    ///
    /// The HTTP response headers did not end with the required "\r\n\r\n"
    /// terminator, indicating a truncated or malformed response.
    #[error("HTTP response from {proxy_addr} headers incomplete (missing \\r\\n\\r\\n terminator)")]
    HTTPResponseHeadersIncomplete {
        /// Proxy address that sent incomplete headers.
        proxy_addr: String,
    },

    /// HTTP headers too large.
    ///
    /// The HTTP response headers exceeded the maximum allowed size, possibly
    /// indicating a malicious response or misconfigured proxy.
    #[error("HTTP response headers from {proxy_addr} exceed maximum size of {max_size} bytes")]
    HTTPHeadersTooLarge {
        /// Proxy address that sent oversized headers.
        proxy_addr: String,
        /// Maximum allowed header size in bytes.
        max_size: usize,
    },

    /// HTTP status line missing space separator.
    ///
    /// The HTTP status line (first line of response) is malformed and does
    /// not contain the required space separators between version, code, and reason.
    #[error("HTTP status line from {proxy_addr} missing space separator")]
    HTTPStatusLineMissingSpace {
        /// Proxy address that sent malformed status line.
        proxy_addr: String,
    },

    /// HTTP status line too short.
    ///
    /// The HTTP status line is shorter than the minimum valid length
    /// (for example, "HTTP/1.1 200 OK" is 15 characters minimum).
    #[error("HTTP status line from {proxy_addr} too short: {length} bytes (minimum {min_length})")]
    HTTPStatusLineTooShort {
        /// Proxy address that sent short status line.
        proxy_addr: String,
        /// Actual length of the status line.
        length: usize,
        /// Minimum required length.
        min_length: usize,
    },

    /// HTTP status code wrong length.
    ///
    /// The status code portion must be exactly 3 digits (for example, "200", "404").
    #[error("HTTP status code from {proxy_addr} wrong length: {length} bytes (expected 3)")]
    HTTPStatusCodeWrongLength {
        /// Proxy address that sent invalid status code.
        proxy_addr: String,
        /// Actual length of the status code.
        length: usize,
    },

    /// HTTP status code contains non-digit.
    ///
    /// The status code must be three decimal digits only. This error occurs
    /// when a non-digit character is found in the status code position.
    #[error("HTTP status code from {proxy_addr} contains non-digit character: '{character}'")]
    HTTPStatusCodeNonDigit {
        /// Proxy address that sent invalid status code.
        proxy_addr: String,
        /// Non-digit character that was found.
        character: char,
    },

    /// HTTP status code out of valid range.
    ///
    /// HTTP status codes must be in the range 100-599. This error occurs when
    /// the numeric value falls outside this range.
    #[error("HTTP status code from {proxy_addr} out of range: {code} (valid: 100-599)")]
    HTTPStatusCodeOutOfRange {
        /// Proxy address that sent invalid status code.
        proxy_addr: String,
        /// Status code value that was out of range.
        code: u16,
    },

    /* Authentication Errors */
    /// Proxy requires authentication.
    ///
    /// The proxy returned 407 Proxy Authentication Required but no credentials
    /// were provided in the configuration. To fix: provide username and password.
    #[error(
        "HTTP proxy at {proxy_addr} requires authentication (407 Proxy Authentication Required)"
    )]
    RequiresAuthentication {
        /// Proxy address requiring authentication.
        proxy_addr: String,
    },

    /// Authentication failed.
    ///
    /// The proxy returned 407 even though credentials were provided. This
    /// indicates the username/password were incorrect or the authentication
    /// method is unsupported.
    #[error(
        "HTTP proxy authentication failed at {proxy_addr} (407 Proxy Authentication Required with credentials provided)"
    )]
    AuthenticationFailed {
        /// Proxy address where authentication failed.
        proxy_addr: String,
    },

    /// Invalid credentials format.
    ///
    /// The provided credentials are malformed (for example, contain invalid
    /// characters, exceed length limits, or violate HTTP Basic Auth rules).
    #[error("invalid HTTP proxy credentials: {reason}")]
    InvalidCredentials {
        /// Reason the credentials are invalid.
        reason: String,
    },

    /// Base64 encoding failed.
    ///
    /// Failed to encode the credentials as Base64 for HTTP Basic Authentication.
    /// This is typically an internal error rather than a user configuration issue.
    #[error("failed to encode credentials as Base64")]
    Base64EncodingFailed,

    /* Authority Validation Errors */
    /// Authority too long.
    ///
    /// The authority (host:port) in the CONNECT request exceeds the maximum
    /// allowed length, typically to prevent buffer overflow attacks.
    #[error("HTTP authority (host:port) too long: {actual} bytes (maximum {max})")]
    AuthorityTooLong {
        /// Actual length of the authority.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Empty authority.
    ///
    /// The authority (host:port) cannot be empty in an HTTP CONNECT request.
    #[error("HTTP authority cannot be empty")]
    EmptyAuthority,

    /// Authority contains header injection attempt.
    ///
    /// The authority contains CR or LF characters, which could be used to
    /// inject additional HTTP headers. This is a security check.
    #[error("HTTP authority contains CR/LF characters (header injection attempt)")]
    AuthorityHeaderInjection,

    /// Invalid authority characters.
    ///
    /// The authority contains characters that are not allowed in HTTP authority
    /// (host:port) components.
    #[error("HTTP authority contains invalid characters: {reason}")]
    InvalidAuthorityCharacters {
        /// Reason describing the invalid characters.
        reason: String,
    },

    /// HTTP CONNECT request too large.
    ///
    /// The complete CONNECT request (including headers) exceeds the maximum
    /// allowed size.
    #[error("HTTP CONNECT request too large: {actual} bytes (maximum {max})")]
    HTTPConnectRequestTooLarge {
        /// Actual size of the request.
        actual: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Invalid port in authority.
    ///
    /// The port component of the authority is not a valid integer or is out
    /// of the valid range (1-65535).
    #[error("invalid port in HTTP authority: {reason}")]
    InvalidPortInAuthority {
        /// Reason the port is invalid.
        reason: String,
    },

    /* Status Code Errors */
    /// HTTP status error (non-200, non-407).
    ///
    /// The proxy returned a status code other than 200 (success) or 407
    /// (authentication required). This includes 4xx client errors and 5xx
    /// server errors.
    #[error("HTTP proxy at {proxy_addr} returned error status {status_code}: {reason}")]
    HTTPStatusError {
        /// Proxy address that returned the error.
        proxy_addr: String,
        /// HTTP status code that was returned.
        status_code: u16,
        /// Human-readable interpretation of the status code.
        reason: String,
    },

    /* Target URL Errors */
    /// Target URL has no host.
    ///
    /// The target URL that the user wants to connect to through the proxy
    /// does not specify a hostname.
    #[error("target URL has no host")]
    NoTargetHost,

    /// Target URL has no port.
    ///
    /// The target URL that the user wants to connect to through the proxy
    /// does not specify a port number.
    #[error("target URL has no port")]
    NoTargetPort,

    /* Wrapped Errors */
    /// Endpoint error during resolution.
    ///
    /// An error occurred while resolving the proxy or target hostname. The
    /// underlying EndpointError provides details.
    #[error("endpoint error: {source}")]
    Endpoint {
        /// Underlying endpoint resolution error.
        #[source]
        source: crate::errors::EndpointError,
    },

    /// Early EOF - connection closed unexpectedly.
    ///
    /// The connection was closed by the proxy before the expected amount of
    /// data was received. This typically indicates a protocol error or proxy crash.
    #[error(
        "connection closed unexpectedly by {proxy_addr} during {phase}: \
         expected {expected}, but connection closed after {received} bytes"
    )]
    EarlyEOF {
        /// Proxy address that closed the connection.
        proxy_addr: String,
        /// Phase where the unexpected EOF occurred.
        phase: String,
        /// Description of what was expected.
        expected: String,
        /// Number of bytes actually received before EOF.
        received: usize,
    },
}

/* Helper Methods */

impl HTTPError {
    /// Convert an HTTP status code to an appropriate error.
    ///
    /// This is an internal helper used by the HTTP protocol implementation to
    /// convert status codes into rich error variants. It maps common HTTP status
    /// codes (404, 500, 502, etc.) to human-readable error messages.
    ///
    /// This method is not part of the public API. Errors are created automatically
    /// during HTTP CONNECT handshakes when the proxy returns non-200 status codes.
    pub(crate) fn from_status_code(status_code: u16, proxy_addr: String) -> Self {
        let reason = match status_code {
            200..=299 => "success (should not be an error)".to_string(),
            300..=399 => format!("redirection ({})", status_code),
            400 => "bad request".to_string(),
            401 => "unauthorized".to_string(),
            403 => "forbidden".to_string(),
            404 => "not found".to_string(),
            407 => "proxy authentication required".to_string(),
            408 => "request timeout".to_string(),
            500 => "internal server error".to_string(),
            501 => "not implemented".to_string(),
            502 => "bad gateway".to_string(),
            503 => "service unavailable".to_string(),
            504 => "gateway timeout".to_string(),
            _ => format!("HTTP status {}", status_code),
        };

        Self::HTTPStatusError {
            proxy_addr,
            status_code,
            reason,
        }
    }
}

/* From Implementations */

impl From<crate::errors::EndpointError> for HTTPError {
    /// Convert EndpointError to HTTPError.
    ///
    /// This allows using `?` operator when calling endpoint resolution
    /// functions from HTTP proxy code.
    fn from(source: crate::errors::EndpointError) -> Self {
        Self::Endpoint { source }
    }
}
