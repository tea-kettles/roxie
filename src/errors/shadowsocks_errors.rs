//! Shadowsocks proxy protocol errors.
//!
//! Defines error types specific to Shadowsocks AEAD proxy connections, including
//! cipher initialization, encryption/decryption, key derivation, and protocol errors.
//!
//! Shadowsocks is an encrypted proxy protocol supporting multiple AEAD ciphers.
//! All errors provide detailed context about which operation failed and why,
//! following the Five W pattern.
//!
//! # Examples
//!
//! Unsupported cipher method:
//!
//! ```
//! use roxie::errors::ShadowsocksError;
//!
//! let err = ShadowsocksError::UnsupportedCipherMethod {
//!     method: "rc4".to_string(),
//! };
//!
//! assert!(err.to_string().contains("unsupported"));
//! assert!(err.to_string().contains("rc4"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::io;

/* Types */

/// Errors specific to Shadowsocks operations.
///
/// Shadowsocks errors cover cipher initialization, encryption/decryption,
/// key derivation (HKDF), chunk length validation, address encoding, and
/// random number generation. The protocol uses AEAD ciphers for security.
///
/// # Supported Ciphers
///
/// AEAD ciphers (recommended):
/// * `aes-128-gcm`, `aes-256-gcm`
/// * `chacha20-ietf-poly1305`
///
/// Legacy ciphers (not supported for security reasons):
/// * `rc4-md5`, `aes-cfb` variants
///
/// # Examples
///
/// Encryption failure with context:
///
/// ```
/// use roxie::errors::ShadowsocksError;
///
/// let err = ShadowsocksError::EncryptionFailed {
///     reason: "nonce overflow detected".to_string(),
/// };
///
/// assert!(err.to_string().contains("encryption failed"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, thiserror::Error)]
pub enum ShadowsocksError {
    /* I/O and Connection Errors */
    /// IO error during Shadowsocks operations.
    ///
    /// Wraps underlying I/O errors that occur during Shadowsocks handshake
    /// or data transfer.
    #[error("IO error during Shadowsocks operation with {proxy_addr}: {source}")]
    Io {
        /// Proxy address where the error occurred.
        proxy_addr: String,
        /// Underlying IO error.
        #[source]
        source: io::Error,
    },

    /// Handshake timeout.
    ///
    /// The Shadowsocks handshake (sending encrypted request) exceeded the
    /// configured timeout.
    #[error(
        "Shadowsocks handshake with {proxy_addr} timed out after {elapsed_ms}ms \
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
    /// A specific phase of the Shadowsocks operation timed out.
    #[error(
        "Shadowsocks {phase} with {proxy_addr} timed out after {elapsed_ms}ms \
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

    /* Cipher Configuration Errors */
    /// Unsupported cipher method.
    ///
    /// The requested cipher method is not implemented or not recognized.
    /// See module docs for list of supported ciphers.
    #[error("unsupported Shadowsocks cipher method: '{method}'")]
    UnsupportedCipherMethod {
        /// Cipher method that was requested.
        method: String,
    },

    /// Legacy cipher not supported.
    ///
    /// Legacy (non-AEAD) ciphers like RC4 and AES-CFB are no longer supported
    /// due to security vulnerabilities. Use AEAD ciphers instead.
    #[error(
        "legacy cipher '{method}' not supported; use AEAD ciphers \
         (aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305)"
    )]
    LegacyCipherNotSupported {
        /// Legacy cipher that was attempted.
        method: String,
    },

    /// Cipher initialization failed.
    ///
    /// Failed to initialize the cipher with the provided password and salt.
    /// This typically indicates a key derivation or cipher construction issue.
    #[error("failed to initialize cipher '{method}': {reason}")]
    CipherInitializationFailed {
        /// Cipher method being initialized.
        method: String,
        /// Reason for initialization failure.
        reason: String,
    },

    /* Encryption/Decryption Errors */
    /// Encryption failed.
    ///
    /// Failed to encrypt data with the configured cipher. This could indicate
    /// a nonce overflow, cipher state corruption, or internal cipher error.
    #[error("encryption failed: {reason}")]
    EncryptionFailed {
        /// Reason for encryption failure.
        reason: String,
    },

    /// Decryption failed.
    ///
    /// Failed to decrypt received data. This typically indicates authentication
    /// tag verification failure (wrong password or corrupted data).
    #[error("decryption failed: {reason}")]
    DecryptionFailed {
        /// Reason for decryption failure.
        reason: String,
    },

    /* Key Derivation Errors */
    /// Key derivation failed.
    ///
    /// Failed to derive encryption keys from the password and salt using
    /// the configured key derivation function.
    #[error("key derivation failed: {reason}")]
    KeyDerivationFailed {
        /// Reason for key derivation failure.
        reason: String,
    },

    /// Invalid key length.
    ///
    /// The derived or provided key does not match the required length for
    /// the selected cipher.
    #[error("invalid key length: expected {expected} bytes, got {actual} bytes")]
    InvalidKeyLength {
        /// Expected key length in bytes.
        expected: usize,
        /// Actual key length in bytes.
        actual: usize,
    },

    /// HKDF expansion failed.
    ///
    /// Failed to expand the master key using HKDF. This is an internal
    /// error that should not normally occur.
    #[error("HKDF expansion failed")]
    HKDFExpansionFailed,

    /* Protocol Validation Errors */
    /// Invalid chunk length.
    ///
    /// Received a chunk with length exceeding the protocol maximum.
    /// Shadowsocks limits chunk lengths to prevent buffer overflows.
    #[error("invalid chunk length: {length} (maximum {max})")]
    InvalidChunkLength {
        /// Chunk length received.
        length: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Payload too large.
    ///
    /// The payload to be sent exceeds the maximum allowed size.
    #[error("payload too large: {size} bytes (maximum {max} bytes)")]
    PayloadTooLarge {
        /// Payload size in bytes.
        size: usize,
        /// Maximum allowed size in bytes.
        max: usize,
    },

    /// Invalid address type.
    ///
    /// The address type byte is not one of the valid Shadowsocks address types
    /// (0x01 = IPv4, 0x03 = domain, 0x04 = IPv6).
    #[error("invalid address type: 0x{atyp:02x}")]
    InvalidAddressType {
        /// Address type byte received.
        atyp: u8,
    },

    /// Domain too long.
    ///
    /// Domain names in Shadowsocks are length-prefixed with a single byte,
    /// limiting them to 255 bytes maximum.
    #[error("domain name too long: {length} bytes (maximum {max} bytes)")]
    DomainTooLong {
        /// Domain length in bytes.
        length: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /* Random Number Generation Errors */
    /// Random generation failed.
    ///
    /// Failed to generate random bytes for salt or nonce. This indicates
    /// a system-level RNG failure.
    #[error("random number generation failed: {source}")]
    RandomGenerationFailed {
        /// Underlying RNG error.
        #[source]
        source: rand::Error,
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

    /// Invalid port.
    ///
    /// The port number is not a valid integer or is outside the valid range.
    #[error("invalid port: {reason}")]
    InvalidPort {
        /// Reason the port is invalid.
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

    /* Security Warnings */
    /// Weak password warning.
    ///
    /// The provided password is weak and may be vulnerable to brute force
    /// attacks. This is a warning rather than a hard error, but strong
    /// passwords are recommended for security.
    #[error("password is weak: {reason} (consider using a stronger password)")]
    WeakPassword {
        /// Reason the password is considered weak.
        reason: String,
    },
}

/* From Implementations */

impl From<crate::errors::EndpointError> for ShadowsocksError {
    /// Convert EndpointError to ShadowsocksError.
    ///
    /// This allows using `?` operator when calling endpoint resolution
    /// functions from Shadowsocks proxy code.
    fn from(source: crate::errors::EndpointError) -> Self {
        Self::Endpoint { source }
    }
}
