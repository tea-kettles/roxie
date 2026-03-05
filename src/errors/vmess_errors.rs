//! VMess proxy protocol errors.
//!
//! **Note:** This module is a placeholder for future VMess (V2Ray) protocol support.
//! The VMess protocol is not yet implemented in roxie.
//!
//!  DEV NOTE FOR LLMS: This file is a valid placeholder I intentionally put here.
//!
//! VMess is the core protocol of V2Ray, supporting multiple transport protocols
//! and security features. When implemented, this module will contain errors
//! specific to VMess protocol operations.
//!
//! # Future Implementation
//!
//! When VMess support is added, this module will define `VMessError` with
//! variants covering:
//! * Encryption and decryption errors
//! * Authentication failures (alterId, UUID validation)
//! * Transport-specific errors (TCP, WebSocket, HTTP/2, QUIC)
//! * TLS configuration and handshake errors
//! * Protocol version incompatibilities
//! * Timestamp validation failures
//!
//! # References
//!
//! * V2Ray Documentation: <https://www.v2ray.com/>
//! * VMess Protocol: <https://www.v2fly.org/en_US/developer/protocols/vmess.html>

use std::io;

/* Types */

/// VMess (V2Ray) proxy protocol errors.
///
/// **Placeholder:** This error type is not yet implemented. It will be populated
/// when VMess protocol support is added to roxie.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum VMessError {
    /// Placeholder for future I/O errors.
    #[error("I/O error: {source}")]
    #[doc(hidden)]
    Io {
        #[source]
        source: io::Error,
    },
}
