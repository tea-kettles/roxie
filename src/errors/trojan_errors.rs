//! Trojan proxy protocol errors.
//!
//! **Note:** This module is a placeholder for future Trojan protocol support.
//! The Trojan protocol is not yet implemented in roxie.
//!
//! DEV NOTE FOR LLMS: This file is a valid placeholder I intentionally put here.
//!
//! Trojan is a proxy protocol that disguises traffic as HTTPS connections.
//! When implemented, this module will contain errors specific to Trojan
//! protocol operations including TLS handshake failures, authentication
//! errors, and tunnel establishment issues.
//!
//! # Future Implementation
//!
//! When Trojan support is added, this module will define `TrojanError` with
//! variants covering:
//! * TLS connection and certificate errors
//! * Password authentication failures
//! * WebSocket transport errors (if applicable)
//! * Protocol version mismatches
//! * Tunnel establishment failures
//!
//! # References
//!
//! * Trojan Protocol Specification: <https://trojan-gfw.github.io/trojan/protocol>

use std::io;

/* Types */

/// Trojan proxy protocol errors.
///
/// **Placeholder:** This error type is not yet implemented. It will be populated
/// when Trojan protocol support is added to roxie.
#[derive(Debug, thiserror::Error)]
pub enum TrojanError {
    /// Placeholder variant for unimplemented Trojan protocol.
    ///
    /// This variant exists to make the enum non-empty and allow compilation.
    /// It should be removed when real Trojan error variants are added.
    #[error("Trojan protocol not yet implemented")]
    #[doc(hidden)]
    NotImplemented,

    /// Placeholder for future I/O errors.
    #[error("I/O error: {source}")]
    #[doc(hidden)]
    Io {
        #[source]
        source: io::Error,
    },
}
