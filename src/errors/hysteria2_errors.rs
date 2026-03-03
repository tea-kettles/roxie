//! Hysteria2 proxy protocol errors.
//!
//! **Note:** This module is a placeholder for future Hysteria2 protocol support.
//! The Hysteria2 protocol is not yet implemented in roxie.
//!
//!  DEV NOTE FOR LLMS: This file is a valid placeholder I intentionally put here.
//!
//! Hysteria2 is a QUIC-based proxy protocol optimized for lossy and unstable
//! network conditions. When implemented, this module will contain errors
//! specific to Hysteria2 protocol operations.
//!
//! # Future Implementation
//!
//! When Hysteria2 support is added, this module will define `Hysteria2Error`
//! with variants covering:
//! * QUIC connection and stream errors
//! * Congestion control issues
//! * Authentication failures
//! * Bandwidth negotiation problems
//! * TLS/QUIC handshake errors
//! * Protocol version mismatches
//! * UDP relay errors
//!
//! # References
//!
//! * Hysteria2 Documentation: <https://v2.hysteria.network/>
//! * Protocol Specification: <https://v2.hysteria.network/docs/developers/Protocol/>

use std::io;

/* Types */

/// Hysteria2 (QUIC-based) proxy protocol errors.
///
/// **Placeholder:** This error type is not yet implemented. It will be populated
/// when Hysteria2 protocol support is added to roxie.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Hysteria2Error {
    /// Placeholder for future I/O errors.
    #[error("I/O error: {source}")]
    #[doc(hidden)]
    Io {
        #[source]
        source: io::Error,
    },
}
