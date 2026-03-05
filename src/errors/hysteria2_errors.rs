//! Hysteria2 proxy protocol errors.
//!
//! Error types for the Hysteria2 QUIC-based proxy protocol.
//! Covers QUIC transport, HTTP/3 authentication, and TCP stream framing errors.

use std::io;

/* Types */

/// Errors that occur during Hysteria2 proxy operations.
///
/// Hysteria2 uses QUIC as its transport and HTTP/3 for authentication,
/// so errors can originate from the QUIC stack, the HTTP/3 layer, or
/// the Hysteria2 framing protocol itself.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Hysteria2Error {
    /// QUIC connection could not be established.
    ///
    /// This covers DNS resolution failures, UDP socket errors, and the
    /// QUIC handshake itself (TLS negotiation, version negotiation, etc.).
    #[error("QUIC connection to {host}:{port} failed: {reason}")]
    QuicConnect {
        host: String,
        port: u16,
        reason: String,
    },

    /// A QUIC stream operation failed after the connection was established.
    ///
    /// Covers stream creation failures and mid-stream transport errors.
    #[error("QUIC stream error: {reason}")]
    QuicStream { reason: String },

    /// The server rejected the authentication credentials.
    ///
    /// The Hysteria2 authentication handshake responded with a non-233 HTTP/3
    /// status code.  `status` is the HTTP status returned by the server.
    #[error("authentication failed: server returned status {status}")]
    AuthFailed { status: u16 },

    /// An error occurred in the HTTP/3 layer during the authentication handshake.
    ///
    /// This includes QPACK encoding/decoding errors, H3 framing errors, and
    /// protocol violations.
    #[error("HTTP/3 error during Hysteria2 auth: {reason}")]
    Http3Error { reason: String },

    /// The server rejected the TCP stream request.
    ///
    /// The Hysteria2 TCP framing response indicated an error.  `message` is
    /// the human-readable error returned by the server.
    #[error("Hysteria2 stream rejected: {message}")]
    StreamRejected { message: String },

    /// TLS or QUIC configuration could not be built.
    ///
    /// This typically means a rustls configuration error — for example, an
    /// invalid SNI hostname or an unsupported algorithm.
    #[error("TLS/QUIC configuration error: {reason}")]
    TlsConfig { reason: String },

    /// DNS resolution for the proxy host failed.
    #[error("DNS resolution failed for host: {host}")]
    DnsResolution { host: String },

    /// I/O error on the underlying socket or stream.
    #[error("I/O error: {source}")]
    Io {
        #[source]
        source: io::Error,
    },
}

impl From<io::Error> for Hysteria2Error {
    fn from(source: io::Error) -> Self {
        Self::Io { source }
    }
}
