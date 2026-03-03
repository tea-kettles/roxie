//! TLS connection establishment.
//!
//! Provides TLS handshake functionality over existing streams using rustls.
//! Supports SNI, ALPN protocol negotiation, and optional certificate verification
//! bypass for testing scenarios.
//!
//! # Protocol Flow
//!
//! 1. Parse server name for SNI
//! 2. Configure rustls with root certificates and options
//! 3. Establish TLS handshake with timeout
//! 4. Return wrapped TLS stream
//!
//! # Examples
//!
//! Basic TLS connection:
//! ```no_run
//! use roxie::transport::tls::establish_tls;
//! use roxie::config::TLSConfig;
//! use tokio::net::TcpStream;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = TLSConfig::new();
//! let tcp = TcpStream::connect("example.com:443").await?;
//! let tls_stream = establish_tls(tcp, "example.com", &config).await?;
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;
use std::time::Instant;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::{debug, error, trace};
use webpki_roots::TLS_SERVER_ROOTS;

use crate::config::TLSConfig;
use crate::errors::TLSError;

/* Implementations */

/// Establish a TLS connection over an existing stream.
///
/// Performs a TLS handshake with the specified server name for SNI.
/// The server name must be a valid DNS hostname without port or scheme.
///
/// # Arguments
///
/// * `stream` - Underlying transport stream (typically TCP)
/// * `server_name` - DNS hostname for SNI (e.g., "example.com")
/// * `config` - TLS configuration including timeout and ALPN
///
/// # Examples
///
/// ```no_run
/// use roxie::transport::tls::establish_tls;
/// use roxie::config::TLSConfig;
/// use tokio::net::TcpStream;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = TLSConfig::new();
/// let tcp = TcpStream::connect("example.com:443").await?;
/// let tls_stream = establish_tls(tcp, "example.com", &config).await?;
/// # Ok(())
/// # }
/// ```
pub async fn establish_tls<S>(
    stream: S,
    server_name: &str,
    config: &TLSConfig,
) -> Result<TlsStream<S>, TLSError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let start = Instant::now();
    let timeout_ms = config.get_handshake_timeout().as_millis() as u64;

    trace!(
        server_name = server_name,
        timeout_ms = timeout_ms,
        alpn_count = config.get_alpn_protocols().len(),
        danger_mode = config.is_danger_accept_invalid_certs(),
        "starting TLS handshake"
    );

    // Parse server name for SNI
    let sni_name = ServerName::try_from(server_name.to_string()).map_err(|_| {
        trace!(server_name = server_name, "invalid server name for SNI");
        TLSError::InvalidServerName {
            host: server_name.to_string(),
        }
    })?;

    trace!(server_name = server_name, "server name parsed successfully");

    // Build TLS connector with configuration
    let connector = build_connector(config)?;

    trace!(
        server_name = server_name,
        "connector built, initiating handshake"
    );

    // Perform handshake with timeout
    let handshake_result = timeout(
        config.get_handshake_timeout(),
        connector.connect(sni_name, stream),
    )
    .await;

    let elapsed = start.elapsed();
    let elapsed_ms = elapsed.as_millis() as u64;

    match handshake_result {
        Ok(Ok(tls_stream)) => {
            debug!(
                server_name = server_name,
                elapsed_ms = elapsed_ms,
                "handshake completed successfully"
            );
            Ok(tls_stream)
        }
        Ok(Err(e)) => {
            error!(
                server_name = server_name,
                elapsed_ms = elapsed_ms,
                error = %e,
                "handshake failed"
            );
            Err(TLSError::HandshakeFailed {
                host: server_name.to_string(),
                source: std::io::Error::new(std::io::ErrorKind::Other, e.to_string()),
            })
        }
        Err(_) => {
            error!(
                server_name = server_name,
                elapsed_ms = elapsed_ms,
                timeout_ms = timeout_ms,
                "handshake timed out"
            );
            Err(TLSError::HandshakeTimeout {
                host: server_name.to_string(),
                phase: "handshake",
                timeout_ms,
            })
        }
    }
}

/// Build a TLS connector from configuration.
///
/// Sets up rustls with root certificates, ALPN protocols, and optionally
/// disables certificate verification for testing.
fn build_connector(config: &TLSConfig) -> Result<TlsConnector, TLSError> {
    trace!("configuring rustls");

    // Load system root certificates
    let mut root_store = RootCertStore::empty();
    root_store.extend(TLS_SERVER_ROOTS.iter().cloned());

    trace!(cert_count = root_store.len(), "loaded root certificates");

    // Build client config with verification
    let mut client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Configure ALPN if specified
    if !config.get_alpn_protocols().is_empty() {
        client_config.alpn_protocols = config.get_alpn_protocols().to_vec();
        trace!(
            alpn_count = config.get_alpn_protocols().len(),
            "ALPN protocols configured"
        );
    }

    // Dangerous mode: disable certificate verification
    if config.is_danger_accept_invalid_certs() {
        trace!("danger mode - disabling certificate verification");
        client_config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerifier));
    }

    trace!("connector configured");
    Ok(TlsConnector::from(Arc::new(client_config)))
}

/* Certificate Verifier */

/// No-op certificate verifier that accepts all certificates.
///
/// **WARNING**: This is dangerous and should only be used for testing
/// or when you have another mechanism to verify the server's identity.
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![]
    }
}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[tokio::test]
    #[ignore] // Live test - requires network
    async fn establish_tls_live_connection() {
        let host = "www.howsmyssl.com";
        let addr = format!("{}:443", host);

        let tcp = TcpStream::connect(&addr).await.expect("tcp connect");

        let config = TLSConfig::new();
        let mut tls = establish_tls(tcp, host, &config)
            .await
            .expect("tls handshake");

        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            host
        );

        tls.write_all(request.as_bytes())
            .await
            .expect("write request");

        let mut response = Vec::new();
        tls.read_to_end(&mut response).await.expect("read response");

        let text = String::from_utf8_lossy(&response);
        assert!(text.contains("HTTP/1.1"), "Expected HTTP response");
    }

    #[tokio::test]
    async fn invalid_server_name() {
        let (client, _server) = tokio::io::duplex(1024);
        let config = TLSConfig::new();

        let result = establish_tls(client, "invalid..domain", &config).await;

        assert!(matches!(result, Err(TLSError::InvalidServerName { .. })));
    }

    #[tokio::test]
    async fn handshake_timeout() {
        use std::time::Duration;

        let (client, _server) = tokio::io::duplex(1024);
        let config = TLSConfig::new().set_handshake_timeout(Duration::from_millis(1));

        let result = establish_tls(client, "example.com", &config).await;

        assert!(matches!(result, Err(TLSError::HandshakeTimeout { .. })));
    }

    #[test]
    fn no_verifier_accepts_any_cert() {
        let verifier = NoVerifier;

        let result = verifier.verify_server_cert(
            &CertificateDer::from(vec![0u8; 32]),
            &[],
            &ServerName::try_from("example.com").unwrap(),
            &[],
            UnixTime::now(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn no_verifier_has_no_schemes() {
        let verifier = NoVerifier;
        assert!(verifier.supported_verify_schemes().is_empty());
    }
}
