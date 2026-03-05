//! Hysteria2 proxy protocol implementation.
//!
//! Implements the Hysteria2 QUIC-based proxy protocol, which uses HTTP/3 for
//! authentication and raw QUIC bidirectional streams for TCP proxying.
//!
//! # Protocol Flow
//!
//! 1. Resolve the proxy server's hostname to a socket address.
//! 2. Build a QUIC client configuration (TLS 1.3, ALPN `h3`).
//! 3. Establish a QUIC connection to the server.
//! 4. Perform an HTTP/3 `POST /auth` handshake.  Server must respond with
//!    HTTP status 233 to signal successful authentication.
//! 5. Open a raw QUIC bidirectional stream.
//! 6. Write the Hysteria2 TCP request frame (type `0x401`).
//! 7. Read the server's response frame.
//! 8. After a successful response the stream is a raw byte pipe.
//!
//! # References
//!
//! * Hysteria2 protocol specification: <https://v2.hysteria.network/docs/developers/Protocol/>
//! * RFC 9000 (QUIC): <https://www.rfc-editor.org/rfc/rfc9000>

use std::net::SocketAddr;
use std::sync::Arc;

use rand::{RngCore, rngs::OsRng};
use rustls::RootCertStore;
use tokio::time::timeout;
use tracing::{debug, trace};
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

use crate::config::Hysteria2Config;
use crate::errors::Hysteria2Error;

/* Salamander obfuscation */

/// Applies Hysteria2's Salamander XOR obfuscation (or deobfuscation) in-place.
///
/// The first 8 bytes of each QUIC UDP datagram are the unmodified seed.
/// All subsequent bytes are XOR'd with a keystream produced by the
/// BLAKE3 XOF seeded with `BLAKE3(password || first_8_bytes)`.
/// The operation is its own inverse: calling it twice restores the original.
fn salamander_crypt(password: &[u8], packet: &mut [u8]) {
    if packet.len() < 8 {
        return;
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(password);
    hasher.update(&packet[..8]);
    let mut reader = hasher.finalize_xof();

    let data_len = packet.len() - 8;
    let mut keystream = vec![0u8; data_len];
    reader.fill(&mut keystream);

    for (byte, key) in packet[8..].iter_mut().zip(keystream.iter()) {
        *byte ^= key;
    }
}

/// A `quinn` UDP socket that transparently applies Salamander obfuscation to
/// every outgoing datagram and deobfuscates every incoming one.
#[derive(Debug)]
struct SalamanderSocket {
    socket: tokio::net::UdpSocket,
    password: Arc<[u8]>,
}

impl SalamanderSocket {
    fn new(socket: tokio::net::UdpSocket, password: &str) -> Self {
        Self {
            socket,
            password: password.as_bytes().into(),
        }
    }
}

impl quinn::AsyncUdpSocket for SalamanderSocket {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(SalamanderPoller { socket: self })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> std::io::Result<()> {
        let mut buf = transmit.contents.to_vec();
        salamander_crypt(&self.password, &mut buf);
        self.socket.try_send_to(&buf, transmit.destination).map(|_| ())
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use tokio::io::ReadBuf;

        let (addr, len) = {
            let mut read_buf = ReadBuf::new(&mut bufs[0]);
            let addr = std::task::ready!(self.socket.poll_recv_from(cx, &mut read_buf))?;
            (addr, read_buf.filled().len())
        };

        salamander_crypt(&self.password, &mut bufs[0][..len]);

        meta[0] = quinn::udp::RecvMeta {
            addr,
            len,
            stride: len,
            ecn: None,
            dst_ip: None,
        };

        std::task::Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

#[derive(Debug)]
struct SalamanderPoller {
    socket: Arc<SalamanderSocket>,
}

impl quinn::UdpPoller for SalamanderPoller {
    fn poll_writable(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.socket.socket.poll_send_ready(cx)
    }
}

/* Constants */

/// Hysteria2 TCP stream frame type (QUIC varint `0x401`).
const FRAME_TYPE_TCP: u64 = 0x401;

/// HTTP status code that Hysteria2 servers return on successful auth.
const AUTH_SUCCESS_STATUS: u16 = 233;

/// Padding added to the auth request header (bytes).
const AUTH_PADDING_LEN: usize = 32;

/* Public Interface */

/// Establishes a Hysteria2 proxy connection to `destination`.
///
/// Returns a pair `(send, recv)` of QUIC stream halves plus the underlying
/// [`quinn::Connection`] (kept alive for the lifetime of the stream).
/// After this function returns the QUIC stream carries a raw byte pipe
/// tunnelled to `destination`.
///
/// # Errors
///
/// Returns [`Hysteria2Error`] for any failure during:
/// * DNS resolution of `host`
/// * QUIC connection setup / TLS handshake
/// * HTTP/3 authentication
/// * TCP stream framing (request/response)
pub async fn establish_hysteria2(
    host: &str,
    port: u16,
    password: &str,
    config: &Hysteria2Config,
    destination: &Url,
) -> Result<(quinn::SendStream, quinn::RecvStream, quinn::Connection), Hysteria2Error> {
    let start = tokio::time::Instant::now();

    // ── 1. DNS resolution ────────────────────────────────────────────────────
    trace!(proxy_host = host, proxy_port = port, "resolving Hysteria2 proxy address");

    let server_addr = resolve_host(host, port).await?;

    trace!(
        proxy_host = host,
        proxy_port = port,
        resolved = %server_addr,
        "proxy address resolved"
    );

    // ── 2. QUIC client configuration ─────────────────────────────────────────
    let sni = config.get_sni().unwrap_or(host);
    let quinn_client_config = build_quic_client_config(config)?;

    // ── 3. QUIC connection ────────────────────────────────────────────────────
    let local_addr: SocketAddr = if server_addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };

    let mut endpoint = if let Some(obfs_pw) = config.get_obfs_password() {
        // Salamander obfuscation: wrap the UDP socket so every datagram is
        // XOR-obfuscated before transmission and deobfuscated on receipt.
        let udp = tokio::net::UdpSocket::bind(local_addr)
            .await
            .map_err(|e| Hysteria2Error::QuicConnect {
                host: host.to_string(),
                port,
                reason: format!("UDP bind failed: {}", e),
            })?;
        let salamander = Arc::new(SalamanderSocket::new(udp, obfs_pw));
        let runtime = quinn::default_runtime().ok_or_else(|| Hysteria2Error::QuicConnect {
            host: host.to_string(),
            port,
            reason: "no async runtime available for QUIC endpoint".to_string(),
        })?;
        quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            salamander,
            runtime,
        )
        .map_err(|e| Hysteria2Error::QuicConnect {
            host: host.to_string(),
            port,
            reason: format!("QUIC endpoint creation failed: {}", e),
        })?
    } else {
        quinn::Endpoint::client(local_addr).map_err(|e| Hysteria2Error::QuicConnect {
            host: host.to_string(),
            port,
            reason: e.to_string(),
        })?
    };
    endpoint.set_default_client_config(quinn_client_config);

    trace!(
        proxy_host = host,
        proxy_port = port,
        sni = sni,
        "connecting QUIC"
    );

    let connecting = endpoint
        .connect(server_addr, sni)
        .map_err(|e| Hysteria2Error::QuicConnect {
            host: host.to_string(),
            port,
            reason: e.to_string(),
        })?;

    let connection = timeout(config.get_connection_timeout(), connecting)
        .await
        .map_err(|_| Hysteria2Error::QuicConnect {
            host: host.to_string(),
            port,
            reason: "connection timed out".to_string(),
        })?
        .map_err(|e| Hysteria2Error::QuicConnect {
            host: host.to_string(),
            port,
            reason: e.to_string(),
        })?;

    trace!(
        proxy_host = host,
        proxy_port = port,
        elapsed_ms = start.elapsed().as_millis(),
        "QUIC connection established"
    );

    // ── 4. HTTP/3 authentication ──────────────────────────────────────────────
    auth_via_h3(&connection, password, config).await?;

    debug!(
        proxy_host = host,
        proxy_port = port,
        elapsed_ms = start.elapsed().as_millis(),
        "Hysteria2 authentication successful"
    );

    // ── 5. Open TCP proxy stream ───────────────────────────────────────────────
    let (mut send_stream, mut recv_stream) =
        connection
            .open_bi()
            .await
            .map_err(|e| Hysteria2Error::QuicStream {
                reason: e.to_string(),
            })?;

    // ── 6. Write TCP request frame ─────────────────────────────────────────────
    write_tcp_request(&mut send_stream, destination).await?;

    trace!(
        proxy_host = host,
        proxy_port = port,
        target = %destination,
        "Hysteria2 TCP request frame sent"
    );

    // ── 7. Read TCP response frame ─────────────────────────────────────────────
    read_tcp_response(&mut recv_stream, host, port).await?;

    debug!(
        proxy_host = host,
        proxy_port = port,
        target = %destination,
        elapsed_ms = start.elapsed().as_millis(),
        "Hysteria2 TCP stream established"
    );

    Ok((send_stream, recv_stream, connection))
}

/* HTTP/3 Authentication */

/// Performs the Hysteria2 HTTP/3 authentication handshake.
async fn auth_via_h3(
    connection: &quinn::Connection,
    password: &str,
    config: &Hysteria2Config,
) -> Result<(), Hysteria2Error> {
    // Clone the connection so h3 can hold its own reference; the raw QUIC
    // streams we open later will use the original.
    let h3_transport = h3_quinn::Connection::new(connection.clone());

    let (mut h3_driver, mut send_request) = h3::client::new(h3_transport)
        .await
        .map_err(|e| Hysteria2Error::Http3Error {
            reason: e.to_string(),
        })?;

    // Spawn the h3 connection driver.  It must be polled to process incoming
    // SETTINGS and QPACK streams from the server.  It exits naturally when
    // the QUIC connection closes.
    let h3_driver_task = tokio::spawn(async move {
        let _ = futures::future::poll_fn(|cx| h3_driver.poll_close(cx)).await;
    });

    // Build auth request headers.
    let rx_bps = (config.get_down_mbps() as u64)
        .saturating_mul(1_000_000)
        .saturating_div(8);

    let padding = random_hex_string(AUTH_PADDING_LEN);

    let request = http::Request::builder()
        .method(http::Method::POST)
        // Hysteria2 requires a fixed auth authority, not the proxy host:port.
        .uri("https://hysteria/auth")
        .header("hysteria-auth", password)
        .header("hysteria-cc-rx", rx_bps.to_string())
        .header("hysteria-padding", &padding)
        .body(())
        .map_err(|e| Hysteria2Error::Http3Error {
            reason: e.to_string(),
        })?;

    let mut req_stream = send_request
        .send_request(request)
        .await
        .map_err(|e| Hysteria2Error::Http3Error {
            reason: e.to_string(),
        })?;

    // Signal end of request body (no body for auth).
    req_stream
        .finish()
        .await
        .map_err(|e| Hysteria2Error::Http3Error {
            reason: e.to_string(),
        })?;

    let response = req_stream
        .recv_response()
        .await
        .map_err(|e| Hysteria2Error::Http3Error {
            reason: e.to_string(),
        })?;

    let status = response.status().as_u16();

    // Drain auth response body before switching the connection to raw stream mode.
    while req_stream
        .recv_data()
        .await
        .map_err(|e| Hysteria2Error::Http3Error {
            reason: e.to_string(),
        })?
        .is_some()
    {}

    // Stop the H3 driver so it does not interpret subsequent raw proxy streams.
    h3_driver_task.abort();

    if status != AUTH_SUCCESS_STATUS {
        return Err(Hysteria2Error::AuthFailed { status });
    }

    Ok(())
}

/* TCP Stream Framing */

/// Writes a Hysteria2 TCP request frame to the send stream.
///
/// Frame layout (all lengths are QUIC varints, big-endian):
/// ```text
/// [varint: 0x401]         frame type
/// [varint: addr_len]
/// [bytes:  addr]          "host:port" as UTF-8
/// [varint: padding_len]
/// [bytes:  padding]       random bytes
/// ```
async fn write_tcp_request(
    stream: &mut quinn::SendStream,
    destination: &Url,
) -> Result<(), Hysteria2Error> {
    let host = destination.host_str().ok_or_else(|| Hysteria2Error::Io {
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing destination host"),
    })?;

    let port = destination
        .port_or_known_default()
        .unwrap_or(if destination.scheme() == "https" { 443 } else { 80 });

    let addr = format!("{}:{}", host, port);
    let addr_bytes = addr.as_bytes();

    // Random padding (0-15 bytes, kept short to minimise overhead).
    let padding_len = (OsRng.next_u32() % 16) as usize;
    let mut padding = vec![0u8; padding_len];
    OsRng.fill_bytes(&mut padding);

    let mut buf = Vec::with_capacity(3 + 1 + addr_bytes.len() + 1 + padding_len);
    write_varint(&mut buf, FRAME_TYPE_TCP);
    write_varint(&mut buf, addr_bytes.len() as u64);
    buf.extend_from_slice(addr_bytes);
    write_varint(&mut buf, padding_len as u64);
    buf.extend_from_slice(&padding);

    stream
        .write_all(&buf)
        .await
        .map_err(|e| Hysteria2Error::QuicStream {
            reason: e.to_string(),
        })
}

/// Reads a Hysteria2 TCP response frame and returns an error on non-zero status.
///
/// Frame layout:
/// ```text
/// [uint8:  status]         0 = OK
/// [varint: msg_len]
/// [bytes:  msg]
/// [varint: padding_len]
/// [bytes:  padding]        discarded
/// ```
async fn read_tcp_response(
    stream: &mut quinn::RecvStream,
    proxy_host: &str,
    proxy_port: u16,
) -> Result<(), Hysteria2Error> {
    // Status byte.
    let mut status_buf = [0u8; 1];
    stream
        .read_exact(&mut status_buf)
        .await
        .map_err(|e| Hysteria2Error::QuicStream {
            reason: e.to_string(),
        })?;
    let status = status_buf[0];

    // Message.
    let msg_len = read_varint(stream).await?;
    const MAX_MSG_LEN: u64 = 65_536;
    if msg_len > MAX_MSG_LEN {
        return Err(Hysteria2Error::QuicStream {
            reason: format!("server message length too large: {} bytes", msg_len),
        });
    }
    let mut msg_buf = vec![0u8; msg_len as usize];
    if msg_len > 0 {
        stream
            .read_exact(&mut msg_buf)
            .await
            .map_err(|e| Hysteria2Error::QuicStream {
                reason: e.to_string(),
            })?;
    }

    // Padding — read and discard.
    let padding_len = read_varint(stream).await?;
    const MAX_PADDING_LEN: u64 = 65_536;
    if padding_len > MAX_PADDING_LEN {
        return Err(Hysteria2Error::QuicStream {
            reason: format!("server padding length too large: {} bytes", padding_len),
        });
    }
    if padding_len > 0 {
        let mut discard = vec![0u8; padding_len as usize];
        stream
            .read_exact(&mut discard)
            .await
            .map_err(|e| Hysteria2Error::QuicStream {
                reason: e.to_string(),
            })?;
    }

    if status != 0 {
        let message = String::from_utf8_lossy(&msg_buf).into_owned();
        trace!(
            proxy_host = proxy_host,
            proxy_port = proxy_port,
            status = status,
            message = %message,
            "Hysteria2 TCP stream rejected"
        );
        return Err(Hysteria2Error::StreamRejected { message });
    }

    Ok(())
}

/* QUIC Varint Encoding */

/// Encodes a value as a QUIC variable-length integer (RFC 9000 §16) and
/// appends it to `buf`.
///
/// The encoding uses the minimum number of bytes needed:
/// * 0–63:         1 byte  (prefix `00`)
/// * 64–16 383:    2 bytes (prefix `01`)
/// * 16 384–2^30-1: 4 bytes (prefix `10`)
/// * 2^30–2^62-1: 8 bytes (prefix `11`)
///
/// # Panics
///
/// Panics in debug builds if `val >= 2^62` (values that large cannot be
/// encoded as QUIC varints).
fn write_varint(buf: &mut Vec<u8>, val: u64) {
    debug_assert!(
        val < (1u64 << 62),
        "QUIC varint value {} exceeds 2^62-1",
        val
    );

    if val < 64 {
        buf.push(val as u8);
    } else if val < 16_384 {
        let encoded = (val as u16) | 0x4000;
        buf.extend_from_slice(&encoded.to_be_bytes());
    } else if val < 1_073_741_824 {
        let encoded = (val as u32) | 0x8000_0000;
        buf.extend_from_slice(&encoded.to_be_bytes());
    } else {
        let encoded = val | 0xC000_0000_0000_0000;
        buf.extend_from_slice(&encoded.to_be_bytes());
    }
}

/// Reads a QUIC variable-length integer from `stream` (RFC 9000 §16).
async fn read_varint(stream: &mut quinn::RecvStream) -> Result<u64, Hysteria2Error> {
    let mut first = [0u8; 1];
    stream
        .read_exact(&mut first)
        .await
        .map_err(|e| Hysteria2Error::QuicStream {
            reason: e.to_string(),
        })?;

    let len_bits = first[0] >> 6;
    let val0 = (first[0] & 0x3F) as u64;

    match len_bits {
        0 => Ok(val0),
        1 => {
            let mut b = [0u8; 1];
            stream
                .read_exact(&mut b)
                .await
                .map_err(|e| Hysteria2Error::QuicStream {
                    reason: e.to_string(),
                })?;
            Ok((val0 << 8) | b[0] as u64)
        }
        2 => {
            let mut b = [0u8; 3];
            stream
                .read_exact(&mut b)
                .await
                .map_err(|e| Hysteria2Error::QuicStream {
                    reason: e.to_string(),
                })?;
            Ok((val0 << 24) | (b[0] as u64) << 16 | (b[1] as u64) << 8 | b[2] as u64)
        }
        _ => {
            let mut b = [0u8; 7];
            stream
                .read_exact(&mut b)
                .await
                .map_err(|e| Hysteria2Error::QuicStream {
                    reason: e.to_string(),
                })?;
            let mut val = val0;
            for byte in b {
                val = (val << 8) | byte as u64;
            }
            Ok(val)
        }
    }
}

/* QUIC Client Configuration */

/// Builds a [`quinn::ClientConfig`] configured for Hysteria2.
///
/// Uses TLS 1.3 only (QUIC requires TLS 1.3).  ALPN is set to `"h3"` as
/// required by the Hysteria2 server.
fn build_quic_client_config(config: &Hysteria2Config) -> Result<quinn::ClientConfig, Hysteria2Error> {
    use quinn::crypto::rustls::QuicClientConfig;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

    // Always TLS 1.3 — QUIC mandates it.
    let builder =
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]);

    let mut rustls_config = if config.is_skip_cert_verify() {
        // Dangerous: accept any certificate.
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
                rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms
                    .supported_schemes()
                    .to_vec()
            }
        }

        let mut c = builder
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        c.dangerous().set_certificate_verifier(Arc::new(NoVerifier));
        c
    } else {
        let mut root_store = RootCertStore::empty();
        root_store.extend(TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(root_store).with_no_client_auth()
    };

    // ALPN protocols — split the comma-separated config value so callers can
    // supply e.g. "h3,h3-29" for broader server compatibility.
    rustls_config.alpn_protocols = config
        .get_alpn()
        .split(',')
        .map(|p| p.trim().as_bytes().to_vec())
        .collect();

    let quic_config = QuicClientConfig::try_from(rustls_config).map_err(|e| {
        Hysteria2Error::TlsConfig {
            reason: e.to_string(),
        }
    })?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_config));

    // Apply transport-level settings from config.
    let mut transport = quinn::TransportConfig::default();

    // Congestion control algorithm.
    match config.get_congestion_control().to_lowercase().as_str() {
        "bbr" => {
            transport.congestion_controller_factory(Arc::new(
                quinn::congestion::BbrConfig::default(),
            ));
        }
        "cubic" => {
            transport.congestion_controller_factory(Arc::new(
                quinn::congestion::CubicConfig::default(),
            ));
        }
        "newreno" => {
            transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            ));
        }
        _ => {} // Unknown value; keep quinn's built-in default.
    }

    // Disable MTU discovery so quinn stays at its default 1200-byte initial MTU.
    // Without this, quinn probes upward and settles at ~1420 bytes, which
    // triggers WSAEMSGSIZE (Windows error 10040) on paths with reduced effective
    // MTU (e.g. VPN encapsulation overhead, tunnels).  1200 bytes is the QUIC
    // spec minimum and works on all path types.
    transport.mtu_discovery_config(None);

    // Idle timeout — convert Duration to milliseconds for quinn's VarInt.
    let idle_ms = config.get_idle_timeout().as_millis() as u64;
    if let Ok(v) = quinn::VarInt::try_from(idle_ms) {
        transport.max_idle_timeout(Some(v.into()));
    }

    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

/* DNS Resolution */

/// Resolves `host:port` to the first available [`SocketAddr`].
async fn resolve_host(host: &str, port: u16) -> Result<SocketAddr, Hysteria2Error> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{}:{}", host, port))
        .await
        .map_err(|_| Hysteria2Error::DnsResolution {
            host: host.to_string(),
        })?
        .collect();

    addrs
        .into_iter()
        .next()
        .ok_or_else(|| Hysteria2Error::DnsResolution {
            host: host.to_string(),
        })
}

/* Utilities */

/// Generates a lowercase hex string of `n` random bytes (length = `2 * n`).
fn random_hex_string(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trips_1byte() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 0);
        assert_eq!(buf, [0x00]);

        buf.clear();
        write_varint(&mut buf, 63);
        assert_eq!(buf, [0x3F]);
    }

    #[test]
    fn varint_round_trips_2byte() {
        let mut buf = Vec::new();
        // 0x401 = 1025 — the Hysteria2 TCP frame type
        write_varint(&mut buf, 0x401);
        assert_eq!(buf, [0x44, 0x01]);
    }

    #[test]
    fn varint_round_trips_4byte() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 16_384);
        // 16384 = 0x4000; 4-byte: prefix 10, value fits in 30 bits
        assert_eq!(buf[0] >> 6, 0b10);
    }

    #[test]
    fn varint_round_trips_8byte() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 1_073_741_824);
        assert_eq!(buf[0] >> 6, 0b11);
    }

    #[test]
    fn random_hex_string_is_correct_length() {
        let s = random_hex_string(16);
        assert_eq!(s.len(), 32);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
