//! SOCKS4/SOCKS4A proxy protocol implementation.
//!
//! Implements the SOCKS4 protocol and its SOCKS4A extension for establishing
//! proxy connections. SOCKS4 supports IPv4 addresses only, while SOCKS4A adds
//! support for domain names.
//!
//! The protocol uses a single-phase handshake:
//! 1. Connection request - send target address and optional user ID
//! 2. Read reply - receive 8-byte fixed response

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};
use tracing::trace;
use url::Url;

use crate::config::{HasBaseProxyConfig, SOCKS4Config};
use crate::errors::SOCKS4Error;
use crate::transport::{Endpoint, idna_encode, parse_ip, resolve_host};

// SOCKS4 Protocol Constants
const SOCKS4_VERSION: u8 = 0x04;
const SOCKS4_CMD_CONNECT: u8 = 0x01;
const SOCKS4_REPLY_NULL: u8 = 0x00;
const SOCKS4_REQUEST_GRANTED: u8 = 0x5A;
const SOCKS4_FAKE_IP: [u8; 4] = [0x00, 0x00, 0x00, 0x01]; // Used in SOCKS4A for domain names
const SOCKS4_NULL_TERMINATOR: u8 = 0x00;

// Buffer Size Limits
const MAX_USER_ID_LENGTH: usize = 255;
const MAX_DOMAIN_LENGTH: usize = 255;
const SOCKS4_HEADER_SIZE: usize = 8; // VER(1) + CMD(1) + PORT(2) + IP(4)
const MAX_SOCKS4_REQUEST: usize =
    SOCKS4_HEADER_SIZE + MAX_USER_ID_LENGTH + 1 + MAX_DOMAIN_LENGTH + 1; // 520 bytes
const SOCKS4_REPLY_SIZE: usize = 8; // VER(1) + STATUS(1) + PORT(2) + IP(4)

/* Public API */

/// Establish a SOCKS4/SOCKS4A connection through a proxy.
///
/// Performs the SOCKS4 handshake including connection request and reply validation.
/// Automatically uses SOCKS4A (domain name extension) when `resolve_locally` is false
/// and the target is a domain name.
///
/// After this function returns successfully, the stream is ready for application
/// data transfer.
///
/// # Examples
///
/// ```no_run
/// use roxie::protocols::socks4::establish_socks4;
/// use roxie::config::SOCKS4Config;
/// use tokio::net::TcpStream;
/// use url::Url;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = SOCKS4Config::new("proxy.example.com", 1080)
///     .set_user_id("myuser");
///
/// let mut stream = TcpStream::connect("proxy.example.com:1080").await?;
/// let target = Url::parse("https://example.com")?;
///
/// establish_socks4(&mut stream, &target, &config).await?;
/// // Stream is now ready for data transfer
/// # Ok(())
/// # }
/// ```
pub async fn establish_socks4(
    stream: &mut TcpStream,
    target_url: &Url,
    config: &SOCKS4Config,
) -> Result<(), SOCKS4Error> {
    let start = Instant::now();
    let proxy_addr = stream
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let protocol_variant = if config.get_base_config().is_resolve_locally() {
        "SOCKS4"
    } else {
        "SOCKS4A"
    };

    trace!(
        target_url = %target_url,
        proxy_addr = %proxy_addr,
        variant = protocol_variant,
        "starting handshake"
    );

    let handshake_timeout = config.get_base_config().get_handshake_timeout();
    let result = timeout(
        handshake_timeout,
        connect(stream, target_url, config, &proxy_addr),
    )
    .await;

    match result {
        Ok(Ok(())) => {
            trace!(
                target_url = %target_url,
                proxy_addr = %proxy_addr,
                variant = protocol_variant,
                elapsed_ms = start.elapsed().as_millis(),
                "handshake complete"
            );
            Ok(())
        }
        Ok(Err(e)) => {
            trace!(
                target_url = %target_url,
                proxy_addr = %proxy_addr,
                error = %e,
                elapsed_ms = start.elapsed().as_millis(),
                "handshake failed"
            );
            Err(e)
        }
        Err(_) => {
            let error = SOCKS4Error::HandshakeTimeout {
                proxy_addr: proxy_addr.clone(),
                elapsed_ms: start.elapsed().as_millis() as u64,
                timeout_ms: handshake_timeout.as_millis() as u64,
            };

            trace!(
                target_url = %target_url,
                proxy_addr = %proxy_addr,
                elapsed_ms = start.elapsed().as_millis(),
                timeout_ms = handshake_timeout.as_millis(),
                "handshake timed out"
            );

            Err(error)
        }
    }
}

/* Protocol Implementation */

/// Send connection request and read response.
async fn connect(
    stream: &mut TcpStream,
    target_url: &Url,
    config: &SOCKS4Config,
    proxy_addr: &str,
) -> Result<(), SOCKS4Error> {
    let start = Instant::now();

    trace!(
        proxy_addr = %proxy_addr,
        target_url = %target_url,
        "sending connection request"
    );

    let phase_timeout = config.get_base_config().get_phase_timeout();

    // Extract target host and port
    let host = target_url.host_str().ok_or(SOCKS4Error::NoTargetHost)?;
    let port = target_url
        .port_or_known_default()
        .ok_or(SOCKS4Error::NoTargetPort)?;

    // Determine endpoint and whether to use SOCKS4A
    let (endpoint, use_socks4a) = match parse_ip(host) {
        Some(Endpoint::V4(octets)) => {
            // Direct IPv4 address - use SOCKS4
            trace!(
                proxy_addr = %proxy_addr,
                host = %host,
                "target is IPv4 address, using SOCKS4"
            );
            (Endpoint::V4(octets), false)
        }
        Some(Endpoint::V6(_)) => {
            // IPv6 not supported by SOCKS4/4A
            trace!(
                proxy_addr = %proxy_addr,
                host = %host,
                "IPv6 not supported by SOCKS4"
            );
            return Err(SOCKS4Error::IPv6NotSupported);
        }
        Some(Endpoint::Domain(_)) => unreachable!("parse_ip never returns Domain"),
        None => {
            // Domain name - resolve locally or use SOCKS4A
            if config.get_base_config().is_resolve_locally() {
                trace!(
                    proxy_addr = %proxy_addr,
                    host = %host,
                    "resolving domain locally for SOCKS4"
                );

                let resolved = resolve_host(host, phase_timeout).await?;
                match resolved {
                    Endpoint::V4(octets) => {
                        trace!(
                            proxy_addr = %proxy_addr,
                            host = %host,
                            "resolved to IPv4, using SOCKS4"
                        );
                        (Endpoint::V4(octets), false)
                    }
                    Endpoint::V6(_) => {
                        trace!(
                            proxy_addr = %proxy_addr,
                            host = %host,
                            "resolved to IPv6, not supported by SOCKS4"
                        );
                        return Err(SOCKS4Error::IPv6NotSupported);
                    }
                    Endpoint::Domain(_) => unreachable!("resolve_host never returns Domain"),
                }
            } else {
                // Use SOCKS4A - send domain to proxy
                trace!(
                    proxy_addr = %proxy_addr,
                    host = %host,
                    "using SOCKS4A to send domain to proxy"
                );
                (Endpoint::Domain(idna_encode(host)?), true)
            }
        }
    };

    // Build request
    let mut request = [0u8; MAX_SOCKS4_REQUEST];
    let request_len = encode_request(
        &mut request,
        port,
        &endpoint,
        config.get_user_id(),
        use_socks4a,
    )?;

    // Send connection request with timeout
    timeout(phase_timeout, stream.write_all(&request[..request_len]))
        .await
        .map_err(|_| SOCKS4Error::PhaseTimeout {
            proxy_addr: proxy_addr.to_string(),
            phase: "connection request (write)".to_string(),
            elapsed_ms: start.elapsed().as_millis() as u64,
            timeout_ms: phase_timeout.as_millis() as u64,
        })?
        .map_err(|source| SOCKS4Error::Io {
            proxy_addr: proxy_addr.to_string(),
            source,
        })?;

    // Read reply with timeout
    let mut reply = [0u8; SOCKS4_REPLY_SIZE];
    timeout(phase_timeout, stream.read_exact(&mut reply))
        .await
        .map_err(|_| SOCKS4Error::PhaseTimeout {
            proxy_addr: proxy_addr.to_string(),
            phase: "connection reply (read)".to_string(),
            elapsed_ms: start.elapsed().as_millis() as u64,
            timeout_ms: phase_timeout.as_millis() as u64,
        })?
        .map_err(|source| {
            // Check for early EOF
            if source.kind() == std::io::ErrorKind::UnexpectedEof {
                SOCKS4Error::EarlyEOF {
                    proxy_addr: proxy_addr.to_string(),
                    phase: "connection reply".to_string(),
                    expected_bytes: SOCKS4_REPLY_SIZE,
                }
            } else {
                SOCKS4Error::Io {
                    proxy_addr: proxy_addr.to_string(),
                    source,
                }
            }
        })?;

    // Validate reply version byte (should be 0x00)
    if reply[0] != SOCKS4_REPLY_NULL {
        let actual_description = detect_protocol(&reply, stream, phase_timeout).await;

        trace!(
            proxy_addr = %proxy_addr,
            reply_version = reply[0],
            actual_protocol = %actual_description,
            elapsed_ms = start.elapsed().as_millis(),
            "protocol mismatch"
        );

        return Err(SOCKS4Error::ProtocolMismatch {
            proxy_addr: proxy_addr.to_string(),
            actual_description,
        });
    }

    // Check reply code
    if reply[1] != SOCKS4_REQUEST_GRANTED {
        trace!(
            proxy_addr = %proxy_addr,
            reply_code = reply[1],
            elapsed_ms = start.elapsed().as_millis(),
            "connection request failed"
        );

        return Err(SOCKS4Error::from_reply_code(
            reply[1],
            proxy_addr.to_string(),
        ));
    }

    // Log bind address for debugging
    let bind_port = u16::from_be_bytes([reply[2], reply[3]]);
    let bind_ip = [reply[4], reply[5], reply[6], reply[7]];

    trace!(
        proxy_addr = %proxy_addr,
        bind_ip = format!("{}.{}.{}.{}", bind_ip[0], bind_ip[1], bind_ip[2], bind_ip[3]),
        bind_port = bind_port,
        elapsed_ms = start.elapsed().as_millis(),
        "connection established"
    );

    Ok(())
}

/// Detect what protocol we actually received.
async fn detect_protocol(
    initial_bytes: &[u8],
    stream: &mut TcpStream,
    phase_timeout: Duration,
) -> String {
    // Check for SOCKS5 version byte
    if !initial_bytes.is_empty() && initial_bytes[0] == 0x05 {
        return "SOCKS5 (version byte 0x05)".to_string();
    }

    // Check for HTTP response
    if initial_bytes.len() >= 4 && &initial_bytes[..4] == b"HTTP" {
        return "HTTP response".to_string();
    }

    // Check for HTTP response that starts with status code
    if initial_bytes.len() >= 2 && initial_bytes[0] == b'H' && initial_bytes[1] == b'T' {
        // Try to read more to confirm
        let mut extra = [0u8; 8];
        if timeout(phase_timeout, stream.read(&mut extra))
            .await
            .is_ok()
        {
            let all_bytes = [initial_bytes, &extra].concat();
            if let Ok(s) = std::str::from_utf8(&all_bytes)
                && s.starts_with("HTTP/")
            {
                return "HTTP server".to_string();
            }
        }
        return "HTTP-like response".to_string();
    }

    // Check for TLS/SSL handshake
    if initial_bytes.len() >= 2 && initial_bytes[0] == 0x16 && initial_bytes[1] == 0x03 {
        return "TLS/SSL handshake".to_string();
    }

    // Unknown
    if initial_bytes.len() >= 2 {
        format!(
            "unknown protocol (0x{:02x}{:02x})",
            initial_bytes[0], initial_bytes[1]
        )
    } else {
        "unknown protocol".to_string()
    }
}

/* Helper Functions */

/// Encode a SOCKS4/SOCKS4A request into a buffer.
///
/// Returns the number of bytes written.
fn encode_request(
    buf: &mut [u8],
    port: u16,
    endpoint: &Endpoint,
    user_id: Option<&str>,
    use_socks4a: bool,
) -> Result<usize, SOCKS4Error> {
    let mut pos = 0;

    // Version and command
    buf[pos] = SOCKS4_VERSION;
    pos += 1;
    buf[pos] = SOCKS4_CMD_CONNECT;
    pos += 1;

    // Port (big-endian)
    buf[pos..pos + 2].copy_from_slice(&port.to_be_bytes());
    pos += 2;

    // IP address or fake IP for SOCKS4A
    match endpoint {
        Endpoint::V4(octets) => {
            buf[pos..pos + 4].copy_from_slice(octets);
            pos += 4;
        }
        Endpoint::Domain(_) if use_socks4a => {
            // Use fake IP for SOCKS4A
            buf[pos..pos + 4].copy_from_slice(&SOCKS4_FAKE_IP);
            pos += 4;
        }
        _ => unreachable!("Invalid endpoint type for SOCKS4"),
    }

    // User ID (optional)
    if let Some(uid) = user_id {
        validate_user_id(uid)?;
        let uid_bytes = uid.as_bytes();
        buf[pos..pos + uid_bytes.len()].copy_from_slice(uid_bytes);
        pos += uid_bytes.len();
    }

    // Null terminator after user ID
    buf[pos] = SOCKS4_NULL_TERMINATOR;
    pos += 1;

    // Domain name for SOCKS4A (if applicable)
    if use_socks4a
        && let Endpoint::Domain(domain) = endpoint
    {
        if domain.len() > MAX_DOMAIN_LENGTH {
            return Err(SOCKS4Error::DomainTooLong);
        }
        buf[pos..pos + domain.len()].copy_from_slice(domain);
        pos += domain.len();

        // Null terminator after domain
        buf[pos] = SOCKS4_NULL_TERMINATOR;
        pos += 1;
    }

    Ok(pos)
}

/// Validate user ID format for SOCKS4.
fn validate_user_id(user_id: &str) -> Result<(), SOCKS4Error> {
    let uid_bytes = user_id.as_bytes();

    if uid_bytes.len() > MAX_USER_ID_LENGTH {
        return Err(SOCKS4Error::InvalidUserId {
            reason: format!("exceeds maximum length of {} bytes", MAX_USER_ID_LENGTH),
        });
    }

    // Check for null bytes (would break protocol framing)
    if uid_bytes.contains(&0x00) {
        return Err(SOCKS4Error::InvalidUserId {
            reason: "contains null byte (would break SOCKS4 framing)".to_string(),
        });
    }

    Ok(())
}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_request_socks4_ipv4_no_userid() {
        let endpoint = Endpoint::V4([192, 168, 1, 1]);
        let mut buf = [0u8; 64];

        let len = encode_request(&mut buf, 80, &endpoint, None, false).unwrap();

        assert_eq!(len, 9); // VER(1) + CMD(1) + PORT(2) + IP(4) + NULL(1)
        assert_eq!(buf[0], SOCKS4_VERSION);
        assert_eq!(buf[1], SOCKS4_CMD_CONNECT);
        assert_eq!(&buf[2..4], &80u16.to_be_bytes());
        assert_eq!(&buf[4..8], &[192, 168, 1, 1]);
        assert_eq!(buf[8], SOCKS4_NULL_TERMINATOR);
    }

    #[test]
    fn encode_request_socks4_ipv4_with_userid() {
        let endpoint = Endpoint::V4([192, 168, 1, 1]);
        let mut buf = [0u8; 64];

        let len = encode_request(&mut buf, 80, &endpoint, Some("testuser"), false).unwrap();

        assert_eq!(len, 17); // VER(1) + CMD(1) + PORT(2) + IP(4) + USERID(8) + NULL(1)
        assert_eq!(buf[0], SOCKS4_VERSION);
        assert_eq!(&buf[8..16], b"testuser");
        assert_eq!(buf[16], SOCKS4_NULL_TERMINATOR);
    }

    #[test]
    fn encode_request_socks4a_domain() {
        let endpoint = Endpoint::Domain(b"example.com".to_vec());
        let mut buf = [0u8; 64];

        let len = encode_request(&mut buf, 443, &endpoint, None, true).unwrap();

        // VER(1) + CMD(1) + PORT(2) + FAKE_IP(4) + NULL(1) + DOMAIN(11) + NULL(1) = 21
        assert_eq!(len, 21);
        assert_eq!(buf[0], SOCKS4_VERSION);
        assert_eq!(&buf[4..8], &SOCKS4_FAKE_IP);
        assert_eq!(buf[8], SOCKS4_NULL_TERMINATOR);
        assert_eq!(&buf[9..20], b"example.com");
        assert_eq!(buf[20], SOCKS4_NULL_TERMINATOR);
    }

    #[test]
    fn encode_request_socks4a_domain_with_userid() {
        let endpoint = Endpoint::Domain(b"test.com".to_vec());
        let mut buf = [0u8; 64];

        let len = encode_request(&mut buf, 8080, &endpoint, Some("user"), true).unwrap();

        // VER(1) + CMD(1) + PORT(2) + FAKE_IP(4) + USERID(4) + NULL(1) + DOMAIN(8) + NULL(1) = 22
        assert_eq!(len, 22);
        assert_eq!(&buf[8..12], b"user");
        assert_eq!(buf[12], SOCKS4_NULL_TERMINATOR);
        assert_eq!(&buf[13..21], b"test.com");
        assert_eq!(buf[21], SOCKS4_NULL_TERMINATOR);
    }

    #[test]
    fn validate_user_id_valid() {
        assert!(validate_user_id("validuser").is_ok());
        assert!(validate_user_id("user123").is_ok());
        assert!(validate_user_id("").is_ok()); // Empty is valid
    }

    #[test]
    fn validate_user_id_too_long() {
        let long_user = "a".repeat(256);
        let result = validate_user_id(&long_user);
        assert!(matches!(result, Err(SOCKS4Error::InvalidUserId { .. })));
    }

    #[test]
    fn validate_user_id_contains_null() {
        let result = validate_user_id("bad\0user");
        assert!(matches!(result, Err(SOCKS4Error::InvalidUserId { .. })));
    }

    #[test]
    fn socks4_reply_code_conversion() {
        let err = SOCKS4Error::from_reply_code(0x5B, "proxy:1080".to_string());
        assert!(matches!(err, SOCKS4Error::RequestRejected { .. }));

        let err = SOCKS4Error::from_reply_code(0x5C, "proxy:1080".to_string());
        assert!(matches!(err, SOCKS4Error::IdentdNotRunning { .. }));

        let err = SOCKS4Error::from_reply_code(0x5D, "proxy:1080".to_string());
        assert!(matches!(err, SOCKS4Error::IdentdMismatch { .. }));

        let err = SOCKS4Error::from_reply_code(0xFF, "proxy:1080".to_string());
        assert!(matches!(err, SOCKS4Error::UnknownError { .. }));
    }

    #[test]
    fn encode_request_domain_too_long() {
        let long_domain = vec![b'a'; 256];
        let endpoint = Endpoint::Domain(long_domain);
        let mut buf = [0u8; 512];

        let result = encode_request(&mut buf, 80, &endpoint, None, true);
        assert!(matches!(result, Err(SOCKS4Error::DomainTooLong)));
    }
}
