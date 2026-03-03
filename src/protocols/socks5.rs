//! SOCKS5 proxy protocol implementation.
//!
//! Implements the SOCKS5 protocol (RFC 1928) for establishing proxy connections.
//! Supports both authenticated and unauthenticated connections, with optional
//! local DNS resolution.
//!
//! The implementation follows a clear three-phase handshake:
//! 1. Greeting - negotiate authentication method
//! 2. Authentication - if required, authenticate with username/password
//! 3. Connection - request connection to target and read bind address

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};
use tracing::trace;
use url::Url;
use zeroize::Zeroize;

use crate::config::{HasBaseProxyConfig, SOCKS5Config};
use crate::errors::SOCKS5Error;
use crate::transport::{Endpoint, idna_encode, parse_ip, resolve_host};

// SOCKS5 Protocol Constants
const SOCKS5_VERSION: u8 = 0x05;
const CONNECT_COMMAND: u8 = 0x01;
const RESERVED_BYTE: u8 = 0x00;

// Authentication Methods
const NO_AUTH: u8 = 0x00;
const USER_PASS_AUTH: u8 = 0x02;
const NO_ACCEPTABLE_METHOD: u8 = 0xFF;
const AUTH_VERSION: u8 = 0x01;
const AUTH_SUCCESS: u8 = 0x00;

// Reply Codes
const REPLY_SUCCESS: u8 = 0x00;

// Address Types
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

// Buffer Size Limits
const MAX_AUTH_REQUEST: usize = 515; // VER(1) + ULEN(1) + UNAME(255) + PLEN(1) + PASSWD(255)
const MAX_CONNECT_REQUEST: usize = 262; // VER(1) + CMD(1) + RSV(1) + ATYP(1) + DOMAIN_LEN(1) + DOMAIN(255) + PORT(2)
const MAX_DOMAIN_WITH_PORT: usize = 257; // DOMAIN(255) + PORT(2)

/* Public API */

/// Establish a SOCKS5 connection through a proxy.
///
/// Performs the complete SOCKS5 handshake including greeting, optional authentication,
/// and connection request. After this function returns successfully, the stream is ready
/// for application data transfer.
///
/// # Examples
///
/// ```no_run
/// use roxie::protocols::socks5::establish_socks5;
/// use roxie::config::SOCKS5Config;
/// use tokio::net::TcpStream;
/// use url::Url;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = SOCKS5Config::new("proxy.example.com", 1080)
///     .set_credentials("user", "pass");
///
/// let mut stream = TcpStream::connect("proxy.example.com:1080").await?;
/// let target = Url::parse("https://example.com")?;
///
/// establish_socks5(&mut stream, &target, &config).await?;
/// // Stream is now ready for data transfer
/// # Ok(())
/// # }
/// ```
pub async fn establish_socks5(
    stream: &mut TcpStream,
    target_url: &Url,
    config: &SOCKS5Config,
) -> Result<(), SOCKS5Error> {
    let start = Instant::now();
    let proxy_addr = stream
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    trace!(
        target_url = %target_url,
        proxy_addr = %proxy_addr,
        "starting handshake"
    );

    let handshake_timeout = config.get_base_config().get_handshake_timeout();
    let result = timeout(handshake_timeout, async {
        // Phase 1: Greeting
        let auth_method = greet(stream, config, &proxy_addr).await?;

        // Phase 2: Authentication (if required)
        if auth_method == USER_PASS_AUTH {
            authenticate(stream, config, &proxy_addr).await?;
        }

        // Phase 3: Connection request
        connect(stream, target_url, config, &proxy_addr).await?;

        Ok::<(), SOCKS5Error>(())
    })
    .await;

    match result {
        Ok(Ok(())) => {
            trace!(
                target_url = %target_url,
                proxy_addr = %proxy_addr,
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
            let error = SOCKS5Error::HandshakeTimeout {
                proxy_addr: proxy_addr.clone(),
                elapsed_ms: start.elapsed().as_millis() as u64,
                timeout_ms: handshake_timeout.as_millis() as u64,
                phase: "overall handshake".to_string(),
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

/// Perform SOCKS5 greeting and negotiate authentication method.
async fn greet(
    stream: &mut TcpStream,
    config: &SOCKS5Config,
    proxy_addr: &str,
) -> Result<u8, SOCKS5Error> {
    let start = Instant::now();
    let has_auth = config.get_username().is_some() && config.get_password().is_some();

    trace!(
        proxy_addr = %proxy_addr,
        has_auth = has_auth,
        "sending SOCKS5 greeting"
    );

    let phase_timeout = config.get_base_config().get_phase_timeout();

    // Build greeting: VERSION, NUM_METHODS, METHODS...
    let greeting: &[u8] = if has_auth {
        &[SOCKS5_VERSION, 0x02, NO_AUTH, USER_PASS_AUTH]
    } else {
        &[SOCKS5_VERSION, 0x01, NO_AUTH]
    };

    // Send greeting with timeout
    timeout(phase_timeout, stream.write_all(greeting))
        .await
        .map_err(|_| SOCKS5Error::PhaseTimeout {
            proxy_addr: proxy_addr.to_string(),
            phase: "greeting (write)".to_string(),
            elapsed_ms: start.elapsed().as_millis() as u64,
            timeout_ms: phase_timeout.as_millis() as u64,
        })?
        .map_err(|source| SOCKS5Error::Io {
            proxy_addr: proxy_addr.to_string(),
            source,
        })?;

    // Read response with timeout
    let mut response = [0u8; 2];
    timeout(phase_timeout, stream.read_exact(&mut response))
        .await
        .map_err(|_| SOCKS5Error::PhaseTimeout {
            proxy_addr: proxy_addr.to_string(),
            phase: "greeting (read)".to_string(),
            elapsed_ms: start.elapsed().as_millis() as u64,
            timeout_ms: phase_timeout.as_millis() as u64,
        })?
        .map_err(|source| SOCKS5Error::Io {
            proxy_addr: proxy_addr.to_string(),
            source,
        })?;

    // Validate SOCKS5 version
    if response[0] != SOCKS5_VERSION {
        let actual_description = detect_protocol(&response, stream, phase_timeout).await;

        trace!(
            proxy_addr = %proxy_addr,
            version_received = response[0],
            actual_protocol = %actual_description,
            elapsed_ms = start.elapsed().as_millis(),
            "protocol mismatch"
        );

        return Err(SOCKS5Error::ProtocolMismatch {
            proxy_addr: proxy_addr.to_string(),
            phase: "greeting".to_string(),
            actual_description,
        });
    }

    let method = response[1];

    // Check for no acceptable method
    if method == NO_ACCEPTABLE_METHOD {
        trace!(
            proxy_addr = %proxy_addr,
            elapsed_ms = start.elapsed().as_millis(),
            "server reported no acceptable authentication method"
        );

        return Err(SOCKS5Error::NoAcceptableAuthMethod {
            proxy_addr: proxy_addr.to_string(),
        });
    }

    // Validate method
    match method {
        NO_AUTH => {
            trace!(
                proxy_addr = %proxy_addr,
                elapsed_ms = start.elapsed().as_millis(),
                "no authentication required"
            );
        }
        USER_PASS_AUTH => {
            if !has_auth {
                trace!(
                    proxy_addr = %proxy_addr,
                    elapsed_ms = start.elapsed().as_millis(),
                    "server requires authentication but none provided"
                );

                return Err(SOCKS5Error::AuthenticationRequired {
                    proxy_addr: proxy_addr.to_string(),
                });
            }

            trace!(
                proxy_addr = %proxy_addr,
                elapsed_ms = start.elapsed().as_millis(),
                "username/password authentication required"
            );
        }
        _ => {
            trace!(
                proxy_addr = %proxy_addr,
                method = method,
                elapsed_ms = start.elapsed().as_millis(),
                "unsupported authentication method"
            );

            return Err(SOCKS5Error::UnsupportedAuthMethod {
                proxy_addr: proxy_addr.to_string(),
                method,
            });
        }
    }

    Ok(method)
}

/// Detect what protocol we actually received.
async fn detect_protocol(
    initial_bytes: &[u8],
    stream: &mut TcpStream,
    phase_timeout: Duration,
) -> String {
    // Check for HTTP response (starts with "HT" for "HTTP/")
    if initial_bytes.len() >= 2 && initial_bytes[0] == b'H' && initial_bytes[1] == b'T' {
        // Try to read more to confirm
        let mut extra = [0u8; 8];
        if timeout(phase_timeout, stream.read(&mut extra))
            .await
            .is_ok()
        {
            let all_bytes = [initial_bytes, &extra].concat();
            if let Ok(s) = std::str::from_utf8(&all_bytes) {
                if s.starts_with("HTTP/") {
                    return "HTTP server".to_string();
                }
            }
        }
        return "HTTP-like response (starts with 'HT')".to_string();
    }

    // Check for SOCKS4 responses
    if initial_bytes.len() >= 2 && initial_bytes[0] == 0x00 {
        return match initial_bytes[1] {
            0x5A => "SOCKS4 server (grant response 0x5A)".to_string(),
            0x5B => "SOCKS4 server (rejection 0x5B - request rejected)".to_string(),
            0x5C => "SOCKS4 server (rejection 0x5C - identd failure)".to_string(),
            0x5D => "SOCKS4 server (rejection 0x5D - identd mismatch)".to_string(),
            _ => format!(
                "unknown protocol (0x{:02x}{:02x})",
                initial_bytes[0], initial_bytes[1]
            ),
        };
    }

    // Check for SOCKS4 version
    if initial_bytes.len() >= 1 && initial_bytes[0] == 0x04 {
        return "SOCKS4 server (version 0x04)".to_string();
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

/// Perform username/password authentication.
async fn authenticate(
    stream: &mut TcpStream,
    config: &SOCKS5Config,
    proxy_addr: &str,
) -> Result<(), SOCKS5Error> {
    let start = Instant::now();
    let username = config
        .get_username()
        .ok_or_else(|| SOCKS5Error::InvalidCredentials {
            reason: "username is missing".to_string(),
        })?;
    let password = config
        .get_password()
        .ok_or_else(|| SOCKS5Error::InvalidCredentials {
            reason: "password is missing".to_string(),
        })?;

    trace!(
        proxy_addr = %proxy_addr,
        username = %username,
        "sending credentials"
    );

    let phase_timeout = config.get_base_config().get_phase_timeout();

    // Validate credentials
    let mut username_bytes = username.as_bytes().to_vec();
    let mut password_bytes = password.as_bytes().to_vec();

    if username_bytes.is_empty() {
        return Err(SOCKS5Error::InvalidCredentials {
            reason: "username cannot be empty".to_string(),
        });
    }

    if password_bytes.is_empty() {
        return Err(SOCKS5Error::InvalidCredentials {
            reason: "password cannot be empty".to_string(),
        });
    }

    if username_bytes.len() > 255 {
        return Err(SOCKS5Error::InvalidCredentials {
            reason: "username exceeds 255 bytes".to_string(),
        });
    }

    if password_bytes.len() > 255 {
        return Err(SOCKS5Error::InvalidCredentials {
            reason: "password exceeds 255 bytes".to_string(),
        });
    }

    // Build authentication request
    let mut request = [0u8; MAX_AUTH_REQUEST];
    let mut pos = 0;

    request[pos] = AUTH_VERSION;
    pos += 1;
    request[pos] = username_bytes.len() as u8;
    pos += 1;
    request[pos..pos + username_bytes.len()].copy_from_slice(&username_bytes);
    pos += username_bytes.len();
    request[pos] = password_bytes.len() as u8;
    pos += 1;
    request[pos..pos + password_bytes.len()].copy_from_slice(&password_bytes);
    pos += password_bytes.len();

    // Send authentication request with timeout
    timeout(phase_timeout, stream.write_all(&request[..pos]))
        .await
        .map_err(|_| SOCKS5Error::PhaseTimeout {
            proxy_addr: proxy_addr.to_string(),
            phase: "authentication (write)".to_string(),
            elapsed_ms: start.elapsed().as_millis() as u64,
            timeout_ms: phase_timeout.as_millis() as u64,
        })?
        .map_err(|source| SOCKS5Error::Io {
            proxy_addr: proxy_addr.to_string(),
            source,
        })?;

    // Zeroize sensitive data
    request.fill(0);
    username_bytes.zeroize();
    password_bytes.zeroize();

    // Read authentication response with timeout
    let mut response = [0u8; 2];
    timeout(phase_timeout, stream.read_exact(&mut response))
        .await
        .map_err(|_| SOCKS5Error::PhaseTimeout {
            proxy_addr: proxy_addr.to_string(),
            phase: "authentication (read)".to_string(),
            elapsed_ms: start.elapsed().as_millis() as u64,
            timeout_ms: phase_timeout.as_millis() as u64,
        })?
        .map_err(|source| SOCKS5Error::Io {
            proxy_addr: proxy_addr.to_string(),
            source,
        })?;

    // Validate authentication response
    if response[0] != AUTH_VERSION || response[1] != AUTH_SUCCESS {
        trace!(
            proxy_addr = %proxy_addr,
            version = response[0],
            status = response[1],
            elapsed_ms = start.elapsed().as_millis(),
            "authentication failed"
        );

        return Err(SOCKS5Error::AuthenticationFailed {
            proxy_addr: proxy_addr.to_string(),
            version: response[0],
            status: response[1],
        });
    }

    trace!(
        proxy_addr = %proxy_addr,
        elapsed_ms = start.elapsed().as_millis(),
        "authentication successful"
    );

    Ok(())
}

/// Send connection request and read response.
async fn connect(
    stream: &mut TcpStream,
    target_url: &Url,
    config: &SOCKS5Config,
    proxy_addr: &str,
) -> Result<(), SOCKS5Error> {
    let start = Instant::now();

    trace!(
        proxy_addr = %proxy_addr,
        target_url = %target_url,
        "sending connection request"
    );

    let phase_timeout = config.get_base_config().get_phase_timeout();

    // Extract target host and port
    let host = target_url.host_str().ok_or(SOCKS5Error::NoTargetHost)?;
    let port = target_url
        .port_or_known_default()
        .ok_or(SOCKS5Error::NoTargetPort)?;

    // Determine endpoint specification
    let endpoint = match parse_ip(host) {
        Some(ep) => ep,
        None => {
            if config.get_base_config().is_resolve_locally() {
                // Resolve locally
                resolve_host(host, phase_timeout).await?
            } else {
                // Send domain name to proxy
                Endpoint::Domain(idna_encode(host)?)
            }
        }
    };

    // Build connection request
    let mut request = [0u8; MAX_CONNECT_REQUEST];
    request[0] = SOCKS5_VERSION;
    request[1] = CONNECT_COMMAND;
    request[2] = RESERVED_BYTE;

    let addr_len = encode_endpoint(&mut request[3..], &endpoint)?;
    let port_start = 3 + addr_len;
    request[port_start..port_start + 2].copy_from_slice(&port.to_be_bytes());

    let total_len = port_start + 2;

    // Send connection request with timeout
    timeout(phase_timeout, stream.write_all(&request[..total_len]))
        .await
        .map_err(|_| SOCKS5Error::PhaseTimeout {
            proxy_addr: proxy_addr.to_string(),
            phase: "connection request (write)".to_string(),
            elapsed_ms: start.elapsed().as_millis() as u64,
            timeout_ms: phase_timeout.as_millis() as u64,
        })?
        .map_err(|source| SOCKS5Error::Io {
            proxy_addr: proxy_addr.to_string(),
            source,
        })?;

    // Read connection response header with timeout
    let mut header = [0u8; 4];
    timeout(phase_timeout, stream.read_exact(&mut header))
        .await
        .map_err(|_| SOCKS5Error::PhaseTimeout {
            proxy_addr: proxy_addr.to_string(),
            phase: "connection response (read header)".to_string(),
            elapsed_ms: start.elapsed().as_millis() as u64,
            timeout_ms: phase_timeout.as_millis() as u64,
        })?
        .map_err(|source| SOCKS5Error::Io {
            proxy_addr: proxy_addr.to_string(),
            source,
        })?;

    // Validate SOCKS5 version
    if header[0] != SOCKS5_VERSION {
        // Check if this looks like HTTP or another protocol
        if header[0] == b'H' && header[1] == b'T' {
            trace!(
                proxy_addr = %proxy_addr,
                elapsed_ms = start.elapsed().as_millis(),
                "received HTTP response during connection phase"
            );

            return Err(SOCKS5Error::ProtocolMismatch {
                proxy_addr: proxy_addr.to_string(),
                phase: "connection response".to_string(),
                actual_description: "HTTP response".to_string(),
            });
        }

        trace!(
            proxy_addr = %proxy_addr,
            version_received = header[0],
            elapsed_ms = start.elapsed().as_millis(),
            "invalid SOCKS5 version in response"
        );

        return Err(SOCKS5Error::InvalidVersion {
            proxy_addr: proxy_addr.to_string(),
            received: header[0],
        });
    }

    // Check reply code
    if header[1] != REPLY_SUCCESS {
        trace!(
            proxy_addr = %proxy_addr,
            reply_code = header[1],
            elapsed_ms = start.elapsed().as_millis(),
            "connection failed with reply code"
        );

        return Err(SOCKS5Error::from_reply_code(
            header[1],
            proxy_addr.to_string(),
        ));
    }

    // Read and discard bind address
    read_bind_address(stream, header[3], phase_timeout, proxy_addr, &start).await?;

    trace!(
        proxy_addr = %proxy_addr,
        target_url = %target_url,
        elapsed_ms = start.elapsed().as_millis(),
        "connection established"
    );

    Ok(())
}

/// Read and discard the bind address from the connection response.
async fn read_bind_address(
    stream: &mut TcpStream,
    atyp: u8,
    phase_timeout: Duration,
    proxy_addr: &str,
    start: &Instant,
) -> Result<(), SOCKS5Error> {
    trace!(
        proxy_addr = %proxy_addr,
        atyp = atyp,
        "reading bind address"
    );

    match atyp {
        ATYP_IPV4 => {
            let mut bind = [0u8; 6]; // 4 bytes IP + 2 bytes port
            timeout(phase_timeout, stream.read_exact(&mut bind))
                .await
                .map_err(|_| SOCKS5Error::PhaseTimeout {
                    proxy_addr: proxy_addr.to_string(),
                    phase: "bind address (IPv4)".to_string(),
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    timeout_ms: phase_timeout.as_millis() as u64,
                })?
                .map_err(|source| SOCKS5Error::Io {
                    proxy_addr: proxy_addr.to_string(),
                    source,
                })?;

            trace!(
                proxy_addr = %proxy_addr,
                bind_addr = ?bind,
                "IPv4 bind address"
            );
        }
        ATYP_IPV6 => {
            let mut bind = [0u8; 18]; // 16 bytes IP + 2 bytes port
            timeout(phase_timeout, stream.read_exact(&mut bind))
                .await
                .map_err(|_| SOCKS5Error::PhaseTimeout {
                    proxy_addr: proxy_addr.to_string(),
                    phase: "bind address (IPv6)".to_string(),
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    timeout_ms: phase_timeout.as_millis() as u64,
                })?
                .map_err(|source| SOCKS5Error::Io {
                    proxy_addr: proxy_addr.to_string(),
                    source,
                })?;

            trace!(
                proxy_addr = %proxy_addr,
                bind_addr = ?bind,
                "IPv6 bind address"
            );
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            timeout(phase_timeout, stream.read_exact(&mut len))
                .await
                .map_err(|_| SOCKS5Error::PhaseTimeout {
                    proxy_addr: proxy_addr.to_string(),
                    phase: "bind address (domain length)".to_string(),
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    timeout_ms: phase_timeout.as_millis() as u64,
                })?
                .map_err(|source| SOCKS5Error::Io {
                    proxy_addr: proxy_addr.to_string(),
                    source,
                })?;

            let mut bind = [0u8; MAX_DOMAIN_WITH_PORT];
            let domain_port_len = len[0] as usize + 2;
            timeout(
                phase_timeout,
                stream.read_exact(&mut bind[..domain_port_len]),
            )
            .await
            .map_err(|_| SOCKS5Error::PhaseTimeout {
                proxy_addr: proxy_addr.to_string(),
                phase: "bind address (domain)".to_string(),
                elapsed_ms: start.elapsed().as_millis() as u64,
                timeout_ms: phase_timeout.as_millis() as u64,
            })?
            .map_err(|source| SOCKS5Error::Io {
                proxy_addr: proxy_addr.to_string(),
                source,
            })?;

            trace!(
                proxy_addr = %proxy_addr,
                bind_addr = ?&bind[..domain_port_len],
                "domain bind address"
            );
        }
        _ => {
            trace!(
                proxy_addr = %proxy_addr,
                atyp = atyp,
                "invalid address type"
            );

            return Err(SOCKS5Error::InvalidAddressType {
                proxy_addr: proxy_addr.to_string(),
                atyp,
            });
        }
    }

    Ok(())
}

/// Encode an endpoint into a buffer for the SOCKS5 protocol.
///
/// Returns the number of bytes written.
fn encode_endpoint(buf: &mut [u8], endpoint: &Endpoint) -> Result<usize, SOCKS5Error> {
    match endpoint {
        Endpoint::V4(octets) => {
            buf[0] = ATYP_IPV4;
            buf[1..5].copy_from_slice(octets);
            Ok(5)
        }
        Endpoint::V6(octets) => {
            buf[0] = ATYP_IPV6;
            buf[1..17].copy_from_slice(octets);
            Ok(17)
        }
        Endpoint::Domain(domain) => {
            if domain.len() > 255 {
                return Err(SOCKS5Error::DomainTooLong);
            }
            buf[0] = ATYP_DOMAIN;
            buf[1] = domain.len() as u8;
            buf[2..2 + domain.len()].copy_from_slice(domain);
            Ok(2 + domain.len())
        }
    }
}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_endpoint_ipv4() {
        let endpoint = Endpoint::V4([192, 168, 1, 1]);
        let mut buf = [0u8; 32];

        let len = encode_endpoint(&mut buf, &endpoint).unwrap();

        assert_eq!(len, 5);
        assert_eq!(buf[0], ATYP_IPV4);
        assert_eq!(&buf[1..5], &[192, 168, 1, 1]);
    }

    #[test]
    fn encode_endpoint_ipv6() {
        let endpoint = Endpoint::V6([0; 16]);
        let mut buf = [0u8; 32];

        let len = encode_endpoint(&mut buf, &endpoint).unwrap();

        assert_eq!(len, 17);
        assert_eq!(buf[0], ATYP_IPV6);
        assert_eq!(&buf[1..17], &[0; 16]);
    }

    #[test]
    fn encode_endpoint_domain() {
        let endpoint = Endpoint::Domain(b"example.com".to_vec());
        let mut buf = [0u8; 32];

        let len = encode_endpoint(&mut buf, &endpoint).unwrap();

        assert_eq!(len, 2 + 11); // ATYP + LEN + domain
        assert_eq!(buf[0], ATYP_DOMAIN);
        assert_eq!(buf[1], 11); // length of "example.com"
        assert_eq!(&buf[2..13], b"example.com");
    }

    #[test]
    fn encode_endpoint_domain_too_long() {
        let long_domain = vec![b'a'; 256];
        let endpoint = Endpoint::Domain(long_domain);
        let mut buf = [0u8; 512];

        let result = encode_endpoint(&mut buf, &endpoint);

        assert!(matches!(result, Err(SOCKS5Error::DomainTooLong)));
    }

    #[test]
    fn socks5_reply_code_conversion() {
        let err = SOCKS5Error::from_reply_code(0x01, "proxy:1080".to_string());
        assert!(err.to_string().contains("general SOCKS server failure"));

        let err = SOCKS5Error::from_reply_code(0x05, "proxy:1080".to_string());
        assert!(err.to_string().contains("connection refused"));

        let err = SOCKS5Error::from_reply_code(0xFF, "proxy:1080".to_string());
        assert!(err.to_string().contains("unknown error code"));
    }
}
