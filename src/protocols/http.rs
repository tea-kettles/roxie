//! HTTP CONNECT proxy protocol implementation.
//!
//! Implements the HTTP CONNECT method (RFC 7231 Section 4.3.6) for establishing
//! tunneled proxy connections. Supports basic authentication via the
//! Proxy-Authorization header.
//!
//! The protocol uses a text-based request/response format:
//! 1. Send CONNECT request with target authority
//! 2. Optionally include Proxy-Authorization header for authentication
//! 3. Read HTTP response and parse status code
//! 4. On 200 status, tunnel is established

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};
use tracing::trace;
use url::Url;
use zeroize::Zeroize;

use crate::config::{HTTPConfig, HasBaseProxyConfig};
use crate::errors::HTTPError;
use crate::transport::{Endpoint, idna_encode, parse_ip, resolve_host};

// Buffer Size Constants
const MAX_AUTHORITY_LENGTH: usize = 255;
const MAX_DOMAIN_LENGTH: usize = 253;
const MAX_RESPONSE_HEADERS: usize = 8192;
const MIN_HTTP_STATUS_LINE: usize = 12; // "HTTP/1.1 200"
const MAX_AUTHORITY_BUFFER: usize = 300; // [IPv6]:port buffer
const MAX_HTTP_REQUEST: usize = 2048;
const MAX_CREDENTIALS_BUFFER: usize = 512; // username(255) + ':' + password(255)
const MAX_HTTP_CREDENTIAL_COMPONENT: usize = 255;

/* Public API */

/// Establish an HTTP CONNECT tunnel through a proxy.
///
/// Performs the HTTP CONNECT handshake including request building, optional
/// authentication, and response parsing. After this function returns successfully,
/// the stream is ready for application data transfer through the established tunnel.
///
/// # Examples
///
/// ```no_run
/// use roxie::protocols::http::establish_http;
/// use roxie::config::HTTPConfig;
/// use tokio::net::TcpStream;
/// use url::Url;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = HTTPConfig::new("proxy.example.com", 8080)
///     .set_credentials("user", "pass");
///
/// let mut stream = TcpStream::connect("proxy.example.com:8080").await?;
/// let target = Url::parse("https://example.com:443")?;
///
/// establish_http(&mut stream, &target, &config).await?;
/// // Stream is now ready for data transfer through the tunnel
/// # Ok(())
/// # }
/// ```
pub async fn establish_http(
    stream: &mut TcpStream,
    target_url: &Url,
    config: &HTTPConfig,
) -> Result<(), HTTPError> {
    let start = Instant::now();
    let proxy_addr = stream
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    trace!(
        target_url = %target_url,
        proxy_addr = %proxy_addr,
        "starting CONNECT handshake"
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
                elapsed_ms = start.elapsed().as_millis(),
                "tunnel established"
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
            let error = HTTPError::HandshakeTimeout {
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

/// Send CONNECT request and read response.
async fn connect(
    stream: &mut TcpStream,
    target_url: &Url,
    config: &HTTPConfig,
    proxy_addr: &str,
) -> Result<(), HTTPError> {
    let start = Instant::now();

    trace!(
        proxy_addr = %proxy_addr,
        target_url = %target_url,
        "preparing CONNECT request"
    );

    let phase_timeout = config.get_base_config().get_phase_timeout();

    // Extract target host and port
    let host = target_url.host_str().ok_or(HTTPError::NoTargetHost)?;
    let port = target_url
        .port_or_known_default()
        .ok_or(HTTPError::NoTargetPort)?;

    if port == 0 {
        return Err(HTTPError::InvalidPortInAuthority {
            reason: "port cannot be 0".to_string(),
        });
    }

    // Determine endpoint specification
    let endpoint = match parse_ip(host) {
        Some(ep) => ep,
        None => {
            if config.get_base_config().is_resolve_locally() {
                trace!(
                    proxy_addr = %proxy_addr,
                    host = %host,
                    "resolving domain locally"
                );
                resolve_host(host, phase_timeout).await?
            } else {
                Endpoint::Domain(idna_encode(host)?)
            }
        }
    };

    // Build authority (host:port)
    let mut authority = [0u8; MAX_AUTHORITY_BUFFER];
    let auth_len = build_authority(&mut authority, &endpoint, port)?;

    trace!(
        proxy_addr = %proxy_addr,
        authority = %String::from_utf8_lossy(&authority[..auth_len]),
        "built authority"
    );

    // Build CONNECT request
    let mut request = [0u8; MAX_HTTP_REQUEST];
    let auth_creds = match (config.get_username(), config.get_password()) {
        (Some(u), Some(p)) => Some((u, p)),
        _ => None,
    };

    let req_len = build_connect_request(&mut request, &authority[..auth_len], auth_creds)?;

    trace!(
        proxy_addr = %proxy_addr,
        request_size = req_len,
        "sending CONNECT request"
    );

    // Send CONNECT request with timeout
    timeout(phase_timeout, stream.write_all(&request[..req_len]))
        .await
        .map_err(|_| HTTPError::PhaseTimeout {
            proxy_addr: proxy_addr.to_string(),
            phase: "CONNECT request (write)".to_string(),
            elapsed_ms: start.elapsed().as_millis() as u64,
            timeout_ms: phase_timeout.as_millis() as u64,
        })?
        .map_err(|source| HTTPError::Io {
            proxy_addr: proxy_addr.to_string(),
            source,
        })?;

    // Wipe the request buffer to avoid retaining proxy credentials in memory.
    request[..req_len].zeroize();

    // Read HTTP response
    let mut response = [0u8; MAX_RESPONSE_HEADERS];
    let resp_len = read_response(stream, &mut response, phase_timeout, proxy_addr, &start).await?;

    trace!(
        proxy_addr = %proxy_addr,
        response_size = resp_len,
        "received HTTP response"
    );

    // Parse status code
    let status = parse_status_code(&response[..resp_len], proxy_addr)?;

    trace!(
        proxy_addr = %proxy_addr,
        status_code = status,
        "parsed status code"
    );

    // Handle status codes
    match (status, auth_creds.is_some()) {
        (200, _) => {
            trace!(
                proxy_addr = %proxy_addr,
                elapsed_ms = start.elapsed().as_millis(),
                "tunnel established (200 OK)"
            );
            Ok(())
        }
        (407, false) => {
            trace!(
                proxy_addr = %proxy_addr,
                elapsed_ms = start.elapsed().as_millis(),
                "authentication required but none provided"
            );
            Err(HTTPError::RequiresAuthentication {
                proxy_addr: proxy_addr.to_string(),
            })
        }
        (407, true) => {
            trace!(
                proxy_addr = %proxy_addr,
                elapsed_ms = start.elapsed().as_millis(),
                "authentication failed"
            );
            Err(HTTPError::AuthenticationFailed {
                proxy_addr: proxy_addr.to_string(),
            })
        }
        (code, _) => {
            trace!(
                proxy_addr = %proxy_addr,
                status_code = code,
                elapsed_ms = start.elapsed().as_millis(),
                "non-success status code"
            );
            Err(HTTPError::from_status_code(code, proxy_addr.to_string()))
        }
    }
}

/// Read HTTP response headers until CRLFCRLF terminator.
async fn read_response(
    stream: &mut TcpStream,
    buf: &mut [u8],
    phase_timeout: Duration,
    proxy_addr: &str,
    start: &Instant,
) -> Result<usize, HTTPError> {
    let mut total = 0;
    let mut search_start: usize = 0;

    trace!(
        proxy_addr = %proxy_addr,
        "reading HTTP response headers"
    );

    loop {
        if total >= buf.len() {
            trace!(
                proxy_addr = %proxy_addr,
                bytes_read = total,
                "headers exceed maximum size"
            );
            return Err(HTTPError::HTTPHeadersTooLarge {
                proxy_addr: proxy_addr.to_string(),
                max_size: buf.len(),
            });
        }

        let n = timeout(phase_timeout, stream.read(&mut buf[total..]))
            .await
            .map_err(|_| HTTPError::PhaseTimeout {
                proxy_addr: proxy_addr.to_string(),
                phase: "response headers (read)".to_string(),
                elapsed_ms: start.elapsed().as_millis() as u64,
                timeout_ms: phase_timeout.as_millis() as u64,
            })?
            .map_err(|source| {
                if source.kind() == std::io::ErrorKind::UnexpectedEof {
                    if total == 0 {
                        HTTPError::EarlyEOF {
                            proxy_addr: proxy_addr.to_string(),
                            phase: "response headers".to_string(),
                            expected: "HTTP response headers".to_string(),
                            received: 0,
                        }
                    } else {
                        HTTPError::EarlyEOF {
                            proxy_addr: proxy_addr.to_string(),
                            phase: "response headers".to_string(),
                            expected: "complete HTTP headers ending with \\r\\n\\r\\n".to_string(),
                            received: total,
                        }
                    }
                } else {
                    HTTPError::Io {
                        proxy_addr: proxy_addr.to_string(),
                        source,
                    }
                }
            })?;

        if n == 0 {
            trace!(
                proxy_addr = %proxy_addr,
                bytes_read = total,
                "connection closed before headers complete"
            );
            return Err(HTTPError::EarlyEOF {
                proxy_addr: proxy_addr.to_string(),
                phase: "response headers".to_string(),
                expected: "complete HTTP headers ending with \\r\\n\\r\\n".to_string(),
                received: total,
            });
        }

        total += n;

        // Search with 3-byte overlap for boundary cases
        let start_pos = search_start.saturating_sub(3);
        if let Some(header_end) = find_header_end(&buf[start_pos..total]) {
            let absolute_end = start_pos + header_end;
            trace!(
                proxy_addr = %proxy_addr,
                bytes_read = absolute_end,
                "found complete headers"
            );
            return Ok(absolute_end);
        }

        search_start = total;
    }
}

/// Find the end of HTTP headers (CRLFCRLF).
fn find_header_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    for i in 0..=buf.len() - 4 {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
    }
    None
}

/// Parse HTTP status code from response.
fn parse_status_code(buf: &[u8], proxy_addr: &str) -> Result<u16, HTTPError> {
    if buf.is_empty() {
        return Err(HTTPError::HTTPResponseEmpty {
            proxy_addr: proxy_addr.to_string(),
        });
    }

    let header_end =
        find_header_end(buf).ok_or_else(|| HTTPError::HTTPResponseHeadersIncomplete {
            proxy_addr: proxy_addr.to_string(),
        })?;

    let headers = &buf[..header_end];
    let mut lines = headers.split(|&b| b == b'\n');
    let status_line = lines.next().ok_or_else(|| HTTPError::HTTPResponseEmpty {
        proxy_addr: proxy_addr.to_string(),
    })?;

    let line = status_line.strip_suffix(b"\r").unwrap_or(status_line);

    if line.len() < MIN_HTTP_STATUS_LINE {
        return Err(HTTPError::HTTPStatusLineTooShort {
            proxy_addr: proxy_addr.to_string(),
            length: line.len(),
            min_length: MIN_HTTP_STATUS_LINE,
        });
    }

    // Check for SOCKS protocol response
    if line.len() >= 2 && (line[0] == 0x04 || line[0] == 0x05) {
        let protocol_name = if line[0] == 0x04 { "SOCKS4" } else { "SOCKS5" };
        return Err(HTTPError::ProtocolMismatch {
            proxy_addr: proxy_addr.to_string(),
            actual_description: format!(
                "{} response (version byte 0x{:02x})",
                protocol_name, line[0]
            ),
        });
    }

    // Validate HTTP version
    if !line.starts_with(b"HTTP/1.") {
        let version = String::from_utf8_lossy(&line[..std::cmp::min(8, line.len())]);
        return Err(HTTPError::HTTPVersionNotSupported {
            version: version.into_owned(),
        });
    }

    // Find status code (after first space)
    let space_pos = line.iter().position(|&b| b == b' ').ok_or_else(|| {
        HTTPError::HTTPStatusLineMissingSpace {
            proxy_addr: proxy_addr.to_string(),
        }
    })?;

    if space_pos + 1 >= line.len() {
        return Err(HTTPError::HTTPStatusLineTooShort {
            proxy_addr: proxy_addr.to_string(),
            length: line.len(),
            min_length: MIN_HTTP_STATUS_LINE,
        });
    }

    let rest = &line[space_pos + 1..];

    // Find end of status code
    let code_end = rest
        .iter()
        .position(|&b| b == b' ' || b == b'\r' || b == b'\n')
        .unwrap_or(rest.len());
    let code_bytes = &rest[..code_end];

    if code_bytes.len() != 3 {
        return Err(HTTPError::HTTPStatusCodeWrongLength {
            proxy_addr: proxy_addr.to_string(),
            length: code_bytes.len(),
        });
    }

    for &byte in code_bytes {
        if !byte.is_ascii_digit() {
            return Err(HTTPError::HTTPStatusCodeNonDigit {
                proxy_addr: proxy_addr.to_string(),
                character: byte as char,
            });
        }
    }

    let code = (code_bytes[0] - b'0') as u16 * 100
        + (code_bytes[1] - b'0') as u16 * 10
        + (code_bytes[2] - b'0') as u16;

    if code < 100 || code > 599 {
        return Err(HTTPError::HTTPStatusCodeOutOfRange {
            proxy_addr: proxy_addr.to_string(),
            code,
        });
    }

    Ok(code)
}

/* Helper Functions */

/// Build authority string (host:port) for HTTP CONNECT.
fn build_authority(buf: &mut [u8], endpoint: &Endpoint, port: u16) -> Result<usize, HTTPError> {
    let mut pos = 0;

    match endpoint {
        Endpoint::V4(octets) => {
            let ip = Ipv4Addr::from(*octets);
            let ip_str = ip.to_string();
            let ip_bytes = ip_str.as_bytes();

            if pos + ip_bytes.len() > buf.len() {
                return Err(HTTPError::AuthorityTooLong {
                    actual: pos + ip_bytes.len(),
                    max: buf.len(),
                });
            }

            buf[pos..pos + ip_bytes.len()].copy_from_slice(ip_bytes);
            pos += ip_bytes.len();
        }
        Endpoint::V6(octets) => {
            let ip = Ipv6Addr::from(*octets);
            let ip_str = ip.to_string();
            let ip_bytes = ip_str.as_bytes();

            // IPv6 requires brackets: [2001:db8::1]
            if pos + 1 + ip_bytes.len() + 1 > buf.len() {
                return Err(HTTPError::AuthorityTooLong {
                    actual: pos + 1 + ip_bytes.len() + 1,
                    max: buf.len(),
                });
            }

            buf[pos] = b'[';
            pos += 1;
            buf[pos..pos + ip_bytes.len()].copy_from_slice(ip_bytes);
            pos += ip_bytes.len();
            buf[pos] = b']';
            pos += 1;
        }
        Endpoint::Domain(domain) => {
            if domain.is_empty() {
                return Err(HTTPError::EmptyAuthority);
            }
            if domain.len() > MAX_DOMAIN_LENGTH {
                return Err(HTTPError::AuthorityTooLong {
                    actual: domain.len(),
                    max: MAX_DOMAIN_LENGTH,
                });
            }

            if pos + domain.len() > buf.len() {
                return Err(HTTPError::AuthorityTooLong {
                    actual: pos + domain.len(),
                    max: buf.len(),
                });
            }

            buf[pos..pos + domain.len()].copy_from_slice(domain);
            pos += domain.len();
        }
    }

    // Add port
    let port_str = port.to_string();
    let port_bytes = port_str.as_bytes();

    if pos + 1 + port_bytes.len() > buf.len() {
        return Err(HTTPError::AuthorityTooLong {
            actual: pos + 1 + port_bytes.len(),
            max: buf.len(),
        });
    }

    buf[pos] = b':';
    pos += 1;
    buf[pos..pos + port_bytes.len()].copy_from_slice(port_bytes);
    pos += port_bytes.len();

    // Validate authority
    validate_authority(&buf[..pos])?;

    Ok(pos)
}

/// Validate authority for header injection and invalid characters.
fn validate_authority(authority: &[u8]) -> Result<(), HTTPError> {
    if authority.is_empty() {
        return Err(HTTPError::EmptyAuthority);
    }

    if authority.len() > MAX_AUTHORITY_LENGTH {
        return Err(HTTPError::AuthorityTooLong {
            actual: authority.len(),
            max: MAX_AUTHORITY_LENGTH,
        });
    }

    // Check for dangerous characters
    for (i, &byte) in authority.iter().enumerate() {
        match byte {
            b'\r' | b'\n' => return Err(HTTPError::AuthorityHeaderInjection),
            b' ' | b'\t' => {
                return Err(HTTPError::InvalidAuthorityCharacters {
                    reason: format!("whitespace at position {}", i),
                });
            }
            b'\0' => {
                return Err(HTTPError::InvalidAuthorityCharacters {
                    reason: format!("null byte at position {}", i),
                });
            }
            0x00..=0x1F | 0x7F => {
                return Err(HTTPError::InvalidAuthorityCharacters {
                    reason: format!("control character 0x{:02x} at position {}", byte, i),
                });
            }
            0x80..=0xFF => {
                return Err(HTTPError::InvalidAuthorityCharacters {
                    reason: format!("non-ASCII character 0x{:02x} at position {}", byte, i),
                });
            }
            _ => {}
        }
    }

    Ok(())
}

/// Calculate Base64 encoded size.
fn base64_encoded_size(input_len: usize) -> usize {
    ((input_len + 2) / 3) * 4
}

/// Build HTTP CONNECT request.
fn build_connect_request(
    buf: &mut [u8],
    authority: &[u8],
    auth: Option<(&str, &str)>,
) -> Result<usize, HTTPError> {
    // Calculate required size
    let mut required = 8 + authority.len() + 11 + 6 + authority.len() + 2; // Request line + Host
    if let Some((username, password)) = auth {
        let cred_len = username.len() + 1 + password.len();
        required += 27 + base64_encoded_size(cred_len) + 2; // Proxy-Authorization
    }
    required += 30 + 2; // Proxy-Connection + final CRLF

    if required > buf.len() {
        return Err(HTTPError::HTTPConnectRequestTooLarge {
            actual: required,
            max: buf.len(),
        });
    }

    let mut pos = 0;

    // CONNECT authority HTTP/1.1\r\n
    buf[pos..pos + 8].copy_from_slice(b"CONNECT ");
    pos += 8;
    buf[pos..pos + authority.len()].copy_from_slice(authority);
    pos += authority.len();
    buf[pos..pos + 11].copy_from_slice(b" HTTP/1.1\r\n");
    pos += 11;

    // Host: authority\r\n
    buf[pos..pos + 6].copy_from_slice(b"Host: ");
    pos += 6;
    buf[pos..pos + authority.len()].copy_from_slice(authority);
    pos += authority.len();
    buf[pos..pos + 2].copy_from_slice(b"\r\n");
    pos += 2;

    // Proxy-Authorization if needed
    if let Some((username, password)) = auth {
        pos = write_proxy_auth(buf, pos, username, password)?;
    }

    // Proxy-Connection: Keep-Alive\r\n
    buf[pos..pos + 30].copy_from_slice(b"Proxy-Connection: Keep-Alive\r\n");
    pos += 30;

    // End of headers\r\n
    buf[pos..pos + 2].copy_from_slice(b"\r\n");
    pos += 2;

    Ok(pos)
}

/// Write Proxy-Authorization header with Base64-encoded credentials.
fn write_proxy_auth(
    buf: &mut [u8],
    start_pos: usize,
    username: &str,
    password: &str,
) -> Result<usize, HTTPError> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let mut pos = start_pos;

    let username_bytes = username.as_bytes();
    let password_bytes = password.as_bytes();

    // Validate credential lengths
    if username_bytes.len() > MAX_HTTP_CREDENTIAL_COMPONENT
        || password_bytes.len() > MAX_HTTP_CREDENTIAL_COMPONENT
    {
        return Err(HTTPError::InvalidCredentials {
            reason: format!(
                "username or password exceeds {} bytes",
                MAX_HTTP_CREDENTIAL_COMPONENT
            ),
        });
    }

    let cred_len = username_bytes.len() + 1 + password_bytes.len();
    if cred_len > MAX_CREDENTIALS_BUFFER {
        return Err(HTTPError::InvalidCredentials {
            reason: format!(
                "combined credentials exceed {} bytes",
                MAX_CREDENTIALS_BUFFER
            ),
        });
    }

    // Prepare credentials string "username:password"
    let mut cred_buf = [0u8; MAX_CREDENTIALS_BUFFER];
    let mut cred_pos = 0;

    cred_buf[cred_pos..cred_pos + username_bytes.len()].copy_from_slice(username_bytes);
    cred_pos += username_bytes.len();
    cred_buf[cred_pos] = b':';
    cred_pos += 1;
    cred_buf[cred_pos..cred_pos + password_bytes.len()].copy_from_slice(password_bytes);
    cred_pos += password_bytes.len();

    // Proxy-Authorization: Basic <base64>\r\n
    buf[pos..pos + 27].copy_from_slice(b"Proxy-Authorization: Basic ");
    pos += 27;

    // Encode directly into buffer
    let encoded_len = STANDARD
        .encode_slice(&cred_buf[..cred_pos], &mut buf[pos..])
        .map_err(|_| HTTPError::Base64EncodingFailed)?;
    pos += encoded_len;

    buf[pos..pos + 2].copy_from_slice(b"\r\n");
    pos += 2;

    // Zero out credential buffer
    cred_buf.zeroize();

    Ok(pos)
}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_authority_ipv4() {
        let endpoint = Endpoint::V4([192, 168, 1, 1]);
        let mut buf = [0u8; 64];

        let len = build_authority(&mut buf, &endpoint, 8080).unwrap();

        assert_eq!(&buf[..len], b"192.168.1.1:8080");
    }

    #[test]
    fn build_authority_ipv6() {
        let endpoint = Endpoint::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let mut buf = [0u8; 64];

        let len = build_authority(&mut buf, &endpoint, 443).unwrap();

        // IPv6 should be bracketed
        let authority = std::str::from_utf8(&buf[..len]).unwrap();
        assert!(authority.starts_with('['));
        assert!(authority.ends_with(":443"));
    }

    #[test]
    fn build_authority_domain() {
        let endpoint = Endpoint::Domain(b"example.com".to_vec());
        let mut buf = [0u8; 64];

        let len = build_authority(&mut buf, &endpoint, 443).unwrap();

        assert_eq!(&buf[..len], b"example.com:443");
    }

    #[test]
    fn validate_authority_rejects_crlf() {
        let result = validate_authority(b"example.com:80\r\n");
        assert!(matches!(result, Err(HTTPError::AuthorityHeaderInjection)));
    }

    #[test]
    fn validate_authority_rejects_control_chars() {
        let result = validate_authority(b"example.com:80\x00");
        assert!(matches!(
            result,
            Err(HTTPError::InvalidAuthorityCharacters { .. })
        ));
    }

    #[test]
    fn build_connect_request_no_auth() {
        let mut buf = [0u8; 512];
        let result = build_connect_request(&mut buf, b"example.com:443", None).unwrap();

        let request = std::str::from_utf8(&buf[..result]).unwrap();
        assert!(request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(request.contains("Host: example.com:443\r\n"));
        assert!(request.contains("Proxy-Connection: Keep-Alive\r\n"));
        assert!(request.ends_with("\r\n\r\n"));
        assert!(!request.contains("Proxy-Authorization"));
    }

    #[test]
    fn build_connect_request_with_auth() {
        let mut buf = [0u8; 512];
        let result =
            build_connect_request(&mut buf, b"example.com:443", Some(("user", "pass"))).unwrap();

        let request = std::str::from_utf8(&buf[..result]).unwrap();
        assert!(request.contains("Proxy-Authorization: Basic "));
    }

    #[test]
    fn parse_status_code_200() {
        let response = b"HTTP/1.1 200 Connection Established\r\n\r\n";
        let code = parse_status_code(response, "proxy:8080").unwrap();
        assert_eq!(code, 200);
    }

    #[test]
    fn parse_status_code_407() {
        let response = b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n";
        let code = parse_status_code(response, "proxy:8080").unwrap();
        assert_eq!(code, 407);
    }

    #[test]
    fn parse_status_code_socks5_detected() {
        let response = b"\x05\x00HTTP/1.1 200 OK\r\n\r\n";
        let result = parse_status_code(response, "proxy:8080");
        assert!(matches!(result, Err(HTTPError::ProtocolMismatch { .. })));
    }

    #[test]
    fn parse_status_code_invalid_version() {
        let response = b"HTTX/1.1 200 OK\r\n\r\n";
        let result = parse_status_code(response, "proxy:8080");
        assert!(matches!(
            result,
            Err(HTTPError::HTTPVersionNotSupported { .. })
        ));
    }

    #[test]
    fn find_header_end_finds_crlf_crlf() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nbody";
        let end = find_header_end(buf).unwrap();
        assert_eq!(&buf[..end], b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    }

    #[test]
    fn find_header_end_not_found() {
        let buf = b"HTTP/1.1 200 OK\r\n";
        assert!(find_header_end(buf).is_none());
    }
}
