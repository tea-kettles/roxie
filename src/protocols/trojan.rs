//! Trojan proxy protocol implementation.
//!
//! # Protocol Flow
//!
//! 1. Caller establishes a TCP connection and performs a TLS handshake with the proxy server.
//! 2. `establish_trojan` is called with that TLS stream and writes the Trojan request header.
//! 3. The stream is returned as a transparent TCP pipe to the destination.
//!
//! # Wire Format
//!
//! ```text
//! +------------------------------------------+------+
//! | hex(SHA224(password))  56 ASCII hex chars | \r\n |
//! +------------------------------------------+------+
//! | CMD (1 byte)  | ATYP (1 byte) | DST.ADDR | DST.PORT (2 BE) | \r\n |
//! +---------------+---------------+----------+-----------------+------+
//! ```
//!
//! * CMD `0x01` = CONNECT (TCP)
//! * ATYP `0x01` = IPv4 (4 bytes), `0x03` = domain name (1-byte length prefix), `0x04` = IPv6 (16 bytes)
//!
//! # Reference
//!
//! <https://trojan-gfw.github.io/trojan/protocol>

use std::net::{Ipv4Addr, Ipv6Addr};

use sha2::{Digest, Sha224};
use tokio::io::AsyncWriteExt;
use tracing::trace;
use url::Url;

use crate::errors::TrojanError;

/* Constants */

/// CONNECT command byte.
const CMD_CONNECT: u8 = 0x01;
/// IPv4 address type.
const ATYP_IPV4: u8 = 0x01;
/// Domain name address type.
const ATYP_DOMAIN: u8 = 0x03;
/// IPv6 address type.
const ATYP_IPV6: u8 = 0x04;

/* Public API */

/// Write the Trojan handshake header to an already-TLS-connected stream.
///
/// After this call the stream acts as a transparent TCP tunnel to `destination`.
/// The caller is responsible for establishing the TLS layer before calling this function.
///
/// # Arguments
///
/// * `stream` - A TLS-connected writable stream to the Trojan proxy
/// * `destination` - The target URL the proxy should forward traffic to
/// * `password` - The Trojan authentication password (hashed internally)
///
/// # Errors
///
/// Returns [`TrojanError::InvalidAddress`] when the destination URL lacks a host or port,
/// or [`TrojanError::Io`] on write failures.
pub async fn establish_trojan<S>(
    stream: &mut S,
    destination: &Url,
    password: &str,
) -> Result<(), TrojanError>
where
    S: AsyncWriteExt + Unpin,
{
    let target_host = destination
        .host_str()
        .ok_or_else(|| TrojanError::InvalidAddress {
            reason: "destination URL has no host".to_string(),
        })?;

    let target_port = destination
        .port_or_known_default()
        .ok_or_else(|| TrojanError::InvalidAddress {
            reason: format!("no port for scheme '{}'", destination.scheme()),
        })?;

    trace!(
        target_host = target_host,
        target_port = target_port,
        "building Trojan header"
    );

    let mut header = Vec::with_capacity(128);

    // hex(SHA224(password)) + CRLF
    let hash = sha224_hex(password);
    header.extend_from_slice(hash.as_bytes());
    header.extend_from_slice(b"\r\n");

    // CMD
    header.push(CMD_CONNECT);

    // ATYP + DST.ADDR
    match destination.host() {
        Some(url::Host::Ipv4(addr)) => {
            header.push(ATYP_IPV4);
            header.extend_from_slice(&addr_ipv4_bytes(addr));
        }
        Some(url::Host::Ipv6(addr)) => {
            header.push(ATYP_IPV6);
            header.extend_from_slice(&addr_ipv6_bytes(addr));
        }
        Some(url::Host::Domain(domain)) => {
            let bytes = domain.as_bytes();
            if bytes.len() > 255 {
                return Err(TrojanError::InvalidAddress {
                    reason: format!("domain name too long ({} bytes)", bytes.len()),
                });
            }
            header.push(ATYP_DOMAIN);
            header.push(bytes.len() as u8);
            header.extend_from_slice(bytes);
        }
        None => {
            return Err(TrojanError::InvalidAddress {
                reason: "destination URL has no host".to_string(),
            });
        }
    }

    // DST.PORT (big-endian u16)
    header.extend_from_slice(&target_port.to_be_bytes());

    // Trailing CRLF
    header.extend_from_slice(b"\r\n");

    stream.write_all(&header).await?;

    trace!(
        target_host = target_host,
        target_port = target_port,
        header_len = header.len(),
        "Trojan header sent"
    );

    Ok(())
}

/* Helpers */

/// Compute SHA-224 of `input` and return it as 56 lowercase hex characters.
fn sha224_hex(input: &str) -> String {
    let mut hasher = Sha224::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    // SHA-224 produces 28 bytes → 56 hex chars
    digest.iter().fold(String::with_capacity(56), |mut s, b| {
        use std::fmt::Write;
        write!(s, "{:02x}", b).unwrap();
        s
    })
}

fn addr_ipv4_bytes(addr: Ipv4Addr) -> [u8; 4] {
    addr.octets()
}

fn addr_ipv6_bytes(addr: Ipv6Addr) -> [u8; 16] {
    addr.octets()
}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha224_hex_length() {
        let h = sha224_hex("password");
        assert_eq!(h.len(), 56, "SHA-224 hex must be 56 chars");
    }

    #[test]
    fn sha224_hex_known_value() {
        // SHA-224("password") = known constant
        let h = sha224_hex("password");
        assert_eq!(
            h,
            "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
    }

    #[test]
    fn sha224_hex_empty_string() {
        let h = sha224_hex("");
        assert_eq!(h.len(), 56);
        // SHA-224("") = d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f
        assert_eq!(h, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    }

    #[test]
    fn sha224_hex_is_lowercase() {
        let h = sha224_hex("test");
        assert!(h.chars().all(|c| c.is_ascii_digit() || c.is_ascii_lowercase()));
    }

    #[tokio::test]
    async fn establish_trojan_writes_expected_header() {
        use tokio::io::AsyncReadExt;

        let target = Url::parse("http://example.com:80").unwrap();
        let password = "secret";

        let (mut client, mut server) = tokio::io::duplex(256);
        establish_trojan(&mut client, &target, password)
            .await
            .expect("should not fail");
        drop(client);

        let mut buf = Vec::new();
        server.read_to_end(&mut buf).await.unwrap();

        // Header starts with SHA-224 hex of "secret"
        let expected_hash = sha224_hex(password);
        assert!(buf.starts_with(expected_hash.as_bytes()));

        // Then CRLF
        assert_eq!(&buf[56..58], b"\r\n");

        // CMD = 0x01 (CONNECT)
        assert_eq!(buf[58], CMD_CONNECT);

        // ATYP = 0x03 (domain)
        assert_eq!(buf[59], ATYP_DOMAIN);

        // Domain length = 11 ("example.com")
        assert_eq!(buf[60], 11);

        // Domain bytes
        assert_eq!(&buf[61..72], b"example.com");

        // Port 80 = [0x00, 0x50]
        assert_eq!(&buf[72..74], &80u16.to_be_bytes());

        // Trailing CRLF
        assert_eq!(&buf[74..76], b"\r\n");
    }

    #[tokio::test]
    async fn establish_trojan_ipv4_address() {
        use tokio::io::AsyncReadExt;

        let target = Url::parse("http://1.2.3.4:8080").unwrap();

        let (mut client, mut server) = tokio::io::duplex(256);
        establish_trojan(&mut client, &target, "pass").await.unwrap();
        drop(client);

        let mut buf = Vec::new();
        server.read_to_end(&mut buf).await.unwrap();

        // ATYP = 0x01 (IPv4)
        assert_eq!(buf[59], ATYP_IPV4);
        // 4 address bytes
        assert_eq!(&buf[60..64], &[1, 2, 3, 4]);
        // Port 8080
        assert_eq!(&buf[64..66], &8080u16.to_be_bytes());
    }

    #[tokio::test]
    async fn establish_trojan_error_no_host() {
        // file:// URLs have no host
        let target = Url::parse("file:///etc/hosts").unwrap();
        let (mut client, _server) = tokio::io::duplex(256);
        let result = establish_trojan(&mut client, &target, "pass").await;
        assert!(matches!(result, Err(TrojanError::InvalidAddress { .. })));
    }
}
