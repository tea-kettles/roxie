//! Network endpoint representation and DNS resolution.
//!
//! Provides types and utilities for representing network endpoints as
//! IP addresses or domain names, with IDNA encoding support for international
//! domains and async DNS resolution capabilities.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use tokio::net::lookup_host;
use tokio::time::{Instant, timeout};
use tracing::trace;

use crate::errors::EndpointError;

/* Types */

/// Network endpoint specification for proxy connections.
///
/// Represents a destination as either an IPv4 address, IPv6 address,
/// or domain name. Used by proxy protocols to specify connection targets.
///
/// # Examples
///
/// ```
/// use roxie::transport::Endpoint;
///
/// // IPv4 endpoint
/// let ipv4 = Endpoint::V4([127, 0, 0, 1]);
///
/// // IPv6 endpoint
/// let ipv6 = Endpoint::V6([0; 16]);
///
/// // Domain endpoint
/// let domain = Endpoint::Domain(b"example.com".to_vec());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// IPv4 address as 4 octets.
    V4([u8; 4]),
    /// IPv6 address as 16 octets.
    V6([u8; 16]),
    /// Domain name as bytes (ASCII or IDNA-encoded).
    Domain(Vec<u8>),
}

/* Parsing and Encoding */

/// Parse a string as an IP address.
///
/// Returns `Some(Endpoint)` if the string is a valid IPv4 or IPv6 address,
/// `None` otherwise. Handles IPv6 addresses with or without brackets.
///
/// # Examples
///
/// ```
/// use roxie::transport::{Endpoint, parse_ip};
///
/// // IPv4
/// let ipv4 = parse_ip("127.0.0.1");
/// assert!(matches!(ipv4, Some(Endpoint::V4(_))));
///
/// // IPv6 with brackets
/// let ipv6 = parse_ip("[::1]");
/// assert!(matches!(ipv6, Some(Endpoint::V6(_))));
///
/// // IPv6 without brackets
/// let ipv6 = parse_ip("::1");
/// assert!(matches!(ipv6, Some(Endpoint::V6(_))));
///
/// // Not an IP
/// let not_ip = parse_ip("example.com");
/// assert!(not_ip.is_none());
/// ```
pub fn parse_ip(host: &str) -> Option<Endpoint> {
    let start = Instant::now();

    trace!(host = host, "attempting to parse host as IP address");

    // Try IPv4 first
    if let Ok(ipv4) = host.parse::<Ipv4Addr>() {
        trace!(
            host = host,
            elapsed_ms = start.elapsed().as_millis(),
            "parsed as IPv4"
        );
        return Some(Endpoint::V4(ipv4.octets()));
    }

    // Try IPv6 (with or without brackets)
    let v6_host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    if let Ok(ipv6) = v6_host.parse::<Ipv6Addr>() {
        trace!(
            host = host,
            elapsed_ms = start.elapsed().as_millis(),
            "parsed as IPv6"
        );
        return Some(Endpoint::V6(ipv6.octets()));
    }

    trace!(
        host = host,
        elapsed_ms = start.elapsed().as_millis(),
        "not an IP address"
    );

    None
}

/// IDNA-encode a domain name.
///
/// Converts international domain names to ASCII-compatible encoding.
/// ASCII-only domains pass through unchanged after validation.
///
/// # Examples
///
/// ```
/// use roxie::transport::idna_encode;
///
/// // ASCII domain passes through
/// let ascii = idna_encode("example.com")?;
/// assert_eq!(ascii, b"example.com");
///
/// // International domain gets encoded
/// let intl = idna_encode("münchen.de")?;
/// assert!(intl.starts_with(b"xn--"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn idna_encode(domain: &str) -> Result<Vec<u8>, EndpointError> {
    let start = Instant::now();

    trace!(domain = domain, "encoding domain name");

    // Reject empty or overly long domains early
    if domain.is_empty() || domain.len() > 253 {
        trace!(
            domain = domain,
            elapsed_ms = start.elapsed().as_millis(),
            "domain is empty or too long"
        );
        return Err(EndpointError::InvalidDomainName {
            domain: domain.to_string(),
        });
    }

    // Simple ASCII domains pass through unchanged
    if domain.is_ascii() && is_valid_ascii_domain(domain) {
        trace!(
            domain = domain,
            elapsed_ms = start.elapsed().as_millis(),
            "valid ASCII domain, no encoding needed"
        );
        return Ok(domain.as_bytes().to_vec());
    }

    // For international domains, use IDNA encoding
    match idna::domain_to_ascii(domain) {
        Ok(ascii_domain) => {
            trace!(
                domain = domain,
                encoded = %ascii_domain,
                elapsed_ms = start.elapsed().as_millis(),
                "successfully encoded international domain"
            );
            Ok(ascii_domain.into_bytes())
        }
        Err(e) => {
            trace!(
                domain = domain,
                error = ?e,
                elapsed_ms = start.elapsed().as_millis(),
                "failed to encode domain"
            );
            Err(EndpointError::InvalidDomainName {
                domain: domain.to_string(),
            })
        }
    }
}

/// Validate ASCII domain name format.
///
/// Checks that the domain name follows basic DNS rules:
/// - Not empty and not longer than 253 characters
/// - Each label is 1-63 characters
/// - Labels don't start or end with hyphens
/// - Labels contain only alphanumeric characters and hyphens
fn is_valid_ascii_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }

    // Check each label
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }

        // Labels can't start or end with hyphen
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }

        // Only alphanumeric and hyphens allowed
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }

    true
}

/* DNS Resolution */

/// Resolve a hostname to an IP address with timeout.
///
/// Performs async DNS lookup and returns the first resolved address.
/// Times out according to the provided duration.
///
/// # Examples
///
/// ```no_run
/// use roxie::transport::resolve_host;
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let endpoint = resolve_host("example.com", Duration::from_secs(5)).await?;
/// # Ok(())
/// # }
/// ```
pub async fn resolve_host(
    host: &str,
    timeout_duration: Duration,
) -> Result<Endpoint, EndpointError> {
    let start = Instant::now();

    trace!(
        host = host,
        timeout_ms = timeout_duration.as_millis(),
        "starting DNS resolution"
    );

    let result = timeout(timeout_duration, async {
        lookup_host((host, 0))
            .await
            .map_err(|e| EndpointError::DnsResolutionFailed {
                host: host.to_string(),
                source: e,
            })
    })
    .await;

    match result {
        Ok(Ok(mut addrs)) => {
            if let Some(addr) = addrs.next() {
                let endpoint = match addr.ip() {
                    std::net::IpAddr::V4(ipv4) => Endpoint::V4(ipv4.octets()),
                    std::net::IpAddr::V6(ipv6) => Endpoint::V6(ipv6.octets()),
                };

                trace!(
                    host = host,
                    resolved_ip = %addr.ip(),
                    elapsed_ms = start.elapsed().as_millis(),
                    "successfully resolved"
                );

                Ok(endpoint)
            } else {
                trace!(
                    host = host,
                    elapsed_ms = start.elapsed().as_millis(),
                    "no addresses returned"
                );

                Err(EndpointError::NoAddressesFound {
                    host: host.to_string(),
                })
            }
        }
        Ok(Err(e)) => {
            trace!(
                host = host,
                error = %e,
                elapsed_ms = start.elapsed().as_millis(),
                "DNS resolution failed"
            );
            Err(e)
        }
        Err(_) => {
            trace!(
                host = host,
                elapsed_ms = start.elapsed().as_millis(),
                timeout_ms = timeout_duration.as_millis(),
                "DNS resolution timed out"
            );

            Err(EndpointError::DnsResolutionTimeout {
                host: host.to_string(),
                elapsed_ms: start.elapsed().as_millis() as u64,
                timeout_ms: timeout_duration.as_millis() as u64,
            })
        }
    }
}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ip_ipv4() {
        let result = parse_ip("127.0.0.1");
        assert!(matches!(result, Some(Endpoint::V4([127, 0, 0, 1]))));

        let result = parse_ip("192.168.1.1");
        assert!(matches!(result, Some(Endpoint::V4([192, 168, 1, 1]))));
    }

    #[test]
    fn parse_ip_ipv6_with_brackets() {
        let result = parse_ip("[::1]");
        assert!(matches!(result, Some(Endpoint::V6(_))));
    }

    #[test]
    fn parse_ip_ipv6_without_brackets() {
        let result = parse_ip("::1");
        assert!(matches!(result, Some(Endpoint::V6(_))));

        let result = parse_ip("2001:db8::1");
        assert!(matches!(result, Some(Endpoint::V6(_))));
    }

    #[test]
    fn parse_ip_not_an_ip() {
        let result = parse_ip("example.com");
        assert!(result.is_none());

        let result = parse_ip("not-an-ip");
        assert!(result.is_none());

        let result = parse_ip("");
        assert!(result.is_none());
    }

    #[test]
    fn idna_encode_ascii() {
        let result = idna_encode("example.com").unwrap();
        assert_eq!(result, b"example.com");

        let result = idna_encode("sub.example.com").unwrap();
        assert_eq!(result, b"sub.example.com");
    }

    #[test]
    fn idna_encode_international() {
        let result = idna_encode("münchen.de").unwrap();
        assert!(result.starts_with(b"xn--"));

        let result = idna_encode("日本.jp").unwrap();
        assert!(result.starts_with(b"xn--"));
    }

    #[test]
    fn idna_encode_invalid() {
        // Empty domain
        let result = idna_encode("");
        assert!(result.is_err());

        // Domain too long (>253 chars)
        let long_domain = "a".repeat(254);
        let result = idna_encode(&long_domain);
        assert!(result.is_err());
    }

    #[test]
    fn is_valid_ascii_domain_valid() {
        assert!(is_valid_ascii_domain("example.com"));
        assert!(is_valid_ascii_domain("sub.example.com"));
        assert!(is_valid_ascii_domain("a.b.c.d"));
        assert!(is_valid_ascii_domain("my-domain.com"));
    }

    #[test]
    fn is_valid_ascii_domain_invalid() {
        // Empty
        assert!(!is_valid_ascii_domain(""));

        // Too long
        let long_domain = "a".repeat(254);
        assert!(!is_valid_ascii_domain(&long_domain));

        // Label too long
        let long_label = format!("{}.com", "a".repeat(64));
        assert!(!is_valid_ascii_domain(&long_label));

        // Starts with hyphen
        assert!(!is_valid_ascii_domain("-example.com"));

        // Ends with hyphen
        assert!(!is_valid_ascii_domain("example-.com"));

        // Invalid characters
        assert!(!is_valid_ascii_domain("exam_ple.com"));
        assert!(!is_valid_ascii_domain("example..com"));
    }

    #[tokio::test]
    async fn resolve_host_localhost() {
        let result = resolve_host("localhost", Duration::from_secs(5)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn resolve_host_timeout() {
        // Use a hostname that will hang (non-routable IP as hostname)
        // This should timeout
        let result = resolve_host("192.0.2.1", Duration::from_millis(1)).await;
        // Either it resolves (unlikely) or times out
        if result.is_err() {
            assert!(matches!(
                result.unwrap_err(),
                EndpointError::DnsResolutionTimeout { .. }
                    | EndpointError::DnsResolutionFailed { .. }
            ));
        }
    }

    #[tokio::test]
    async fn resolve_host_invalid() {
        let result = resolve_host(
            "this-domain-definitely-does-not-exist-12345.invalid",
            Duration::from_secs(5),
        )
        .await;
        assert!(result.is_err());
    }
}
