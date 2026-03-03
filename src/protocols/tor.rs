//! Tor proxy protocol implementation.
//!
//! Tor uses SOCKS5 for the actual proxy connection, but can be configured via
//! the control port for circuit options, exit node selection, and bridge usage.
//! This module wraps SOCKS5 and adds optional control port configuration.
//!
//! The protocol flow:
//! 1. Optionally connect to control port and apply configuration
//! 2. Delegate to SOCKS5 for actual tunnel establishment

use std::time::Duration;

use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};
use tracing::trace;
use url::Url;
use zeroize::Zeroize;

use crate::config::{HasBaseProxyConfig, SOCKS5Config, TorConfig};
use crate::errors::TorError;

// Control Port Reply Constants
const FINAL_OK: &str = "250";
const EVENT_PREFIX: &str = "650";

/* Public API */

/// Establish a Tor SOCKS5 tunnel with optional control port configuration.
///
/// If control port configuration is requested, connects to the Tor control port,
/// authenticates, applies circuit configuration (exit nodes, bridges, etc), then
/// delegates to SOCKS5 for the actual tunnel establishment.
///
/// # Examples
///
/// ```no_run
/// use roxie::protocols::tor::establish_tor;
/// use roxie::config::TorConfig;
/// use tokio::net::TcpStream;
/// use url::Url;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Basic Tor connection (no control port configuration)
/// let config = TorConfig::new();
/// let mut stream = TcpStream::connect("localhost:9050").await?;
/// let target = Url::parse("https://example.com:443")?;
///
/// establish_tor(&mut stream, &target, &config, false).await?;
///
/// // With control port configuration
/// let config = TorConfig::new()
///     .set_control_host("localhost")
///     .set_control_port(9051)
///     .set_exit_nodes("{us},{uk}")
///     .set_strict_nodes(true);
///
/// let mut stream = TcpStream::connect("localhost:9050").await?;
/// establish_tor(&mut stream, &target, &config, true).await?;
/// # Ok(())
/// # }
/// ```
pub async fn establish_tor(
    stream: &mut TcpStream,
    target_url: &Url,
    config: &TorConfig,
    apply_config: bool,
) -> Result<(), TorError> {
    let start = Instant::now();
    let proxy_socket = stream.peer_addr().map_err(|source| TorError::Io {
        proxy_addr: "unknown".to_string(),
        source,
    })?;
    let proxy_addr = proxy_socket.to_string();

    trace!(
        target_url = %target_url,
        proxy_addr = %proxy_addr,
        apply_config = apply_config,
        "starting tor tunnel setup"
    );

    let handshake_timeout = config.get_base_config().get_handshake_timeout();
    let result = timeout(handshake_timeout, async {
        // Apply control port configuration if requested
        if apply_config {
            apply_control_settings(config).await?;
        }

        // Build a SOCKS5 config derived from Tor settings (Tor always resolves remotely)
        let mut socks5_config =
            SOCKS5Config::new(proxy_socket.ip().to_string(), proxy_socket.port());
        *socks5_config.get_base_config_mut() = config.get_base().clone();
        socks5_config
            .get_base_config_mut()
            .set_resolve_locally(false);

        crate::protocols::socks5::establish_socks5(stream, target_url, &socks5_config).await?;
        Ok::<(), TorError>(())
    })
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
                "tunnel setup failed"
            );
            Err(e)
        }
        Err(_) => {
            let error = TorError::HandshakeTimeout {
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

/* Control Port Management */

/// Apply Tor control port settings.
async fn apply_control_settings(config: &TorConfig) -> Result<(), TorError> {
    let start = Instant::now();
    let control_host = config.get_control_host();
    let control_port = config.get_control_port();
    let phase_timeout = config.get_base_config().get_phase_timeout();

    trace!(
        control_host = %control_host,
        control_port = control_port,
        "connecting to control port"
    );

    // Connect to control port
    let mut control = connect_control_port(control_host, control_port, phase_timeout).await?;

    // Get protocol info
    trace!(
        control_host = %control_host,
        control_port = control_port,
        "sending PROTOCOLINFO"
    );

    let protocol_info = send_control_command(
        &mut control,
        "PROTOCOLINFO\r\n",
        phase_timeout,
        control_host,
        control_port,
    )
    .await?;

    // Authenticate
    authenticate_control_port(&mut control, &protocol_info, config, phase_timeout).await?;

    // Configure Tor settings
    configure_tor_settings(&mut control, config, phase_timeout).await?;

    // Light-weight check that Tor is responsive (ignore errors)
    trace!(
        control_host = %control_host,
        control_port = control_port,
        "checking circuit status"
    );

    if let Err(e) = send_control_command(
        &mut control,
        "GETINFO status/circuit-established\r\n",
        phase_timeout,
        control_host,
        control_port,
    )
    .await
    {
        trace!(
            control_host = %control_host,
            control_port = control_port,
            error = %e,
            "circuit status check failed (non-fatal)"
        );
    }

    trace!(
        control_host = %control_host,
        control_port = control_port,
        elapsed_ms = start.elapsed().as_millis(),
        "configuration applied"
    );

    Ok(())
}

/// Connect to Tor control port.
async fn connect_control_port(
    host: &str,
    port: u16,
    phase_timeout: Duration,
) -> Result<TcpStream, TorError> {
    let addr = format!("{}:{}", host, port);
    let start = Instant::now();

    trace!(control_addr = %addr, "connecting");

    let stream = timeout(phase_timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| TorError::ControlPortTimeout {
            host: host.to_string(),
            port,
            elapsed_ms: start.elapsed().as_millis() as u64,
            timeout_ms: phase_timeout.as_millis() as u64,
        })?
        .map_err(|source| TorError::ControlPortConnectionFailed {
            host: host.to_string(),
            port,
            source,
        })?;

    trace!(
        control_addr = %addr,
        elapsed_ms = start.elapsed().as_millis(),
        "connected"
    );

    Ok(stream)
}

/// Authenticate with Tor control port.
async fn authenticate_control_port(
    stream: &mut TcpStream,
    protocol_info: &[String],
    config: &TorConfig,
    phase_timeout: Duration,
) -> Result<(), TorError> {
    let start = Instant::now();
    let control_host = config.get_control_host();
    let control_port = config.get_control_port();

    trace!(
        control_host = %control_host,
        control_port = control_port,
        "authenticating"
    );

    // Determine authentication method (priority: password > manual cookie > auto cookie > null)
    let mut auth_cmd = if let Some(password) = config.get_control_password() {
        trace!(
            control_host = %control_host,
            control_port = control_port,
            "using password auth"
        );
        let mut password_owned = password.to_string();
        let cmd = format!("AUTHENTICATE \"{}\"\r\n", password_owned);
        password_owned.zeroize();
        cmd
    } else if let Some(cookie_hex) = config.get_control_cookie() {
        trace!(
            control_host = %control_host,
            control_port = control_port,
            "using manual cookie auth"
        );
        let mut cookie_owned = cookie_hex.to_string();
        let cmd = format!("AUTHENTICATE {}\r\n", cookie_owned);
        cookie_owned.zeroize();
        cmd
    } else {
        // Try to get cookie automatically
        match get_control_cookie(protocol_info).await {
            Ok(Some(cookie_hex)) => {
                trace!(
                    control_host = %control_host,
                    control_port = control_port,
                    "using automatic cookie auth"
                );
                let mut cookie_owned = cookie_hex;
                let cmd = format!("AUTHENTICATE {}\r\n", cookie_owned);
                cookie_owned.zeroize();
                cmd
            }
            Ok(None) => {
                trace!(
                    control_host = %control_host,
                    control_port = control_port,
                    "using null auth"
                );
                "AUTHENTICATE\r\n".to_string()
            }
            Err(e) => {
                trace!(
                    control_host = %control_host,
                    control_port = control_port,
                    error = %e,
                    "cookie read failed, trying null auth"
                );
                "AUTHENTICATE\r\n".to_string()
            }
        }
    };

    let auth_reply_result =
        send_control_command(stream, &auth_cmd, phase_timeout, control_host, control_port).await;
    auth_cmd.zeroize();
    let auth_reply = auth_reply_result?;

    if !auth_reply.iter().any(|line| line.starts_with(FINAL_OK)) {
        return Err(TorError::ControlPortAuthenticationFailed {
            host: control_host.to_string(),
            port: control_port,
            reason: auth_reply.join("; "),
        });
    }

    trace!(
        control_host = %control_host,
        control_port = control_port,
        elapsed_ms = start.elapsed().as_millis(),
        "authenticated"
    );

    Ok(())
}

/// Configure Tor settings via control port.
async fn configure_tor_settings(
    stream: &mut TcpStream,
    config: &TorConfig,
    phase_timeout: Duration,
) -> Result<(), TorError> {
    let start = Instant::now();
    let control_host = config.get_control_host();
    let control_port = config.get_control_port();

    trace!(
        control_host = %control_host,
        control_port = %control_port,
        "building configuration"
    );

    let mut setconf_args: Vec<String> = Vec::new();

    if let Some(nodes) = config.get_exit_nodes() {
        validate_node_spec(nodes, "ExitNodes")?;
        setconf_args.push(format!("ExitNodes={}", nodes));
    }

    if let Some(nodes) = config.get_exclude_exit_nodes() {
        validate_node_spec(nodes, "ExcludeExitNodes")?;
        setconf_args.push(format!("ExcludeExitNodes={}", nodes));
    }

    setconf_args.push(format!(
        "StrictNodes={}",
        if config.is_strict_nodes() { "1" } else { "0" }
    ));

    setconf_args.push(format!(
        "UseBridges={}",
        if config.is_use_bridges() { "1" } else { "0" }
    ));

    if let Some(bridges) = config.get_bridges() {
        validate_bridges(bridges)?;
        for line in bridges.lines().map(|l| l.trim()).filter(|l| !l.is_empty()) {
            setconf_args.push(format!("Bridge={}", line));
        }
    }

    if !setconf_args.is_empty() {
        let setconf_cmd = format!("SETCONF {}\r\n", setconf_args.join(" "));

        trace!(
            control_host = %control_host,
            control_port = control_port,
            args_count = setconf_args.len(),
            "sending SETCONF"
        );

        let reply = send_control_command(
            stream,
            &setconf_cmd,
            phase_timeout,
            control_host,
            control_port,
        )
        .await?;

        if !reply.iter().any(|line| line.starts_with(FINAL_OK)) {
            return Err(TorError::ConfigurationFailed {
                host: control_host.to_string(),
                port: control_port,
                command: "SETCONF".to_string(),
                reason: reply.join("; "),
            });
        }

        trace!(
            control_host = %control_host,
            control_port = control_port,
            elapsed_ms = start.elapsed().as_millis(),
            "configuration applied"
        );
    } else {
        trace!(
            control_host = %control_host,
            control_port = control_port,
            "no configuration to apply"
        );
    }

    Ok(())
}

/* Control Port Protocol */

/// Send a command to Tor control port and read reply.
async fn send_control_command(
    stream: &mut TcpStream,
    command: &str,
    phase_timeout: Duration,
    host: &str,
    port: u16,
) -> Result<Vec<String>, TorError> {
    let start = Instant::now();

    // Write command
    timeout(phase_timeout, stream.write_all(command.as_bytes()))
        .await
        .map_err(|_| TorError::ControlPortTimeout {
            host: host.to_string(),
            port,
            elapsed_ms: start.elapsed().as_millis() as u64,
            timeout_ms: phase_timeout.as_millis() as u64,
        })?
        .map_err(|source| TorError::Io {
            proxy_addr: format!("{}:{}", host, port),
            source,
        })?;

    // Read reply lines
    let mut lines = Vec::new();
    let mut current = Vec::new();

    loop {
        let mut byte = [0u8; 1];
        let n = timeout(phase_timeout, stream.read(&mut byte))
            .await
            .map_err(|_| TorError::ControlPortTimeout {
                host: host.to_string(),
                port,
                elapsed_ms: start.elapsed().as_millis() as u64,
                timeout_ms: phase_timeout.as_millis() as u64,
            })?
            .map_err(|source| TorError::Io {
                proxy_addr: format!("{}:{}", host, port),
                source,
            })?;

        if n == 0 {
            return Err(TorError::ControlPortConnectionClosed {
                host: host.to_string(),
                port,
            });
        }

        current.push(byte[0]);

        if byte[0] != b'\n' {
            continue;
        }

        // We have a full line
        let line = String::from_utf8_lossy(&current)
            .trim_end_matches(&['\r', '\n'][..])
            .to_string();
        current.clear();

        // Skip async events
        if line.starts_with(EVENT_PREFIX) {
            trace!(
                control_host = %host,
                control_port = port,
                event = %line,
                "skipping async event"
            );
            continue;
        }

        // Check for error
        if line.starts_with('5') {
            return Err(TorError::ControlPortCommandFailed {
                host: host.to_string(),
                port,
                command: command.trim().to_string(),
                reply: line,
            });
        }

        lines.push(line.clone());

        // Final line in reply: "250 " or "250 OK" (not "250-")
        if is_final_reply(&line) {
            break;
        }
    }

    Ok(lines)
}

/// Get control cookie from PROTOCOLINFO and filesystem.
async fn get_control_cookie(protocol_info: &[String]) -> Result<Option<String>, TorError> {
    // Parse cookie path from PROTOCOLINFO
    let cookie_path = match parse_cookie_path(protocol_info) {
        Some(path) => path,
        None => {
            trace!("no cookie path in PROTOCOLINFO");
            return Ok(None);
        }
    };

    trace!(
        cookie_path = %cookie_path,
        "reading cookie file"
    );

    // Read cookie file
    let mut bytes =
        fs::read(&cookie_path)
            .await
            .map_err(|source| TorError::ControlPortCookieReadFailed {
                path: cookie_path.clone(),
                source,
            })?;

    // Convert to hex
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &b in &bytes {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{:02X}", b);
    }
    bytes.zeroize();

    trace!(
        cookie_path = %cookie_path,
        cookie_len = hex.len(),
        "cookie read"
    );

    Ok(Some(hex))
}

/* Helper Functions */

/// Parse cookie file path from PROTOCOLINFO output.
fn parse_cookie_path(protocol_info: &[String]) -> Option<String> {
    for line in protocol_info {
        if let Some(pos) = line.find("COOKIEFILE=\"") {
            let start = pos + "COOKIEFILE=\"".len();
            if let Some(rest) = line.get(start..)
                && let Some(end) = rest.find('"')
            {
                return Some(rest[..end].to_string());
            }
        }
    }
    None
}

/// Check if a control reply line is final.
fn is_final_reply(line: &str) -> bool {
    line.starts_with(FINAL_OK) && !line.starts_with("250-")
}

/// Validate node specification (basic format check).
fn validate_node_spec(spec: &str, field_name: &str) -> Result<(), TorError> {
    if spec.is_empty() {
        return Err(TorError::InvalidExitNodes {
            value: spec.to_string(),
            reason: format!("{} cannot be empty", field_name),
        });
    }

    // Basic validation: should contain only alphanumeric, {}, commas, $, ~
    // This catches obvious errors without trying to validate every Tor node format
    for ch in spec.chars() {
        if !ch.is_alphanumeric() && ch != '{' && ch != '}' && ch != ',' && ch != '$' && ch != '~' {
            return Err(TorError::InvalidExitNodes {
                value: spec.to_string(),
                reason: format!(
                    "{} contains invalid character '{}' (allowed: alphanumeric, {{, }}, comma, $, ~)",
                    field_name, ch
                ),
            });
        }
    }

    Ok(())
}

/// Validate bridge configuration (basic format check).
fn validate_bridges(bridges: &str) -> Result<(), TorError> {
    if bridges.trim().is_empty() {
        return Err(TorError::InvalidBridgeConfiguration {
            reason: "bridge configuration cannot be empty".to_string(),
        });
    }

    // Just check that each line is non-empty when trimmed
    // Tor will do the actual validation
    for line in bridges.lines() {
        if !line.trim().is_empty() && line.trim().len() < 3 {
            return Err(TorError::InvalidBridgeConfiguration {
                reason: format!("bridge line too short: '{}'", line.trim()),
            });
        }
    }

    Ok(())
}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cookie_path_extracts_path() {
        let protocol_info = vec![
            "250-PROTOCOLINFO 1".to_string(),
            "250-AUTH METHODS=COOKIE COOKIEFILE=\"/var/lib/tor/control_auth_cookie\"".to_string(),
            "250 OK".to_string(),
        ];

        let path = parse_cookie_path(&protocol_info).unwrap();
        assert_eq!(path, "/var/lib/tor/control_auth_cookie");
    }

    #[test]
    fn parse_cookie_path_returns_none_when_missing() {
        let protocol_info = vec![
            "250-PROTOCOLINFO 1".to_string(),
            "250-AUTH METHODS=SAFECOOKIE".to_string(),
            "250 OK".to_string(),
        ];

        assert!(parse_cookie_path(&protocol_info).is_none());
    }

    #[test]
    fn is_final_reply_detects_final() {
        assert!(is_final_reply("250 OK"));
        assert!(is_final_reply("250 circuit-established=1"));
        assert!(!is_final_reply("250-AUTH METHODS=COOKIE"));
        assert!(!is_final_reply("650 STATUS_CLIENT"));
    }

    #[test]
    fn validate_node_spec_accepts_valid() {
        assert!(validate_node_spec("{us}", "ExitNodes").is_ok());
        assert!(validate_node_spec("{us},{uk},{ca}", "ExitNodes").is_ok());
        assert!(validate_node_spec("$FINGERPRINT", "ExitNodes").is_ok());
        assert!(validate_node_spec("{us},$FINGERPRINT", "ExitNodes").is_ok());
    }

    #[test]
    fn validate_node_spec_rejects_invalid() {
        assert!(validate_node_spec("", "ExitNodes").is_err());
        assert!(validate_node_spec("{us};{uk}", "ExitNodes").is_err()); // semicolon not allowed
        assert!(validate_node_spec("{us} {uk}", "ExitNodes").is_err()); // space not allowed
    }

    #[test]
    fn validate_bridges_accepts_valid() {
        assert!(validate_bridges("bridge1:443").is_ok());
        assert!(validate_bridges("bridge1:443\nbridge2:443").is_ok());
        assert!(validate_bridges("obfs4 bridge:443 fingerprint").is_ok());
    }

    #[test]
    fn validate_bridges_rejects_invalid() {
        assert!(validate_bridges("").is_err());
        assert!(validate_bridges("   ").is_err());
        assert!(validate_bridges("x").is_err()); // too short
    }
}
