//! JSON export utilities for proxy configurations.
//!
//! This module provides functionality to convert [`Proxy`] enum variants into their
//! corresponding JSON representations as defined in [`json_structure`]. The export
//! architecture mirrors the connection dispatch pattern found in `proxy.rs`, where
//! a top-level arbitrator delegates to protocol-specific implementation functions.
//!
//! # Architecture
//!
//! The export system follows a three-tier architecture:
//!
//! 1. **Collection Export** ([`export_proxies_to_json`]): Writes multiple proxies to disk
//! 2. **Single Proxy Dispatch** ([`proxy_to_json`]): Routes to protocol-specific converters
//! 3. **Protocol Converters** ([`export_http`], [`export_socks5`], etc.): Build typed JSON structures
//!
//! This design ensures:
//! - Type safety through `ProxyJson` enum variants
//! - Clean separation of concerns
//! - Easy extensibility for new protocols
//! - Consistent error handling
//!
//! # Output Format
//!
//! The exported JSON groups proxies by their base configuration to reduce duplication
//! and enable efficient Arc-based config sharing:
//!
//! ```json
//! {
//!   "configs": [
//!     {
//!       "base": {
//!         "handshake_timeout": 10,
//!         "phase_timeout": 5,
//!         "resolve_locally": false,
//!         "tcp_nodelay": true,
//!         "keep_alive": 60,
//!         "auto_tls": true
//!       },
//!       "proxies": [
//!         {
//!           "protocol": "http",
//!           "host": "proxy.example.com",
//!           "port": 8080,
//!           "username": "user",
//!           "password": "pass"
//!         }
//!       ]
//!     }
//!   ]
//! }
//! ```
//!
//! # Examples
//!
//! ## Export a Proxy List
//!
//! ```no_run
//! use roxie::transport::ProxyList;
//! use std::path::Path;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let list = ProxyList::from_lines("http://proxy.com:8080")?;
//! list.export_json(Path::new("proxies.json")).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Convert Individual Proxy
//!
//! ```no_run
//! use roxie::transport::Proxy;
//! use roxie::config::HTTPConfig;
//! use roxie::utils::json_export::proxy_to_json;
//! use std::sync::Arc;
//!
//! let proxy = Proxy::HTTP {
//!     host: "proxy.com".to_string(),
//!     port: 8080,
//!     config: Arc::new(HTTPConfig::new("proxy.com", 8080)),
//! };
//!
//! let json = proxy_to_json(&proxy);
//! println!("{}", serde_json::to_string_pretty(&json).unwrap());
//! ```
//!
//! # Feature Flags
//!
//! Export functions are conditionally compiled based on cargo features:
//! - `http` - HTTP/HTTPS proxy export
//! - `socks4` - SOCKS4/SOCKS4A proxy export
//! - `socks5` - SOCKS5/SOCKS5H proxy export
//! - `tor` - Tor proxy export
//! - `shadowsocks` - Shadowsocks proxy export

use std::path::Path;
use std::sync::Arc;

use serde_json::Value;
use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::config::*;
use crate::errors::ProxyError;
use crate::transport::Proxy;
use crate::utils::json_structure::*;

/* Public API */

/// Exports a collection of proxies to a JSON file.
///
/// This function groups proxies by their base configuration to reduce duplication
/// and enable efficient Arc-based config sharing at parse time. Proxies with matching
/// base configurations are grouped together in the output.
///
/// # Format
///
/// The resulting JSON file groups proxies by their base configuration:
///
/// ```json
/// {
///   "configs": [
///     {
///       "base": { "handshake_timeout": 10, ... },
///       "proxies": [
///         { "protocol": "http", "host": "...", ... },
///         { "protocol": "socks5", "host": "...", ... }
///       ]
///     }
///   ]
/// }
/// ```
///
/// Each proxy is serialized according to its protocol-specific schema as defined
/// in [`json_structure`], with the base configuration extracted and deduplicated.
///
/// # Arguments
///
/// * `proxies` - Iterator over proxy references to serialize
/// * `output_path` - Filesystem path where the JSON file will be written
///
/// # Errors
///
/// Returns [`ProxyError::SerializationError`] if JSON serialization fails.
/// Returns [`ProxyError::IoError`] if file writing fails.
///
/// # Examples
///
/// ```no_run
/// use roxie::transport::Proxy;
/// use roxie::config::HTTPConfig;
/// use roxie::utils::json_export::export_proxies_to_json;
/// use std::path::Path;
/// use std::sync::Arc;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let proxies = vec![
///     Proxy::HTTP {
///         host: "proxy1.com".to_string(),
///         port: 8080,
///         config: Arc::new(HTTPConfig::new("proxy1.com", 8080)),
///     },
///     Proxy::HTTP {
///         host: "proxy2.com".to_string(),
///         port: 8081,
///         config: Arc::new(HTTPConfig::new("proxy2.com", 8081)),
///     },
/// ];
///
/// export_proxies_to_json(proxies.iter(), Path::new("proxies.json")).await?;
/// # Ok(())
/// # }
/// ```
pub async fn export_proxies_to_json<'a, I>(proxies: I, output_path: &Path) -> Result<(), ProxyError>
where
    I: Iterator<Item = &'a Proxy>,
{
    // Group proxies by their base configuration
    let mut groups: Vec<ProxyGroupJson> = Vec::new();

    for proxy in proxies {
        let base_config = extract_base_config_from_proxy(proxy);
        let mut proxy_json = proxy_to_json(proxy);

        // The grouped output supplies base config at the group level, so strip any per-proxy base.
        if let Some(obj) = proxy_json.as_object_mut() {
            obj.remove("base");
        }

        // Find existing group with matching base config
        let found_group = groups
            .iter_mut()
            .find(|group| base_configs_match(&group.base, &base_config));

        match found_group {
            Some(group) => {
                // Add to existing group
                group.add_proxy(
                    serde_json::from_value(proxy_json)
                        .expect("ProxyJson deserialization should not fail"),
                );
            }
            None => {
                // Create new group
                let mut new_group = ProxyGroupJson::new(base_config);
                new_group.add_proxy(
                    serde_json::from_value(proxy_json)
                        .expect("ProxyJson deserialization should not fail"),
                );
                groups.push(new_group);
            }
        }
    }

    // Build root structure
    let root = ProxyListJson { configs: groups };

    // Serialize with pretty formatting for human readability
    let json_string =
        serde_json::to_string_pretty(&root).map_err(|e| ProxyError::SerializationError {
            message: e.to_string(),
        })?;

    // Write to filesystem asynchronously
    let mut file = fs::File::create(output_path)
        .await
        .map_err(|e| ProxyError::IoError { source: e })?;

    file.write_all(json_string.as_bytes())
        .await
        .map_err(|e| ProxyError::IoError { source: e })?;

    Ok(())
}

/// Converts a single [`Proxy`] to its JSON representation.
///
/// This function serves as the dispatch arbitrator, routing each proxy variant
/// to its protocol-specific conversion function. The architecture mirrors
/// [`Proxy::connect`] from `proxy.rs`, providing a consistent pattern across
/// the codebase.
///
/// # Type Safety
///
/// The function returns a [`Value`] rather than [`ProxyJson`] to allow for
/// graceful handling of unsupported protocols. In practice, all active protocols
/// produce valid [`ProxyJson`] variants which are then serialized.
///
/// # Feature Gates
///
/// Protocol-specific branches are conditionally compiled based on cargo features.
/// Disabled protocols fall through to a minimal JSON representation.
///
/// # Examples
///
/// ```no_run
/// use roxie::transport::Proxy;
/// use roxie::config::SOCKS5Config;
/// use roxie::utils::json_export::proxy_to_json;
/// use std::sync::Arc;
///
/// let proxy = Proxy::SOCKS5 {
///     host: "localhost".to_string(),
///     port: 1080,
///     config: Arc::new(SOCKS5Config::new("localhost", 1080)),
/// };
///
/// let json = proxy_to_json(&proxy);
/// assert_eq!(json.get("protocol").and_then(|v| v.as_str()), Some("socks5"));
/// ```
pub fn proxy_to_json(proxy: &Proxy) -> Value {
    // Dispatch to protocol-specific export function based on variant
    let proxy_json = match proxy {
        #[cfg(feature = "http")]
        Proxy::HTTP { host, port, config } => export_http(host, *port, config),

        #[cfg(feature = "http")]
        Proxy::HTTPS { host, port, config } => export_https(host, *port, config),

        #[cfg(feature = "socks4")]
        Proxy::SOCKS4 { host, port, config } => export_socks4(host, *port, config),

        #[cfg(feature = "socks4")]
        Proxy::SOCKS4A { host, port, config } => export_socks4a(host, *port, config),

        #[cfg(feature = "socks5")]
        Proxy::SOCKS5 { host, port, config } => export_socks5(host, *port, config),

        #[cfg(feature = "socks5")]
        Proxy::SOCKS5H { host, port, config } => export_socks5h(host, *port, config),

        #[cfg(feature = "tor")]
        Proxy::Tor { host, port, config } => export_tor(host, *port, config),

        #[cfg(feature = "shadowsocks")]
        Proxy::Shadowsocks {
            host,
            port,
            password,
            config,
        } => export_shadowsocks(host, *port, password, config),

        // Fallback for protocols disabled by feature flags
        #[allow(unreachable_patterns)]
        _ => ProxyJson::Http(HttpProxyJson {
            host: proxy.get_host().to_string(),
            port: proxy.get_port(),
            username: None,
            password: None,
            base: None,
        }),
    };

    // Serialize the ProxyJson enum to a JSON Value
    // The #[serde(tag = "protocol")] attribute on ProxyJson automatically
    // adds the correct protocol discriminator field during serialization
    serde_json::to_value(&proxy_json).expect("ProxyJson serialization should not fail")
}

/* Protocol-Specific Export Functions */

/// Exports an HTTP proxy to its JSON representation.
///
/// Constructs an [`HttpProxyJson`] structure containing the proxy's connection
/// parameters, optional authentication credentials, and base configuration settings.
///
/// # Arguments
///
/// * `host` - Proxy server hostname or IP address
/// * `port` - Proxy server port number
/// * `config` - HTTP proxy configuration containing credentials and base settings
///
/// # Returns
///
/// A [`ProxyJson::Http`] variant ready for serialization.
#[cfg(feature = "http")]
fn export_http(host: &str, port: u16, config: &Arc<HTTPConfig>) -> ProxyJson {
    let base = config.get_base_config();

    ProxyJson::Http(HttpProxyJson {
        host: host.to_string(),
        port,
        username: config.get_username().map(String::from),
        password: config.get_password().map(String::from),
        base: Some(export_base_config(base)),
    })
}

/// Exports an HTTPS proxy to its JSON representation.
///
/// Identical to [`export_http`] but produces an [`HttpsProxyJson`] structure
/// to distinguish HTTPS proxies in the serialized output.
///
/// # Arguments
///
/// * `host` - Proxy server hostname or IP address
/// * `port` - Proxy server port number
/// * `config` - HTTPS proxy configuration containing credentials and base settings
///
/// # Returns
///
/// A [`ProxyJson::Https`] variant ready for serialization.
#[cfg(feature = "http")]
fn export_https(host: &str, port: u16, config: &Arc<HTTPConfig>) -> ProxyJson {
    let base = config.get_base_config();

    ProxyJson::Https(HttpsProxyJson {
        host: host.to_string(),
        port,
        username: config.get_username().map(String::from),
        password: config.get_password().map(String::from),
        base: Some(export_base_config(base)),
    })
}

/// Exports a SOCKS4 proxy to its JSON representation.
///
/// Constructs a [`Socks4ProxyJson`] structure containing the proxy's connection
/// parameters, optional user ID, and base configuration settings.
///
/// # Arguments
///
/// * `host` - Proxy server hostname or IP address
/// * `port` - Proxy server port number
/// * `config` - SOCKS4 proxy configuration containing user ID and base settings
///
/// # Returns
///
/// A [`ProxyJson::Socks4`] variant ready for serialization.
#[cfg(feature = "socks4")]
fn export_socks4(host: &str, port: u16, config: &Arc<SOCKS4Config>) -> ProxyJson {
    let base = config.get_base_config();

    ProxyJson::Socks4(Socks4ProxyJson {
        host: host.to_string(),
        port,
        user_id: config.get_user_id().map(String::from),
        base: Some(export_base_config(base)),
    })
}

/// Exports a SOCKS4A proxy to its JSON representation.
///
/// SOCKS4A extends SOCKS4 with remote DNS resolution capability. This function
/// produces a [`Socks4aProxyJson`] structure to distinguish the variant.
///
/// # Arguments
///
/// * `host` - Proxy server hostname or IP address
/// * `port` - Proxy server port number
/// * `config` - SOCKS4A proxy configuration containing user ID and base settings
///
/// # Returns
///
/// A [`ProxyJson::Socks4a`] variant ready for serialization.
#[cfg(feature = "socks4")]
fn export_socks4a(host: &str, port: u16, config: &Arc<SOCKS4Config>) -> ProxyJson {
    let base = config.get_base_config();

    ProxyJson::Socks4a(Socks4aProxyJson {
        host: host.to_string(),
        port,
        user_id: config.get_user_id().map(String::from),
        base: Some(export_base_config(base)),
    })
}

/// Exports a SOCKS5 proxy to its JSON representation.
///
/// Constructs a [`Socks5ProxyJson`] structure containing the proxy's connection
/// parameters, optional authentication credentials, and base configuration settings.
///
/// # Arguments
///
/// * `host` - Proxy server hostname or IP address
/// * `port` - Proxy server port number
/// * `config` - SOCKS5 proxy configuration containing credentials and base settings
///
/// # Returns
///
/// A [`ProxyJson::Socks5`] variant ready for serialization.
#[cfg(feature = "socks5")]
fn export_socks5(host: &str, port: u16, config: &Arc<SOCKS5Config>) -> ProxyJson {
    let base = config.get_base_config();

    ProxyJson::Socks5(Socks5ProxyJson {
        host: host.to_string(),
        port,
        username: config.get_username().map(String::from),
        password: config.get_password().map(String::from),
        base: Some(export_base_config(base)),
    })
}

/// Exports a SOCKS5H proxy to its JSON representation.
///
/// SOCKS5H forces remote DNS resolution for all hostnames. This function
/// produces a [`Socks5hProxyJson`] structure to distinguish the variant.
///
/// # Arguments
///
/// * `host` - Proxy server hostname or IP address
/// * `port` - Proxy server port number
/// * `config` - SOCKS5H proxy configuration containing credentials and base settings
///
/// # Returns
///
/// A [`ProxyJson::Socks5h`] variant ready for serialization.
#[cfg(feature = "socks5")]
fn export_socks5h(host: &str, port: u16, config: &Arc<SOCKS5Config>) -> ProxyJson {
    let base = config.get_base_config();

    ProxyJson::Socks5h(Socks5hProxyJson {
        host: host.to_string(),
        port,
        username: config.get_username().map(String::from),
        password: config.get_password().map(String::from),
        base: Some(export_base_config(base)),
    })
}

/// Exports a Tor proxy to its JSON representation.
///
/// Constructs a [`TorProxyJson`] structure containing the proxy's SOCKS connection
/// parameters, base configuration settings, and Tor-specific control port configuration.
///
/// # Arguments
///
/// * `host` - Tor SOCKS proxy hostname or IP address
/// * `port` - Tor SOCKS proxy port number
/// * `config` - Tor proxy configuration containing control port settings
///
/// # Returns
///
/// A [`ProxyJson::Tor`] variant ready for serialization.
#[cfg(feature = "tor")]
fn export_tor(host: &str, port: u16, config: &Arc<TorConfig>) -> ProxyJson {
    let base = config.get_base_config();

    ProxyJson::Tor(TorProxyJson {
        host: host.to_string(),
        port,
        base: Some(export_base_config(base)),
        config: Some(export_tor_config(config)),
    })
}

/// Exports a Shadowsocks proxy to its JSON representation.
///
/// Constructs a [`ShadowsocksProxyJson`] structure containing the proxy's connection
/// parameters, encryption password, base configuration settings, and Shadowsocks-specific
/// cipher and plugin configuration.
///
/// # Arguments
///
/// * `host` - Shadowsocks server hostname or IP address
/// * `port` - Shadowsocks server port number
/// * `password` - Encryption password for the Shadowsocks connection
/// * `config` - Shadowsocks configuration containing cipher method and plugin settings
///
/// # Returns
///
/// A [`ProxyJson::Shadowsocks`] variant ready for serialization.
#[cfg(feature = "shadowsocks")]
fn export_shadowsocks(
    host: &str,
    port: u16,
    password: &str,
    config: &Arc<ShadowsocksConfig>,
) -> ProxyJson {
    let base = config.get_base_config();

    ProxyJson::Shadowsocks(ShadowsocksProxyJson {
        host: host.to_string(),
        port,
        password: password.to_string(),
        base: Some(export_base_config(base)),
        config: Some(export_shadowsocks_config(config)),
    })
}

/* Configuration Export Helpers */

/* Helper Functions */

/// Extracts the base configuration from a proxy.
///
/// This function retrieves the base proxy configuration from any proxy variant,
/// allowing for comparison and grouping of proxies with matching configurations.
///
/// # Arguments
///
/// * `proxy` - Reference to a proxy from which to extract the base configuration
///
/// # Returns
///
/// A [`ProxyConfigJson`] representing the proxy's base configuration.
fn extract_base_config_from_proxy(proxy: &Proxy) -> ProxyConfigJson {
    let base = match proxy {
        #[cfg(feature = "http")]
        Proxy::HTTP { config, .. } => config.get_base_config(),

        #[cfg(feature = "http")]
        Proxy::HTTPS { config, .. } => config.get_base_config(),

        #[cfg(feature = "socks4")]
        Proxy::SOCKS4 { config, .. } => config.get_base_config(),

        #[cfg(feature = "socks4")]
        Proxy::SOCKS4A { config, .. } => config.get_base_config(),

        #[cfg(feature = "socks5")]
        Proxy::SOCKS5 { config, .. } => config.get_base_config(),

        #[cfg(feature = "socks5")]
        Proxy::SOCKS5H { config, .. } => config.get_base_config(),

        #[cfg(feature = "tor")]
        Proxy::Tor { config, .. } => config.get_base_config(),

        #[cfg(feature = "shadowsocks")]
        Proxy::Shadowsocks { config, .. } => config.get_base_config(),

        #[allow(unreachable_patterns)]
        _ => &BaseProxyConfig::new(),
    };

    export_base_config(base)
}

/// Compares two base configurations for equality.
///
/// Determines if two [`ProxyConfigJson`] instances represent the same configuration,
/// enabling grouping of proxies that share identical base settings.
///
/// # Arguments
///
/// * `a` - First base configuration to compare
/// * `b` - Second base configuration to compare
///
/// # Returns
///
/// `true` if all configuration fields match, `false` otherwise.
fn base_configs_match(a: &ProxyConfigJson, b: &ProxyConfigJson) -> bool {
    a.handshake_timeout == b.handshake_timeout
        && a.phase_timeout == b.phase_timeout
        && a.resolve_locally == b.resolve_locally
        && a.tcp_nodelay == b.tcp_nodelay
        && a.keep_alive == b.keep_alive
        && a.auto_tls == b.auto_tls
        && tls_configs_match(&a.tls_config, &b.tls_config)
}

/// Compares two optional TLS configurations for equality.
///
/// Helper function for [`base_configs_match`] that handles the comparison
/// of optional TLS configuration fields.
///
/// # Arguments
///
/// * `a` - First optional TLS configuration
/// * `b` - Second optional TLS configuration
///
/// # Returns
///
/// `true` if both configurations match (including both being `None`), `false` otherwise.
fn tls_configs_match(a: &Option<TLSConfigJson>, b: &Option<TLSConfigJson>) -> bool {
    match (a, b) {
        (None, None) => true,
        (
            Some(TLSConfigJson::Default { alpn: a_alpn }),
            Some(TLSConfigJson::Default { alpn: b_alpn }),
        ) => a_alpn == b_alpn,
        (
            Some(TLSConfigJson::DangerAcceptInvalidCerts),
            Some(TLSConfigJson::DangerAcceptInvalidCerts),
        ) => true,
        _ => false,
    }
}

/// Converts [`BaseProxyConfig`] to its JSON representation.
///
/// Extracts all base configuration parameters including timeouts, TCP settings,
/// TLS configuration, and DNS resolution preferences into a [`ProxyConfigJson`]
/// structure suitable for serialization.
///
/// # Arguments
///
/// * `base` - Base proxy configuration containing common settings
///
/// # Returns
///
/// A [`ProxyConfigJson`] structure with all configuration parameters extracted.
///
/// # Notes
///
/// All duration values are converted to seconds for JSON serialization.
/// Optional fields are preserved as `Option<T>` to allow selective configuration.
fn export_base_config(base: &BaseProxyConfig) -> ProxyConfigJson {
    ProxyConfigJson {
        handshake_timeout: Some(base.get_handshake_timeout().as_secs()),
        phase_timeout: Some(base.get_phase_timeout().as_secs()),
        resolve_locally: Some(base.is_resolve_locally()),
        tcp_nodelay: Some(base.is_tcp_nodelay()),
        keep_alive: base.get_keep_alive().map(|d| d.as_secs()),
        auto_tls: Some(base.is_auto_tls()),
        tls_config: base.get_tls_config().map(export_tls_config),
    }
}

/// Converts [`TLSConfig`] to its JSON representation.
///
/// Maps the TLS configuration enum to its corresponding [`TLSConfigJson`] variant,
/// preserving ALPN protocol lists and certificate validation settings.
///
/// # Arguments
///
/// * `tls` - TLS configuration enum variant
///
/// # Returns
///
/// A [`TLSConfigJson`] variant matching the input configuration.
///
/// # Variants
///
/// - [`TLSConfig::Default`] → [`TLSConfigJson::Default`] with ALPN protocols
/// - [`TLSConfig::DangerAcceptInvalidCerts`] → [`TLSConfigJson::DangerAcceptInvalidCerts`]
fn export_tls_config(tls: &TLSConfig) -> TLSConfigJson {
    if tls.is_danger_accept_invalid_certs() {
        TLSConfigJson::DangerAcceptInvalidCerts
    } else {
        TLSConfigJson::Default {
            alpn: tls.get_alpn().as_ref().map(|protocols| {
                protocols
                    .iter()
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .collect::<Vec<String>>()
            }),
        }
    }
}

/// Converts [`ShadowsocksConfig`] to its JSON representation.
///
/// Extracts Shadowsocks-specific configuration including encryption method,
/// obfuscation plugin settings, connection timeout, and protocol features
/// into a [`ShadowsocksConfigJson`] structure.
///
/// # Arguments
///
/// * `config` - Shadowsocks configuration containing cipher and plugin settings
///
/// # Returns
///
/// A [`ShadowsocksConfigJson`] structure with all Shadowsocks parameters extracted.
///
/// # Notes
///
/// The connection timeout is converted from [`Duration`] to seconds.
#[cfg(feature = "shadowsocks")]
fn export_shadowsocks_config(config: &Arc<ShadowsocksConfig>) -> ShadowsocksConfigJson {
    ShadowsocksConfigJson {
        method: config.get_method().to_string(),
        plugin: config.get_plugin().map(String::from),
        plugin_opts: config.get_plugin_opts().map(String::from),
        connection_timeout: Some(config.get_connection_timeout().as_secs()),
        udp_relay: Some(config.is_udp_relay()),
        tcp_fast_open: Some(config.is_tcp_fast_open()),
    }
}

/// Converts [`TorConfig`] to its JSON representation.
///
/// Extracts Tor-specific configuration including control port settings,
/// exit node selection, bridge relay configuration, and authentication
/// into a [`TorConfigJson`] structure.
///
/// # Arguments
///
/// * `config` - Tor configuration containing control port and circuit settings
///
/// # Returns
///
/// A [`TorConfigJson`] structure with all Tor parameters extracted.
///
/// # Notes
///
/// The control port configuration is separate from the SOCKS port configuration
/// and is used for circuit management and Tor daemon control.
#[cfg(feature = "tor")]
fn export_tor_config(config: &Arc<TorConfig>) -> TorConfigJson {
    TorConfigJson {
        control_host: config.get_control_host().to_string(),
        control_port: config.get_control_port(),
        control_password: config.get_control_password().map(String::from),
        exit_nodes: config.get_exit_nodes().map(String::from),
        exclude_exit_nodes: config.get_exclude_exit_nodes().map(String::from),
        strict_nodes: Some(config.is_strict_nodes()),
        use_bridges: Some(config.is_use_bridges()),
        bridges: config.get_bridges().map(String::from),
    }
}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Tests HTTP proxy export to JSON, verifying all fields are correctly serialized.
    #[cfg(feature = "http")]
    #[test]
    fn export_http_proxy_to_json() {
        let config = Arc::new(
            HTTPConfig::new("proxy.com", 8080)
                .set_username("user")
                .set_password("pass"),
        );

        let proxy = Proxy::HTTP {
            host: "proxy.com".to_string(),
            port: 8080,
            config,
        };

        let json = proxy_to_json(&proxy);

        // Verify protocol discriminator
        assert_eq!(json.get("protocol").and_then(|v| v.as_str()), Some("http"));

        // Verify connection parameters
        assert_eq!(json.get("host").and_then(|v| v.as_str()), Some("proxy.com"));
        assert_eq!(json.get("port").and_then(|v| v.as_u64()), Some(8080));

        // Verify authentication credentials
        assert_eq!(json.get("username").and_then(|v| v.as_str()), Some("user"));
        assert_eq!(json.get("password").and_then(|v| v.as_str()), Some("pass"));

        // Verify base configuration exists
        assert!(json.get("base").is_some());
    }

    /// Tests SOCKS5 proxy export to JSON, verifying protocol-specific fields.
    #[cfg(feature = "socks5")]
    #[test]
    fn export_socks5_proxy_to_json() {
        let config = Arc::new(
            SOCKS5Config::new("localhost", 1080)
                .set_username("user")
                .set_password("pass"),
        );

        let proxy = Proxy::SOCKS5 {
            host: "localhost".to_string(),
            port: 1080,
            config,
        };

        let json = proxy_to_json(&proxy);

        // Verify protocol discriminator
        assert_eq!(
            json.get("protocol").and_then(|v| v.as_str()),
            Some("socks5")
        );

        // Verify connection parameters
        assert_eq!(json.get("host").and_then(|v| v.as_str()), Some("localhost"));
        assert_eq!(json.get("port").and_then(|v| v.as_u64()), Some(1080));
    }

    /// Tests exporting multiple proxies to a file and verifies the output structure.
    #[cfg(feature = "http")]
    #[tokio::test]
    async fn export_proxies_to_file() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("proxies.json");

        // Create test proxy collection
        let proxies = vec![
            Proxy::HTTP {
                host: "proxy1.com".to_string(),
                port: 8080,
                config: Arc::new(HTTPConfig::new("proxy1.com", 8080)),
            },
            Proxy::HTTP {
                host: "proxy2.com".to_string(),
                port: 8081,
                config: Arc::new(HTTPConfig::new("proxy2.com", 8081)),
            },
        ];

        // Export to file
        export_proxies_to_json(proxies.iter(), &output_path)
            .await
            .unwrap();

        // Verify file exists
        assert!(output_path.exists());

        // Verify file content is valid JSON
        let content = fs::read_to_string(&output_path).await.unwrap();
        let parsed: Value = serde_json::from_str(&content).unwrap();

        // Verify grouped root structure
        let configs = parsed
            .get("configs")
            .and_then(|v| v.as_array())
            .expect("configs array missing");
        assert_eq!(configs.len(), 1, "proxies with same base should group");
        assert!(configs[0].get("base").is_some());

        // Verify proxy count within the group
        let proxies = configs[0]
            .get("proxies")
            .and_then(|v| v.as_array())
            .expect("proxies array missing");
        assert_eq!(proxies.len(), 2);

        // Proxies should not duplicate the base config; it is supplied by the group.
        assert!(proxies.iter().all(|p| !p.get("base").is_some()));
    }

    /// Tests that base configuration is correctly exported with all fields.
    #[cfg(feature = "http")]
    #[test]
    fn export_base_config_includes_all_fields() {
        use std::time::Duration;

        let mut base = BaseProxyConfig::new();
        base.set_handshake_timeout(Duration::from_secs(15));
        base.set_phase_timeout(Duration::from_secs(10));
        base.set_tcp_nodelay(true);
        base.set_auto_tls(true);

        let json = export_base_config(&base);

        // Verify all timeout values
        assert_eq!(json.handshake_timeout, Some(15));
        assert_eq!(json.phase_timeout, Some(10));

        // Verify TCP settings
        assert_eq!(json.tcp_nodelay, Some(true));

        // Verify TLS setting
        assert_eq!(json.auto_tls, Some(true));
    }
}
