//! Proxy URL and JSON parsing utilities.
//!
//! Provides functions to parse proxy configurations from URLs and JSON,
//! converting them into strongly-typed Proxy enum variants.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tracing::warn;
use url::Url;

use crate::config::*;
use crate::errors::ParseError;
use crate::transport::Proxy;

/* Constants */

const DEFAULT_HTTP_PORT: u16 = 8080;
const DEFAULT_HTTPS_PORT: u16 = 8443;
const DEFAULT_SOCKS4_PORT: u16 = 1080;
const DEFAULT_SOCKS5_PORT: u16 = 1080;
const DEFAULT_TOR_PORT: u16 = 9050;
const DEFAULT_SHADOWSOCKS_PORT: u16 = 8388;

/* URL Parsing */

/// Parse a proxy URL into a Proxy enum variant.
///
/// Supported schemes: http, https, socks4, socks4a, socks5, socks5h, tor, shadowsocks (ss)
///
/// # Examples
///
/// ```
/// use roxie::utils::parse_proxy_url;
///
/// let proxy = parse_proxy_url("http://user:pass@proxy.com:8080")?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn parse_proxy_url(url_str: &str) -> Result<Option<Proxy>, ParseError> {
    let url = Url::parse(url_str).map_err(|e| ParseError::InvalidUrl {
        url: url_str.to_string(),
        reason: e.to_string(),
    })?;

    let scheme = url.scheme();
    let host = url
        .host_str()
        .ok_or_else(|| ParseError::MissingHost {
            url: url_str.to_string(),
        })?
        .to_string();

    let port = url
        .port()
        .unwrap_or_else(|| default_port_for_scheme(scheme));

    let username = if url.username().is_empty() {
        None
    } else {
        Some(url.username().to_string())
    };

    let password = url.password().map(|s| s.to_string());

    match scheme {
        #[cfg(feature = "http")]
        "http" => {
            let mut config = HTTPConfig::new(host.clone(), port);
            if let (Some(u), Some(p)) = (username.as_deref(), password.as_deref()) {
                config = config.set_credentials(u, p);
            } else if let Some(u) = username.as_deref() {
                config = config.set_username(u);
            } else if let Some(p) = password.as_deref() {
                config = config.set_password(p);
            }
            Ok(Some(Proxy::HTTP {
                host,
                port,
                config: Arc::new(config),
            }))
        }

        #[cfg(feature = "http")]
        "https" => {
            let mut config = HTTPConfig::new(host.clone(), port);
            if let (Some(u), Some(p)) = (username.as_deref(), password.as_deref()) {
                config = config.set_credentials(u, p);
            } else if let Some(u) = username.as_deref() {
                config = config.set_username(u);
            } else if let Some(p) = password.as_deref() {
                config = config.set_password(p);
            }
            Ok(Some(Proxy::HTTPS {
                host,
                port,
                config: Arc::new(config),
            }))
        }

        #[cfg(feature = "socks4")]
        "socks4" => {
            let mut config = SOCKS4Config::new(host.clone(), port);
            if let Some(u) = username.as_deref() {
                config = config.set_user_id(u);
            }
            Ok(Some(Proxy::SOCKS4 {
                host,
                port,
                config: Arc::new(config),
            }))
        }

        #[cfg(feature = "socks4")]
        "socks4a" => {
            let mut config = SOCKS4Config::new(host.clone(), port);
            if let Some(u) = username.as_deref() {
                config = config.set_user_id(u);
            }
            Ok(Some(Proxy::SOCKS4A {
                host,
                port,
                config: Arc::new(config),
            }))
        }

        #[cfg(feature = "socks5")]
        "socks5" => {
            let mut config = SOCKS5Config::new(host.clone(), port);
            if let (Some(u), Some(p)) = (username.as_deref(), password.as_deref()) {
                config = config.set_credentials(u, p);
            } else if let Some(u) = username.as_deref() {
                config = config.set_username(u);
            } else if let Some(p) = password.as_deref() {
                config = config.set_password(p);
            }
            Ok(Some(Proxy::SOCKS5 {
                host,
                port,
                config: Arc::new(config),
            }))
        }

        #[cfg(feature = "socks5")]
        "socks5h" => {
            let mut config = SOCKS5Config::new(host.clone(), port);
            if let (Some(u), Some(p)) = (username.as_deref(), password.as_deref()) {
                config = config.set_credentials(u, p);
            } else if let Some(u) = username.as_deref() {
                config = config.set_username(u);
            } else if let Some(p) = password.as_deref() {
                config = config.set_password(p);
            }
            Ok(Some(Proxy::SOCKS5H {
                host,
                port,
                config: Arc::new(config),
            }))
        }

        #[cfg(feature = "tor")]
        "tor" => {
            // Tor doesn't use URL auth, config is separate
            Ok(Some(Proxy::Tor {
                host,
                port,
                config: Arc::new(TorConfig::new()),
            }))
        }

        #[cfg(feature = "shadowsocks")]
        "shadowsocks" | "ss" => {
            let password = password.clone().ok_or_else(|| ParseError::MissingField {
                field: "password".to_string(),
            })?;

            Ok(Some(Proxy::Shadowsocks {
                host,
                port,
                password,
                config: Arc::new(ShadowsocksConfig::new()),
            }))
        }

        _ => {
            warn!(scheme = scheme, "unsupported scheme, skipping");
            Err(ParseError::UnsupportedScheme {
                scheme: scheme.to_string(),
            })
        }
    }
}

fn default_port_for_scheme(scheme: &str) -> u16 {
    match scheme {
        "http" => DEFAULT_HTTP_PORT,
        "https" => DEFAULT_HTTPS_PORT,
        "socks4" | "socks4a" => DEFAULT_SOCKS4_PORT,
        "socks5" | "socks5h" => DEFAULT_SOCKS5_PORT,
        "tor" => DEFAULT_TOR_PORT,
        "shadowsocks" | "ss" => DEFAULT_SHADOWSOCKS_PORT,
        _ => 8080, // Fallback
    }
}

/* JSON Parsing */

/// Parse a JSON object into a Proxy enum variant.
///
/// Expected JSON structure:
/// ```json
/// {
///     "protocol": "http",
///     "host": "proxy.example.com",
///     "port": 8080,
///     "username": "user",
///     "password": "pass",
///     "config": { ... }
/// }
/// ```
pub fn parse_proxy_json(value: &Value) -> Result<Option<Proxy>, ParseError> {
    let obj = value
        .as_object()
        .ok_or_else(|| ParseError::InvalidJsonStructure {
            expected: "object".to_string(),
            found: value_type_name(value),
        })?;

    let protocol = obj
        .get("protocol")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ParseError::MissingField {
            field: "protocol".to_string(),
        })?;

    let host = obj
        .get("host")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ParseError::MissingField {
            field: "host".to_string(),
        })?
        .to_string();

    let port = obj
        .get("port")
        .and_then(|v| v.as_u64())
        .map(|p| p as u16)
        .unwrap_or_else(|| default_port_for_scheme(protocol));

    let username = obj
        .get("username")
        .and_then(|v| v.as_str())
        .map(String::from);
    let password = obj
        .get("password")
        .and_then(|v| v.as_str())
        .map(String::from);

    // Parse config if present
    let config_value = obj.get("config");
    let base_value = obj.get("base");

    match protocol {
        #[cfg(feature = "http")]
        "http" => {
            let mut config = HTTPConfig::new(host.clone(), port);
            if let Some(cfg) = config_value {
                config = parse_http_config(cfg)?
                    .set_host(host.clone())
                    .set_port(port);
            }
            if let Some(base) = base_value {
                apply_base_config(&mut config, base)?;
            }
            if let Some(u) = username.as_deref() {
                config = config.set_username(u);
            }
            if let Some(p) = password.as_deref() {
                config = config.set_password(p);
            }

            Ok(Some(Proxy::HTTP {
                host,
                port,
                config: Arc::new(config),
            }))
        }

        #[cfg(feature = "http")]
        "https" => {
            let mut config = HTTPConfig::new(host.clone(), port);
            if let Some(cfg) = config_value {
                config = parse_http_config(cfg)?
                    .set_host(host.clone())
                    .set_port(port);
            }
            if let Some(base) = base_value {
                apply_base_config(&mut config, base)?;
            }
            if let Some(u) = username.as_deref() {
                config = config.set_username(u);
            }
            if let Some(p) = password.as_deref() {
                config = config.set_password(p);
            }

            Ok(Some(Proxy::HTTPS {
                host,
                port,
                config: Arc::new(config),
            }))
        }

        #[cfg(feature = "socks4")]
        "socks4" => {
            let mut config = SOCKS4Config::new(host.clone(), port);
            if let Some(cfg) = config_value {
                config = parse_socks4_config(cfg)?
                    .set_host(host.clone())
                    .set_port(port);
            }
            if let Some(base) = base_value {
                apply_base_config(&mut config, base)?;
            }

            if let Some(u) = username.as_deref() {
                config = config.set_user_id(u);
            }

            Ok(Some(Proxy::SOCKS4 {
                host,
                port,
                config: Arc::new(config),
            }))
        }

        #[cfg(feature = "socks4")]
        "socks4a" => {
            let mut config = SOCKS4Config::new(host.clone(), port);
            if let Some(cfg) = config_value {
                config = parse_socks4_config(cfg)?
                    .set_host(host.clone())
                    .set_port(port);
            }
            if let Some(base) = base_value {
                apply_base_config(&mut config, base)?;
            }

            if let Some(u) = username.as_deref() {
                config = config.set_user_id(u);
            }

            Ok(Some(Proxy::SOCKS4A {
                host,
                port,
                config: Arc::new(config),
            }))
        }

        #[cfg(feature = "socks5")]
        "socks5" => {
            let mut config = SOCKS5Config::new(host.clone(), port);
            if let Some(cfg) = config_value {
                config = parse_socks5_config(cfg, &host, port)?
                    .set_host(host.clone())
                    .set_port(port);
            }
            if let Some(base) = base_value {
                apply_base_config(&mut config, base)?;
            }

            if let Some(u) = username.as_deref() {
                config = config.set_username(u);
            }
            if let Some(p) = password.as_deref() {
                config = config.set_password(p);
            }

            Ok(Some(Proxy::SOCKS5 {
                host,
                port,
                config: Arc::new(config),
            }))
        }

        #[cfg(feature = "socks5")]
        "socks5h" => {
            let mut config = SOCKS5Config::new(host.clone(), port);
            if let Some(cfg) = config_value {
                config = parse_socks5_config(cfg, &host, port)?
                    .set_host(host.clone())
                    .set_port(port);
            }
            if let Some(base) = base_value {
                apply_base_config(&mut config, base)?;
            }

            if let Some(u) = username.as_deref() {
                config = config.set_username(u);
            }
            if let Some(p) = password.as_deref() {
                config = config.set_password(p);
            }

            Ok(Some(Proxy::SOCKS5H {
                host,
                port,
                config: Arc::new(config),
            }))
        }

        #[cfg(feature = "tor")]
        "tor" => {
            let mut config = if let Some(cfg) = config_value {
                parse_tor_config(cfg)?
            } else {
                TorConfig::new()
            };
            if let Some(base) = base_value {
                apply_base_config(&mut config, base)?;
            }

            Ok(Some(Proxy::Tor {
                host,
                port,
                config: Arc::new(config),
            }))
        }

        #[cfg(feature = "shadowsocks")]
        "shadowsocks" | "ss" => {
            let password = password.clone().ok_or_else(|| ParseError::MissingField {
                field: "password".to_string(),
            })?;

            let mut config = if let Some(cfg) = config_value {
                parse_shadowsocks_config(cfg)?
            } else {
                ShadowsocksConfig::new()
            };
            if let Some(base) = base_value {
                apply_base_config(&mut config, base)?;
            }

            Ok(Some(Proxy::Shadowsocks {
                host,
                port,
                password,
                config: Arc::new(config),
            }))
        }

        _ => {
            warn!(protocol = protocol, "unsupported protocol, skipping");
            Err(ParseError::UnsupportedScheme {
                scheme: protocol.to_string(),
            })
        }
    }
}

/// Parse a grouped proxy list JSON into a vector of Proxy variants.
///
/// This function parses the grouped JSON format where proxies sharing the same
/// base configuration are organized together. Each group's base config is Arc'd
/// and shared across all proxies in that group.
///
/// Expected JSON structure:
/// ```json
/// {
///     "configs": [
///         {
///             "base": {
///                 "handshake_timeout": 10,
///                 "phase_timeout": 5,
///                 "resolve_locally": false,
///                 "tcp_nodelay": true,
///                 "keep_alive": 60,
///                 "auto_tls": true
///             },
///             "proxies": [
///                 {
///                     "protocol": "http",
///                     "host": "proxy.example.com",
///                     "port": 8080,
///                     "username": "user",
///                     "password": "pass"
///                 }
///             ]
///         }
///     ]
/// }
/// ```
///
/// # Arguments
///
/// * `json_str` - JSON string containing the grouped proxy list
///
/// # Returns
///
/// A vector of [`Proxy`] variants with Arc'd base configurations shared within groups.
///
/// # Errors
///
/// Returns [`ParseError`] if:
/// - JSON is malformed
/// - Required fields are missing
/// - Field types are incorrect
/// - Unsupported protocols are encountered
pub fn parse_proxy_list_json(json_str: &str) -> Result<Vec<Proxy>, ParseError> {
    let parsed: Value = serde_json::from_str(json_str)?;

    let configs_array = parsed
        .get("configs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ParseError::InvalidJsonStructure {
            expected: "object with 'configs' array".to_string(),
            found: "other".to_string(),
        })?;

    let mut all_proxies = Vec::new();

    for group_value in configs_array {
        let group_obj =
            group_value
                .as_object()
                .ok_or_else(|| ParseError::InvalidJsonStructure {
                    expected: "config group object".to_string(),
                    found: value_type_name(group_value),
                })?;

        // Parse base config for this group
        let base_value = group_obj
            .get("base")
            .ok_or_else(|| ParseError::MissingField {
                field: "base".to_string(),
            })?;

        // Parse proxies array
        let proxies_array = group_obj
            .get("proxies")
            .and_then(|v| v.as_array())
            .ok_or_else(|| ParseError::InvalidJsonStructure {
                expected: "proxies array in config group".to_string(),
                found: "other".to_string(),
            })?;

        // Parse all proxies in this group
        let mut group_proxies: Vec<Proxy> = Vec::new();
        for proxy_value in proxies_array {
            if let Some(proxy) = parse_proxy_json(proxy_value)? {
                group_proxies.push(proxy);
            }
        }

        // Apply the shared base config to all proxies in this group
        if !group_proxies.is_empty() {
            // Parse the base config once
            let base_config = parse_base_config_from_json(base_value)?;
            let shared_base = Arc::new(base_config);

            // Apply to all proxies in group
            for proxy in group_proxies {
                let configured_proxy = proxy.with_base_config(shared_base.clone());
                all_proxies.push(configured_proxy);
            }
        }
    }

    Ok(all_proxies)
}

/// Parse a base config JSON object into a BaseProxyConfig.
///
/// Helper function for [`parse_proxy_list_json`] that converts a JSON
/// representation of base configuration into a [`BaseProxyConfig`] instance.
///
/// # Arguments
///
/// * `value` - JSON value containing base configuration fields
///
/// # Returns
///
/// A [`BaseProxyConfig`] with the parsed configuration.
///
/// # Errors
///
/// Returns [`ParseError`] if required fields are missing or have invalid types.
fn parse_base_config_from_json(value: &Value) -> Result<BaseProxyConfig, ParseError> {
    let obj = value
        .as_object()
        .ok_or_else(|| ParseError::InvalidJsonStructure {
            expected: "base config object".to_string(),
            found: value_type_name(value),
        })?;

    let mut config = BaseProxyConfig::new();

    if let Some(timeout) = obj.get("handshake_timeout").and_then(|v| v.as_u64()) {
        config.set_handshake_timeout(Duration::from_secs(timeout));
    }

    if let Some(timeout) = obj.get("phase_timeout").and_then(|v| v.as_u64()) {
        config.set_phase_timeout(Duration::from_secs(timeout));
    }

    if let Some(resolve_locally) = obj.get("resolve_locally").and_then(|v| v.as_bool()) {
        config.set_resolve_locally(resolve_locally);
    }

    if let Some(tcp_nodelay) = obj.get("tcp_nodelay").and_then(|v| v.as_bool()) {
        config.set_tcp_nodelay(tcp_nodelay);
    }

    if let Some(keep_alive_value) = obj.get("keep_alive") {
        match keep_alive_value {
            Value::Null => config.clear_keep_alive(),
            _ => {
                if let Some(keep_alive) = keep_alive_value.as_u64() {
                    config.set_keep_alive(Duration::from_secs(keep_alive));
                }
            }
        }
    }

    if let Some(auto_tls) = obj.get("auto_tls").and_then(|v| v.as_bool()) {
        config.set_auto_tls(auto_tls);
    }

    if let Some(tls_value) = obj.get("tls_config") {
        if !tls_value.is_null() {
            let tls_config = parse_tls_config(tls_value)?;
            config.set_tls_config(tls_config);
        }
    }

    Ok(config)
}

/* Config Parsers */

#[cfg(feature = "http")]
fn parse_http_config(value: &Value) -> Result<HTTPConfig, ParseError> {
    let obj = value
        .as_object()
        .ok_or_else(|| ParseError::InvalidJsonStructure {
            expected: "object".to_string(),
            found: value_type_name(value),
        })?;

    let mut config = HTTPConfig::new("dummy", 1);

    if let Some(timeout) = obj.get("handshake_timeout").and_then(|v| v.as_u64()) {
        config = config.set_handshake_timeout(Duration::from_secs(timeout));
    }

    if let Some(timeout) = obj.get("phase_timeout").and_then(|v| v.as_u64()) {
        config = config.set_phase_timeout(Duration::from_secs(timeout));
    }

    Ok(config)
}

#[cfg(feature = "socks4")]
fn parse_socks4_config(value: &Value) -> Result<SOCKS4Config, ParseError> {
    let obj = value
        .as_object()
        .ok_or_else(|| ParseError::InvalidJsonStructure {
            expected: "object".to_string(),
            found: value_type_name(value),
        })?;

    let mut config = SOCKS4Config::new("dummy", 1);

    if let Some(timeout) = obj.get("handshake_timeout").and_then(|v| v.as_u64()) {
        config = config.set_handshake_timeout(Duration::from_secs(timeout));
    }

    if let Some(timeout) = obj.get("phase_timeout").and_then(|v| v.as_u64()) {
        config = config.set_phase_timeout(Duration::from_secs(timeout));
    }

    Ok(config)
}

#[cfg(feature = "socks5")]
fn parse_socks5_config(value: &Value, host: &str, port: u16) -> Result<SOCKS5Config, ParseError> {
    let obj = value
        .as_object()
        .ok_or_else(|| ParseError::InvalidJsonStructure {
            expected: "object".to_string(),
            found: value_type_name(value),
        })?;

    let mut config = SOCKS5Config::new(host.to_string(), port);

    if let Some(timeout) = obj.get("handshake_timeout").and_then(|v| v.as_u64()) {
        config = config.set_handshake_timeout(Duration::from_secs(timeout));
    }

    if let Some(timeout) = obj.get("phase_timeout").and_then(|v| v.as_u64()) {
        config = config.set_phase_timeout(Duration::from_secs(timeout));
    }

    Ok(config)
}

#[cfg(feature = "tor")]
fn parse_tor_config(value: &Value) -> Result<TorConfig, ParseError> {
    let obj = value
        .as_object()
        .ok_or_else(|| ParseError::InvalidJsonStructure {
            expected: "object".to_string(),
            found: value_type_name(value),
        })?;

    let mut config = TorConfig::new();

    if let Some(host) = obj.get("control_host").and_then(|v| v.as_str()) {
        config = config.set_control_host(host);
    }

    if let Some(port) = obj.get("control_port").and_then(|v| v.as_u64()) {
        config = config.set_control_port(port as u16);
    }

    if let Some(password) = obj.get("control_password").and_then(|v| v.as_str()) {
        config = config.set_control_password(password);
    }

    if let Some(nodes) = obj.get("exit_nodes").and_then(|v| v.as_str()) {
        config = config.set_exit_nodes(nodes);
    }

    Ok(config)
}

#[cfg(feature = "shadowsocks")]
fn parse_shadowsocks_config(value: &Value) -> Result<ShadowsocksConfig, ParseError> {
    let obj = value
        .as_object()
        .ok_or_else(|| ParseError::InvalidJsonStructure {
            expected: "object".to_string(),
            found: value_type_name(value),
        })?;

    let mut config = ShadowsocksConfig::new();

    if let Some(method) = obj.get("method").and_then(|v| v.as_str()) {
        config = config.set_method(method);
    }

    if let Some(timeout) = obj.get("handshake_timeout").and_then(|v| v.as_u64()) {
        config = config.set_handshake_timeout(Duration::from_secs(timeout));
    }

    Ok(config)
}

fn apply_base_config<T: HasBaseProxyConfig>(
    config: &mut T,
    value: &Value,
) -> Result<(), ParseError> {
    if value.is_null() {
        return Ok(());
    }

    let obj = value
        .as_object()
        .ok_or_else(|| ParseError::InvalidJsonStructure {
            expected: "base object".to_string(),
            found: value_type_name(value),
        })?;

    let base = config.get_base_config_mut();

    if let Some(timeout) = obj.get("handshake_timeout").and_then(|v| v.as_u64()) {
        base.set_handshake_timeout(Duration::from_secs(timeout));
    }

    if let Some(timeout) = obj.get("phase_timeout").and_then(|v| v.as_u64()) {
        base.set_phase_timeout(Duration::from_secs(timeout));
    }

    if let Some(resolve_locally) = obj.get("resolve_locally").and_then(|v| v.as_bool()) {
        base.set_resolve_locally(resolve_locally);
    }

    if let Some(tcp_nodelay) = obj.get("tcp_nodelay").and_then(|v| v.as_bool()) {
        base.set_tcp_nodelay(tcp_nodelay);
    }

    if let Some(keep_alive_value) = obj.get("keep_alive") {
        match keep_alive_value {
            Value::Null => base.clear_keep_alive(),
            _ => {
                if let Some(keep_alive) = keep_alive_value.as_u64() {
                    base.set_keep_alive(Duration::from_secs(keep_alive));
                } else {
                    return Err(ParseError::InvalidFieldValue {
                        field: "keep_alive".to_string(),
                        reason: format!(
                            "expected number or null, found {}",
                            value_type_name(keep_alive_value)
                        ),
                    });
                }
            }
        }
    }

    if let Some(auto_tls) = obj.get("auto_tls").and_then(|v| v.as_bool()) {
        base.set_auto_tls(auto_tls);
    }

    if let Some(tls_value) = obj.get("tls_config") {
        if tls_value.is_null() {
            base.clear_tls_config();
        } else {
            let tls_config = parse_tls_config(tls_value)?;
            base.set_tls_config(tls_config);
        }
    }

    Ok(())
}

fn parse_tls_config(value: &Value) -> Result<TLSConfig, ParseError> {
    let obj = value
        .as_object()
        .ok_or_else(|| ParseError::InvalidJsonStructure {
            expected: "tls_config object".to_string(),
            found: value_type_name(value),
        })?;

    let config_type =
        obj.get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ParseError::MissingField {
                field: "tls_config.type".to_string(),
            })?;

    match config_type {
        "default" => {
            let mut config = TLSConfig::new();
            if let Some(alpn_value) = obj.get("alpn") {
                if !alpn_value.is_null() {
                    let alpn = parse_tls_alpn(alpn_value)?;
                    config = config.set_alpn(alpn);
                }
            }
            Ok(config)
        }
        "danger_accept_invalid_certs" => Ok(TLSConfig::new().set_danger_accept_invalid_certs(true)),
        _ => Err(ParseError::InvalidFieldValue {
            field: "tls_config.type".to_string(),
            reason: format!("unsupported tls config type '{}'", config_type),
        }),
    }
}

fn parse_tls_alpn(value: &Value) -> Result<Vec<Vec<u8>>, ParseError> {
    let array = value
        .as_array()
        .ok_or_else(|| ParseError::InvalidJsonStructure {
            expected: "alpn array".to_string(),
            found: value_type_name(value),
        })?;

    let mut protocols = Vec::with_capacity(array.len());
    for entry in array {
        let protocol = entry
            .as_str()
            .ok_or_else(|| ParseError::InvalidFieldValue {
                field: "tls_config.alpn".to_string(),
                reason: format!("expected string, found {}", value_type_name(entry)),
            })?;
        protocols.push(protocol.as_bytes().to_vec());
    }

    Ok(protocols)
}

/* Helpers */

fn value_type_name(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(_) => "boolean".to_string(),
        Value::Number(_) => "number".to_string(),
        Value::String(_) => "string".to_string(),
        Value::Array(_) => "array".to_string(),
        Value::Object(_) => "object".to_string(),
    }
}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "http")]
    fn parse_http_url() {
        let proxy = parse_proxy_url("http://user:pass@proxy.com:8080").unwrap();
        assert!(proxy.is_some());

        match proxy.unwrap() {
            Proxy::HTTP { host, port, .. } => {
                assert_eq!(host, "proxy.com");
                assert_eq!(port, 8080);
            }
            _ => panic!("Expected HTTP proxy"),
        }
    }

    #[test]
    #[cfg(feature = "socks5")]
    fn parse_socks5_url() {
        let proxy = parse_proxy_url("socks5://user:pass@localhost:1080").unwrap();
        assert!(proxy.is_some());

        match proxy.unwrap() {
            Proxy::SOCKS5 { host, port, .. } => {
                assert_eq!(host, "localhost");
                assert_eq!(port, 1080);
            }
            _ => panic!("Expected SOCKS5 proxy"),
        }
    }

    #[test]
    fn parse_invalid_url() {
        let result = parse_proxy_url("not a url");
        assert!(result.is_err());
    }

    #[test]
    fn parse_unsupported_scheme() {
        let result = parse_proxy_url("ftp://proxy.com:21");
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "http")]
    fn parse_http_json() {
        let json = r#"{
            "protocol": "http",
            "host": "proxy.com",
            "port": 8080,
            "username": "user",
            "password": "pass"
        }"#;

        let value: Value = serde_json::from_str(json).unwrap();
        let proxy = parse_proxy_json(&value).unwrap();
        assert!(proxy.is_some());

        match proxy.unwrap() {
            Proxy::HTTP { host, port, .. } => {
                assert_eq!(host, "proxy.com");
                assert_eq!(port, 8080);
            }
            _ => panic!("Expected HTTP proxy"),
        }
    }

    #[test]
    fn parse_json_missing_protocol() {
        let json = r#"{"host": "proxy.com", "port": 8080}"#;
        let value: Value = serde_json::from_str(json).unwrap();
        let result = parse_proxy_json(&value);
        assert!(result.is_err());
    }
}
