//! Proxy URL and JSON parsing utilities.
//!
//! Provides functions to parse proxy configurations from URLs and JSON,
//! converting them into strongly-typed Proxy enum variants.

use std::sync::Arc;
use std::time::Duration;

#[cfg(all(feature = "http", feature = "shadowsocks"))]
use base64::Engine as _;
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
#[cfg(feature = "hysteria2")]
const DEFAULT_HYSTERIA2_PORT: u16 = 443;

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

        #[cfg(feature = "trojan")]
        "trojan" | "trojan-gfw" => {
            // trojan://password@host:port?sni=example.com&allowInsecure=1
            let password = match (username.as_deref(), password.as_deref()) {
                (Some(u), None) if !u.is_empty() => u.to_string(),
                // Some clients put the password in the standard password field
                (None, Some(p)) if !p.is_empty() => p.to_string(),
                (Some(u), Some(_)) if !u.is_empty() => u.to_string(),
                _ => {
                    return Err(ParseError::MissingField {
                        field: "password (trojan expects password@host:port)".to_string(),
                    });
                }
            };

            let mut config = TrojanConfig::new();

            for (key, value) in url.query_pairs() {
                match key.as_ref() {
                    "sni" | "peer" => config = config.set_sni(value.as_ref()),
                    "allowInsecure" | "insecure" => {
                        config =
                            config.set_skip_cert_verify(value == "1" || value == "true")
                    }
                    "alpn" => config = config.set_alpn(value.as_ref()),
                    "type" => {
                        if value == "ws" || value == "websocket" {
                            config = config.set_ws_enabled(true);
                        }
                    }
                    "path" => config = config.set_ws_path(value.as_ref()),
                    "host" => config = config.set_ws_host(value.as_ref()),
                    _ => {}
                }
            }

            Ok(Some(Proxy::Trojan {
                host,
                port,
                password,
                config: Arc::new(config),
            }))
        }

        #[cfg(feature = "shadowsocks")]
        "shadowsocks" | "ss" => {
            let (host, port, password, config) = parse_shadowsocks_url_credentials(
                &host,
                port,
                &username,
                &password,
                url_str,
            )?;

            Ok(Some(Proxy::Shadowsocks {
                host,
                port,
                password,
                config: Arc::new(config),
            }))
        }

        #[cfg(feature = "hysteria2")]
        "hysteria2" | "hy2" => {
            // hysteria2://password@host:port?sni=...&insecure=1&upmbps=10&downmbps=50
            // The password is in the username position; there is no URL password.
            let password = match (username.as_deref(), password.as_deref()) {
                (Some(u), None) if !u.is_empty() => u.to_string(),
                (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => {
                    // Some clients encode as user:pass — treat the whole thing as password.
                    format!("{}:{}", u, p)
                }
                _ => {
                    return Err(ParseError::MissingField {
                        field: "password (hysteria2 expects password@host:port)".to_string(),
                    });
                }
            };

            let mut config = Hysteria2Config::new();
            let mut obfs_type: Option<String> = None;
            let mut obfs_password_param: Option<String> = None;

            // Parse optional query parameters.
            for (key, value) in url.query_pairs() {
                match key.as_ref() {
                    "sni" => config = config.set_sni(value.as_ref()),
                    "insecure" => {
                        config = config.set_skip_cert_verify(value == "1" || value == "true")
                    }
                    "upmbps" => {
                        if let Ok(v) = value.parse::<u32>() {
                            let down = config.get_down_mbps();
                            config = config.set_bandwidth(v, down);
                        }
                    }
                    "downmbps" => {
                        if let Ok(v) = value.parse::<u32>() {
                            let up = config.get_up_mbps();
                            config = config.set_bandwidth(up, v);
                        }
                    }
                    "cc" => config = config.set_congestion_control(value.as_ref()),
                    "obfs" => obfs_type = Some(value.into_owned()),
                    "obfs-password" => obfs_password_param = Some(value.into_owned()),
                    _ => {}
                }
            }

            // Enable Salamander obfuscation when requested.  When no explicit
            // obfs-password is provided the auth password doubles as the obfs
            // password (standard Hysteria2 client behaviour).
            if obfs_type.as_deref() == Some("salamander") {
                let obfs_pw = obfs_password_param.unwrap_or_else(|| password.clone());
                config = config.set_obfs_password(obfs_pw);
            }

            Ok(Some(Proxy::Hysteria2 {
                host,
                port,
                password,
                config: Arc::new(config),
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
        #[cfg(feature = "hysteria2")]
        "hysteria2" | "hy2" => DEFAULT_HYSTERIA2_PORT,
        #[cfg(feature = "trojan")]
        "trojan" | "trojan-gfw" => 443,
        _ => 8080, // Fallback
    }
}

#[cfg(feature = "shadowsocks")]
fn parse_shadowsocks_url_credentials(
    host: &str,
    port: u16,
    username: &Option<String>,
    password: &Option<String>,
    url_str: &str,
) -> Result<(String, u16, String, ShadowsocksConfig), ParseError> {
    if let Some(pass) = password {
        let mut config = ShadowsocksConfig::new();
        if let Some(method) = username
            && !method.is_empty()
        {
            config = config.set_method(method);
        }
        return Ok((host.to_string(), port, pass.clone(), config));
    }

    if let Some(encoded) = username
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        let decoded = decode_ss_userinfo(encoded).ok_or_else(|| ParseError::InvalidFieldValue {
            field: "ss userinfo".to_string(),
            reason: format!(
                "expected base64-encoded 'method:password' in URL '{}'",
                url_str
            ),
        })?;

        let (method, pass) = decoded
            .split_once(':')
            .ok_or_else(|| ParseError::InvalidFieldValue {
                field: "ss userinfo".to_string(),
                reason: format!("decoded userinfo must be 'method:password', got '{}'", decoded),
            })?;

        if method.is_empty() || pass.is_empty() {
            return Err(ParseError::InvalidFieldValue {
                field: "ss userinfo".to_string(),
                reason: "decoded method/password cannot be empty".to_string(),
            });
        }

        let config = ShadowsocksConfig::new().set_method(method);
        return Ok((host.to_string(), port, pass.to_string(), config));
    }

    // Legacy SIP002 variant:
    // ss://BASE64(method:password@host:port)#tag
    if let Some(decoded) = decode_ss_userinfo(host)
        && let Some((creds, host_port)) = decoded.rsplit_once('@')
        && let Some((method, pass)) = creds.split_once(':')
        && let Some((decoded_host, decoded_port)) = split_host_port(host_port)
        && !method.is_empty()
        && !pass.is_empty()
    {
        let config = ShadowsocksConfig::new().set_method(method);
        return Ok((decoded_host.to_string(), decoded_port, pass.to_string(), config));
    }

    Err(ParseError::MissingField {
        field: "password".to_string(),
    })
}

#[cfg(feature = "shadowsocks")]
fn split_host_port(host_port: &str) -> Option<(&str, u16)> {
    let (h, p) = host_port.rsplit_once(':')?;
    let port = p.parse::<u16>().ok()?;
    Some((h, port))
}

#[cfg(all(feature = "http", feature = "shadowsocks"))]
fn decode_ss_userinfo(encoded: &str) -> Option<String> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};

    let bytes = STANDARD
        .decode(encoded)
        .or_else(|_| STANDARD_NO_PAD.decode(encoded))
        .or_else(|_| URL_SAFE.decode(encoded))
        .or_else(|_| URL_SAFE_NO_PAD.decode(encoded))
        .ok()?;

    String::from_utf8(bytes).ok()
}

#[cfg(all(not(feature = "http"), feature = "shadowsocks"))]
fn decode_ss_userinfo(_encoded: &str) -> Option<String> {
    None
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

        #[cfg(feature = "hysteria2")]
        "hysteria2" | "hy2" => {
            let password = password.clone().ok_or_else(|| ParseError::MissingField {
                field: "password".to_string(),
            })?;

            let mut config = if let Some(cfg) = config_value {
                parse_hysteria2_config(cfg)?
            } else {
                Hysteria2Config::new()
            };
            if let Some(base) = base_value {
                apply_base_config(&mut config, base)?;
            }

            Ok(Some(Proxy::Hysteria2 {
                host,
                port,
                password,
                config: Arc::new(config),
            }))
        }

        #[cfg(feature = "trojan")]
        "trojan" | "trojan-gfw" => {
            let password = password.clone().ok_or_else(|| ParseError::MissingField {
                field: "password".to_string(),
            })?;

            // Support both nested `config` and legacy top-level Trojan fields.
            let mut config = if let Some(cfg) = config_value {
                parse_trojan_config(cfg)?
            } else {
                TrojanConfig::new()
            };

            // Backward-compatible top-level overrides.
            if let Some(sni) = obj.get("sni").and_then(|v| v.as_str()) {
                config = config.set_sni(sni);
            }
            if let Some(skip) = obj.get("skip_cert_verify").and_then(|v| v.as_bool()) {
                config = config.set_skip_cert_verify(skip);
            }
            if let Some(alpn) = obj.get("alpn").and_then(|v| v.as_str()) {
                config = config.set_alpn(alpn);
            }
            if let Some(enabled) = obj.get("ws_enabled").and_then(|v| v.as_bool()) {
                config = config.set_ws_enabled(enabled);
            }
            if let Some(path) = obj.get("ws_path").and_then(|v| v.as_str()) {
                config = config.set_ws_path(path);
            }
            if let Some(host) = obj.get("ws_host").and_then(|v| v.as_str()) {
                config = config.set_ws_host(host);
            }
            if let Some(headers) = obj.get("ws_headers").and_then(|v| v.as_str()) {
                config = config.set_ws_headers(headers);
            }
            if let Some(timeout) = obj.get("connection_timeout").and_then(|v| v.as_u64()) {
                config = config.set_connection_timeout(Duration::from_secs(timeout));
            }

            if let Some(base) = base_value {
                apply_base_config(&mut config, base)?;
            }

            Ok(Some(Proxy::Trojan {
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

    if let Some(tls_value) = obj.get("tls_config")
        && !tls_value.is_null()
    {
        let tls_config = parse_tls_config(tls_value)?;
        config.set_tls_config(tls_config);
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

#[cfg(feature = "hysteria2")]
fn parse_hysteria2_config(value: &Value) -> Result<Hysteria2Config, ParseError> {
    let obj = value
        .as_object()
        .ok_or_else(|| ParseError::InvalidJsonStructure {
            expected: "object".to_string(),
            found: value_type_name(value),
        })?;

    let mut config = Hysteria2Config::new();

    if let Some(up) = obj.get("up_mbps").and_then(|v| v.as_u64()) {
        let down = config.get_down_mbps();
        config = config.set_bandwidth(up as u32, down);
    }

    if let Some(down) = obj.get("down_mbps").and_then(|v| v.as_u64()) {
        let up = config.get_up_mbps();
        config = config.set_bandwidth(up, down as u32);
    }

    if let Some(cc) = obj.get("congestion_control").and_then(|v| v.as_str()) {
        config = config.set_congestion_control(cc);
    }

    if let Some(sni) = obj.get("sni").and_then(|v| v.as_str()) {
        config = config.set_sni(sni);
    }

    if let Some(skip) = obj.get("skip_cert_verify").and_then(|v| v.as_bool()) {
        config = config.set_skip_cert_verify(skip);
    }

    if let Some(alpn) = obj.get("alpn").and_then(|v| v.as_str()) {
        config = config.set_alpn(alpn);
    }

    if let Some(obfs_password) = obj.get("obfs_password").and_then(|v| v.as_str()) {
        config = config.set_obfs_password(obfs_password);
    }

    Ok(config)
}

#[cfg(feature = "trojan")]
fn parse_trojan_config(value: &Value) -> Result<TrojanConfig, ParseError> {
    let obj = value
        .as_object()
        .ok_or_else(|| ParseError::InvalidJsonStructure {
            expected: "object".to_string(),
            found: value_type_name(value),
        })?;

    let mut config = TrojanConfig::new();

    if let Some(sni) = obj.get("sni").and_then(|v| v.as_str()) {
        config = config.set_sni(sni);
    }
    if let Some(skip) = obj.get("skip_cert_verify").and_then(|v| v.as_bool()) {
        config = config.set_skip_cert_verify(skip);
    }
    if let Some(alpn) = obj.get("alpn").and_then(|v| v.as_str()) {
        config = config.set_alpn(alpn);
    }
    if let Some(enabled) = obj.get("ws_enabled").and_then(|v| v.as_bool()) {
        config = config.set_ws_enabled(enabled);
    }
    if let Some(path) = obj.get("ws_path").and_then(|v| v.as_str()) {
        config = config.set_ws_path(path);
    }
    if let Some(host) = obj.get("ws_host").and_then(|v| v.as_str()) {
        config = config.set_ws_host(host);
    }
    if let Some(headers) = obj.get("ws_headers").and_then(|v| v.as_str()) {
        config = config.set_ws_headers(headers);
    }
    if let Some(timeout) = obj.get("connection_timeout").and_then(|v| v.as_u64()) {
        config = config.set_connection_timeout(Duration::from_secs(timeout));
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
            if let Some(alpn_value) = obj.get("alpn")
                && !alpn_value.is_null()
            {
                let alpn = parse_tls_alpn(alpn_value)?;
                config = config.set_alpn(alpn);
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

    #[test]
    #[cfg(all(feature = "shadowsocks", feature = "http"))]
    fn parse_ss_base64_userinfo_url() {
        let proxy = parse_proxy_url(
            "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpxSm1qUUZQUG42TGJEWHdkRkxJeFd0@209.74.82.189:21520",
        )
        .unwrap()
        .expect("expected shadowsocks proxy");

        match proxy {
            Proxy::Shadowsocks {
                host,
                port,
                password,
                config,
            } => {
                assert_eq!(host, "209.74.82.189");
                assert_eq!(port, 21520);
                assert_eq!(password, "qJmjQFPPn6LbDXwdFLIxWt");
                assert_eq!(config.get_method(), "chacha20-ietf-poly1305");
            }
            _ => panic!("Expected Shadowsocks proxy"),
        }
    }

    #[test]
    #[cfg(all(feature = "shadowsocks", feature = "http"))]
    fn parse_ss_legacy_full_blob_url() {
        let proxy = parse_proxy_url(
            "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpBUmd2R1p5d0ErZ2FjZ0dWMjZCdm11MDUrd1ptUlcvaitBZFUrWjhCdDQ0PUAxNDcuNzguMC4xODI6OTkw#tag",
        )
        .unwrap()
        .expect("expected shadowsocks proxy");

        match proxy {
            Proxy::Shadowsocks {
                host,
                port,
                password,
                config,
            } => {
                assert_eq!(host, "147.78.0.182");
                assert_eq!(port, 990);
                assert_eq!(password, "ARgvGZywA+gacgGV26Bvmu05+wZmRW/j+AdU+Z8Bt44=");
                assert_eq!(config.get_method(), "chacha20-ietf-poly1305");
            }
            _ => panic!("Expected Shadowsocks proxy"),
        }
    }

    // ── URL parsing – all scheme variants ────────────────────────────────────

    #[test]
    #[cfg(feature = "http")]
    fn parse_https_url() {
        let proxy = parse_proxy_url("https://user:pass@proxy.com:8443").unwrap().unwrap();
        match proxy {
            Proxy::HTTPS { host, port, .. } => {
                assert_eq!(host, "proxy.com");
                assert_eq!(port, 8443);
            }
            _ => panic!("expected HTTPS proxy"),
        }
    }

    #[test]
    #[cfg(feature = "http")]
    fn parse_http_url_no_port_uses_default() {
        let proxy = parse_proxy_url("http://proxy.com").unwrap().unwrap();
        match proxy {
            Proxy::HTTP { port, .. } => assert_eq!(port, 8080),
            _ => panic!("expected HTTP proxy"),
        }
    }

    #[test]
    #[cfg(feature = "http")]
    fn parse_http_url_no_credentials() {
        let proxy = parse_proxy_url("http://proxy.com:8080").unwrap().unwrap();
        assert_eq!(proxy.get_host(), "proxy.com");
        assert_eq!(proxy.get_port(), 8080);
    }

    #[test]
    #[cfg(feature = "socks4")]
    fn parse_socks4_url() {
        let proxy = parse_proxy_url("socks4://proxy.com:1080").unwrap().unwrap();
        match proxy {
            Proxy::SOCKS4 { host, port, .. } => {
                assert_eq!(host, "proxy.com");
                assert_eq!(port, 1080);
            }
            _ => panic!("expected SOCKS4 proxy"),
        }
    }

    #[test]
    #[cfg(feature = "socks4")]
    fn parse_socks4_url_with_user_id() {
        let proxy = parse_proxy_url("socks4://myuser@proxy.com:1080").unwrap().unwrap();
        match proxy {
            Proxy::SOCKS4 { host, port, config } => {
                assert_eq!(host, "proxy.com");
                assert_eq!(port, 1080);
                assert_eq!(config.get_user_id(), Some("myuser"));
            }
            _ => panic!("expected SOCKS4 proxy"),
        }
    }

    #[test]
    #[cfg(feature = "socks4")]
    fn parse_socks4_url_no_port_uses_default() {
        let proxy = parse_proxy_url("socks4://proxy.com").unwrap().unwrap();
        match proxy {
            Proxy::SOCKS4 { port, .. } => assert_eq!(port, 1080),
            _ => panic!("expected SOCKS4 proxy"),
        }
    }

    #[test]
    #[cfg(feature = "socks4")]
    fn parse_socks4a_url() {
        let proxy = parse_proxy_url("socks4a://proxy.com:1080").unwrap().unwrap();
        match proxy {
            Proxy::SOCKS4A { host, port, .. } => {
                assert_eq!(host, "proxy.com");
                assert_eq!(port, 1080);
            }
            _ => panic!("expected SOCKS4A proxy"),
        }
    }

    #[test]
    #[cfg(feature = "socks5")]
    fn parse_socks5_url_no_credentials() {
        let proxy = parse_proxy_url("socks5://proxy.com:1080").unwrap().unwrap();
        match proxy {
            Proxy::SOCKS5 { host, port, .. } => {
                assert_eq!(host, "proxy.com");
                assert_eq!(port, 1080);
            }
            _ => panic!("expected SOCKS5 proxy"),
        }
    }

    #[test]
    #[cfg(feature = "socks5")]
    fn parse_socks5h_url() {
        let proxy = parse_proxy_url("socks5h://user:pass@proxy.com:1080").unwrap().unwrap();
        match proxy {
            Proxy::SOCKS5H { host, port, .. } => {
                assert_eq!(host, "proxy.com");
                assert_eq!(port, 1080);
            }
            _ => panic!("expected SOCKS5H proxy"),
        }
    }

    #[test]
    #[cfg(feature = "socks5")]
    fn parse_socks5_url_no_port_uses_default() {
        let proxy = parse_proxy_url("socks5://proxy.com").unwrap().unwrap();
        match proxy {
            Proxy::SOCKS5 { port, .. } => assert_eq!(port, 1080),
            _ => panic!("expected SOCKS5 proxy"),
        }
    }

    #[test]
    #[cfg(feature = "tor")]
    fn parse_tor_url() {
        let proxy = parse_proxy_url("tor://127.0.0.1:9050").unwrap().unwrap();
        match proxy {
            Proxy::Tor { host, port, .. } => {
                assert_eq!(host, "127.0.0.1");
                assert_eq!(port, 9050);
            }
            _ => panic!("expected Tor proxy"),
        }
    }

    #[test]
    #[cfg(feature = "tor")]
    fn parse_tor_url_no_port_uses_default() {
        let proxy = parse_proxy_url("tor://127.0.0.1").unwrap().unwrap();
        match proxy {
            Proxy::Tor { port, .. } => assert_eq!(port, 9050),
            _ => panic!("expected Tor proxy"),
        }
    }

    #[test]
    #[cfg(feature = "hysteria2")]
    fn parse_hysteria2_url_basic() {
        let proxy = parse_proxy_url("hysteria2://mypassword@proxy.com:443").unwrap().unwrap();
        match proxy {
            Proxy::Hysteria2 { host, port, password, .. } => {
                assert_eq!(host, "proxy.com");
                assert_eq!(port, 443);
                assert_eq!(password, "mypassword");
            }
            _ => panic!("expected Hysteria2 proxy"),
        }
    }

    #[test]
    #[cfg(feature = "hysteria2")]
    fn parse_hy2_scheme_alias() {
        let proxy = parse_proxy_url("hy2://mypassword@proxy.com:443").unwrap().unwrap();
        match proxy {
            Proxy::Hysteria2 { host, port, password, .. } => {
                assert_eq!(host, "proxy.com");
                assert_eq!(port, 443);
                assert_eq!(password, "mypassword");
            }
            _ => panic!("expected Hysteria2 proxy from hy2:// alias"),
        }
    }

    #[test]
    #[cfg(feature = "hysteria2")]
    fn parse_hysteria2_url_no_port_uses_default() {
        let proxy = parse_proxy_url("hysteria2://mypassword@proxy.com").unwrap().unwrap();
        match proxy {
            Proxy::Hysteria2 { port, .. } => assert_eq!(port, 443),
            _ => panic!("expected Hysteria2 proxy"),
        }
    }

    #[test]
    #[cfg(feature = "hysteria2")]
    fn parse_hysteria2_url_with_sni_and_insecure() {
        let proxy = parse_proxy_url(
            "hysteria2://pass@proxy.com:8443?sni=my.host.com&insecure=1",
        )
        .unwrap()
        .unwrap();
        match proxy {
            Proxy::Hysteria2 { config, .. } => {
                assert_eq!(config.get_sni(), Some("my.host.com"));
                assert!(config.is_skip_cert_verify());
            }
            _ => panic!("expected Hysteria2 proxy"),
        }
    }

    #[test]
    #[cfg(feature = "hysteria2")]
    fn parse_hysteria2_url_with_bandwidth_params() {
        let proxy = parse_proxy_url(
            "hysteria2://pass@proxy.com:443?upmbps=20&downmbps=100",
        )
        .unwrap()
        .unwrap();
        match proxy {
            Proxy::Hysteria2 { config, .. } => {
                assert_eq!(config.get_up_mbps(), 20);
                assert_eq!(config.get_down_mbps(), 100);
            }
            _ => panic!("expected Hysteria2 proxy"),
        }
    }

    #[test]
    #[cfg(feature = "hysteria2")]
    fn parse_hysteria2_url_with_salamander_obfs() {
        let proxy = parse_proxy_url(
            "hysteria2://authpass@proxy.com:443?obfs=salamander&obfs-password=obfspass",
        )
        .unwrap()
        .unwrap();
        match proxy {
            Proxy::Hysteria2 { password, config, .. } => {
                assert_eq!(password, "authpass");
                assert_eq!(config.get_obfs_password(), Some("obfspass"));
            }
            _ => panic!("expected Hysteria2 proxy"),
        }
    }

    #[test]
    #[cfg(feature = "hysteria2")]
    fn parse_hysteria2_url_salamander_falls_back_to_auth_password() {
        // When obfs=salamander but no obfs-password, auth password is used as obfs password.
        let proxy = parse_proxy_url(
            "hysteria2://mypass@proxy.com:443?obfs=salamander",
        )
        .unwrap()
        .unwrap();
        match proxy {
            Proxy::Hysteria2 { password, config, .. } => {
                assert_eq!(password, "mypass");
                assert_eq!(config.get_obfs_password(), Some("mypass"));
            }
            _ => panic!("expected Hysteria2 proxy"),
        }
    }

    #[test]
    #[cfg(feature = "hysteria2")]
    fn parse_hysteria2_url_missing_password_is_error() {
        // hysteria2 requires password in userinfo position.
        let result = parse_proxy_url("hysteria2://proxy.com:443");
        assert!(result.is_err(), "missing password should return Err");
    }

    // ── JSON parsing – all scheme variants ───────────────────────────────────

    #[test]
    #[cfg(feature = "http")]
    fn parse_https_json() {
        let json = r#"{"protocol":"https","host":"proxy.com","port":8443}"#;
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        let proxy = parse_proxy_json(&value).unwrap().unwrap();
        match proxy {
            Proxy::HTTPS { host, port, .. } => {
                assert_eq!(host, "proxy.com");
                assert_eq!(port, 8443);
            }
            _ => panic!("expected HTTPS proxy"),
        }
    }

    #[test]
    #[cfg(feature = "socks4")]
    fn parse_socks4_json() {
        let json = r#"{"protocol":"socks4","host":"proxy.com","port":1080}"#;
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        let proxy = parse_proxy_json(&value).unwrap().unwrap();
        match proxy {
            Proxy::SOCKS4 { host, port, .. } => {
                assert_eq!(host, "proxy.com");
                assert_eq!(port, 1080);
            }
            _ => panic!("expected SOCKS4 proxy"),
        }
    }

    #[test]
    #[cfg(feature = "socks4")]
    fn parse_socks4a_json() {
        let json = r#"{"protocol":"socks4a","host":"proxy.com","port":1080}"#;
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        let proxy = parse_proxy_json(&value).unwrap().unwrap();
        match proxy {
            Proxy::SOCKS4A { host, port, .. } => {
                assert_eq!(host, "proxy.com");
                assert_eq!(port, 1080);
            }
            _ => panic!("expected SOCKS4A proxy"),
        }
    }

    #[test]
    #[cfg(feature = "socks5")]
    fn parse_socks5_json() {
        let json = r#"{"protocol":"socks5","host":"proxy.com","port":1080,"username":"u","password":"p"}"#;
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        let proxy = parse_proxy_json(&value).unwrap().unwrap();
        match proxy {
            Proxy::SOCKS5 { host, port, .. } => {
                assert_eq!(host, "proxy.com");
                assert_eq!(port, 1080);
            }
            _ => panic!("expected SOCKS5 proxy"),
        }
    }

    #[test]
    #[cfg(feature = "socks5")]
    fn parse_socks5h_json() {
        let json = r#"{"protocol":"socks5h","host":"proxy.com","port":1080}"#;
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        let proxy = parse_proxy_json(&value).unwrap().unwrap();
        match proxy {
            Proxy::SOCKS5H { host, port, .. } => {
                assert_eq!(host, "proxy.com");
                assert_eq!(port, 1080);
            }
            _ => panic!("expected SOCKS5H proxy"),
        }
    }

    #[test]
    #[cfg(feature = "tor")]
    fn parse_tor_json() {
        let json = r#"{"protocol":"tor","host":"127.0.0.1","port":9050}"#;
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        let proxy = parse_proxy_json(&value).unwrap().unwrap();
        match proxy {
            Proxy::Tor { host, port, .. } => {
                assert_eq!(host, "127.0.0.1");
                assert_eq!(port, 9050);
            }
            _ => panic!("expected Tor proxy"),
        }
    }

    #[test]
    #[cfg(feature = "shadowsocks")]
    fn parse_shadowsocks_json() {
        let json = r#"{"protocol":"shadowsocks","host":"proxy.com","port":8388,"password":"secret"}"#;
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        let proxy = parse_proxy_json(&value).unwrap().unwrap();
        match proxy {
            Proxy::Shadowsocks { host, port, password, .. } => {
                assert_eq!(host, "proxy.com");
                assert_eq!(port, 8388);
                assert_eq!(password, "secret");
            }
            _ => panic!("expected Shadowsocks proxy"),
        }
    }

    #[test]
    #[cfg(feature = "shadowsocks")]
    fn parse_ss_alias_json() {
        let json = r#"{"protocol":"ss","host":"proxy.com","port":8388,"password":"secret"}"#;
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        let proxy = parse_proxy_json(&value).unwrap().unwrap();
        match proxy {
            Proxy::Shadowsocks { .. } => {}
            _ => panic!("expected Shadowsocks proxy"),
        }
    }

    #[test]
    #[cfg(feature = "shadowsocks")]
    fn parse_shadowsocks_json_missing_password_is_error() {
        let json = r#"{"protocol":"shadowsocks","host":"proxy.com","port":8388}"#;
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        let result = parse_proxy_json(&value);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "hysteria2")]
    fn parse_hysteria2_json() {
        let json = r#"{"protocol":"hysteria2","host":"proxy.com","port":443,"password":"mypass"}"#;
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        let proxy = parse_proxy_json(&value).unwrap().unwrap();
        match proxy {
            Proxy::Hysteria2 { host, port, password, .. } => {
                assert_eq!(host, "proxy.com");
                assert_eq!(port, 443);
                assert_eq!(password, "mypass");
            }
            _ => panic!("expected Hysteria2 proxy"),
        }
    }

    #[test]
    #[cfg(feature = "hysteria2")]
    fn parse_hy2_alias_json() {
        let json = r#"{"protocol":"hy2","host":"proxy.com","port":443,"password":"mypass"}"#;
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        let proxy = parse_proxy_json(&value).unwrap().unwrap();
        match proxy {
            Proxy::Hysteria2 { .. } => {}
            _ => panic!("expected Hysteria2 proxy"),
        }
    }

    #[test]
    fn parse_json_not_an_object_is_error() {
        let value: serde_json::Value = serde_json::from_str(r#"["array"]"#).unwrap();
        let result = parse_proxy_json(&value);
        assert!(result.is_err());
    }

    #[test]
    fn parse_json_unsupported_protocol_is_error() {
        let json = r#"{"protocol":"ftp","host":"proxy.com","port":21}"#;
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        let result = parse_proxy_json(&value);
        assert!(result.is_err());
    }

    #[test]
    fn parse_json_port_defaults_when_missing() {
        // When port is absent the default for the scheme must be used.
        #[cfg(feature = "http")]
        {
            let json = r#"{"protocol":"http","host":"proxy.com"}"#;
            let value: serde_json::Value = serde_json::from_str(json).unwrap();
            let proxy = parse_proxy_json(&value).unwrap().unwrap();
            assert_eq!(proxy.get_port(), 8080);
        }
    }

    // ── parse_proxy_list_json (grouped format) ────────────────────────────────

    #[test]
    #[cfg(feature = "http")]
    fn parse_proxy_list_json_grouped_format() {
        let json = r#"{
            "configs": [
                {
                    "base": {
                        "handshake_timeout": 10,
                        "phase_timeout": 5,
                        "resolve_locally": false,
                        "tcp_nodelay": true,
                        "auto_tls": true
                    },
                    "proxies": [
                        {"protocol": "http", "host": "proxy1.com", "port": 8080},
                        {"protocol": "http", "host": "proxy2.com", "port": 8080}
                    ]
                }
            ]
        }"#;
        let proxies = parse_proxy_list_json(json).unwrap();
        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0].get_host(), "proxy1.com");
        assert_eq!(proxies[1].get_host(), "proxy2.com");
    }

    #[test]
    #[cfg(all(feature = "http", feature = "socks5"))]
    fn parse_proxy_list_json_multiple_groups() {
        let json = r#"{
            "configs": [
                {
                    "base": {"handshake_timeout": 10, "phase_timeout": 5, "resolve_locally": false, "tcp_nodelay": false, "auto_tls": false},
                    "proxies": [
                        {"protocol": "http", "host": "proxy1.com", "port": 8080}
                    ]
                },
                {
                    "base": {"handshake_timeout": 20, "phase_timeout": 10, "resolve_locally": true, "tcp_nodelay": true, "auto_tls": false},
                    "proxies": [
                        {"protocol": "socks5", "host": "proxy2.com", "port": 1080}
                    ]
                }
            ]
        }"#;
        let proxies = parse_proxy_list_json(json).unwrap();
        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0].get_scheme(), "http");
        assert_eq!(proxies[1].get_scheme(), "socks5");
    }

    #[test]
    fn parse_proxy_list_json_missing_configs_is_error() {
        let json = r#"{"proxies": []}"#;
        let result = parse_proxy_list_json(json);
        assert!(result.is_err());
    }

    // ── Default port mapping ──────────────────────────────────────────────────

    #[test]
    fn default_port_http() {
        assert_eq!(default_port_for_scheme("http"), 8080);
    }

    #[test]
    fn default_port_https() {
        assert_eq!(default_port_for_scheme("https"), 8443);
    }

    #[test]
    fn default_port_socks4() {
        assert_eq!(default_port_for_scheme("socks4"), 1080);
        assert_eq!(default_port_for_scheme("socks4a"), 1080);
    }

    #[test]
    fn default_port_socks5() {
        assert_eq!(default_port_for_scheme("socks5"), 1080);
        assert_eq!(default_port_for_scheme("socks5h"), 1080);
    }

    #[test]
    fn default_port_tor() {
        assert_eq!(default_port_for_scheme("tor"), 9050);
    }

    #[test]
    fn default_port_shadowsocks() {
        assert_eq!(default_port_for_scheme("shadowsocks"), 8388);
        assert_eq!(default_port_for_scheme("ss"), 8388);
    }

    #[test]
    #[cfg(feature = "hysteria2")]
    fn default_port_hysteria2() {
        assert_eq!(default_port_for_scheme("hysteria2"), 443);
        assert_eq!(default_port_for_scheme("hy2"), 443);
    }

    #[test]
    fn default_port_unknown_falls_back() {
        assert_eq!(default_port_for_scheme("unknown"), 8080);
    }
}
