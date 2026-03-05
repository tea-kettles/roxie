//! Static proxy collection.
//!
//! Provides parsing and storage for lists of proxies with efficient
//! access patterns. ProxyList is immutable once created and allows
//! random selection and iteration.

use std::path::Path;
use std::sync::Arc;

use rand::seq::SliceRandom;
use rand::thread_rng;
use serde_json::{Value, from_str};
use tracing::info;

use crate::config::BaseProxyConfig;
use crate::errors::{ParseError, ProxyError};
use crate::transport::Proxy;
use crate::utils::{json_export, parse_proxy_json, parse_proxy_list_json, parse_proxy_url};

/* Types */

/// Static proxy collection providing efficient access patterns.
///
/// # Examples
///
/// From newline-separated URLs:
/// ```
/// use roxie::transport::ProxyList;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let lines = r#"
/// http://user:pass@proxy1.com:8080
/// socks5://user:pass@proxy2.com:1080
/// "#;
///
/// let list = ProxyList::from_lines(lines)?;
/// assert_eq!(list.len(), 2);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ProxyList {
    proxies: Arc<Vec<Proxy>>,
}

/* Implementations */

impl ProxyList {
    /// Creates a ProxyList from a pre-parsed proxy vector.
    pub(crate) fn from_proxies(proxies: Vec<Proxy>) -> Self {
        Self {
            proxies: Arc::new(proxies),
        }
    }

    /// Creates a ProxyList from newline-separated proxy URLs.
    ///
    /// Lines starting with `#` are ignored as comments.
    /// Empty lines are skipped.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyList;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let lines = r#"
    /// # Comment line
    /// http://user:pass@proxy1.com:8080
    /// https://user:pass@proxy2.com:8443
    /// socks4://proxy3.com:1080
    /// socks5://user:pass@proxy4.com:1080
    /// "#;
    ///
    /// let list = ProxyList::from_lines(lines)?;
    /// assert_eq!(list.len(), 4);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_lines(lines_str: &str) -> Result<Self, ParseError> {
        info!("parsing proxy lines");

        let mut proxies = Vec::new();
        let mut candidate_count = 0;

        for (index, line) in lines_str.lines().enumerate() {
            let line_num = index + 1;
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            candidate_count += 1;
            match parse_proxy_url(line) {
                Ok(Some(proxy)) => proxies.push(proxy),
                Ok(None) => {} // Skipped with warning
                Err(e) => {
                    return Err(ParseError::ParseErrorAtLine {
                        line: line_num,
                        source: Box::new(e),
                    });
                }
            }
        }

        info!(
            "{}/{} proxies successfully added",
            proxies.len(),
            candidate_count
        );

        Ok(Self::from_proxies(proxies))
    }

    /// Creates a ProxyList from JSON array of proxy URL strings.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyList;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let json = r#"[
    ///     "http://user:pass@proxy1.com:8080",
    ///     "socks5://user:pass@proxy2.com:1080"
    /// ]"#;
    ///
    /// let list = ProxyList::from_array(json)?;
    /// assert_eq!(list.len(), 2);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_array(json_str: &str) -> Result<Self, ParseError> {
        info!("parsing JSON array");

        let parsed: Vec<Value> = from_str(json_str)?;
        let mut proxies = Vec::with_capacity(parsed.len());

        for (index, value) in parsed.iter().enumerate() {
            if let Value::String(proxy_str) = value {
                match parse_proxy_url(proxy_str) {
                    Ok(Some(proxy)) => proxies.push(proxy),
                    Ok(None) => {} // Skipped
                    Err(e) => {
                        return Err(ParseError::ParseErrorAtIndex {
                            index,
                            source: Box::new(e),
                        });
                    }
                }
            }
        }

        info!(
            "{}/{} proxies successfully added",
            proxies.len(),
            parsed.len()
        );

        Ok(Self::from_proxies(proxies))
    }

    /// Creates a ProxyList from structured JSON format.
    ///
    /// Supports both the new grouped format and legacy format for backwards compatibility.
    ///
    /// New grouped format groups proxies by shared base configuration:
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
    ///                     "host": "proxy.com",
    ///                     "port": 8080
    ///                 }
    ///             ]
    ///         }
    ///     ]
    /// }
    /// ```
    ///
    /// Legacy format (still supported):
    /// ```json
    /// {
    ///     "proxies": [
    ///         {
    ///             "protocol": "http",
    ///             "host": "proxy.com",
    ///             "port": 8080,
    ///             "base": { ... }
    ///         }
    ///     ]
    /// }
    /// ```
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyList;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let json = r#"{
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
    ///                     "host": "proxy.com",
    ///                     "port": 8080
    ///                 }
    ///             ]
    ///         }
    ///     ]
    /// }"#;
    ///
    /// let list = ProxyList::from_json(json)?;
    /// assert_eq!(list.len(), 1);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_json(json_str: &str) -> Result<Self, ParseError> {
        info!("parsing JSON object");

        // Try new grouped format first
        if let Ok(proxies) = parse_proxy_list_json(json_str) {
            info!(
                "{} proxies successfully parsed from grouped format",
                proxies.len()
            );
            return Ok(Self::from_proxies(proxies));
        }

        // Fall back to legacy format for backwards compatibility
        let parsed: Value = from_str(json_str)?;

        let proxies_array = parsed
            .get("proxies")
            .and_then(|v| v.as_array())
            .ok_or_else(|| ParseError::InvalidJsonStructure {
                expected: "object with 'proxies' or 'configs' array".to_string(),
                found: "other".to_string(),
            })?;

        let mut proxies = Vec::with_capacity(proxies_array.len());

        for (index, proxy_value) in proxies_array.iter().enumerate() {
            match parse_proxy_json(proxy_value) {
                Ok(Some(proxy)) => proxies.push(proxy),
                Ok(None) => {} // Skipped
                Err(e) => {
                    return Err(ParseError::ParseErrorAtIndex {
                        index,
                        source: Box::new(e),
                    });
                }
            }
        }

        info!(
            "{}/{} proxies successfully added from legacy format",
            proxies.len(),
            proxies_array.len()
        );

        Ok(Self::from_proxies(proxies))
    }

    /// Returns the total number of proxies in the list.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyList;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let lines = "http://proxy.com:8080\nsocks5://localhost:1080";
    /// let list = ProxyList::from_lines(lines)?;
    /// assert_eq!(list.len(), 2);
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn len(&self) -> usize {
        self.proxies.len()
    }

    /// Returns true if the proxy list contains no proxies.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyList;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let list = ProxyList::from_lines("")?;
    /// assert!(list.is_empty());
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    /// Gets a proxy by its index in the list.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyList;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let lines = "http://proxy.com:8080";
    /// let list = ProxyList::from_lines(lines)?;
    /// assert!(list.get(0).is_some());
    /// assert!(list.get(1).is_none());
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn get(&self, index: usize) -> Option<&Proxy> {
        self.proxies.get(index)
    }

    /// Returns iterator over all proxies in the list.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyList;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let lines = "http://proxy1.com:8080\nhttp://proxy2.com:8080";
    /// let list = ProxyList::from_lines(lines)?;
    ///
    /// for proxy in list.iter() {
    ///     println!("Proxy: {}:{}", proxy.get_host(), proxy.get_port());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &Proxy> + '_ {
        self.proxies.iter()
    }

    /// Gets a random proxy from the entire list.
    ///
    /// Returns `None` if the list is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyList;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let lines = "http://proxy1.com:8080\nhttp://proxy2.com:8080";
    /// let list = ProxyList::from_lines(lines)?;
    /// let random = list.random();
    /// assert!(random.is_some());
    /// # Ok(())
    /// # }
    /// ```
    pub fn random(&self) -> Option<&Proxy> {
        let mut rng = thread_rng();
        self.proxies.as_slice().choose(&mut rng)
    }

    /// Applies base configuration to all proxies in the list.
    ///
    /// Takes ownership of the list and returns a new list where all proxies
    /// share the same base configuration (timeouts, TLS settings, etc.).
    /// This is the primary way to configure proxy behavior at scale.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyList;
    /// use roxie::config::BaseProxyConfig;
    /// use std::time::Duration;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let lines = "http://proxy1.com:8080\nhttp://proxy2.com:8080";
    /// let list = ProxyList::from_lines(lines)?;
    ///
    /// let mut config = BaseProxyConfig::new();
    /// config.set_handshake_timeout(Duration::from_secs(15));
    /// config.set_tcp_nodelay(true);
    /// config.set_auto_tls(true);
    ///
    /// let configured_list = list.config(config);
    /// # Ok(())
    /// # }
    /// ```
    pub fn config(self, base: BaseProxyConfig) -> Self {
        let shared = Arc::new(base);

        let proxies = self
            .proxies
            .iter()
            .cloned()
            .map(|proxy| proxy.with_base_config(shared.clone()))
            .collect();

        Self {
            proxies: Arc::new(proxies),
        }
    }

    /// Exports the proxy list to a JSON file.
    ///
    /// Creates a structured JSON document containing all proxies in the list and
    /// writes it to the specified filesystem path. The output format matches the
    /// structure expected by [`ProxyList::from_json`], enabling roundtrip
    /// serialization and deserialization.
    ///
    /// # Arguments
    ///
    /// * `output_path` - Filesystem path where the JSON file will be written
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::SerializationError`] if JSON serialization fails.
    /// Returns [`ProxyError::Io`] if file writing fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use roxie::transport::ProxyList;
    /// use std::path::Path;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let list = ProxyList::from_lines("http://proxy.com:8080")?;
    /// list.export_json(Path::new("proxies.json")).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn export_json<P: AsRef<Path>>(&self, output_path: P) -> Result<(), ProxyError> {
        json_export::export_proxies_to_json(self.iter(), output_path.as_ref()).await
    }
}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HasBaseProxyConfig;

    #[test]
    #[cfg(feature = "http")]
    fn from_lines_parses_http() {
        let lines = "http://user:pass@proxy.com:8080";
        let list = ProxyList::from_lines(lines).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list.get(0).unwrap().get_host(), "proxy.com");
    }

    #[test]
    fn from_lines_ignores_comments() {
        let lines = "# This is a comment\nhttp://proxy.com:8080";
        let list = ProxyList::from_lines(lines).unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn from_lines_ignores_empty_lines() {
        let lines = "\n\nhttp://proxy.com:8080\n\n";
        let list = ProxyList::from_lines(lines).unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    #[cfg(feature = "http")]
    fn from_array_parses_proxies() {
        let json = r#"["http://proxy.com:8080", "http://proxy2.com:8080"]"#;
        let list = ProxyList::from_array(json).unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    #[cfg(feature = "http")]
    fn from_json_parses_proxies() {
        let json = r#"{
            "proxies": [
                {"protocol": "http", "host": "proxy.com", "port": 8080}
            ]
        }"#;
        let list = ProxyList::from_json(json).unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn is_empty_returns_true_for_empty() {
        let list = ProxyList::from_lines("").unwrap();
        assert!(list.is_empty());
    }

    #[test]
    #[cfg(feature = "http")]
    fn is_empty_returns_false_for_nonempty() {
        let list = ProxyList::from_lines("http://proxy.com:8080").unwrap();
        assert!(!list.is_empty());
    }

    #[test]
    #[cfg(feature = "http")]
    fn get_returns_proxy_at_index() {
        let list = ProxyList::from_lines("http://proxy.com:8080").unwrap();
        assert!(list.get(0).is_some());
        assert!(list.get(1).is_none());
    }

    #[test]
    #[cfg(feature = "http")]
    fn iter_iterates_all_proxies() {
        let lines = "http://proxy1.com:8080\nhttp://proxy2.com:8080";
        let list = ProxyList::from_lines(lines).unwrap();
        let count = list.iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    #[cfg(feature = "http")]
    fn random_returns_some_for_nonempty() {
        let list = ProxyList::from_lines("http://proxy.com:8080").unwrap();
        assert!(list.random().is_some());
    }

    #[test]
    fn random_returns_none_for_empty() {
        let list = ProxyList::from_lines("").unwrap();
        assert!(list.random().is_none());
    }

    #[test]
    #[cfg(feature = "http")]
    fn from_json_grouped_format_parses_proxies() {
        let json = r#"{
            "configs": [
                {
                    "base": {
                        "handshake_timeout": 10,
                        "phase_timeout": 5,
                        "resolve_locally": false,
                        "tcp_nodelay": true,
                        "auto_tls": false
                    },
                    "proxies": [
                        {"protocol": "http", "host": "proxy1.com", "port": 8080},
                        {"protocol": "http", "host": "proxy2.com", "port": 8080}
                    ]
                }
            ]
        }"#;
        let list = ProxyList::from_json(json).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list.get(0).unwrap().get_host(), "proxy1.com");
        assert_eq!(list.get(1).unwrap().get_host(), "proxy2.com");
    }

    #[test]
    #[cfg(feature = "http")]
    fn from_json_legacy_format_parses_proxies() {
        let json = r#"{
            "proxies": [
                {"protocol": "http", "host": "proxy.com", "port": 8080}
            ]
        }"#;
        let list = ProxyList::from_json(json).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list.get(0).unwrap().get_host(), "proxy.com");
    }

    #[test]
    #[cfg(feature = "http")]
    fn config_applies_base_to_all_proxies() {
        use std::time::Duration;
        let lines = "http://proxy1.com:8080\nhttp://proxy2.com:8080";
        let list = ProxyList::from_lines(lines).unwrap();

        let mut base = BaseProxyConfig::new();
        base.set_handshake_timeout(Duration::from_secs(77));
        base.set_tcp_nodelay(true);

        let configured = list.config(base);
        assert_eq!(configured.len(), 2);

        for proxy in configured.iter() {
            match proxy {
                Proxy::HTTP { config, .. } => {
                    assert_eq!(
                        config.get_base_config().get_handshake_timeout(),
                        Duration::from_secs(77)
                    );
                    assert!(config.get_base_config().is_tcp_nodelay());
                }
                _ => panic!("expected HTTP proxy"),
            }
        }
    }

    #[test]
    #[cfg(feature = "http")]
    fn config_returns_list_of_same_length() {
        let list = ProxyList::from_lines("http://proxy.com:8080").unwrap();
        let configured = list.config(BaseProxyConfig::new());
        assert_eq!(configured.len(), 1);
    }

    #[test]
    fn from_lines_returns_error_on_invalid_url() {
        // A non-empty, non-comment line that is not a valid URL should yield an error.
        let result = ProxyList::from_lines("not a url at all");
        assert!(result.is_err(), "expected Err for invalid URL line");
    }

    #[test]
    #[cfg(feature = "http")]
    fn from_array_skips_non_string_entries() {
        // JSON array with a mix of strings and non-strings – non-strings are silently skipped.
        let json = r#"["http://proxy.com:8080", 42, null, "http://proxy2.com:8080"]"#;
        let list = ProxyList::from_array(json).unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn from_array_returns_error_on_invalid_json() {
        let result = ProxyList::from_array("{not json}");
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "http")]
    fn iter_returns_all_proxies_in_order() {
        let lines = "http://first.com:8080\nhttp://second.com:8080\nhttp://third.com:8080";
        let list = ProxyList::from_lines(lines).unwrap();
        let hosts: Vec<&str> = list.iter().map(|p| p.get_host()).collect();
        assert_eq!(hosts, ["first.com", "second.com", "third.com"]);
    }

    #[test]
    #[cfg(feature = "http")]
    fn get_returns_none_past_end() {
        let list = ProxyList::from_lines("http://proxy.com:8080").unwrap();
        assert!(list.get(0).is_some());
        assert!(list.get(1).is_none());
        assert!(list.get(100).is_none());
    }

    #[test]
    #[cfg(all(feature = "http", feature = "socks5"))]
    fn from_lines_parses_multiple_protocols() {
        let lines = "http://proxy.com:8080\nsocks5://proxy2.com:1080";
        let list = ProxyList::from_lines(lines).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list.get(0).unwrap().get_scheme(), "http");
        assert_eq!(list.get(1).unwrap().get_scheme(), "socks5");
    }
}
