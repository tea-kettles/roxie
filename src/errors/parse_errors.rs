//! Proxy parsing error types.
//!
//! Errors that can occur when parsing proxy URLs and JSON configurations.
//! These errors provide detailed context about what was invalid in the input
//! and where in the parsing process the error occurred.
//!
//! # Examples
//!
//! URL parsing error:
//!
//! ```
//! use roxie::errors::ParseError;
//!
//! let err = ParseError::InvalidUrl {
//!     url: "not-a-valid-url".to_string(),
//!     reason: "missing scheme (http/https/socks5/etc)".to_string(),
//! };
//!
//! assert!(err.to_string().contains("not-a-valid-url"));
//! assert!(err.to_string().contains("missing scheme"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use serde_json::Error as JsonError;

/* Types */

/// Errors that can occur during proxy URL and configuration parsing.
///
/// Parse errors are organized into three categories:
/// 1. URL parsing errors (scheme, host, port validation)
/// 2. JSON parsing errors (structure, field validation)
/// 3. Context errors (line/index information for batch parsing)
///
/// All errors provide actionable information about what was invalid and why.
///
/// # Examples
///
/// Missing required field in JSON:
///
/// ```
/// use roxie::errors::ParseError;
///
/// let err = ParseError::MissingField {
///     field: "host".to_string(),
/// };
///
/// assert_eq!(err.to_string(), "missing required field: 'host'");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// Invalid port number:
///
/// ```
/// use roxie::errors::ParseError;
///
/// let err = ParseError::InvalidPort {
///     url: "proxy.example.com:99999".to_string(),
///     reason: "port must be between 1 and 65535".to_string(),
/// };
///
/// assert!(err.to_string().contains("99999"));
/// assert!(err.to_string().contains("65535"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /* URL Parsing Errors */
    //
    // Errors related to parsing proxy URLs including scheme, host, port,
    // and credential validation.
    /// Invalid proxy URL format.
    ///
    /// This error occurs when a URL cannot be parsed or contains invalid
    /// components. The reason field provides specific details about what
    /// was wrong with the URL.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::errors::ParseError;
    ///
    /// let err = ParseError::InvalidUrl {
    ///     url: "ht!tp://bad".to_string(),
    ///     reason: "invalid character in scheme".to_string(),
    /// };
    ///
    /// assert!(err.to_string().contains("invalid character"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[error("invalid proxy URL: '{url}' - {reason}")]
    InvalidUrl {
        /// The invalid URL that was provided.
        url: String,
        /// Specific reason the URL is invalid.
        reason: String,
    },

    /// Missing scheme in proxy URL.
    ///
    /// This error occurs when a URL lacks a protocol scheme (for example,
    /// "http://", "socks5://"). The scheme is required to determine which
    /// proxy protocol to use.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::errors::ParseError;
    ///
    /// let err = ParseError::MissingScheme {
    ///     url: "proxy.example.com:1080".to_string(),
    /// };
    ///
    /// assert!(err.to_string().contains("missing scheme"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[error("missing scheme in proxy URL: '{url}'")]
    MissingScheme {
        /// URL that is missing a scheme.
        url: String,
    },

    /// Unsupported proxy scheme.
    ///
    /// This error occurs when the URL scheme is not recognized as a supported
    /// proxy protocol (for example, "ftp://" when only HTTP and SOCKS are supported).
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::errors::ParseError;
    ///
    /// let err = ParseError::UnsupportedScheme {
    ///     scheme: "ftp".to_string(),
    /// };
    ///
    /// assert!(err.to_string().contains("unsupported"));
    /// assert!(err.to_string().contains("ftp"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[error("unsupported proxy scheme: '{scheme}'")]
    UnsupportedScheme {
        /// The unsupported scheme that was encountered.
        scheme: String,
    },

    /// Missing host in proxy URL.
    ///
    /// This error occurs when the URL does not specify a hostname or IP address
    /// for the proxy server.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::errors::ParseError;
    ///
    /// let err = ParseError::MissingHost {
    ///     url: "socks5://:1080".to_string(),
    /// };
    ///
    /// assert!(err.to_string().contains("missing host"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[error("missing host in proxy URL: '{url}'")]
    MissingHost {
        /// URL that is missing a host.
        url: String,
    },

    /// Missing port in proxy URL.
    ///
    /// This error occurs when the URL does not specify a port number and no
    /// default port is available for the protocol.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::errors::ParseError;
    ///
    /// let err = ParseError::MissingPort {
    ///     url: "socks5://proxy.example.com".to_string(),
    /// };
    ///
    /// assert!(err.to_string().contains("missing port"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[error("missing port in proxy URL: '{url}'")]
    MissingPort {
        /// URL that is missing a port.
        url: String,
    },

    /// Invalid port in proxy URL.
    ///
    /// This error occurs when the port number is not a valid integer or is
    /// outside the valid range (1-65535).
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::errors::ParseError;
    ///
    /// let err = ParseError::InvalidPort {
    ///     url: "proxy.example.com:99999".to_string(),
    ///     reason: "port out of range (1-65535)".to_string(),
    /// };
    ///
    /// assert!(err.to_string().contains("99999"));
    /// assert!(err.to_string().contains("out of range"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[error("invalid port in proxy URL: '{url}' - {reason}")]
    InvalidPort {
        /// URL containing the invalid port.
        url: String,
        /// Specific reason the port is invalid.
        reason: String,
    },

    /* JSON Parsing Errors */
    //
    // Errors related to parsing JSON configuration files including
    // structure validation and field validation.
    /// Invalid JSON syntax.
    ///
    /// This error wraps serde_json parsing errors and preserves the underlying
    /// error for detailed diagnostics.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::errors::ParseError;
    /// use serde_json::Error as JsonError;
    ///
    /// // This would typically come from serde_json::from_str
    /// let json_err = serde_json::from_str::<serde_json::Value>("{invalid}").unwrap_err();
    /// let err = ParseError::InvalidJson { source: json_err };
    ///
    /// assert!(err.to_string().contains("invalid JSON"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[error("invalid JSON: {source}")]
    InvalidJson {
        /// Underlying serde_json parsing error.
        #[source]
        source: JsonError,
    },

    /// Invalid JSON structure.
    ///
    /// This error occurs when JSON is syntactically valid but doesn't match
    /// the expected structure (for example, expected an object but got an array).
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::errors::ParseError;
    ///
    /// let err = ParseError::InvalidJsonStructure {
    ///     expected: "object with 'host' and 'port' fields".to_string(),
    ///     found: "array".to_string(),
    /// };
    ///
    /// assert!(err.to_string().contains("expected object"));
    /// assert!(err.to_string().contains("found array"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[error("invalid JSON structure: expected {expected}, found {found}")]
    InvalidJsonStructure {
        /// Description of the expected structure.
        expected: String,
        /// Description of what was actually found.
        found: String,
    },

    /// Missing required field in JSON.
    ///
    /// This error occurs when a required field is not present in the JSON
    /// configuration object.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::errors::ParseError;
    ///
    /// let err = ParseError::MissingField {
    ///     field: "password".to_string(),
    /// };
    ///
    /// assert!(err.to_string().contains("password"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[error("missing required field: '{field}'")]
    MissingField {
        /// Name of the missing required field.
        field: String,
    },

    /// Invalid field value in JSON.
    ///
    /// This error occurs when a field's value is present but invalid (for example,
    /// wrong type, out of range, or doesn't match expected format).
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::errors::ParseError;
    ///
    /// let err = ParseError::InvalidFieldValue {
    ///     field: "timeout".to_string(),
    ///     reason: "must be a positive number".to_string(),
    /// };
    ///
    /// assert!(err.to_string().contains("timeout"));
    /// assert!(err.to_string().contains("positive number"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[error("invalid field value for '{field}': {reason}")]
    InvalidFieldValue {
        /// Name of the field with an invalid value.
        field: String,
        /// Reason the value is invalid.
        reason: String,
    },

    /* Parse Error Context */
    //
    // Errors that provide positional context when parsing lists or files
    // containing multiple proxy configurations.
    /// Error parsing proxy at specific index.
    ///
    /// This error wraps another ParseError and adds positional context for
    /// batch parsing operations (for example, parsing an array of proxy configs).
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::errors::ParseError;
    ///
    /// let inner = ParseError::MissingHost {
    ///     url: "socks5://:1080".to_string(),
    /// };
    ///
    /// let err = ParseError::ParseErrorAtIndex {
    ///     index: 3,
    ///     source: Box::new(inner),
    /// };
    ///
    /// assert!(err.to_string().contains("index 3"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[error("error parsing proxy at index {index}: {source}")]
    ParseErrorAtIndex {
        /// Zero-based index of the proxy that failed to parse.
        index: usize,
        /// Underlying parse error.
        #[source]
        source: Box<ParseError>,
    },

    /// Error parsing proxy at specific line.
    ///
    /// This error wraps another ParseError and adds line number context for
    /// file parsing operations (for example, parsing a newline-delimited list).
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::errors::ParseError;
    ///
    /// let inner = ParseError::UnsupportedScheme {
    ///     scheme: "telnet".to_string(),
    /// };
    ///
    /// let err = ParseError::ParseErrorAtLine {
    ///     line: 42,
    ///     source: Box::new(inner),
    /// };
    ///
    /// assert!(err.to_string().contains("line 42"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[error("error parsing proxy at line {line}: {source}")]
    ParseErrorAtLine {
        /// One-based line number where the error occurred.
        line: usize,
        /// Underlying parse error.
        #[source]
        source: Box<ParseError>,
    },

    /* Configuration Parsing Errors */
    //
    // Errors specific to parsing configuration values like timeouts and booleans.
    /// Invalid timeout value.
    ///
    /// This error occurs when a timeout value cannot be parsed or is outside
    /// the acceptable range.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::errors::ParseError;
    ///
    /// let err = ParseError::InvalidTimeout {
    ///     value: "-5".to_string(),
    ///     reason: "timeout cannot be negative".to_string(),
    /// };
    ///
    /// assert!(err.to_string().contains("negative"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[error("invalid timeout value: {value} - {reason}")]
    InvalidTimeout {
        /// The invalid timeout value.
        value: String,
        /// Reason the timeout is invalid.
        reason: String,
    },

    /// Invalid boolean value.
    ///
    /// This error occurs when a field expects a boolean but receives a value
    /// that cannot be interpreted as true/false.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::errors::ParseError;
    ///
    /// let err = ParseError::InvalidBoolean {
    ///     field: "enabled".to_string(),
    ///     value: "maybe".to_string(),
    /// };
    ///
    /// assert!(err.to_string().contains("enabled"));
    /// assert!(err.to_string().contains("maybe"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[error("invalid boolean value for '{field}': {value}")]
    InvalidBoolean {
        /// Name of the field expecting a boolean.
        field: String,
        /// The invalid value that was provided.
        value: String,
    },
}

/* From Implementations */

impl From<JsonError> for ParseError {
    /// Convert serde_json errors into ParseError.
    ///
    /// This allows using `?` operator when parsing JSON, automatically
    /// wrapping serde_json errors in our error type.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::errors::ParseError;
    ///
    /// fn parse_config(json: &str) -> Result<serde_json::Value, ParseError> {
    ///     let value = serde_json::from_str(json)?; // Auto-converts JsonError
    ///     Ok(value)
    /// }
    ///
    /// assert!(parse_config("{invalid}").is_err());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn from(source: JsonError) -> Self {
        Self::InvalidJson { source }
    }
}
