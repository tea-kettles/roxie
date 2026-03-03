//! Configuration validation errors.
//!
//! Rich, descriptive errors returned by `Config::validate` implementations
//! across all proxy configuration modules. These errors identify exactly
//! which field is invalid and what the expected values are.
//!
//! # Examples
//!
//! ```
//! use roxie::errors::config_errors::ConfigError;
//!
//! let err = ConfigError::InvalidValue {
//!     field: "port".to_string(),
//!     value: "0".to_string(),
//!     expected: "1-65535".to_string(),
//! };
//!
//! assert!(err.to_string().contains("port"));
//! assert!(err.to_string().contains("expected 1-65535"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use thiserror::Error;

/* Types */

/// Errors emitted during configuration validation.
///
/// All configuration errors follow a consistent pattern of identifying
/// the problematic field, the invalid value received, and what was expected.
/// This makes configuration issues immediately actionable.
///
/// # Examples
///
/// Missing required field:
///
/// ```
/// use roxie::errors::config_errors::ConfigError;
///
/// let err = ConfigError::MissingRequiredField {
///     field: "host".to_string(),
/// };
///
/// assert_eq!(err.to_string(), "missing required configuration field 'host'");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// Invalid value with guidance:
///
/// ```
/// use roxie::errors::config_errors::ConfigError;
///
/// let err = ConfigError::InvalidValue {
///     field: "method".to_string(),
///     value: "bad-cipher".to_string(),
///     expected: "aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305".to_string(),
/// };
///
/// assert!(err.to_string().contains("bad-cipher"));
/// assert!(err.to_string().contains("expected"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    /// A required configuration field was not provided.
    ///
    /// This error identifies exactly which field is missing, allowing the
    /// caller to immediately know what configuration is incomplete.
    #[error("missing required configuration field '{field}'")]
    MissingRequiredField {
        /// Name of the missing required field.
        field: String,
    },

    /// A configuration field contained an invalid value.
    ///
    /// This error provides the field name, the invalid value that was provided,
    /// and a description of what values are valid. This allows immediate
    /// correction of the configuration issue.
    #[error(
        "invalid value for configuration field '{field}': received '{value}', expected {expected}"
    )]
    InvalidValue {
        /// Name of the field with an invalid value.
        field: String,
        /// The invalid value that was provided.
        value: String,
        /// Description of valid values or the expected range.
        expected: String,
    },
}

/* Aliases */

/// Convenience result type for configuration validation.
///
/// This type alias reduces boilerplate in configuration validation code by
/// providing a consistent return type across all `validate()` methods.
///
/// # Examples
///
/// ```
/// use roxie::errors::config_errors::{ConfigError, ConfigResult};
///
/// fn validate_port(port: u16) -> ConfigResult<()> {
///     if port == 0 {
///         return Err(ConfigError::InvalidValue {
///             field: "port".to_string(),
///             value: "0".to_string(),
///             expected: "1-65535".to_string(),
///         });
///     }
///     Ok(())
/// }
///
/// assert!(validate_port(8080).is_ok());
/// assert!(validate_port(0).is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub type ConfigResult<T> = std::result::Result<T, ConfigError>;
