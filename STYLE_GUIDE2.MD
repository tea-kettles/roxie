# Rust STYLE_GUIDE.md

Project wide style rules for Rust code in this repository.

Goals:
- Code reads like a clear narrative.
- Errors are full incident reports, not guesses.
- Examples are copy pasteable and work as is.
- Logs allow you to replay what happened almost line by line.

**Note:** This guide represents our team's preferences and practices, developed through experience building networked systems and proxy infrastructure. While prescriptive, these rules are meant to be followed with judgment - if you have a good reason to deviate, document it.

---

## 1. General principles

- Prefer clarity over cleverness.
- Prefer explicit structure over hidden behavior.
- Favor small, composable pieces with clear responsibilities.
- Keep items as private as possible and expose only what callers need.
- Manual and explicit code is preferred over macro magic - if you can't easily search for where a log comes from, it's too clever.
- Quality over quantity in all things - tests, dependencies, abstractions.

---

## 2. Naming

### 2.1 Methods

Methods use concise, imperative verbs. The type and module provide context.

- Good:
  - `greet`
  - `authenticate`
  - `connect`
  - `get`
- Avoid:
  - `socks_5_greeting_phase`
  - `perform_connection_authentication_handshake`

Examples:
```rust
impl Connection {
    pub fn new(addr: SocketAddr) -> Result<Self> { /* ... */ }
    pub fn connect(&mut self) -> Result<()> { /* ... */ }
    pub fn authenticate(&mut self) -> Result<()> { /* ... */ }
}

impl SocksClient {
    pub fn greet(&mut self) -> Result<()> { /* ... */ }
}
```

Guidelines:
* Constructors: Always use `new()` for the basic constructor. Use `from_*` for alternative constructors. Use `builder()` for complex configuration.
* Getters: `get_foo()` for simple accessors when obvious, `set_foo()` for setters. These are not standard Rust syntax, but enforce these so the API is consistent and predictable. You shouldn't need to read more than the method name itself to know exactly what is a getter and what is a setter.
* Boolean methods: use `is_`, `has_`, `can_`, `should_` (`is_connected`, `has_expired`).
* Async: do not suffix `_async` unless you must distinguish sync and async variants.
* Blocking operations in async contexts: suffix with `_blocking` if there's potential confusion.

### 2.2 Constructor patterns

All basic constructors must be named `new()`. The context comes from the struct/impl itself:

```rust
impl Connection {
    /// Basic constructor - always named `new()`
    pub fn new(addr: SocketAddr) -> Result<Self> { /* ... */ }
    
    /// Alternative constructors use `from_*` prefix
    pub fn from_stream(stream: TcpStream) -> Result<Self> { /* ... */ }
    pub fn from_config(config: &Config) -> Result<Self> { /* ... */ }
    
    /// Complex configuration uses builder pattern
    pub fn builder() -> ConnectionBuilder { /* ... */ }
    
    /// Methods that modify state, not constructors
    pub fn connect(&mut self) -> Result<()> { /* ... */ }
    pub fn authenticate(&mut self) -> Result<()> { /* ... */ }
}
```

This makes the distinction clear: `new()` creates objects, other methods provide functions.

### 2.2.1 Getter patterns

All object or string returning getters must be prefixed with `get_*()` to prevent confusion and for disambiguation.

Getters must be cheap, side-effect free, and must not perform mutation, I O, synchronization, or state transitions.

Optional getters must return `Option<T>` when the absence of a value is meaningful (for example, denoting whether a feature is enabled).

Sizes:
- Size getter methods that measure length must end in `*_len()` (ex. byte size).
- Size getter methods that measure quantity must end in `*_count()` (ex. item count).

Booleans:
- Boolean getter methods that measure state must be prefixed with `is_*()`.
- Boolean getter methods that measure existence must start with `has_*()`.
- Boolean getter methods that measure capability must start with `can_*()`.

Ownership:
- Getters must not transfer ownership.
- Accessors that move values out must use explicit verbs such as `take_*()`.
- Getters must return borrowed values unless the type is Copy. If ownership transfer is required, use a take_*() method explicitly.

Mutability:
- Mutable accessors return `&mut T` and still use the `get_*()` prefix.
- Mutable variants must follow the same naming structure (get_*_mut) only if the method returns &mut T. Do not overload get_*() with internal mutation.

Conventions:
- The `try_*` prefix is reserved for methods returning `Result<T, E>` and must not be used for optional getters.
- Time based getters must include explicit units in the name.

### 2.2.2 Setter patterns

Setter methods mutate state and must be explicit about intent.

Naming:
- Use `set_*()` only for direct, synchronous assignment.
- Setters must not perform I/O, synchronization, async work, or state transitions.

Fallibility:
- If mutation can fail, do not use `set_*`.
- Use an explicit verb and return `Result<T, E>`.

Booleans:
- Boolean setters use `set_*` with explicit intent (`set_tls_enabled`).
- Use action verbs (`enable_*`, `disable_*`) only when behavior occurs.

Optional fields:
- `set_*()` explicitly configures or enables a value.
- `clear_*()` explicitly removes or disables a value.
- Do not accept `Option<T>` in setters.

Invariants:
- Avoid multiple setters that must be kept in sync.
- Prefer a single method that updates related state together.

Ownership:
- Setters that consume values take ownership explicitly.
- Document expensive clones when unavoidable.

### 2.3 Types and modules

* Structs, enums, traits, type aliases: `PascalCase`
  Example: `SocksClient`, `AuthState`, `HandshakeError`
* Modules and files: `snake_case`
  Example: `connection.rs`, `auth.rs`, `encryption.rs`

### 2.4 Structured logging fields

Use consistent, descriptive names for structured fields in logs:

- Connection info: `local_addr`, `remote_addr`, `peer_addr`, `proxy_addr`
- Timing: `elapsed_ms`, `timeout_ms`, `duration_ms`
- Data transfer: `bytes_sent`, `bytes_recv` (prefer full words over abbreviations like `tx`/`rx`)
- Status codes: `status_code`, `response_code`, `error_code`
- Identifiers: `username`, `user_id`, `session_id`, `connection_id`
- Phases/stages: `phase`, `stage`, `step`

---

## 3. Constants

Constants are defined based on their scope and usage pattern.

### 3.1 File-level constants

Constants used by multiple functions or across the file go at the top, immediately after imports:

```rust
use std::time::Duration;

// Constants
const MAX_HANDSHAKE_ATTEMPTS: u32 = 3;
const BASE_TIMEOUT_MS: u64 = 500;
const EXTENDED_TIMEOUT_MS: u64 = BASE_TIMEOUT_MS * 2;
const MAX_BUFFER_SIZE: usize = 16 * 1024;
```

### 3.2 Impl-specific constants

Constants used exclusively by a single impl block are defined within that impl:

```rust
impl Connection {
    const DEFAULT_TIMEOUT_MS: u64 = 5000;
    const KEEPALIVE_INTERVAL_MS: u64 = 1000;
    const MAX_RETRIES: u32 = 3;
    
    pub fn connect(&mut self) -> Result<()> {
        // Uses Self::DEFAULT_TIMEOUT_MS
    }
}
```

### 3.3 Guidelines

* Names are descriptive and in `SCREAMING_SNAKE_CASE`.
* Constants that depend on others are defined in terms of previous constants.
* Avoid magic numbers in body code.
* Group related constants and add section headers with short comments if needed.

---

## 4. File layout and section headers

Each Rust file should be structured like this:
1. Module-level documentation (if non-trivial module)
2. `use` imports
3. Constants (file-level only)
4. Types (structs, enums, traits)
5. Implementations and functions
6. `#[cfg(test)]` module

Sections are marked with special comments.

### 4.1 Section headers

Use `/* */` single line block comments to mark sections with optional description. This is a personal opinion.

Single-line section headers are fine when self-explanatory:
```rust
/* Types */

pub struct Connection {
    // ...
}
```

Add descriptions when the section header alone is not sufficient:
```rust
/* Encryption and Authentication */
//
// Handles client encryption setup and authentication handshake.
// This includes TLS negotiation and credential validation.
```

Example file skeleton:
```rust
//! Connection management and handshakes.
//!
//! This module owns the types that establish and maintain connections to
//! upstream proxies or targets.

use std::time::Duration;

// Constants
const MAX_HANDSHAKE_ATTEMPTS: u32 = 3;

/* Types */
//
// Core types used for connection management.

pub struct Connection {
    // ...
}

/* Implementations */
//
// Concrete behavior for the core types.

impl Connection {
    const DEFAULT_TIMEOUT_MS: u64 = 5000;
    
    pub fn new(addr: SocketAddr) -> Result<Self> {
        // ...
    }
    
    pub fn connect(&mut self) -> Result<()> {
        // ...
    }
}

/* Tests */
//
// Unit tests and integration style tests local to this module.

#[cfg(test)]
mod tests {
    use super::*;
    // ...
}
```

---

## 5. Documentation and comments

### 5.1 Module level documentation

Each non-trivial module should explain its role at the top using `//!` doc comments:

```rust
//! Connection management and handshakes.
//!
//! This module owns the types that establish and maintain connections to
//! upstream proxies or targets. It defines:
//!   * `Connection` - the main handle used by callers
//!   * `ConnectionConfig` - parameters that tune timeouts and retries
//!   * `HandshakeState` - internal state machine for protocol setup
```

### 5.2 Section comments

Use the `/* */` pattern for larger logical sections (as shown in 4.1).

### 5.3 Internal comments

Comments for code that is not immediately obvious go **above** the code, not inline.

* Good:
```rust
// Performs the SOCKS5 greeting and validates the server response.
let greeting = build_greeting();
let response = send_greeting(&mut stream, greeting)?;
validate_greeting_response(response)?;
```

* Avoid inline comments that repeat the code:
```rust
let x = x + 1; // increments x by 1
```

Explain why, not just what, and only include comments when it is not immediately obvious what the code does.

### 5.4 Rustdoc comments

All public types and functions must have doc comments (`///`).

* First line: short summary.
* Then a blank line.
* Then more detail and at least one doctest example.

```rust
/// Establishes a connection with the configured endpoint.
///
/// This does not perform the full handshake; it only opens the underlying
/// TCP connection to the proxy.
///
/// # Examples
///
/// ```
/// use mylib::Connection;
///
/// let mut conn = Connection::new("127.0.0.1:1080".parse()?)?;
/// conn.connect()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn connect(&mut self) -> Result<()> {
    // ...
}
```

---

## 6. Doctests

Every public method should have a doctest that:
* Shows realistic usage with valid input.
* Can be copied and pasted into user code and compiled without modification.
* Serves as both example and test - demonstrates correct usage and proves the method works.
* Handles errors appropriately (using `?`, `unwrap()`, or assertions).

Doctests prove that the method works with correct, valid input. Unit tests (in the test module) prove that the method correctly rejects invalid input and handles edge cases.

### 6.1 Visibility rule

Doctests must be copy-pasteable and work as a complete example.

* Do not hide:
  * Imports of the library itself.
  * Type or function declarations that are part of the example.
  * The code that demonstrates usage.
* You may hide:
  * Non-library imports (standard library or helper imports).
  * Boilerplate setup and helpers that distract from the main API.

Public facing docs should import the crate as a user would:
```rust
/// Establishes a connection with the configured endpoint.
///
/// # Examples
///
/// ```
/// use your_crate::Connection;
///
/// let mut conn = Connection::new("127.0.0.1:1080".parse()?)?;
/// conn.connect()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn connect(&mut self) -> Result<()> {
    // ...
}
```

Hide only the non-library pieces:
```rust
/// Authenticates the connection with the remote server.
///
/// # Examples
///
/// ```
/// # use std::net::TcpStream;
/// use your_crate::Connection;
///
/// # fn test_stream() -> TcpStream {
/// #     TcpStream::connect("127.0.0.1:1080").unwrap()
/// # }
///
/// let stream = test_stream();
/// let mut conn = Connection::from_stream(stream)?;
///
/// conn.authenticate()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn authenticate(&mut self) -> Result<()> {
    // ...
}
```

### 6.2 Testing philosophy

All doctests demonstrate the happy path with valid input. All unit tests verify error handling and edge cases. Together they prove correctness across the entire input space.

**Quality over quantity:** 50 thoughtful tests that verify behavior are infinitely more valuable than 500 generated tests that merely prove the code doesn't panic. Every test should validate correctness, not just compilation.

---

## 7. Testing

There are two layers of tests:
1. Doctests on each public method (happy path with valid input).
2. A full test module at the bottom of the file for error cases and edge cases.

### 7.1 Doctests as usage specs

Doctests show minimal but realistic examples with valid input and ensure the API works as documented. They must compile and run.

### 7.2 Unit tests and suites

At the bottom of each file:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_rejects_invalid_endpoint() {
        let conn = Connection::new("not an address".parse().unwrap_err());
        // This should fail at parse time, which is correct
    }

    #[test]
    fn authenticate_fails_on_invalid_credentials() {
        // Test that invalid credentials are properly rejected
    }
    
    #[test]
    fn connection_handles_timeout() {
        // Test timeout behavior
    }
    
    #[test]
    fn buffer_rejects_oversized_input() {
        // Test size limits
    }
}
```

These tests:
* Prove that methods correctly reject invalid input.
* Verify that edge cases are handled properly.
* Assert that components work together correctly.
* Validate that error conditions produce the right errors.

Every test should be **thoughtful and thorough**, verifying behavior rather than just proving the code compiles.

### 7.3 Integration tests

Use the `tests/` directory for larger integration tests that span multiple modules. The structure and organization of integration tests is project-specific and should be built out manually for each library based on its particular needs.

---

## 8. Error handling

Errors must be rich, verbose, and specific.

* Prefer unique, domain-specific error variants.
* Generic errors are allowed only when the cause is truly unknown or unknowable.
* Even generic errors must still carry detailed context.

### 8.1 Error organization

All error types live in an `error/` directory. Each file follows the `*_errors.rs` naming convention.

**Why separate error files:**
- Once errors are defined, they rarely change.
- Keeps primary implementation files trim and focused.
- Makes errors easy to find - everything is in `error/`.
- Reduces merge conflicts - error changes don't conflict with logic changes.

Structure for small projects (<30 error variants):
```
src/
  error/
    mod.rs
    lib_errors.rs
  connection.rs
  parser.rs
  lib.rs
```

```rust
// error/mod.rs
mod lib_errors;

pub use lib_errors::Error;
pub type Result<T> = std::result::Result<T, Error>;
```

```rust
// error/lib_errors.rs
use std::io;
use std::net::SocketAddr;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /* Connection Errors */
    #[error("failed to connect to {addr}: {source}")]
    ConnectionFailed {
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },
    
    /* Parser Errors */
    #[error("invalid syntax at line {line}, column {col}")]
    InvalidSyntax { line: usize, col: usize },
}
```

Structure for large projects (>30 error variants):
```
src/
  error/
    mod.rs
    connection_errors.rs
    parser_errors.rs
    database_errors.rs
  connection.rs
  parser.rs
  lib.rs
```

```rust
// error/mod.rs
mod connection_errors;
mod parser_errors;
mod database_errors;

pub use connection_errors::ConnectionError;
pub use parser_errors::ParserError;
pub use database_errors::DatabaseError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    
    #[error(transparent)]
    Parser(#[from] ParserError),
    
    #[error(transparent)]
    Database(#[from] DatabaseError),
}
```

**Benefits:**
- Users always import `use mylib::error::Result;`
- One unified error type for the public API
- Internally organized by domain
- No merge conflicts on error definitions
- Fast compile times
- Easy to find and maintain errors

### 8.2 Five W pattern

Every error should, as much as possible, answer:
* What was attempted?
* Where did it happen? (address, path, resource)
* Who or what was involved? (username, peer, component)
* When in the flow did it fail? (phase, step, state)
* Why did it fail? (underlying cause, status, code, message)

Example:
```rust
use std::io;
use std::net::SocketAddr;

#[derive(Debug, thiserror::Error)]
pub enum SocksError {
    // === TLS ===
    #[error("TLS handshake failed with peer {peer} during {phase}: {source}")]
    TLSHandshakeFailed {
        /// Remote endpoint we attempted to secure.
        peer: SocketAddr,
        /// High level phase, for example "client_hello" or "certificate_verification".
        phase: &'static str,
        /// Underlying IO or TLS error.
        #[source]
        source: io::Error,
    },

    #[error("TLS handshake with peer {peer} timed out during {phase} after {timeout_ms} ms")]
    TLSHandshakeTimeout {
        peer: SocketAddr,
        phase: &'static str,
        timeout_ms: u64,
    },

    // === Proxy Authentication ===
    #[error("proxy authentication failed for user '{username}' at {proxy_addr}: {reason}")]
    ProxyAuthenticationFailed {
        proxy_addr: SocketAddr,
        username: String,
        reason: AuthFailureReason,
    },

    // === Proxy Connection Failures ===
    #[error("failed to connect to proxy at {proxy_addr} using {scheme}: {source}")]
    ProxyConnectionFailed {
        proxy_addr: SocketAddr,
        scheme: &'static str,
        #[source]
        source: io::Error,
    },

    // === SOCKS5 Specific Errors ===
    #[error(
        "SOCKS5 server at {proxy_addr} returned unknown reply code {code:#04x} during {phase}"
    )]
    SOCKS5UnknownError {
        proxy_addr: SocketAddr,
        code: u8,
        phase: &'static str,
    },

    #[error(
        "invalid SOCKS5 version from {proxy_addr} during {phase}: \
         received 0x{received:02x}, expected 0x{expected:02x}"
    )]
    InvalidSOCKS5Version {
        proxy_addr: SocketAddr,
        phase: &'static str,
        received: u8,
        expected: u8,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum AuthFailureReason {
    #[error("invalid credentials")]
    InvalidCredentials,
    
    #[error("no acceptable authentication method (offered={offered:?})")]
    NoAcceptableMethod { offered: Vec<u8> },
    
    #[error("unsupported authentication method 0x{method:02x}")]
    UnsupportedMethod { method: u8 },
    
    #[error("credentials contain invalid characters")]
    InvalidChars,
}
```

### 8.3 Generic errors

If the cause is unknown, the error must still be descriptive:
```rust
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error(
        "connection to {addr} failed for an unknown reason during {phase} \
         (remote closed unexpectedly, no error code available)"
    )]
    Unknown {
        addr: SocketAddr,
        phase: &'static str,
    },
}
```

There should be no plain `Unknown error` messages.

### 8.4 Panics vs results

* Library code must not panic on recoverable conditions.
* Use `Result` for operations that can fail at runtime.
* `unwrap()` and `expect()` are allowed only when:
  * It is truly impossible to fail (logic invariants).
  * In tests.
  * In small, private helpers with clearly documented invariants.

If failure depends on user input, network state, or external I/O, return an error instead of panicking.

### 8.5 Unwrap and expect policy

- `unwrap()`: Only in tests or when panicking is truly the correct behavior
- `expect()`: Use with detailed message explaining the invariant:
  ```rust
  // GOOD
  config.get("required_field")
      .expect("required_field must be present: validated in Config::new()")
  
  // BAD
  config.get("required_field").unwrap()
  ```

### 8.6 Privacy

Rich errors must not leak secrets.
* Never include passwords, tokens, or private keys in error messages.
* Usernames, redacted identifiers, and lengths are acceptable.

### 8.7 Error context

When using `anyhow` or similar for error context, prefer explicit enum variants over generic `.context()` chains for errors that are part of your public API. Use `.context()` for internal errors or in application code where the full error type doesn't need to be exposed.

---

## 9. Imports and module organization

Imports are grouped and ordered:
1. Standard library
2. Third-party crates
3. Local crate modules

Example:
```rust
use std::io::{self, Read, Write};
use std::net::TcpStream;

use bytes::BytesMut;

use crate::auth::Authenticator;
use crate::error::Result;
```

Guidelines:
* Avoid wildcard imports such as `use crate::foo::*;` except in tests or small internal modules.
* Keep modules focused. Prefer multiple small modules over one huge one.

---

## 10. Re-exports and public API

By default, export primary public types and methods from the crate root. End users should not need to dig through a file tree to find methods.

Favor `lib::Connection` instead of `lib::connection::connection::Connection`.

### 10.1 Standard re-export pattern
```rust
// lib.rs - re-export main types at crate root
mod connection;
mod auth;
pub mod error;

pub use connection::{Connection, ConnectionConfig};
pub use auth::{Authenticator, AuthMethod};
pub use error::{Error, Result};

// Users import: use mylib::Connection;
// Not: use mylib::connection::Connection;
```

### 10.2 When to export the module itself

If more than 3 methods or types come from a single file, OR the file represents a cohesive data type with many associated items, export the module itself for import purposes.
```rust
// lib.rs
pub mod protocol; // exports many methods or protocol-related types

// Users can then:
use mylib::protocol::{self, Method1, Method2, Method3, Method4};
// or
use mylib::protocol;
protocol::method();
```

This balances discoverability with namespace cleanliness.

---

## 11. Ownership and APIs

Design function signatures to avoid unnecessary allocations and copies.

* Prefer `&str` over `String` where ownership is not needed.
* Prefer `&T` or `&mut T` when borrowing is sufficient.
* Use `Cow<str>` when you might need to own the string.

Examples:
```rust
fn connect_to(endpoint: &str) -> Result<()> {
    // ...
}

fn authenticate(conn: &mut Connection) -> Result<()> {
    // ...
}
```

Clone only when necessary and document expensive clones if they are unavoidable.

---

## 12. Type aliases and newtypes

### 12.1 Type aliases

Use for convenience and clarity:
```rust
pub type Result<T> = std::result::Result<T, Error>;
pub type ConnectionResult<T> = std::result::Result<T, ConnectionError>;
pub type ByteBuffer = Vec<u8>;
```

Benefits:
- Less typing
- Clear intent in signatures
- Easy to change underlying type

### 12.2 Newtypes

Use for type safety and domain modeling:
```rust
pub struct Username(String);
pub struct Password(String);
pub struct SessionId(Uuid);
```

Benefits:
- Prevents mixing up similar types (can't pass Password where Username expected)
- Can implement traits separately
- Clear domain semantics
- Enforces validation:

```rust
impl Username {
    pub fn new(s: String) -> Result<Self> {
        if s.is_empty() || s.len() > 32 {
            return Err(Error::InvalidUsername);
        }
        Ok(Self(s))
    }
    
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
```

**When to choose:**
- Type alias: Pure convenience, no validation needed
- Newtype: Type safety, validation, distinct behavior

---

## 13. Builder pattern

Use builders for types with:
- Many optional fields (>3)
- Complex validation rules
- Interdependent configuration

### 13.1 Basic builder

```rust
pub struct ConnectionBuilder {
    addr: Option<SocketAddr>,
    timeout: Option<Duration>,
    max_retries: Option<u32>,
    tls: bool,
}

impl ConnectionBuilder {
    pub fn new() -> Self {
        Self {
            addr: None,
            timeout: None,
            max_retries: None,
            tls: false,
        }
    }
    
    pub fn addr(mut self, addr: SocketAddr) -> Self {
        self.addr = Some(addr);
        self
    }
    
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
    
    pub fn tls(mut self, enabled: bool) -> Self {
        self.tls = enabled;
        self
    }
    
    pub fn build(self) -> Result<Connection> {
        let addr = self.addr.ok_or(Error::MissingAddress)?;
        Ok(Connection {
            addr,
            timeout: self.timeout.unwrap_or(DEFAULT_TIMEOUT),
            max_retries: self.max_retries.unwrap_or(DEFAULT_RETRIES),
            tls: self.tls,
        })
    }
}

impl Connection {
    pub fn builder() -> ConnectionBuilder {
        ConnectionBuilder::new()
    }
}
```

Usage:
```rust
let conn = Connection::builder()
    .addr("127.0.0.1:8080".parse()?)
    .timeout(Duration::from_secs(10))
    .tls(true)
    .build()?;
```

### 13.2 When not to use builders

- Types with ≤3 fields all required → use `new()`
- Simple structs with all public fields → direct initialization

---

## 14. Feature flags and optional dependencies

Feature flags control which code is compiled and which dependencies are pulled in.

### 14.1 Core rules

**All features must be purely additive:**
- Enabling a feature only adds capabilities.
- Features never break or change existing APIs.
- If a default method doesn't work with a feature, the feature implements its own version.

**All optional dependencies must be feature-gated:**
- Reduces binary size when features aren't used.
- Improves compile times.
- Makes dependency tree explicit.

### 14.2 Feature definition in Cargo.toml

```toml
[features]
# Document each feature
default = []

# Core features - runtime selection
tokio-runtime = ["tokio"]
async-std-runtime = ["async-std"]

# Protocol support - can be combined
tls = ["rustls", "tokio-native-tls"]
socks5 = []
http-proxy = ["hyper"]

# Utility features
compression = ["flate2"]

[dependencies]
# Required dependencies
bytes = "1.5"

# Optional - only pulled in if feature enabled
tokio = { version = "1.35", optional = true }
rustls = { version = "0.21", optional = true }
```

### 14.3 Feature mutual exclusion

If features cannot coexist, enforce at compile time:

```rust
#[cfg(all(feature = "tokio-runtime", feature = "async-std-runtime"))]
compile_error!("Cannot enable both tokio-runtime and async-std-runtime");
```

### 14.4 Feature-gated code organization

Prefer feature-gating entire modules to reduce visual clutter:

```rust
// lib.rs - GOOD: Clean and scannable
#[cfg(feature = "tls")]
pub mod tls {
    pub use crate::protocols::core::establish_tls;
    pub use crate::utils::config::TlsConfig;
}

// Users: use mylib::tls::{establish_tls, TlsConfig};
```

Avoid scattering feature gates throughout files:
```rust
// lib.rs - AVOID: Visual noise
#[cfg(feature = "tls")]
pub use crate::protocols::core::establish_tls;

#[cfg(feature = "tls")]
pub use crate::utils::config::TlsConfig;

#[cfg(feature = "tls")]
pub use crate::tls_helpers::TlsHelper;
// ... 10 more scattered feature gates
```

**Why this matters:**
- Easier to see what's feature-gated at a glance
- Less visual noise
- Clearer module boundaries
- Simpler to maintain

### 14.5 Documentation

Document features in the crate-level docs:

```rust
//! # Features
//!
//! - `tls`: Enables TLS support for secure connections using rustls
//! - `socks5`: SOCKS5 proxy protocol support
//! - `http-proxy`: HTTP CONNECT proxy support
//! - `tokio-runtime`: Use tokio as the async runtime (conflicts with async-std-runtime)
```

### 14.6 Testing features

Test feature combinations in CI:

```yaml
# .github/workflows/ci.yml
strategy:
  matrix:
    features:
      - ""  # no features
      - "tls"
      - "socks5"
      - "tls,socks5"
```

### 14.7 Feature anti-patterns

Avoid:
- Features that change behavior rather than add it
- Features that break API compatibility
- Features with unclear names (`extra`, `full`, `unstable`)
- Circular feature dependencies

---

## 15. Dependency management

### 15.1 Version bounds

Use the following patterns:
- `"1.0"` - caret requirements (^1.0), accepts semver-compatible updates
- `"=1.0.5"` - exact version, only for applications or security-critical pins

Avoid:
- `"*"` - never use wildcard versions
- No version - always specify versions explicitly

### 15.2 Dependency selection

**Use the latest version** of all dependencies unless:
- A new version breaks compatibility with existing code
- A specific version is required for a critical bug fix or security patch

When pinning to an older version, **always document why:**

```toml
[dependencies]
# Using 1.2.3 instead of 1.3.0 because 1.3.0 changed the API for
# connection pooling in a way that's incompatible with our usage.
# See issue #123 for details.
some-crate = "=1.2.3"
```

### 15.3 Optional dependencies

Mark dependencies optional if they're only needed for certain features:
```toml
[dependencies]
serde = { version = "1.0", optional = true }

[features]
serialization = ["serde"]
```

### 15.4 Security

- Run `cargo audit` in CI
- Address security advisories within 7 days
- Never ignore security warnings without documented justification

---

## 16. Performance considerations

### 16.1 Allocation

- Prefer `&str` over `String` in function parameters
- Use `Cow<str>` when you might need to own the string
- Pre-allocate collections when size is known:
  ```rust
  let mut buf = Vec::with_capacity(expected_size);
  ```

### 16.2 Copying vs cloning

- Prefer `Copy` types for small, cheap-to-copy data (≤ 2 words)
- Implement `Clone` for larger types
- Document expensive clones:
  ```rust
  /// Clones the internal buffer (potentially expensive for large data).
  pub fn clone_buffer(&self) -> Vec<u8> {
      self.buffer.clone()
  }
  ```

### 16.3 Iteration

- Prefer iterators over indexed loops
- Use `iter()` over `into_iter()` unless consuming is intended
- Chain iterator adapters instead of collecting intermediate results:
  ```rust
  // GOOD
  items.iter()
      .filter(|x| x.is_valid())
      .map(|x| x.process())
      .collect::<Vec<_>>()
  
  // AVOID
  let filtered: Vec<_> = items.iter().filter(|x| x.is_valid()).collect();
  let processed: Vec<_> = filtered.iter().map(|x| x.process()).collect();
  ```

### 16.4 Avoid

- Unnecessary `String::from()` when `&str` suffices
- Cloning in hot paths
- Allocations inside tight loops

---

## 17. Async and concurrency

### 17.1 Runtime selection

Pick one async runtime for your project:
- `tokio`: Most common, best ecosystem, production-ready
- `async-std`: Simpler API, smaller ecosystem
- `smol`: Lightweight, good for embedded

**Never support multiple runtimes in the same binary.** Abstract the runtime in tests if needed, but don't make runtime selection a runtime decision.

### 17.2 Method naming

- Do not suffix async methods with `_async` unless distinguishing from a sync variant
- Suffix blocking operations in async contexts with `_blocking` if clarity is needed:
  ```rust
  impl Database {
      async fn query(&self, sql: &str) -> Result<Rows> { /* ... */ }
      
      // Blocks the thread - make it explicit
      fn query_blocking(&self, sql: &str) -> Result<Rows> { /* ... */ }
  }
  ```

### 17.3 Blocking operations

Never block the async executor:
```rust
// BAD - blocks the executor thread
async fn read_config() -> Config {
    std::fs::read_to_string("config.toml")  // blocks!
        .unwrap()
        .parse()
        .unwrap()
}

// GOOD - uses async I/O
async fn read_config() -> Result<Config> {
    let contents = tokio::fs::read_to_string("config.toml").await?;
    let config = tokio::task::spawn_blocking(move || {
        toml::from_str(&contents)
    })
    .await??;
    Ok(config)
}
```

### 17.4 Timeouts

Always use timeouts for external operations:
```rust
use tokio::time::{timeout, Duration};

async fn connect_with_timeout(addr: &str) -> Result<Connection> {
    timeout(
        Duration::from_secs(10),
        Connection::connect(addr)
    )
    .await
    .map_err(|_| Error::ConnectionTimeout)??
}
```

### 17.5 Cancellation

Async operations can be cancelled at any `.await` point. Design accordingly:
```rust
// This might be cancelled mid-operation
async fn process_requests(mut stream: TcpStream) -> Result<()> {
    loop {
        let req = read_request(&mut stream).await?;
        // If cancelled here, cleanup won't run
        process_request(req).await?;
    }
}

// Better: use Drop for cleanup
struct Connection {
    stream: TcpStream,
}

impl Drop for Connection {
    fn drop(&mut self) {
        // Cleanup happens even if cancelled
    }
}
```

### 17.6 Async destructors

Rust doesn't support async `Drop`. Use explicit cleanup:
```rust
impl Connection {
    pub async fn close(self) -> Result<()> {
        // Async cleanup
        self.stream.shutdown().await?;
        Ok(())
    }
}
```

### 17.7 Send + Sync bounds

Be explicit about Send bounds for spawned tasks:
```rust
async fn spawn_handler<F>(f: F)
where
    F: Future<Output = Result<()>> + Send + 'static,
{
    tokio::spawn(f);
}
```

### 17.8 Common pitfalls

- Holding locks across `.await` points (causes deadlocks)
- Not using `tokio::sync::Mutex` in async code (use async-aware primitives)
- Spawning without handling JoinHandle errors
- Forgetting to drive futures to completion

---

## 18. Logging and diagnostics

Use the `tracing` crate for all logging with automatic instrumentation for function-level observability.

Errors themselves are not automatically logged at every layer. They are returned as rich values and should be logged once at a logical boundary (for example at the top level of an operation or in application code).

### 18.1 Logging ecosystem

* Use `tracing` for logging.
* Use levels as follows:
  * `trace` for mechanical, step-by-step execution details intended for deep debugging.
  * `debug` for meaningful internal state transitions and decisions.
  * `info` for normal operation events visible to operators.
  * `warn` for unusual but non-fatal conditions.
  * `error` for failures at boundaries where you handle or surface them.

`trace` explains *how* the code executed.  
`debug` explains *what* happened.

### 18.2 Library vs application logging

* Libraries should emit `trace`, `debug`, `info`, and `warn` logs.
* The application decides what to log via filtering.
* In practice:
  * `trace` is often unusable in production due to noise from dependencies.
  * `debug` must remain readable and intentional, even when other libraries are present.

Library `debug` logs are treated as the primary diagnostic level for understanding behavior in real deployments.

### 18.3 Instrumentation with #[instrument]

The `#[instrument]` macro is the primary way to add tracing to functions. It automatically:
* Creates a span for the function
* Logs entry and exit with timing
* Captures function arguments as structured fields
* Propagates context to nested calls
* Handles cleanup even on panic or early return

By default, spans are created at `trace` level. This is acceptable for:
* Small functions
* Low-frequency operations
* Code paths where trace-level detail is genuinely useful

For high-traffic or semantically important functions, prefer elevating the span level:

```rust
#[instrument(level = "debug", skip(self))]
pub fn connect(&mut self, addr: SocketAddr) -> Result<()> {
    trace!("establishing TCP connection");
    self.do_connect(addr)?;
    debug!("connection established");
    Ok(())
}
````

### 18.4 Instrumentation parameters

Common parameters for `#[instrument]`:

**Skip arguments:**

```rust
#[instrument(skip(self, password))]
pub fn authenticate(&self, username: &str, password: &str) -> Result<()> {
    // Logs username but not password
}
```

**Add custom fields:**

```rust
#[instrument(skip(self), fields(endpoint = %self.endpoint, user_id = %self.user_id))]
pub fn fetch_data(&self, query: &str) -> Result<Vec<Item>> {
    // All logs inside inherit endpoint and user_id fields
}
```

**Log errors automatically:**

```rust
#[instrument(err)]
pub fn risky_operation() -> Result<()> {
    // Automatically logs errors at ERROR level
}
```

**Log return values:**

```rust
#[instrument(ret)]
pub fn calculate(x: i32) -> i32 {
    x * 2
}
// Logs: calculate{x=5}: return=10
```

**Custom log level:**

```rust
#[instrument(level = "debug")]
pub fn detailed_work() -> Result<()> {
    // Span created at debug level instead of default trace
}
```

**Skip all arguments:**

```rust
#[instrument(skip_all)]
pub fn internal_helper(a: Foo, b: Bar, c: Baz) -> Result<()> {
    // Function is traced but no args logged
}
```

### 18.5 Async instrumentation

`#[instrument]` works seamlessly with async functions and preserves span context across `.await` points:

```rust
#[instrument(skip(self), fields(endpoint = %self.endpoint))]
pub async fn handshake(&mut self) -> Result<()> {
    trace!("sending greeting");
    self.greet().await?;
    
    trace!("authenticating");
    self.authenticate().await?;
    
    trace!("handshake complete");
    Ok(())
}
```

Output shows hierarchical span nesting:

```
TRACE handshake{endpoint="proxy.io"}: entered
  TRACE greet{endpoint="proxy.io"}: entered
  TRACE greet{endpoint="proxy.io"}: sending greeting
  TRACE greet{endpoint="proxy.io"}: exited elapsed=12ms
  TRACE authenticate{endpoint="proxy.io"}: entered
  TRACE authenticate{endpoint="proxy.io"}: verifying credentials
  TRACE authenticate{endpoint="proxy.io"}: exited elapsed=45ms
TRACE handshake{endpoint="proxy.io"}: handshake complete
TRACE handshake{endpoint="proxy.io"}: exited elapsed=58ms
```

### 18.6 Manual spans for complex control flow

When you need more control than `#[instrument]` provides, create spans manually:

```rust
use tracing::{info_span, trace};

pub fn process_batch(&mut self, batch_id: u64) -> Result<()> {
    let span = info_span!("process_batch", batch_id);
    let _guard = span.enter();
    
    trace!("validating batch");
    self.validate()?;
    
    trace!("processing items");
    for item in &self.items {
        let item_span = trace_span!("process_item", item_id = %item.id);
        let _item_guard = item_span.enter();
        self.process_item(item)?;
    }
    
    trace!("batch complete");
    Ok(())
}
```

### 18.7 Dynamic field values

Record field values after span creation when they're not known upfront:

```rust
use tracing::Span;

#[instrument(fields(bytes_processed = tracing::field::Empty))]
pub fn process_data(&mut self, data: &[u8]) -> Result<()> {
    let bytes = self.do_process(data)?;
    
    // Record the value once known
    Span::current().record("bytes_processed", bytes);
    
    Ok(())
}
```

### 18.8 Structured logging fields

Always use structured fields for variable data:

```rust
trace!(
    remote_addr = %addr,
    bytes_sent = sent,
    bytes_recv = recv,
    "connection closed"
);
```

Not:

```rust
trace!("connection to {} closed, sent {} bytes, recv {} bytes", addr, sent, recv);
```

Use consistent, descriptive names for structured fields:

* Connection info: `local_addr`, `remote_addr`, `peer_addr`, `proxy_addr`
* Timing: `elapsed_ms`, `timeout_ms`, `duration_ms`, `rtt_ms`
* Data transfer: `bytes_sent`, `bytes_recv`, `packet_size`
* Status codes: `status_code`, `response_code`, `error_code`
* Identifiers: `username`, `user_id`, `session_id`, `connection_id`, `request_id`
* Phases/stages: `phase`, `stage`, `step`
* Performance: `elapsed_micros`, `allocation_count`, `cache_hit_rate`
* Network: `bandwidth_mbps`, `packet_loss_pct`, `queue_depth`
* Retry: `attempt_num`, `max_attempts`, `backoff_ms`

### 18.9 Trace logging policy

`trace` logs exist to reconstruct execution mechanics, not system behavior.

Use `trace` for:

* Fine-grained internal steps
* Branch decisions that normally succeed
* I/O mechanics (send/receive, parse steps)
* Retry loops, polling, and protocol state machines
* Logs that may fire many times per operation

For every instrumented method:

* `#[instrument]` handles entry/exit and timing
* Add `trace!` logs for mechanical steps and internal flow
* Prefer short, factual messages with structured fields
* Expect `trace` to be disabled in most production environments

### 18.9.1 Debug logging policy

`debug` logs represent semantic events and state transitions.

They should answer: “What meaningful thing just happened?”

Use `debug` for:

* State transitions (`connected`, `authenticated`, `closed`)
* Significant branch outcomes (`2FA required`, `fallback selected`)
* One-time events per request, session, or connection
* Decisions that affect behavior but are not errors

Rules:

* A `debug` log should generally fire once per operation, not per step.
* `debug` logs must remain readable even when other libraries are logging.
* If a log helps someone understand system behavior without knowing internals, it belongs in `debug`, not `trace`.

Example:

```rust
#[instrument(
    skip(self, credentials),
    fields(endpoint = %self.endpoint, username = %credentials.username),
    err
)]
pub async fn authenticate(&mut self, credentials: &Credentials) -> Result<Token> {
    trace!("sending authentication request");

    let response = self.send_auth_request(credentials).await?;

    if response.requires_2fa {
        debug!("two-factor authentication required");
        return self.handle_2fa(response).await;
    }

    debug!("authentication successful");
    Ok(response.token)
}
```

### 18.10 Errors and logs

* Rich error types already contain detailed information.
* Do not rephrase or duplicate error messages manually in logs.
* The `#[instrument(err)]` parameter automatically logs errors at the ERROR level.
* Optionally add context with manual error logs at boundaries.

Example at a boundary:

```rust
#[instrument(skip(conn), err)]
pub fn run_handshake(conn: &mut Connection) -> Result<()> {
    trace!("starting handshake");
    conn.handshake()?;
    trace!("handshake complete");
    Ok(())
}
```

If the handshake fails, the error is automatically logged:

```
TRACE run_handshake: starting handshake
ERROR run_handshake: error="connection refused" elapsed=45ms
```

Logs and errors should complement each other: errors carry structured incident data, and trace logs show the full story of how the code got there.

### 18.11 Conditional instrumentation and lazy evaluation

The `tracing` crate automatically skips event dispatch when the log level is disabled, which is sufficient for most logging. However, Rust uses eager evaluation—function arguments are evaluated before checking if tracing is enabled. This means expensive operations in log fields will execute even when logs are discarded.

**Default approach – trust automatic optimization:**

For normal operations with cheap field formatting, rely on automatic optimization:

```rust
#[instrument(skip(self))]
pub fn connect(&mut self, addr: SocketAddr) -> Result<()> {
    trace!(endpoint = %self.endpoint, "establishing connection");
    self.do_connect(addr)?;
    trace!("connection established");
    Ok(())
}
```

**Manual checks for expensive operations:**

Add explicit level checks when field computation is expensive:

```rust
#[instrument(skip(self, response))]
pub fn log_response(&self, response: &ApiResponse) -> Result<()> {
    if tracing::enabled!(tracing::Level::TRACE) {
        trace!(
            json = %serde_json::to_string_pretty(response).unwrap(),
            "received response"
        );
    }
    Ok(())
}
```

**Hot loops – sample or skip logging:**

Avoid logging every iteration. Either sample periodically or skip entirely:

```rust
pub fn process_batch(&mut self, items: &[Item]) -> Result<()> {
    trace!(item_count = items.len(), "processing batch");
    
    for (idx, item) in items.iter().enumerate() {
        self.process_item(item)?;
        
        // Log every 1000 items
        if idx % 1000 == 0 {
            trace!(processed = idx, total = items.len(), "progress update");
        }
    }
    
    trace!("batch complete");
    Ok(())
}
```

**Guidelines for when to use manual checks:**

Add `if tracing::enabled!(Level::TRACE)` when:

* Serializing to JSON/YAML/TOML
* Formatting large binary data (hex dumps, base64)
* Computing checksums or hashes just for logging
* Building strings or allocating collections for log fields
* Inside loops that run 100+ iterations

Do NOT add manual checks for:

* Simple field formatting (`%self.endpoint`, `%addr`)
* Primitive types and Display implementations
* Normal function calls (not in hot paths)
* Operations that would happen anyway (don't duplicate work)

**Compile-time removal for ultra-hot paths:**

For functions called millions of times per second, use feature-gated instrumentation:

```rust
#[cfg_attr(feature = "detailed-tracing", instrument)]
pub fn hot_path_function(&self) -> Result<()> {
    // Critical path code
}
```

This completely removes instrumentation from production builds when compiled without the feature flag.

### 18.12 Subscriber configuration

Initialize tracing in your application's main function:

```rust
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,my_crate=trace".into())
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_line_number(true)
        )
        .init();
}
```

This allows filtering by environment variable:

```bash
RUST_LOG=trace cargo run
RUST_LOG=my_crate::connection=debug cargo run
```

### 18.13 Testing with tracing

Capture and assert on logs in tests:

```rust
#[cfg(test)]
mod tests {
    use tracing_test::traced_test;
    
    #[traced_test]
    #[test]
    fn test_logs_capture() {
        my_function();
        
        // Assert on logs
        assert!(logs_contain("expected log message"));
    }
}
```

### 18.14 Span guards for RAII

Spans automatically exit when their guard is dropped, ensuring cleanup even on panic or early return:

```rust
pub fn process_with_timing(&mut self) -> Result<()> {
    let span = info_span!("process_with_timing");
    let _guard = span.enter(); // Exits on drop
    
    // If this panics or early returns, span still exits cleanly
    self.do_work()?;
    
    Ok(())
} // Span exits here automatically
```

```

## 19. Macros

Macros should be a last resort. Use functions or traits when possible.

### 19.1 When to write macros

- Reducing truly unavoidable boilerplate
- Generating code that requires access to identifiers or types
- Creating DSLs (sparingly)

### 19.2 Macro style

- Use declarative macros (`macro_rules!`) over procedural when possible
- Name macro invocations clearly: `define_error_codes!` not `errors!`
- Document what the macro generates
- Provide examples

### 19.3 Avoiding macros

Often a macro can be replaced:
```rust
// Instead of a macro
define_handlers!(foo, bar, baz);

// Use a builder or function
HandlerRegistry::new()
    .register("foo", foo_handler)
    .register("bar", bar_handler)
    .register("baz", baz_handler)
    .build()
```

---

## 20. Unsafe code

Unsafe code is allowed only when absolutely necessary.

Rules:
* Every `unsafe` block must have a comment that explains the safety invariants.
* Prefer to wrap unsafe pieces in small, well-tested safe abstractions.
* Do not scatter unsafe blocks throughout the code. Centralize where possible.

Example:
```rust
// Safety: `ptr` is guaranteed to be valid and properly aligned by `new()`,
// and it never escapes this module. All accesses respect aliasing rules.
unsafe {
    ptr.write(value);
}
```

---

## 21. Module privacy

Use visibility modifiers intentionally:
* `pub`: Exposed in the public API, part of the crate's contract.
* `pub(crate)`: Internal to the crate, shared between modules but not exposed.
* Private (no modifier): Internal to the module, implementation detail.

Keep as much private as possible. Only expose what users of your crate genuinely need.

---

## 22. Tooling

* Code must be formatted with `rustfmt`.
* `cargo clippy` should run clean or with documented `allow` attributes.
* Consider a `rust-toolchain.toml` to pin a Rust version for reproducibility.

---

## Summary

This style guide prioritizes:
* **Clarity** - code should read like a story.
* **Searchability** - logs, errors, and code should be easy to find.
* **Explicitness** - manual over magical, visible over hidden.
* **Richness** - errors and logs tell the full story of what happened.
* **Usability** - public APIs should be discoverable and examples should just work.
* **Quality** - thoughtful tests, careful dependencies, deliberate design.

When in doubt, ask: "Could someone unfamiliar with this code understand what happened by reading the logs and errors alone?" If yes, you're on the right track.