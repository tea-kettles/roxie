# Roxie Audit Report & TODO

**Date:** 2026-03-02
**Version:** 0.1.0
**Scope:** Full ground-up audit — code quality, style guide adherence, doctests, logic, design

---

## Project Overview

- **Lines of code:** ~22,000 across 55 files
- **Protocols implemented:** HTTP CONNECT, SOCKS4/4A, SOCKS5, Shadowsocks (AEAD), Tor
- **Protocols placeholder:** Trojan, VMess, Hysteria2
- **Edition:** Rust 2024
- **Feature flags:** 9 (one per protocol + TLS + extensions)

---

## Build Health

| Tool                          | Result                                           |
| ----------------------------- | ------------------------------------------------ |
| `cargo check --all-features`  | PASS — 2 warnings (unused imports)               |
| `cargo clippy --all-features` | 29 warnings                                      |
| `cargo test --all-features`   | 200 lib + 289 doc tests PASS, 2 integration FAIL |
| `cargo doc --all-features`    | 7 warnings (broken intra-doc links)              |

---

## Architecture & Design

### Strengths

- **Clean module separation** — config / errors / protocols / transport / extensions layers are well-defined
- **Trait-based config composition** — `HasBaseProxyConfig` + blanket `BaseProxyConfigBuilder` eliminates boilerplate
- **Five W error pattern** — every error type carries what/where/who/when/why context
- **Feature gating** — each protocol behind its own Cargo feature flag, zero cost when disabled
- **Credential zeroization** — `zeroize` applied consistently across HTTP, SOCKS5, Shadowsocks, Tor
- **Exponential decay scoring** — ProxyPool uses `score * e^(-0.1 * hours_elapsed)` for fair proxy ranking
- **RAII connection pooling** — `PooledStream` guard returns connections to pool on `Drop`
- **Protocol mismatch detection** — each protocol can identify when it's talking to the wrong server type

### Design Issues

1. **TLS wrapping duplication in `src/transport/proxy.rs`** — the same ~30-line TLS wrapping block is copy-pasted 4 times (HTTP, SOCKS5, Shadowsocks, Tor). Should be extracted into a helper.

2. **`ConnectionPool::get()` returns `Result<_, String>`** in `src/client/connection_pool.rs` — violates the style guide requirement for typed error enums. Should use a proper error type.

3. **Duplicate I/O variants in `ProxyError`** in `src/errors/proxy_errors.rs` — has both `Io` and `IoError` variants that serve the same purpose.

4. **`from_reply_code(0x5A)` uses `unreachable!()`** in `src/errors/socks4_errors.rs` — this is a panic risk if a success code is accidentally passed. Should return a `Result` or handle gracefully.

5. **Empty protocol files** — `src/protocols/trojan.rs`, `vmess.rs`, `hysteria2.rs` are completely empty (just CRLF). The config and error modules for these are fleshed out but the protocol files contain nothing.

---

## Style Guide Adherence

### Compliant

- [x] Section markers (`/* Types */`, `/* Public Methods */`, etc.) used consistently
- [x] `thiserror` for all error types
- [x] Module-level `//!` documentation on all files
- [x] `#[must_use]` on getters and constructors
- [x] Builder pattern for configs via blanket impl
- [x] `tracing` for logging (not `println!`)
- [x] Unit tests in `#[cfg(test)] mod tests` blocks

### Non-Compliant

- [ ] **Missing doctests on getters** — `src/config/tls_config.rs` and `src/config/vmess_config.rs` have bare getter methods without `/// # Examples` blocks. The style guide requires doctests on all public API items.
- [ ] **`Result<_, String>` in `connection_pool.rs`** — style guide mandates typed error enums, not string errors.
- [ ] **Empty stub tests** in `src/extensions/proxy_list_ext.rs` — test functions exist but contain no assertions. Style guide says tests should verify behavior.
- [ ] **Broken doc links** in `src/extensions/proxy_list_ext.rs` — references to items that don't resolve, causing `cargo doc` warnings.
- [ ] **Links to private items** in `src/utils/json_export.rs` — doc links reference private types, causing warnings.
- [ ] **Unused imports** in `src/extensions/proxy_pool_ext.rs` — dead code that should be cleaned up.

---

## Logic & Correctness

### Potential Issues

1. **`socks4_errors.rs:from_reply_code(0x5A)`** — calls `unreachable!()` for the success code. If this function is ever called with 0x5A (which represents success), it will panic at runtime.

2. **`proxy_pool.rs` exponential decay** — scoring is sound mathematically, but the fast-path sampling (`choose_multiple`) could theoretically starve low-scored proxies in large pools.

3. **`proxy_pool_ext.rs` potential race condition** — score updates and proxy selection happen across `await` points without synchronization beyond the `RwLock`. Under heavy concurrency, stale scores could influence selection.

4. **`connection_pool.rs` idle connection validation** — connections are returned to the pool on drop but there's no health check on retrieval. Stale TCP connections could be handed out.

5. **`shadowsocks.rs` nonce management** — nonce is incremented correctly per chunk, but there's no explicit overflow check. With a 12-byte nonce this is practically unreachable, but the style guide encourages defensive coding.

### Sound Logic

- SOCKS4/4A variant auto-selection based on target type is correct
- SOCKS5 three-phase handshake follows RFC 1928 faithfully
- Shadowsocks AEAD chunk format `[len(2)+tag(16)][data+tag(16)]` is correct per spec
- HTTP CONNECT header injection prevention (rejecting `\r`, `\n` in values) is properly implemented
- Tor control port protocol parsing handles multi-line replies correctly

---

## Dependencies

### Misplaced Dependencies

These are in `[dependencies]` but should be `[dev-dependencies]`:

| Crate                 | Used In              | Should Be         |
| --------------------- | -------------------- | ------------------ |
| `scraper`             | tests only           | `[dev-dependencies]` |
| `tracing-subscriber`  | examples only        | `[dev-dependencies]` |
| `tempfile`            | tests only           | `[dev-dependencies]` |

Moving these to `[dev-dependencies]` will reduce the dependency tree for downstream consumers.

---

## Summary Scorecard

| Category                | Grade | Notes                                          |
| ----------------------- | ----- | ---------------------------------------------- |
| Architecture            | A     | Clean layering, good trait composition          |
| Error handling          | A     | Five W pattern, typed errors throughout (mostly)|
| Documentation           | B+    | Strong module docs, some getters lack doctests  |
| Test coverage           | B+    | 489 tests pass, but stub tests and 2 failures  |
| Style guide adherence   | B     | Mostly compliant, a few gaps noted above        |
| Security                | A     | Zeroization, injection prevention, AEAD         |
| Code duplication        | B-    | TLS wrapping repeated 4x in proxy.rs            |
| Dependency hygiene      | B-    | 3 misplaced deps                                |
| Clippy cleanliness      | C+    | 29 warnings                                     |
| Production readiness    | B     | Solid foundation, needs the cleanup below       |

**Overall: B+** — Strong library with clean architecture and excellent error handling. Needs a cleanup pass.

---

## Action Items

### Priority 1 — Must Fix

- [x] **Move misplaced dependencies to `[dev-dependencies]`**
  - `scraper`, `tracing-subscriber`, `tempfile` in `Cargo.toml`
  - These inflate the dependency tree for all downstream users

- [x] **Fix 2 failing integration tests** in `tests/export_import.rs`
  - `proxylist_export_import_roundtrip` and `proxylist_export_import_applies_auto_tls_overrides` panic because `tests/proxies.json` is gitignored and absent on fresh clone
  - Either add `#[ignore]` attributes or embed test data inline

- [ ] **Clean up 29 clippy warnings**
  - `needless_borrow`, `collapsible_if`, `manual_non_exhaustive`, `unused_imports`, etc.
  - Run `cargo clippy --all-features --fix` for the auto-fixable ones, manually address the rest

### Priority 2 — Should Fix

- [ ] **Extract TLS wrapping helper in `src/transport/proxy.rs`**
  - The same ~30-line block appears 4 times (HTTP, SOCKS5, Shadowsocks, Tor connect methods)
  - Extract to a private `wrap_tls_if_configured()` helper

- [ ] **Replace `Result<_, String>` in `src/client/connection_pool.rs`**
  - `ConnectionPool::get()` returns string errors
  - Create a `ConnectionPoolError` enum or use an existing error type

- [ ] **Fix `from_reply_code(0x5A)` panic risk** in `src/errors/socks4_errors.rs`
  - Replace `unreachable!()` with a safe return or `debug_assert`

- [ ] **Fix duplicate `Io`/`IoError` variants** in `src/errors/proxy_errors.rs`
  - Consolidate into a single I/O error variant

- [ ] **Fix broken intra-doc links** (7 warnings from `cargo doc`)
  - `src/extensions/proxy_list_ext.rs` — references to non-existent items
  - `src/utils/json_export.rs` — links to private types

### Priority 3 — Nice to Have

- [ ] **Add missing doctests to bare getters**
  - `src/config/tls_config.rs` — getters like `handshake_timeout()`, `alpn_protocols()`, etc.
  - `src/config/vmess_config.rs` — multiple getters without `# Examples` blocks

- [ ] **Fill in stub tests** in `src/extensions/proxy_list_ext.rs`
  - Test functions exist but contain no assertions

- [x] **Remove unused imports** in `src/extensions/proxy_pool_ext.rs`

- [ ] **Add idle connection health checks** in `src/client/connection_pool.rs`
  - Connections returned to pool have no staleness validation on retrieval

- [ ] **Consider nonce overflow guard** in `src/protocols/shadowsocks.rs`
  - Practically unreachable with 12-byte nonce, but defensive coding is preferred per style guide
