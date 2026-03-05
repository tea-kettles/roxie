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

| Tool                          | Result                                                    |
| ----------------------------- | --------------------------------------------------------- |
| `cargo check --all-features`  | PASS — 0 warnings                                         |
| `cargo clippy --all-features` | 0 warnings                                                |
| `cargo test --all-features`   | 290 lib + doc tests PASS, 0 failures                      |
| `cargo doc --all-features`    | 0 warnings                                                |

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

### Design Issues Resolved

1. ~~**TLS wrapping duplication in `src/transport/proxy.rs`**~~ — **Fixed.** Extracted to `wrap_tls_if_needed()` private helper; all 4 call sites now delegate to it.

2. ~~**`ConnectionPool::get()` returns `Result<_, String>`**~~ — **Fixed.** `ConnectionPoolError` typed enum with `NoProxiesAvailable`, `ConnectionLimitReached`, and `ConnectFailed` variants.

3. ~~**Duplicate I/O variants in `ProxyError`**~~ — **Fixed.** `IoError` removed; all sites consolidated onto `Io`.

4. ~~**`from_reply_code(0x5A)` uses `unreachable!()`**~~ — **Fixed.** Returns `UnexpectedSuccessCode` variant instead of panicking.

### Remaining Design Issues

5. **Empty protocol files** — `src/protocols/trojan.rs`, `vmess.rs`, `hysteria2.rs` are intentional stubs. Config and error modules are fleshed out; placeholder error enums now carry `#[non_exhaustive]`.

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

### Non-Compliant (Resolved)

- [x] ~~**`Result<_, String>` in `connection_pool.rs`**~~ — **Fixed.** `ConnectionPoolError` typed enum.
- [x] ~~**Empty stub tests** in `src/extensions/proxy_list_ext.rs`~~ — **Fixed.** All 4 stubs now assert real behavior; 3 new `#[tokio::test]` async tests added for empty-list fast-paths.
- [x] ~~**Broken doc links** in `src/extensions/proxy_list_ext.rs`~~ — **Fixed.** Qualified as `ProxyListExt::connect_*`.
- [x] ~~**Links to private items** in `src/utils/json_export.rs`~~ — **Fixed.** Changed to backtick prose.
- [x] ~~**Unused imports** in `src/extensions/proxy_pool_ext.rs`~~ — **Fixed.**

### Non-Compliant (Remaining)

- [ ] **Missing doctests on getters** — `src/config/tls_config.rs` and `src/config/vmess_config.rs` have bare getter methods without `/// # Examples` blocks. The style guide requires doctests on all public API items.

---

## Logic & Correctness

### Potential Issues (Resolved)

1. ~~**`socks4_errors.rs:from_reply_code(0x5A)`**~~ — **Fixed.** Returns `UnexpectedSuccessCode` variant; no panic path.

2. ~~**`shadowsocks.rs` nonce management**~~ — **Fixed.** `debug_assert!` guards the 2^96 nonce space in `Nonce::advance()`, documents the bound, and will catch exhaustion in debug builds.

### Potential Issues (Remaining)

3. **`proxy_pool.rs` exponential decay** — scoring is sound mathematically, but the fast-path sampling (`choose_multiple`) could theoretically starve low-scored proxies in large pools.

4. **`proxy_pool_ext.rs` potential race condition** — score updates and proxy selection happen across `await` points without synchronization beyond the `RwLock`. Under heavy concurrency, stale scores could influence selection.

5. **`connection_pool.rs` idle connection validation** — connections are returned to the pool on drop but there's no health check on retrieval. Stale TCP connections could be handed out.

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

| Category                | Grade | Delta | Notes                                                          |
| ----------------------- | ----- | ----- | -------------------------------------------------------------- |
| Architecture            | A     | →     | TLS helper extracted; clean layering maintained                |
| Error handling          | A+    | ↑     | All panic risks eliminated; no string errors; no duplicate variants |
| Documentation           | A-    | ↑     | 0 doc warnings; intra-doc links clean; getters still lack doctests |
| Test coverage           | A-    | ↑     | 290 tests, 0 failures; stub tests replaced with real assertions |
| Style guide adherence   | A-    | ↑     | All P1/P2 violations resolved; one P3 gap remains (getter doctests) |
| Security                | A     | →     | Nonce overflow guard added; zeroization and AEAD unchanged     |
| Code duplication        | A-    | ↑     | TLS wrapping consolidated from 4× to single helper             |
| Dependency hygiene      | A     | ↑     | All 3 misplaced deps moved to `[dev-dependencies]`             |
| Clippy cleanliness      | A     | ↑     | 29 warnings → 0                                                |
| Production readiness    | A-    | ↑     | All P1 + P2 complete; two P3 items remain                      |

**Overall: A-** *(was B+)* — All Priority 1 and Priority 2 action items resolved. The remaining gaps are a single P3 style issue (getter doctests) and two open correctness considerations (connection pool health checks, proxy pool sampling fairness).

---

## Action Items

### Priority 1 — Must Fix

- [x] **Move misplaced dependencies to `[dev-dependencies]`**
  - `scraper`, `tracing-subscriber`, `tempfile` in `Cargo.toml`
  - These inflate the dependency tree for all downstream users

- [x] **Fix 2 failing integration tests** in `tests/export_import.rs`
  - `proxylist_export_import_roundtrip` and `proxylist_export_import_applies_auto_tls_overrides` panic because `tests/proxies.json` is gitignored and absent on fresh clone
  - Either add `#[ignore]` attributes or embed test data inline

- [x] **Clean up 29 clippy warnings**
  - `needless_borrow`, `collapsible_if`, `manual_non_exhaustive`, `unused_imports`, etc.
  - Run `cargo clippy --all-features --fix` for the auto-fixable ones, manually address the rest

### Priority 2 — Should Fix

- [x] **Extract TLS wrapping helper in `src/transport/proxy.rs`**
  - The same ~30-line block appears 4 times (HTTP, SOCKS5, Shadowsocks, Tor connect methods)
  - Extract to a private `wrap_tls_if_configured()` helper

- [x] **Replace `Result<_, String>` in `src/client/connection_pool.rs`**
  - `ConnectionPool::get()` returns string errors
  - Create a `ConnectionPoolError` enum or use an existing error type

- [x] **Fix `from_reply_code(0x5A)` panic risk** in `src/errors/socks4_errors.rs`
  - Replace `unreachable!()` with a safe return or `debug_assert`

- [x] **Fix duplicate `Io`/`IoError` variants** in `src/errors/proxy_errors.rs`
  - Consolidate into a single I/O error variant

- [x] **Fix broken intra-doc links** (7 warnings from `cargo doc`)
  - `src/extensions/proxy_list_ext.rs` — references to non-existent items
  - `src/utils/json_export.rs` — links to private types

### Priority 3 — Nice to Have

- [ ] **Add missing doctests to bare getters**
  - `src/config/tls_config.rs` — getters like `handshake_timeout()`, `alpn_protocols()`, etc.
  - `src/config/vmess_config.rs` — multiple getters without `# Examples` blocks

- [x] **Fill in stub tests** in `src/extensions/proxy_list_ext.rs`
  - Test functions exist but contain no assertions

- [x] **Remove unused imports** in `src/extensions/proxy_pool_ext.rs`

- [ ] **Add idle connection health checks** in `src/client/connection_pool.rs`
  - Connections returned to pool have no staleness validation on retrieval

- [x] **Consider nonce overflow guard** in `src/protocols/shadowsocks.rs`
  - Practically unreachable with 12-byte nonce, but defensive coding is preferred per style guide
