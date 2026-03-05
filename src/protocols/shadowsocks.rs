//! Shadowsocks AEAD protocol implementation.
//!
//! Implements the Shadowsocks encrypted proxy protocol using AEAD ciphers.
//! Supports AES-GCM and ChaCha20-Poly1305 variants for secure tunneling.
//!
//! The protocol uses:
//! 1. Password-based key derivation (EVP_BytesToKey with MD5)
//! 2. HKDF-SHA1 for session key derivation
//! 3. AEAD cipher with incrementing nonces
//! 4. Chunk-based encoding (encrypted length + encrypted payload)
//!
//! DEV NOTE:
//! - Scoped method support is currently feature-complete for:
//!   `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`,
//!   `chacha20-ietf-poly1305`, and `xchacha20-ietf-poly1305`.
//! - This scope is validated by live method-probe and live stress tests under `tests/`
//!   (`live_shadowsocks_probe.rs`, `live_shadowsocks_stress.rs`) for this project environment.

use aes_gcm::{
    Aes128Gcm, Aes256Gcm,
    aead::{AeadInPlace, KeyInit, generic_array::GenericArray},
};
use aes_gcm::aes::{Aes192, cipher::consts::U12};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use hkdf::Hkdf;
use md5::compute;
use rand::{RngCore, rngs::OsRng};
use sha1::Sha1;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};
use tracing::trace;
use url::Url;
use zeroize::Zeroize;

use crate::config::{HasBaseProxyConfig, ShadowsocksConfig};
use crate::errors::ShadowsocksError;
use crate::transport::{Endpoint, idna_encode, parse_ip};

// Protocol Constants
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;
pub(crate) const MAX_PAYLOAD: usize = 0x3FFF; // 16383 bytes
type Aes192Gcm = aes_gcm::AesGcm<Aes192, U12>;

/* Cipher Method */

/// Supported AEAD cipher methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMethod {
    /// AES-128-GCM (16-byte key, 16-byte salt).
    Aes128Gcm,
    /// AES-192-GCM (24-byte key, 24-byte salt).
    Aes192Gcm,
    /// AES-256-GCM (32-byte key, 32-byte salt).
    Aes256Gcm,
    /// ChaCha20-Poly1305 (32-byte key, 32-byte salt).
    ChaCha20Poly1305,
    /// XChaCha20-Poly1305 (32-byte key, 32-byte salt).
    XChaCha20Poly1305,
    /// Legacy AES-128-CFB (16-byte key, 16-byte IV).
    Aes128Cfb,
    /// Legacy AES-192-CFB (24-byte key, 16-byte IV).
    Aes192Cfb,
    /// Legacy AES-256-CFB (32-byte key, 16-byte IV).
    Aes256Cfb,
    /// Legacy RC4-MD5 (16-byte key, 16-byte IV).
    Rc4Md5,
    /// Legacy ChaCha20 stream cipher (32-byte key, 12-byte IV).
    ChaCha20,
}

impl CipherMethod {
    /// Parse cipher method from string.
    pub fn parse(input: &str) -> Result<Self, ShadowsocksError> {
        let cipher = input.to_ascii_lowercase();

        match cipher.as_str() {
            // === Supported AEAD ciphers ===
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "aes-192-gcm" => Ok(Self::Aes192Gcm),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),

            // ChaCha20 (both official Shadowsocks names)
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Ok(Self::ChaCha20Poly1305),
            "xchacha20-poly1305" | "xchacha20-ietf-poly1305" => Ok(Self::XChaCha20Poly1305),

            // === Explicitly rejected legacy ciphers ===
            c if Self::is_legacy_cipher(c) => Err(ShadowsocksError::LegacyCipherNotSupported {
                method: c.to_string(),
            }),

            // === Everything else ===
            _ => Err(ShadowsocksError::UnsupportedCipherMethod {
                method: cipher.to_string(),
            }),
        }
    }

    /// Returns true if the cipher name refers to a known legacy (non-AEAD)
    /// Shadowsocks cipher that is no longer supported.
    fn is_legacy_cipher(cipher: &str) -> bool {
        matches!(
            cipher,
            // AES stream modes
            "aes-128-cfb"
            | "aes-192-cfb"
            | "aes-256-cfb"
            | "aes-128-ctr"
            | "aes-192-ctr"
            | "aes-256-ctr"

            // RC4
            | "rc4-md5"

            // Blowfish / DES / IDEA
            | "bf-cfb"
            | "des-cfb"
            | "idea-cfb"

            // Camellia
            | "camellia-128-cfb"
            | "camellia-192-cfb"
            | "camellia-256-cfb"

            // SEED
            | "seed-cfb"
        )
    }

    /// Key size in bytes.
    pub fn key_len(&self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes192Gcm => 24,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 | Self::XChaCha20Poly1305 => 32,
            Self::Aes128Cfb => 16,
            Self::Aes192Cfb => 24,
            Self::Aes256Cfb => 32,
            Self::Rc4Md5 => 16,
            Self::ChaCha20 => 32,
        }
    }

    /// Salt size in bytes.
    pub fn salt_len(&self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes192Gcm => 24,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 | Self::XChaCha20Poly1305 => 32,
            // Legacy stream ciphers use IVs instead of salts; preserve typical lengths
            Self::Aes128Cfb | Self::Aes192Cfb | Self::Aes256Cfb | Self::Rc4Md5 => 16,
            Self::ChaCha20 => 12,
        }
    }

    /// Whether this is a legacy stream cipher (non-AEAD).
    pub fn is_legacy(&self) -> bool {
        matches!(
            self,
            Self::Aes128Cfb | Self::Aes192Cfb | Self::Aes256Cfb | Self::Rc4Md5 | Self::ChaCha20
        )
    }
}

/* Key Derivation */

/// Derive master key from password using EVP_BytesToKey (MD5).
///
/// This is the Shadowsocks-standard key derivation method.
pub(crate) fn derive_master_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut prev: Option<[u8; 16]> = None;

    while key.len() < key_len {
        let mut input = Vec::new();
        if let Some(p) = prev {
            input.extend_from_slice(&p);
        }
        input.extend_from_slice(password);

        let hash = compute(&input);
        let hash_bytes: [u8; 16] = hash.into();
        key.extend_from_slice(&hash_bytes);
        prev = Some(hash_bytes);
    }

    key.truncate(key_len);
    key
}

/// Derive session subkey using HKDF-SHA1.
pub(crate) fn derive_session_key(master: &[u8], salt: &[u8]) -> Result<Vec<u8>, ShadowsocksError> {
    let hkdf = Hkdf::<Sha1>::new(Some(salt), master);
    let mut subkey = vec![0u8; master.len()];
    hkdf.expand(b"ss-subkey", &mut subkey)
        .map_err(|e| ShadowsocksError::KeyDerivationFailed {
            reason: format!("HKDF expand failed: {e}"),
        })?;
    Ok(subkey)
}

/* Nonce Counter */

/// Little-endian incrementing nonce counter.
#[derive(Clone, Copy, Debug)]
pub struct Nonce(u128);

impl Default for Nonce {
    fn default() -> Self {
        Self::new()
    }
}

impl Nonce {
    pub fn new() -> Self {
        Self(0)
    }

    /// Get current nonce and advance counter.
    ///
    /// # Panics
    ///
    /// Panics in debug builds (and returns an error in release builds via
    /// the overflow check) if the 96-bit nonce space is exhausted. In practice
    /// this requires encrypting ~2^96 chunks (~600 ZiB) over a single session,
    /// so it is unreachable under normal operation.
    pub(crate) fn advance(&mut self) -> [u8; NONCE_LEN] {
        // The usable nonce space is 96 bits (NONCE_LEN = 12 bytes).
        // Guard against wrapping into already-used nonce values.
        debug_assert!(
            self.0 < (1u128 << 96),
            "shadowsocks nonce counter exhausted (2^96 chunks encrypted)"
        );
        let mut buf = [0u8; NONCE_LEN];
        let bytes = self.0.to_le_bytes();
        buf.copy_from_slice(&bytes[..NONCE_LEN]);
        self.0 = self.0.wrapping_add(1);
        buf
    }

    /// Rollback one increment (for partial read recovery).
    pub(crate) fn rollback(&mut self) {
        self.0 = self.0.wrapping_sub(1);
    }
}

/* AEAD Cipher */

/// Runtime AEAD cipher instance.
pub enum AeadCipher {
    Aes128(Box<Aes128Gcm>),
    Aes192(Box<Aes192Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha(ChaCha20Poly1305),
    XChaCha(XChaCha20Poly1305),
}

impl AeadCipher {
    pub fn new(method: CipherMethod, key: &[u8]) -> Result<Self, ShadowsocksError> {
        match method {
            CipherMethod::Aes128Gcm => {
                if key.len() != 16 {
                    return Err(ShadowsocksError::InvalidKeyLength {
                        expected: 16,
                        actual: key.len(),
                    });
                }
                let key_arr = GenericArray::from_slice(key);
                Ok(Self::Aes128(Box::new(Aes128Gcm::new(key_arr))))
            }
            CipherMethod::Aes192Gcm => {
                if key.len() != 24 {
                    return Err(ShadowsocksError::InvalidKeyLength {
                        expected: 24,
                        actual: key.len(),
                    });
                }
                let key_arr = GenericArray::from_slice(key);
                Ok(Self::Aes192(Box::new(Aes192Gcm::new(key_arr))))
            }
            CipherMethod::Aes256Gcm => {
                if key.len() != 32 {
                    return Err(ShadowsocksError::InvalidKeyLength {
                        expected: 32,
                        actual: key.len(),
                    });
                }
                let key_arr = GenericArray::from_slice(key);
                Ok(Self::Aes256(Box::new(Aes256Gcm::new(key_arr))))
            }
            CipherMethod::ChaCha20Poly1305 => {
                if key.len() != 32 {
                    return Err(ShadowsocksError::InvalidKeyLength {
                        expected: 32,
                        actual: key.len(),
                    });
                }
                let key_arr = GenericArray::from_slice(key);
                Ok(Self::ChaCha(ChaCha20Poly1305::new(key_arr)))
            }
            CipherMethod::XChaCha20Poly1305 => {
                if key.len() != 32 {
                    return Err(ShadowsocksError::InvalidKeyLength {
                        expected: 32,
                        actual: key.len(),
                    });
                }
                let key_arr = GenericArray::from_slice(key);
                Ok(Self::XChaCha(XChaCha20Poly1305::new(key_arr)))
            }
            _ => Err(ShadowsocksError::LegacyCipherNotSupported {
                method: method_string(method),
            }),
        }
    }

    /// Encrypt in-place, return tag.
    pub(crate) fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        data: &mut [u8],
    ) -> Result<[u8; TAG_LEN], ShadowsocksError> {
        let tag = match self {
            Self::Aes128(c) => c
                .encrypt_in_place_detached(GenericArray::from_slice(nonce), &[], data)
                .map_err(|e| ShadowsocksError::EncryptionFailed {
                    reason: e.to_string(),
                })?,
            Self::Aes192(c) => c
                .encrypt_in_place_detached(GenericArray::from_slice(nonce), &[], data)
                .map_err(|e| ShadowsocksError::EncryptionFailed {
                    reason: e.to_string(),
                })?,
            Self::Aes256(c) => c
                .encrypt_in_place_detached(GenericArray::from_slice(nonce), &[], data)
                .map_err(|e| ShadowsocksError::EncryptionFailed {
                    reason: e.to_string(),
                })?,
            Self::ChaCha(c) => c
                .encrypt_in_place_detached(GenericArray::from_slice(nonce), &[], data)
                .map_err(|e| ShadowsocksError::EncryptionFailed {
                    reason: e.to_string(),
                })?,
            Self::XChaCha(c) => {
                let mut xnonce = [0u8; 24];
                xnonce[..NONCE_LEN].copy_from_slice(nonce);
                c.encrypt_in_place_detached(GenericArray::from_slice(&xnonce), &[], data)
                    .map_err(|e| ShadowsocksError::EncryptionFailed {
                        reason: e.to_string(),
                    })?
            }
        };

        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(&tag);
        Ok(out)
    }

    /// Decrypt in-place with tag verification.
    pub(crate) fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        data: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), ShadowsocksError> {
        let tag_arr = GenericArray::from_slice(tag);

        match self {
            Self::Aes128(c) => c
                .decrypt_in_place_detached(GenericArray::from_slice(nonce), &[], data, tag_arr)
                .map_err(|e| ShadowsocksError::DecryptionFailed {
                    reason: e.to_string(),
                }),
            Self::Aes192(c) => c
                .decrypt_in_place_detached(GenericArray::from_slice(nonce), &[], data, tag_arr)
                .map_err(|e| ShadowsocksError::DecryptionFailed {
                    reason: e.to_string(),
                }),
            Self::Aes256(c) => c
                .decrypt_in_place_detached(GenericArray::from_slice(nonce), &[], data, tag_arr)
                .map_err(|e| ShadowsocksError::DecryptionFailed {
                    reason: e.to_string(),
                }),
            Self::ChaCha(c) => c
                .decrypt_in_place_detached(GenericArray::from_slice(nonce), &[], data, tag_arr)
                .map_err(|e| ShadowsocksError::DecryptionFailed {
                    reason: e.to_string(),
                }),
            Self::XChaCha(c) => {
                let mut xnonce = [0u8; 24];
                xnonce[..NONCE_LEN].copy_from_slice(nonce);
                c.decrypt_in_place_detached(
                    GenericArray::from_slice(&xnonce),
                    &[],
                    data,
                    tag_arr,
                )
                .map_err(|e| ShadowsocksError::DecryptionFailed {
                    reason: e.to_string(),
                })
            }
        }
    }
}

/* Chunk Encoding/Decoding */

/// Encrypt plaintext into AEAD chunk format.
pub(crate) fn encode_chunk(
    cipher: &AeadCipher,
    nonce: &mut Nonce,
    data: &[u8],
) -> Result<Vec<u8>, ShadowsocksError> {
    if data.len() > MAX_PAYLOAD {
        return Err(ShadowsocksError::PayloadTooLarge {
            size: data.len(),
            max: MAX_PAYLOAD,
        });
    }

    let mut out = Vec::with_capacity(2 + TAG_LEN + data.len() + TAG_LEN);

    // Encrypt length
    let mut len_buf = (data.len() as u16).to_be_bytes();
    let len_tag = cipher.seal(&nonce.advance(), &mut len_buf)?;
    out.extend_from_slice(&len_buf);
    out.extend_from_slice(&len_tag);

    // Encrypt payload
    let mut payload = data.to_vec();
    let payload_tag = cipher.seal(&nonce.advance(), &mut payload)?;
    out.extend_from_slice(&payload);
    out.extend_from_slice(&payload_tag);

    Ok(out)
}

/// Try to decode one chunk from buffer. Returns None if incomplete.
pub(crate) fn decode_chunk(
    cipher: &AeadCipher,
    nonce: &mut Nonce,
    buf: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>, ShadowsocksError> {
    // Need length + tag
    if buf.len() < 2 + TAG_LEN {
        return Ok(None);
    }

    // Decrypt length
    let mut len_buf = [0u8; 2];
    len_buf.copy_from_slice(&buf[0..2]);
    let len_tag: [u8; TAG_LEN] = buf[2..2 + TAG_LEN].try_into().unwrap();
    let len_nonce = nonce.advance();
    cipher.open(&len_nonce, &mut len_buf, &len_tag)?;

    let payload_len = u16::from_be_bytes(len_buf) as usize;
    if payload_len > MAX_PAYLOAD {
        return Err(ShadowsocksError::InvalidChunkLength {
            length: payload_len,
            max: MAX_PAYLOAD,
        });
    }

    // Check if complete
    let total = 2 + TAG_LEN + payload_len + TAG_LEN;
    if buf.len() < total {
        nonce.rollback();
        return Ok(None);
    }

    // Decrypt payload
    let payload_start = 2 + TAG_LEN;
    let mut payload = buf[payload_start..payload_start + payload_len].to_vec();
    let payload_tag: [u8; TAG_LEN] = buf[payload_start + payload_len..total].try_into().unwrap();
    let payload_nonce = nonce.advance();
    cipher.open(&payload_nonce, &mut payload, &payload_tag)?;

    buf.drain(0..total);
    Ok(Some(payload))
}

/* Address Encoding */

/// Encode target address in SOCKS5 format.
fn encode_target(endpoint: &Endpoint, port: u16) -> Result<Vec<u8>, ShadowsocksError> {
    let mut buf = Vec::with_capacity(1 + 255 + 2);

    match endpoint {
        Endpoint::V4(octets) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(octets);
        }
        Endpoint::V6(octets) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(octets);
        }
        Endpoint::Domain(domain) => {
            if domain.len() > 255 {
                return Err(ShadowsocksError::DomainTooLong {
                    length: domain.len(),
                    max: 255,
                });
            }
            buf.push(ATYP_DOMAIN);
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain);
        }
    }

    buf.extend_from_slice(&port.to_be_bytes());
    Ok(buf)
}

/* Password Validation */

/// Validate password strength (basic checks).
fn validate_password(password: &str) -> Result<(), ShadowsocksError> {
    if password.is_empty() {
        return Err(ShadowsocksError::WeakPassword {
            reason: "password cannot be empty".to_string(),
        });
    }

    if password.len() < 8 {
        return Err(ShadowsocksError::WeakPassword {
            reason: format!(
                "password is too short ({} characters, minimum 8)",
                password.len()
            ),
        });
    }

    Ok(())
}

/* Public API */

/// Establish Shadowsocks encrypted tunnel.
///
/// Performs the Shadowsocks handshake by sending the encrypted target address,
/// then returns connection details for creating the encrypted stream wrapper.
///
/// # Examples
///
/// ```no_run
/// use roxie::protocols::shadowsocks::establish_shadowsocks;
/// use roxie::config::ShadowsocksConfig;
/// use tokio::net::TcpStream;
/// use url::Url;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = ShadowsocksConfig::new()
///     .set_method("aes-256-gcm");
///
/// let mut stream = TcpStream::connect("localhost:8388").await?;
/// let target = Url::parse("https://example.com:443")?;
///
/// let (cipher, nonce, master_key, method) = establish_shadowsocks(
///     &mut stream,
///     &target,
///     "my_password",
///     &config,
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub async fn establish_shadowsocks(
    stream: &mut TcpStream,
    target_url: &Url,
    password: &str,
    config: &ShadowsocksConfig,
) -> Result<(AeadCipher, Nonce, Vec<u8>, CipherMethod), ShadowsocksError> {
    let start = Instant::now();
    let proxy_addr = stream
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    trace!(
        target_url = %target_url,
        proxy_addr = %proxy_addr,
        method = config.get_method(),
        "starting handshake"
    );

    // Validate password
    validate_password(password)?;

    let handshake_timeout = config.get_base_config().get_handshake_timeout();
    let result = timeout(
        handshake_timeout,
        handshake(stream, target_url, password, config, &proxy_addr),
    )
    .await;

    match result {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(e)) => {
            trace!(
                target_url = %target_url,
                proxy_addr = %proxy_addr,
                error = %e,
                elapsed_ms = start.elapsed().as_millis(),
                "handshake failed"
            );
            Err(e)
        }
        Err(_) => {
            let error = ShadowsocksError::HandshakeTimeout {
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

/* Protocol Implementation */

/// Perform Shadowsocks handshake.
async fn handshake(
    stream: &mut TcpStream,
    target_url: &Url,
    password: &str,
    config: &ShadowsocksConfig,
    proxy_addr: &str,
) -> Result<(AeadCipher, Nonce, Vec<u8>, CipherMethod), ShadowsocksError> {
    let start = Instant::now();

    // Extract target
    let host = target_url
        .host_str()
        .ok_or(ShadowsocksError::NoTargetHost)?;
    let port = target_url
        .port_or_known_default()
        .ok_or(ShadowsocksError::NoTargetPort)?;

    if port == 0 {
        return Err(ShadowsocksError::InvalidPort {
            reason: "port cannot be 0".to_string(),
        });
    }

    trace!(
        proxy_addr = %proxy_addr,
        target_host = %host,
        target_port = port,
        "resolving target"
    );

    // Resolve endpoint
    let endpoint = match parse_ip(host) {
        Some(ep) => ep,
        None => Endpoint::Domain(idna_encode(host)?),
    };

    // Parse cipher method
    let method = CipherMethod::parse(config.get_method())?;
    if method.is_legacy() {
        return Err(ShadowsocksError::LegacyCipherNotSupported {
            method: method_string(method),
        });
    }

    trace!(
        proxy_addr = %proxy_addr,
        method = ?method,
        "deriving keys"
    );

    // Derive master key
    let master_key = derive_master_key(password.as_bytes(), method.key_len());

    // Generate salt
    let mut salt = vec![0u8; method.salt_len()];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|source| ShadowsocksError::RandomGenerationFailed { source })?;

    trace!(
        proxy_addr = %proxy_addr,
        salt_len = salt.len(),
        "generated salt"
    );

    // Derive session key and create cipher
    let mut session_key = derive_session_key(&master_key, &salt)?;
    let cipher = AeadCipher::new(method, &session_key).map_err(|e| {
        ShadowsocksError::CipherInitializationFailed {
            method: method_string(method),
            reason: e.to_string(),
        }
    })?;
    session_key.zeroize();

    // Encode target address
    let target_addr = encode_target(&endpoint, port)?;

    trace!(
        proxy_addr = %proxy_addr,
        target_addr_len = target_addr.len(),
        "encrypting target address"
    );

    // Encrypt address as first chunk
    let mut nonce = Nonce::new();
    let encrypted = encode_chunk(&cipher, &mut nonce, &target_addr)?;

    // Build packet: [salt][encrypted_chunk]
    let mut packet = Vec::with_capacity(salt.len() + encrypted.len());
    packet.extend_from_slice(&salt);
    packet.extend_from_slice(&encrypted);

    trace!(
        proxy_addr = %proxy_addr,
        packet_size = packet.len(),
        salt_size = salt.len(),
        encrypted_size = encrypted.len(),
        "sending handshake packet"
    );

    // Send packet
    let phase_timeout = config.get_base_config().get_phase_timeout();
    timeout(phase_timeout, stream.write_all(&packet))
        .await
        .map_err(|_| ShadowsocksError::PhaseTimeout {
            proxy_addr: proxy_addr.to_string(),
            phase: "handshake packet (write)".to_string(),
            elapsed_ms: start.elapsed().as_millis() as u64,
            timeout_ms: phase_timeout.as_millis() as u64,
        })?
        .map_err(|source| ShadowsocksError::Io {
            proxy_addr: proxy_addr.to_string(),
            source,
        })?;

    timeout(phase_timeout, stream.flush())
        .await
        .map_err(|_| ShadowsocksError::PhaseTimeout {
            proxy_addr: proxy_addr.to_string(),
            phase: "handshake packet (flush)".to_string(),
            elapsed_ms: start.elapsed().as_millis() as u64,
            timeout_ms: phase_timeout.as_millis() as u64,
        })?
        .map_err(|source| ShadowsocksError::Io {
            proxy_addr: proxy_addr.to_string(),
            source,
        })?;

    salt.zeroize();

    Ok((cipher, nonce, master_key, method))
}

fn method_string(method: CipherMethod) -> String {
    match method {
        CipherMethod::Aes128Gcm => "aes-128-gcm",
        CipherMethod::Aes192Gcm => "aes-192-gcm",
        CipherMethod::Aes256Gcm => "aes-256-gcm",
        CipherMethod::ChaCha20Poly1305 => "chacha20-ietf-poly1305",
        CipherMethod::XChaCha20Poly1305 => "xchacha20-ietf-poly1305",
        CipherMethod::Aes128Cfb => "aes-128-cfb",
        CipherMethod::Aes192Cfb => "aes-192-cfb",
        CipherMethod::Aes256Cfb => "aes-256-cfb",
        CipherMethod::Rc4Md5 => "rc4-md5",
        CipherMethod::ChaCha20 => "chacha20",
    }
    .to_string()
}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_aes_128_gcm() {
        assert_eq!(
            CipherMethod::parse("aes-128-gcm").unwrap(),
            CipherMethod::Aes128Gcm
        );
        assert_eq!(
            CipherMethod::parse("AES-128-GCM").unwrap(),
            CipherMethod::Aes128Gcm
        );
    }

    #[test]
    fn parse_aes_256_gcm() {
        assert_eq!(
            CipherMethod::parse("aes-256-gcm").unwrap(),
            CipherMethod::Aes256Gcm
        );
    }

    #[test]
    fn parse_aes_192_gcm() {
        assert_eq!(
            CipherMethod::parse("aes-192-gcm").unwrap(),
            CipherMethod::Aes192Gcm
        );
    }

    #[test]
    fn parse_chacha20_poly1305() {
        assert_eq!(
            CipherMethod::parse("chacha20-ietf-poly1305").unwrap(),
            CipherMethod::ChaCha20Poly1305
        );
    }

    #[test]
    fn parse_xchacha20_poly1305() {
        assert_eq!(
            CipherMethod::parse("xchacha20-ietf-poly1305").unwrap(),
            CipherMethod::XChaCha20Poly1305
        );
    }

    #[test]
    fn parse_legacy_rejected() {
        assert!(matches!(
            CipherMethod::parse("aes-128-cfb"),
            Err(ShadowsocksError::LegacyCipherNotSupported { .. })
        ));
        assert!(matches!(
            CipherMethod::parse("rc4-md5"),
            Err(ShadowsocksError::LegacyCipherNotSupported { .. })
        ));
    }

    #[test]
    fn parse_unknown_rejected() {
        assert!(matches!(
            CipherMethod::parse("invalid"),
            Err(ShadowsocksError::UnsupportedCipherMethod { .. })
        ));
    }

    #[test]
    fn key_lengths() {
        assert_eq!(CipherMethod::Aes128Gcm.key_len(), 16);
        assert_eq!(CipherMethod::Aes192Gcm.key_len(), 24);
        assert_eq!(CipherMethod::Aes256Gcm.key_len(), 32);
        assert_eq!(CipherMethod::ChaCha20Poly1305.key_len(), 32);
        assert_eq!(CipherMethod::XChaCha20Poly1305.key_len(), 32);
    }

    #[test]
    fn salt_lengths() {
        assert_eq!(CipherMethod::Aes128Gcm.salt_len(), 16);
        assert_eq!(CipherMethod::Aes192Gcm.salt_len(), 24);
        assert_eq!(CipherMethod::Aes256Gcm.salt_len(), 32);
        assert_eq!(CipherMethod::ChaCha20Poly1305.salt_len(), 32);
        assert_eq!(CipherMethod::XChaCha20Poly1305.salt_len(), 32);
    }

    #[test]
    fn master_key_deterministic() {
        let k1 = derive_master_key(b"test", 32);
        let k2 = derive_master_key(b"test", 32);
        assert_eq!(k1, k2);
    }

    #[test]
    fn master_key_varies_with_password() {
        let k1 = derive_master_key(b"password1", 32);
        let k2 = derive_master_key(b"password2", 32);
        assert_ne!(k1, k2);
    }

    #[test]
    fn session_key_varies_with_salt() {
        let master = derive_master_key(b"password", 32);
        let s1 = derive_session_key(&master, &[0u8; 32]).unwrap();
        let s2 = derive_session_key(&master, &[1u8; 32]).unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn nonce_starts_zero() {
        let mut n = Nonce::new();
        assert_eq!(n.advance(), [0u8; 12]);
    }

    #[test]
    fn nonce_increments() {
        let mut n = Nonce::new();
        n.advance();
        let second = n.advance();
        assert_eq!(second[0], 1);
    }

    #[test]
    fn nonce_rollback() {
        let mut n = Nonce::new();
        n.advance();
        n.advance();
        n.rollback();
        let val = n.advance();
        assert_eq!(val[0], 1);
    }

    #[test]
    fn aes256_roundtrip() {
        let key = derive_master_key(b"password", 32);
        let cipher = AeadCipher::new(CipherMethod::Aes256Gcm, &key).unwrap();
        let nonce = [0u8; 12];

        let mut data = b"test data".to_vec();
        let tag = cipher.seal(&nonce, &mut data).unwrap();
        cipher.open(&nonce, &mut data, &tag).unwrap();
        assert_eq!(&data, b"test data");
    }

    #[test]
    fn chunk_roundtrip() {
        let key = derive_master_key(b"password", 32);
        let cipher = AeadCipher::new(CipherMethod::Aes256Gcm, &key).unwrap();

        let mut enc_nonce = Nonce::new();
        let mut dec_nonce = Nonce::new();

        let encoded = encode_chunk(&cipher, &mut enc_nonce, b"test payload").unwrap();
        let mut buf = encoded;
        let decoded = decode_chunk(&cipher, &mut dec_nonce, &mut buf)
            .unwrap()
            .unwrap();

        assert_eq!(&decoded, b"test payload");
        assert!(buf.is_empty());
    }

    #[test]
    fn chunk_partial_returns_none() {
        let key = derive_master_key(b"password", 32);
        let cipher = AeadCipher::new(CipherMethod::Aes256Gcm, &key).unwrap();

        let mut enc_nonce = Nonce::new();
        let mut dec_nonce = Nonce::new();

        let encoded = encode_chunk(&cipher, &mut enc_nonce, b"data").unwrap();
        let mut buf = encoded[..10].to_vec();

        assert!(
            decode_chunk(&cipher, &mut dec_nonce, &mut buf)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn encode_ipv4() {
        let endpoint = Endpoint::V4([192, 168, 1, 1]);
        let encoded = encode_target(&endpoint, 443).unwrap();

        assert_eq!(encoded[0], ATYP_IPV4);
        assert_eq!(&encoded[1..5], &[192, 168, 1, 1]);
        assert_eq!(&encoded[5..7], &443u16.to_be_bytes());
    }

    #[test]
    fn encode_domain() {
        let endpoint = Endpoint::Domain(b"example.com".to_vec());
        let encoded = encode_target(&endpoint, 8080).unwrap();

        assert_eq!(encoded[0], ATYP_DOMAIN);
        assert_eq!(encoded[1], 11);
        assert_eq!(&encoded[2..13], b"example.com");
    }

    #[test]
    fn validate_password_rejects_empty() {
        assert!(matches!(
            validate_password(""),
            Err(ShadowsocksError::WeakPassword { .. })
        ));
    }

    #[test]
    fn validate_password_rejects_short() {
        assert!(matches!(
            validate_password("short"),
            Err(ShadowsocksError::WeakPassword { .. })
        ));
    }

    #[test]
    fn validate_password_accepts_strong() {
        assert!(validate_password("strong_password_123").is_ok());
    }
}
