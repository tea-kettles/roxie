//! Unified stream wrapper for protocol implementations.
//!
//! Provides `ProxyStream`, a type-erased wrapper around various stream types
//! (TCP, TLS, encrypted protocols) that implements `AsyncRead + AsyncWrite`.
//! This allows protocol implementations to work with any stream type without
//! caring about the underlying transport.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

#[cfg(feature = "tls")]
use tokio_rustls::client::TlsStream;

#[cfg(feature = "shadowsocks")]
use crate::protocols::shadowsocks::{AeadCipher, CipherMethod, Nonce};
#[cfg(feature = "shadowsocks")]
use zeroize::Zeroize;

/* Types */

/// Shadowsocks encrypted stream wrapper.
///
/// Transparently encrypts outgoing data and decrypts incoming data using
/// AEAD ciphers with chunk-based encoding.
#[cfg(feature = "shadowsocks")]
pub struct ShadowsocksStream {
    inner: TcpStream,
    // Encryption (client to server)
    send_cipher: AeadCipher,
    send_nonce: Nonce,
    // Decryption (server to client)
    recv_cipher: Option<AeadCipher>,
    recv_nonce: Nonce,
    master_key: Vec<u8>,
    method: CipherMethod,
    salt_received: bool,
    // Write buffering
    write_buf: Vec<u8>,
    write_pos: usize,
    write_pending: usize,
    // Read buffering
    recv_raw: Vec<u8>,
    recv_plain: Vec<u8>,
    eof: bool,
}

#[cfg(feature = "shadowsocks")]
impl fmt::Debug for ShadowsocksStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowsocksStream")
            .field("write_buf_len", &self.write_buf.len())
            .field("recv_raw_len", &self.recv_raw.len())
            .field("recv_plain_len", &self.recv_plain.len())
            .field("eof", &self.eof)
            .finish()
    }
}

/// Unified stream type that wraps various transport types.
///
/// Provides a single type that can represent TCP streams, TLS streams,
/// or encrypted transports like Shadowsocks. Protocol implementations work with
/// `ProxyStream` and don't need to know the underlying transport.
///
/// # Examples
///
/// ```
/// use roxie::transport::ProxyStream;
/// use tokio::net::TcpStream;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let tcp = TcpStream::connect("127.0.0.1:8080").await?;
/// let stream = ProxyStream::from_tcp(tcp);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub enum ProxyStream {
    /// Raw TCP stream.
    Tcp(TcpStream),

    /// TLS-wrapped TCP stream.
    #[cfg(feature = "tls")]
    Tls(Box<TlsStream<TcpStream>>),

    /// Shadowsocks encrypted stream.
    #[cfg(feature = "shadowsocks")]
    Shadowsocks(Box<ShadowsocksStream>),
}

/* Implementations */

impl ProxyStream {
    /// Wrap a TCP stream.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyStream;
    /// use tokio::net::TcpStream;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let tcp = TcpStream::connect("127.0.0.1:8080").await?;
    /// let stream = ProxyStream::from_tcp(tcp);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_tcp(stream: TcpStream) -> Self {
        Self::Tcp(stream)
    }

    /// Wrap a TLS stream.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(feature = "tls")]
    /// # {
    /// use roxie::transport::ProxyStream;
    /// use tokio::net::TcpStream;
    /// use tokio_rustls::TlsConnector;
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let tcp = TcpStream::connect("127.0.0.1:443").await?;
    /// let config = rustls::ClientConfig::builder()
    ///     .with_root_certificates(rustls::RootCertStore::empty())
    ///     .with_no_client_auth();
    /// let connector = TlsConnector::from(Arc::new(config));
    /// let domain = rustls::pki_types::ServerName::try_from("localhost")?;
    /// let tls = connector.connect(domain, tcp).await?;
    /// let stream = ProxyStream::from_tls(tls);
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    #[cfg(feature = "tls")]
    pub fn from_tls(stream: TlsStream<TcpStream>) -> Self {
        Self::Tls(Box::new(stream))
    }

    /// Wrap a Shadowsocks encrypted stream.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(feature = "shadowsocks")]
    /// # {
    /// use roxie::transport::ProxyStream;
    /// use roxie::protocols::shadowsocks::establish_shadowsocks;
    /// use roxie::config::ShadowsocksConfig;
    /// use tokio::net::TcpStream;
    /// use url::Url;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = ShadowsocksConfig::new().set_method("aes-256-gcm");
    /// let mut tcp = TcpStream::connect("127.0.0.1:8388").await?;
    /// let target = Url::parse("https://example.com")?;
    ///
    /// let (cipher, nonce, master_key, method) =
    ///     establish_shadowsocks(&mut tcp, &target, "password", &config).await?;
    ///
    /// let stream = ProxyStream::from_shadowsocks(tcp, cipher, nonce, master_key, method);
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    #[cfg(feature = "shadowsocks")]
    pub fn from_shadowsocks(
        stream: TcpStream,
        send_cipher: AeadCipher,
        send_nonce: Nonce,
        master_key: Vec<u8>,
        method: CipherMethod,
    ) -> Self {
        Self::Shadowsocks(Box::new(ShadowsocksStream {
            inner: stream,
            send_cipher,
            send_nonce,
            recv_cipher: None,
            recv_nonce: Nonce::new(),
            master_key,
            method,
            salt_received: false,
            write_buf: Vec::new(),
            write_pos: 0,
            write_pending: 0,
            recv_raw: Vec::new(),
            recv_plain: Vec::new(),
            eof: false,
        }))
    }

    /// Get a reference to the underlying TCP stream if this is TCP.
    ///
    /// Returns `None` if the stream is TLS-wrapped or Shadowsocks-encrypted.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyStream;
    /// use tokio::net::TcpStream;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let tcp = TcpStream::connect("127.0.0.1:8080").await?;
    /// let stream = ProxyStream::from_tcp(tcp);
    ///
    /// assert!(stream.get_tcp().is_some());
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_tcp(&self) -> Option<&TcpStream> {
        match self {
            Self::Tcp(stream) => Some(stream),
            #[cfg(feature = "tls")]
            Self::Tls(_) => None,
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(_) => None,
        }
    }

    /// Get a mutable reference to the underlying TCP stream if this is TCP.
    ///
    /// Returns `None` if the stream is TLS-wrapped or Shadowsocks-encrypted.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxie::transport::ProxyStream;
    /// use tokio::net::TcpStream;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let tcp = TcpStream::connect("127.0.0.1:8080").await?;
    /// let mut stream = ProxyStream::from_tcp(tcp);
    ///
    /// if let Some(tcp) = stream.get_tcp_mut() {
    ///     tcp.set_nodelay(true)?;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_tcp_mut(&mut self) -> Option<&mut TcpStream> {
        match self {
            Self::Tcp(stream) => Some(stream),
            #[cfg(feature = "tls")]
            Self::Tls(_) => None,
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(_) => None,
        }
    }

    /// Get a reference to the underlying TLS stream if this is TLS.
    ///
    /// Returns `None` if the stream is raw TCP.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(feature = "tls")]
    /// # {
    /// use roxie::transport::ProxyStream;
    /// use tokio::net::TcpStream;
    /// use tokio_rustls::TlsConnector;
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let tcp = TcpStream::connect("127.0.0.1:443").await?;
    /// let config = rustls::ClientConfig::builder()
    ///     .with_root_certificates(rustls::RootCertStore::empty())
    ///     .with_no_client_auth();
    /// let connector = TlsConnector::from(Arc::new(config));
    /// let domain = rustls::pki_types::ServerName::try_from("localhost")?;
    /// let tls = connector.connect(domain, tcp).await?;
    /// let stream = ProxyStream::from_tls(tls);
    ///
    /// assert!(stream.get_tls().is_some());
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    #[cfg(feature = "tls")]
    pub fn get_tls(&self) -> Option<&TlsStream<TcpStream>> {
        match self {
            Self::Tcp(_) => None,
            Self::Tls(stream) => Some(stream),
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(_) => None,
        }
    }

    /// Get a mutable reference to the underlying TLS stream if this is TLS.
    ///
    /// Returns `None` if the stream is raw TCP.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(feature = "tls")]
    /// # {
    /// use roxie::transport::ProxyStream;
    /// use tokio::net::TcpStream;
    /// use tokio_rustls::TlsConnector;
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let tcp = TcpStream::connect("127.0.0.1:443").await?;
    /// let config = rustls::ClientConfig::builder()
    ///     .with_root_certificates(rustls::RootCertStore::empty())
    ///     .with_no_client_auth();
    /// let connector = TlsConnector::from(Arc::new(config));
    /// let domain = rustls::pki_types::ServerName::try_from("localhost")?;
    /// let tls = connector.connect(domain, tcp).await?;
    /// let mut stream = ProxyStream::from_tls(tls);
    ///
    /// assert!(stream.get_tls_mut().is_some());
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    #[cfg(feature = "tls")]
    pub fn get_tls_mut(&mut self) -> Option<&mut TlsStream<TcpStream>> {
        match self {
            Self::Tcp(_) => None,
            Self::Tls(stream) => Some(stream),
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(_) => None,
        }
    }
}

/* AsyncRead Implementation */

impl AsyncRead for ProxyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(stream) => shadowsocks_poll_read(stream, cx, buf),
        }
    }
}

/* AsyncWrite Implementation */

impl AsyncWrite for ProxyStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(stream) => shadowsocks_poll_write(stream, cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(stream) => shadowsocks_poll_flush(stream, cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(stream) => shadowsocks_poll_shutdown(stream, cx),
        }
    }
}

/* Shadowsocks Stream Implementation */

#[cfg(feature = "shadowsocks")]
fn shadowsocks_poll_write(
    stream: &mut ShadowsocksStream,
    cx: &mut Context<'_>,
    buf: &[u8],
) -> Poll<io::Result<usize>> {
    // Flush pending encrypted data
    while stream.write_pos < stream.write_buf.len() {
        match Pin::new(&mut stream.inner).poll_write(cx, &stream.write_buf[stream.write_pos..]) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")));
            }
            Poll::Ready(Ok(n)) => stream.write_pos += n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }

    // Return pending plaintext count
    if stream.write_pending > 0 {
        let n = stream.write_pending;
        stream.write_buf.clear();
        stream.write_pos = 0;
        stream.write_pending = 0;
        return Poll::Ready(Ok(n));
    }

    if buf.is_empty() {
        return Poll::Ready(Ok(0));
    }

    // Encrypt new data
    let chunk_len = buf.len().min(crate::protocols::shadowsocks::MAX_PAYLOAD);
    let encrypted = crate::protocols::shadowsocks::encode_chunk(
        &stream.send_cipher,
        &mut stream.send_nonce,
        &buf[..chunk_len],
    )
    .map_err(|e| io::Error::other(e.to_string()))?;

    stream.write_buf = encrypted;
    stream.write_pos = 0;
    stream.write_pending = chunk_len;

    // Try immediate write
    while stream.write_pos < stream.write_buf.len() {
        match Pin::new(&mut stream.inner).poll_write(cx, &stream.write_buf[stream.write_pos..]) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")));
            }
            Poll::Ready(Ok(n)) => stream.write_pos += n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }

    let n = stream.write_pending;
    stream.write_buf.clear();
    stream.write_pos = 0;
    stream.write_pending = 0;
    Poll::Ready(Ok(n))
}

#[cfg(feature = "shadowsocks")]
fn shadowsocks_poll_flush(
    stream: &mut ShadowsocksStream,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    while stream.write_pos < stream.write_buf.len() {
        match Pin::new(&mut stream.inner).poll_write(cx, &stream.write_buf[stream.write_pos..]) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "flush failed",
                )));
            }
            Poll::Ready(Ok(n)) => stream.write_pos += n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }

    stream.write_buf.clear();
    stream.write_pos = 0;
    stream.write_pending = 0;

    Pin::new(&mut stream.inner).poll_flush(cx)
}

#[cfg(feature = "shadowsocks")]
fn shadowsocks_poll_shutdown(
    stream: &mut ShadowsocksStream,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    match shadowsocks_poll_flush(stream, cx) {
        Poll::Ready(Ok(())) => {}
        other => return other,
    }
    Pin::new(&mut stream.inner).poll_shutdown(cx)
}

#[cfg(feature = "shadowsocks")]
fn shadowsocks_poll_read(
    stream: &mut ShadowsocksStream,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
) -> Poll<io::Result<()>> {
    // Serve buffered plaintext first
    if !stream.recv_plain.is_empty() {
        let n = buf.remaining().min(stream.recv_plain.len());
        buf.put_slice(&stream.recv_plain.drain(..n).collect::<Vec<_>>());
        return Poll::Ready(Ok(()));
    }

    if stream.eof {
        return Poll::Ready(Ok(()));
    }

    // Read server salt on first read
    if !stream.salt_received {
        let salt_len = stream.method.salt_len();

        while stream.recv_raw.len() < salt_len {
            let mut tmp = [0u8; 4096];
            let mut tmp_buf = ReadBuf::new(&mut tmp);

            match Pin::new(&mut stream.inner).poll_read(cx, &mut tmp_buf) {
                Poll::Ready(Ok(())) if tmp_buf.filled().is_empty() => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed before server salt",
                    )));
                }
                Poll::Ready(Ok(())) => {
                    stream.recv_raw.extend_from_slice(tmp_buf.filled());
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let salt: Vec<u8> = stream.recv_raw.drain(..salt_len).collect();
        let session_key =
            crate::protocols::shadowsocks::derive_session_key(&stream.master_key, &salt)
                .map_err(|e| io::Error::other(e.to_string()))?;
        stream.recv_cipher = Some(
            AeadCipher::new(stream.method, &session_key)
                .map_err(|e| io::Error::other(e.to_string()))?,
        );
        stream.salt_received = true;
    }

    // Try to decrypt any buffered data first
    let cipher = stream.recv_cipher.as_ref().unwrap();
    loop {
        match crate::protocols::shadowsocks::decode_chunk(
            cipher,
            &mut stream.recv_nonce,
            &mut stream.recv_raw,
        ) {
            Ok(Some(plain)) => stream.recv_plain.extend_from_slice(&plain),
            Ok(None) => break,
            Err(e) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    e.to_string(),
                )));
            }
        }
    }

    // Return decrypted data if available
    if !stream.recv_plain.is_empty() {
        let n = buf.remaining().min(stream.recv_plain.len());
        buf.put_slice(&stream.recv_plain.drain(..n).collect::<Vec<_>>());
        return Poll::Ready(Ok(()));
    }

    // Need more data from network
    let mut tmp = [0u8; 8192];
    let mut tmp_buf = ReadBuf::new(&mut tmp);

    match Pin::new(&mut stream.inner).poll_read(cx, &mut tmp_buf) {
        Poll::Ready(Ok(())) => {
            if tmp_buf.filled().is_empty() {
                stream.eof = true;
                return Poll::Ready(Ok(()));
            }
            stream.recv_raw.extend_from_slice(tmp_buf.filled());
        }
        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        Poll::Pending => return Poll::Pending,
    }

    // Try to decrypt newly received data
    loop {
        match crate::protocols::shadowsocks::decode_chunk(
            cipher,
            &mut stream.recv_nonce,
            &mut stream.recv_raw,
        ) {
            Ok(Some(plain)) => stream.recv_plain.extend_from_slice(&plain),
            Ok(None) => break,
            Err(e) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    e.to_string(),
                )));
            }
        }
    }

    // Return decrypted data if available, otherwise signal we need more
    if !stream.recv_plain.is_empty() {
        let n = buf.remaining().min(stream.recv_plain.len());
        buf.put_slice(&stream.recv_plain.drain(..n).collect::<Vec<_>>());
        Poll::Ready(Ok(()))
    } else {
        // We read data but couldn't form a complete chunk yet
        // Wake ourselves to try again
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

#[cfg(feature = "shadowsocks")]
impl Drop for ShadowsocksStream {
    fn drop(&mut self) {
        self.master_key.zeroize();
        self.write_buf.zeroize();
        self.recv_raw.zeroize();
        self.recv_plain.zeroize();
    }
}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn proxystream_tcp_creation() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let tcp = TcpStream::connect(addr).await.unwrap();
        let stream = ProxyStream::from_tcp(tcp);

        assert!(stream.get_tcp().is_some());
    }

    #[tokio::test]
    async fn proxystream_tcp_mut_access() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut stream = ProxyStream::from_tcp(tcp);

        if let Some(tcp) = stream.get_tcp_mut() {
            tcp.set_nodelay(true).unwrap();
        }
    }

    #[tokio::test]
    async fn proxystream_tcp_read_write() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a server task
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 5];
            socket.read_exact(&mut buf).await.unwrap();
            socket.write_all(&buf).await.unwrap();
        });

        // Connect and test
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut stream = ProxyStream::from_tcp(tcp);

        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn proxystream_tls_handshake_timeout_enforced() {
        use std::time::Duration;
        use tokio::net::{TcpListener, TcpStream};

        use crate::config::TLSConfig;
        use crate::errors::TLSError;
        use crate::transport::tls::establish_tls;

        // Bind a TCP listener that never speaks TLS
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Do NOT accept the connection: handshake must stall
        let tcp = TcpStream::connect(addr).await.unwrap();

        // TLS config with a very short handshake timeout
        let tls_config = TLSConfig::new().set_handshake_timeout(Duration::from_millis(50));

        // Call YOUR TLS abstraction
        let result = establish_tls(tcp, "localhost", &tls_config).await;

        // Must fail with a handshake timeout
        match result {
            Err(TLSError::HandshakeTimeout { .. }) => {}
            other => panic!("expected HandshakeTimeout, got {:?}", other),
        }
    }
}
