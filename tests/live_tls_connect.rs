use std::time::Duration;

use roxie::config::TLSConfig;
use roxie::transport::tls::establish_tls;
use tokio::time::timeout;
use url::Url;

#[tokio::test]
#[ignore]
async fn direct_tls_handshake_succeeds() {
    // Install tracing subscriber at TRACE level
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .try_init();

    let target = Url::parse("https://www.google.com").unwrap();

    // Step 1: raw TCP connect
    let addr = format!(
        "{}:{}",
        target.host_str().unwrap(),
        target.port_or_known_default().unwrap()
    );
    let tcp = timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr))
        .await
        .expect("TCP connect timed out")
        .expect("TCP connect failed");

    // Step 2: TLS config
    let tls_config = TLSConfig::default();

    // Step 3: TLS handshake (this is the thing we want to test)
    let tls_stream = timeout(
        Duration::from_secs(5),
        establish_tls(tcp, target.host_str().unwrap(), &tls_config),
    )
    .await
    .expect("TLS handshake timed out")
    .expect("TLS handshake failed");

    // If we get here, TLS completed successfully
    drop(tls_stream);
}
