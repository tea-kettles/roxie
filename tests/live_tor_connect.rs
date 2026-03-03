use std::sync::Arc;
use std::time::Duration;

use roxie::config::TorConfig;
use roxie::transport::Proxy;
use tokio::time::timeout;
use url::Url;

// cargo test --test live_tor_connect -- --ignored

#[tokio::test]
#[ignore]
#[cfg(feature = "tor")]
async fn tor_connects_to_google() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_test_writer()
        .try_init();

    let target = Url::parse("https://www.google.com").expect("failed to parse target URL");

    let proxy = Proxy::Tor {
        host: "127.0.0.1".to_string(),
        port: 9050,
        config: Arc::new(TorConfig::new()),
    };

    let result = timeout(Duration::from_secs(20), proxy.connect(&target)).await;

    let stream = result
        .expect("tor connect timed out")
        .expect("tor connect failed");

    drop(stream);
}

#[tokio::test]
#[ignore]
#[cfg(feature = "tor")]
async fn tor_fetches_onion_html() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_test_writer()
        .try_init();

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // DuckDuckGo onion service
    let target =
        Url::parse("http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/")
            .expect("failed to parse onion URL");

    let proxy = Proxy::Tor {
        host: "127.0.0.1".to_string(),
        port: 9050,
        config: Arc::new(TorConfig::new()),
    };

    let mut stream = timeout(Duration::from_secs(30), proxy.connect(&target))
        .await
        .expect("tor connect timed out")
        .expect("tor connect failed");

    // Full HTTP GET request
    let request = b"GET / HTTP/1.1\r\n\
                    Host: duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion\r\n\
                    User-Agent: roxie-test\r\n\
                    Connection: close\r\n\r\n";

    stream
        .write_all(request)
        .await
        .expect("failed to write HTTP request over Tor");

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("failed to read HTTP response over Tor");

    let text = String::from_utf8_lossy(&response);

    tracing::info!(
        response_len = text.len(),
        "received HTML over Tor:\n{}",
        text
    );

    // Minimal correctness check
    assert!(
        text.contains("<html") || text.contains("<!DOCTYPE"),
        "response did not look like HTML"
    );
}
