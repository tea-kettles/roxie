//! Minimal Shadowsocks server connectivity example.
//!
//! Defaults match:
//! `ssserver.exe -s 0.0.0.0 -k password123 -m aes-256-gcm`
//!
//! Run with:
//! `cargo run --example shadowsocks_server_test`
//!
//! Optional environment overrides:
//! - `SS_SERVER` (default: `75.187.247.92`)
//! - `SS_PORT` (default: `8388`)
//! - `SS_PASSWORD` (default: `password123`)
//! - `SS_METHOD` (default: `aes-256-gcm`)
//! - `SS_TARGET` (default: `http://example.com/`)

use std::error::Error;
use std::sync::Arc;

use roxie::config::ShadowsocksConfig;
use roxie::transport::Proxy;
use url::Url;

const DEFAULT_SERVER: &str = "100.82.255.88";
const DEFAULT_PORT: u16 = 25565;
const DEFAULT_PASSWORD: &str = "password123";
const DEFAULT_METHOD: &str = "aes-256-gcm";
const DEFAULT_TARGET: &str = "http://httpbin.org/ip";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let server = std::env::var("SS_SERVER").unwrap_or_else(|_| DEFAULT_SERVER.to_string());
    let port = std::env::var("SS_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT);
    let password = std::env::var("SS_PASSWORD").unwrap_or_else(|_| DEFAULT_PASSWORD.to_string());
    let method = std::env::var("SS_METHOD").unwrap_or_else(|_| DEFAULT_METHOD.to_string());
    let target = std::env::var("SS_TARGET").unwrap_or_else(|_| DEFAULT_TARGET.to_string());

    let config = ShadowsocksConfig::new().set_method(method);
    let proxy = Proxy::Shadowsocks {
        host: server,
        port,
        password,
        config: Arc::new(config),
    };

    let target_url = Url::parse(&target)?;
    let body = proxy.get(&target_url).await?;

    println!("Connected through Shadowsocks successfully.");
    println!("Target: {}", target_url);
    println!(
        "Response preview (first 300 chars):\n{}",
        body.chars().take(300).collect::<String>()
    );

    Ok(())
}
