// Live integration test — validates every self-hosted proxy endpoint.
//
// Connects through each server in tests/local-test-servers and confirms that
// httpbin.org/ip returns a valid origin IP. Requires all servers to be
// running (start_servers.bat / start_servers.sh).
//
// Run with:
//   cargo test --test test_servers -- --ignored --nocapture
//
// Environment variables (all optional — defaults assume servers running on localhost):
//   SS_SERVER       Shadowsocks/proxy server IP    (default: 127.0.0.1)
//   SS_PASSWORD     Shadowsocks password           (default: password123)
//   HY2_URL         Full hysteria2:// URL          (default: built from SS_SERVER)
//   HY2_PASSWORD    Hysteria2 password             (default: Se7RAuFZ8Lzg)
//   SOCKS5_SERVER   SOCKS5/SOCKS5H server IP       (default: SS_SERVER)
//   SOCKS5_PORT     SOCKS5/SOCKS5H port            (default: 1080)
//   SOCKS4_SERVER   SOCKS4/SOCKS4A server IP       (default: SS_SERVER)
//   SOCKS4_PORT     SOCKS4/SOCKS4A port            (default: 1081)
//   HTTP_SERVER     HTTP CONNECT server IP         (default: SS_SERVER)
//   HTTP_PORT       HTTP CONNECT port              (default: 8080)
//   TROJAN_SERVER   Trojan server hostname         (required — set to your Tailscale hostname for valid TLS)
//   TROJAN_PORT     Trojan port                    (default: 4443)
//   TROJAN_PASSWORD Trojan password                (default: password123)
//   TOR_SERVER      Tor SOCKS5 server              (default: 127.0.0.1)
//   TOR_PORT        Tor SOCKS5 port                (default: 9050)

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use url::Url;

const TARGET: &str = "http://httpbin.org/ip";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const DEFAULT_SERVER: &str = "127.0.0.1";
const DEFAULT_SS_PASSWORD: &str = "password123";
const DEFAULT_HY2_PASSWORD: &str = "Se7RAuFZ8Lzg";
const DEFAULT_TROJAN_PASSWORD: &str = "password123";

fn env_str(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_port(key: &str, default: u16) -> u16 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// Connects through `proxy` to httpbin /ip and returns the `origin` field.
async fn get_origin(proxy: roxie::transport::Proxy) -> Result<String, String> {
    let target = Url::parse(TARGET).unwrap();

    let mut stream = timeout(CONNECT_TIMEOUT, proxy.connect(&target))
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|e| format!("connect error: {e}"))?;

    let req = "GET /ip HTTP/1.0\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n";
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("write error: {e}"))?;
    stream.flush().await.ok();

    let mut body = Vec::new();
    timeout(CONNECT_TIMEOUT, stream.read_to_end(&mut body))
        .await
        .map_err(|_| "read timed out".to_string())?
        .map_err(|e| format!("read error: {e}"))?;

    let text = String::from_utf8_lossy(&body);
    let json = text.find("\r\n\r\n").map(|i| &text[i + 4..]).unwrap_or(&text);

    serde_json::from_str::<serde_json::Value>(json.trim())
        .ok()
        .and_then(|v| v.get("origin")?.as_str().map(str::to_string))
        .ok_or_else(|| format!("no 'origin' in response: {}", &json.chars().take(120).collect::<String>()))
}

struct Case {
    label: &'static str,
    proxy: roxie::transport::Proxy,
}

#[tokio::test]
#[ignore]
async fn all_self_hosted_proxies_return_valid_ip() {
    #[cfg(feature = "hysteria2")]
    let _ = rustls::crypto::ring::default_provider().install_default();

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();

    let server = env_str("SS_SERVER", DEFAULT_SERVER);
    let ss_password = env_str("SS_PASSWORD", DEFAULT_SS_PASSWORD);

    let mut cases: Vec<Case> = Vec::new();

    // ── Shadowsocks ───────────────────────────────────────────────────────────
    #[cfg(feature = "shadowsocks")]
    {
        use roxie::config::ShadowsocksConfig;
        use roxie::transport::Proxy;

        for (label, port, method) in [
            ("Shadowsocks chacha20-ietf-poly1305 :25565", 25565u16, "chacha20-ietf-poly1305"),
            ("Shadowsocks aes-128-gcm           :25566", 25566,     "aes-128-gcm"),
            ("Shadowsocks aes-256-gcm           :25567", 25567,     "aes-256-gcm"),
        ] {
            cases.push(Case {
                label,
                proxy: Proxy::Shadowsocks {
                    host: server.clone(),
                    port,
                    password: ss_password.clone(),
                    config: Arc::new(ShadowsocksConfig::new().set_method(method)),
                },
            });
        }
    }

    // ── Hysteria2 ─────────────────────────────────────────────────────────────
    #[cfg(feature = "hysteria2")]
    {
        use roxie::utils::parse_proxy_url;

        let hy2_url = std::env::var("HY2_URL").unwrap_or_else(|_| {
            let password = env_str("HY2_PASSWORD", DEFAULT_HY2_PASSWORD);
            let hy2_port = env_port("HY2_PORT", 8443);
            let sni = env_str("TROJAN_SERVER", &server); // reuse TROJAN_SERVER as SNI if set
            format!("hysteria2://{password}@{server}:{hy2_port}?insecure=1&sni={sni}")
        });

        match parse_proxy_url(&hy2_url) {
            Ok(Some(proxy)) => cases.push(Case { label: "Hysteria2                          :8443", proxy }),
            Ok(None) => eprintln!("[SKIP] Hysteria2: HY2_URL parsed to None"),
            Err(e) => eprintln!("[SKIP] Hysteria2: failed to parse HY2_URL: {e}"),
        }
    }

    // ── SOCKS5 + SOCKS5H ──────────────────────────────────────────────────────
    #[cfg(feature = "socks5")]
    {
        use roxie::config::SOCKS5Config;
        use roxie::transport::Proxy;

        let host = env_str("SOCKS5_SERVER", &server);
        let port = env_port("SOCKS5_PORT", 1080);
        cases.push(Case {
            label: "SOCKS5                             :1080",
            proxy: Proxy::SOCKS5 {
                host: host.clone(),
                port,
                config: Arc::new(SOCKS5Config::new(&host, port)),
            },
        });
        cases.push(Case {
            label: "SOCKS5H (remote DNS)               :1080",
            proxy: Proxy::SOCKS5H {
                host: host.clone(),
                port,
                config: Arc::new(SOCKS5Config::new(&host, port)),
            },
        });
    }

    // ── SOCKS4 + SOCKS4A ──────────────────────────────────────────────────────
    #[cfg(feature = "socks4")]
    {
        use roxie::config::SOCKS4Config;
        use roxie::transport::Proxy;

        let host = env_str("SOCKS4_SERVER", &server);
        let port = env_port("SOCKS4_PORT", 1081);
        cases.push(Case {
            label: "SOCKS4                             :1081",
            proxy: Proxy::SOCKS4 {
                host: host.clone(),
                port,
                config: Arc::new(SOCKS4Config::new(&host, port)),
            },
        });
        cases.push(Case {
            label: "SOCKS4A (remote DNS)               :1081",
            proxy: Proxy::SOCKS4A {
                host: host.clone(),
                port,
                config: Arc::new(SOCKS4Config::new(&host, port)),
            },
        });
    }

    // ── HTTP CONNECT ──────────────────────────────────────────────────────────
    #[cfg(feature = "http")]
    {
        use roxie::config::HTTPConfig;
        use roxie::transport::Proxy;

        let host = env_str("HTTP_SERVER", &server);
        let port = env_port("HTTP_PORT", 8080);
        cases.push(Case {
            label: "HTTP CONNECT                       :8080",
            proxy: Proxy::HTTP {
                host: host.clone(),
                port,
                config: Arc::new(HTTPConfig::new(&host, port)),
            },
        });
    }

    // ── Trojan ────────────────────────────────────────────────────────────────
    #[cfg(feature = "trojan")]
    {
        use roxie::config::TrojanConfig;
        use roxie::transport::Proxy;

        let trojan_host = std::env::var("TROJAN_SERVER").unwrap_or_else(|_| {
            eprintln!(
                "[WARN] TROJAN_SERVER not set — defaulting to IP {}. \
                 TLS will fail unless it matches the cert's hostname. \
                 Set TROJAN_SERVER to your Tailscale hostname.",
                server
            );
            server.clone()
        });
        let port = env_port("TROJAN_PORT", 4443);
        let password = env_str("TROJAN_PASSWORD", DEFAULT_TROJAN_PASSWORD);

        cases.push(Case {
            label: "Trojan (TLS)                       :4443",
            proxy: Proxy::Trojan {
                host: trojan_host.clone(),
                port,
                password,
                config: Arc::new(TrojanConfig::new().set_sni(&trojan_host)),
            },
        });
    }

    // ── Tor ───────────────────────────────────────────────────────────────────
    #[cfg(feature = "tor")]
    {
        use roxie::config::TorConfig;
        use roxie::transport::Proxy;

        let host = env_str("TOR_SERVER", "127.0.0.1");
        let port = env_port("TOR_PORT", 9050);
        cases.push(Case {
            label: "Tor (SOCKS5)                       :9050",
            proxy: Proxy::Tor {
                host,
                port,
                config: Arc::new(TorConfig::new()),
            },
        });
    }

    assert!(!cases.is_empty(), "no proxy cases built — check feature flags");

    eprintln!(
        "\n  Probing {} endpoints via {} ...\n",
        cases.len(),
        TARGET
    );

    // Run all cases concurrently.
    let handles: Vec<_> = cases
        .into_iter()
        .map(|c| tokio::spawn(async move { (c.label, get_origin(c.proxy).await) }))
        .collect();

    let mut results: Vec<(&'static str, Result<String, String>)> = Vec::new();
    for h in handles {
        results.push(h.await.expect("task panicked"));
    }
    results.sort_by_key(|(label, _)| *label);

    eprintln!("  {:<45}  {}", "Proxy", "Result");
    eprintln!("  {:-<45}  {:-<35}", "", "");

    let mut failed: Vec<(&'static str, String)> = Vec::new();

    for (label, result) in &results {
        match result {
            Ok(ip)   => eprintln!("  {:<45}  OK   origin: {}", label, ip),
            Err(msg) => {
                eprintln!("  {:<45}  FAIL {}", label, msg);
                failed.push((label, msg.clone()));
            }
        }
    }

    let passed = results.len() - failed.len();
    eprintln!("\n  {}/{} passed\n", passed, results.len());

    assert!(
        failed.is_empty(),
        "{} endpoint(s) failed: {}",
        failed.len(),
        failed.iter().map(|(l, e)| format!("{l}: {e}")).collect::<Vec<_>>().join("; ")
    );
}
