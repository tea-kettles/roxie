use std::collections::HashMap;
use std::time::Duration;

use roxie::config::{BaseProxyConfig, HasBaseProxyConfig};
use roxie::transport::Proxy;
use roxie::transport::ProxyList;
use serde_json::{Value, json};
use tempfile::TempDir;
use tracing_subscriber;

/// Inline proxy list used by tests that previously required an external file.
///
/// Covers HTTP, HTTPS, SOCKS4, SOCKS4A, SOCKS5, and SOCKS5H to exercise
/// all protocol-specific export/import paths.
const SAMPLE_PROXIES_JSON: &str = r#"[
    "http://proxy1.test:8080",
    "http://user:pass@proxy2.test:8080",
    "https://proxy3.test:8443",
    "https://user:pass@proxy4.test:8443",
    "socks4://proxy5.test:1080",
    "socks4a://proxy6.test:1080",
    "socks5://proxy7.test:1080",
    "socks5://user:pass@proxy8.test:1080",
    "socks5h://proxy9.test:1080"
]"#;

#[tokio::test]
async fn proxylist_export_import_roundtrip() {
    init_test_logging();

    let list = ProxyList::from_array(SAMPLE_PROXIES_JSON)
        .expect("failed to parse inline proxy list");
    assert!(!list.is_empty(), "inline proxy list contained no proxies");

    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let export_path = temp_dir.path().join("exported_proxies.json");

    list.export_json(&export_path)
        .await
        .expect("failed to export proxy list to json");

    let exported = tokio::fs::read_to_string(&export_path)
        .await
        .unwrap_or_else(|e| panic!("failed to read exported json: {}", e));

    let reloaded = ProxyList::from_json(&exported)
        .unwrap_or_else(|e| panic!("failed to parse exported json: {}", e));

    assert_eq!(
        list.len(),
        reloaded.len(),
        "export/import changed proxy count"
    );

    for (index, (original, parsed)) in list.iter().zip(reloaded.iter()).enumerate() {
        assert_eq!(
            original, parsed,
            "proxy at index {} changed after export/import",
            index
        );
    }

    assert!(
        !reloaded.is_empty(),
        "exported proxies json contained no proxies"
    );
}

#[tokio::test]
async fn proxylist_export_import_applies_auto_tls_overrides() {
    init_test_logging();

    let list = ProxyList::from_array(SAMPLE_PROXIES_JSON)
        .expect("failed to parse inline proxy list");
    assert!(!list.is_empty(), "inline proxy list contained no proxies");

    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let export_path = temp_dir.path().join("exported_proxies.json");

    list.export_json(&export_path)
        .await
        .expect("failed to export proxy list to json");

    let exported = tokio::fs::read_to_string(&export_path)
        .await
        .unwrap_or_else(|e| panic!("failed to read exported json: {}", e));

    let mut value: Value = serde_json::from_str(&exported)
        .unwrap_or_else(|e| panic!("failed to parse exported json: {}", e));

    let configs = value
        .get_mut("configs")
        .and_then(|v| v.as_array_mut())
        .expect("exported json missing configs array");

    for group in configs.iter_mut() {
        let base = group
            .get_mut("base")
            .and_then(|v| v.as_object_mut())
            .expect("exported config missing base object");
        base.insert("auto_tls".to_string(), Value::Bool(false));
    }

    let updated = serde_json::to_string_pretty(&value).expect("failed to serialize updated json");

    tokio::fs::write(&export_path, &updated)
        .await
        .expect("failed to write updated json");

    let reloaded = ProxyList::from_json(&updated)
        .unwrap_or_else(|e| panic!("failed to parse updated json: {}", e));

    assert!(
        reloaded.iter().all(|proxy| !proxy_auto_tls(proxy)),
        "auto_tls remained enabled after import"
    );
}

#[tokio::test]
async fn proxylist_export_import_preserves_custom_config() {
    init_test_logging();

    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let export_path = temp_dir.path().join("exported_proxies_custom.json");

    let custom_json = json!({
        "configs": [{
            "base": {
                "handshake_timeout": 21,
                "phase_timeout": 9,
                "resolve_locally": true,
                "tcp_nodelay": false,
                "keep_alive": 45,
                "auto_tls": false,
                "tls_config": { "type": "danger_accept_invalid_certs" }
            },
            "proxies": [{
                "protocol": "http",
                "host": "custom.proxy.test",
                "port": 4321,
                "username": "userx",
                "password": "passx"
            }]
        }]
    });

    let custom_json_str =
        serde_json::to_string_pretty(&custom_json).expect("failed to serialize custom json");
    let list = ProxyList::from_json(&custom_json_str)
        .unwrap_or_else(|e| panic!("failed to parse custom proxy json: {}", e));

    list.export_json(&export_path)
        .await
        .expect("failed to export proxy list to json");

    let exported = tokio::fs::read_to_string(&export_path)
        .await
        .unwrap_or_else(|e| panic!("failed to read exported json: {}", e));

    let reloaded = ProxyList::from_json(&exported)
        .unwrap_or_else(|e| panic!("failed to parse exported json: {}", e));

    let original = list.get(0).expect("original list missing proxy");
    let roundtrip = reloaded.get(0).expect("reloaded list missing proxy");

    assert_eq!(list.len(), 1);
    assert_eq!(reloaded.len(), 1);
    assert_eq!(original, roundtrip, "proxy changed after export/import");

    let assert_http_config = |proxy: &Proxy| match proxy {
        #[cfg(feature = "http")]
        Proxy::HTTP { host, port, config } | Proxy::HTTPS { host, port, config } => {
            assert_eq!(host, "custom.proxy.test");
            assert_eq!(*port, 4321);
            assert_eq!(config.get_username(), Some("userx"));
            assert_eq!(config.get_password(), Some("passx"));

            let base = config.get_base_config();
            assert_eq!(base.get_handshake_timeout(), Duration::from_secs(21));
            assert_eq!(base.get_phase_timeout(), Duration::from_secs(9));
            assert!(base.is_resolve_locally());
            assert!(!base.is_tcp_nodelay());
            assert_eq!(base.get_keep_alive(), Some(Duration::from_secs(45)));
            assert!(!base.is_auto_tls());

            let tls = base
                .get_tls_config()
                .expect("tls config missing after roundtrip");
            assert!(tls.is_danger_accept_invalid_certs());
        }
        _ => panic!("expected HTTP proxy variant"),
    };

    assert_http_config(original);
    assert_http_config(roundtrip);
}

#[tokio::test]
async fn proxylist_export_import_shared_bases_remain_shared() {
    init_test_logging();

    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let export_path = temp_dir.path().join("exported_proxies_shared.json");

    let make_group = |handshake: u64, count: usize, prefix: &str| {
        let proxies: Vec<_> = (0..count)
            .map(|i| {
                json!({
                    "protocol": "http",
                    "host": format!("{}{}", prefix, i),
                    "port": 8000 + i as u16
                })
            })
            .collect();

        json!({
            "base": {
                "handshake_timeout": handshake,
                "phase_timeout": handshake / 2,
                "resolve_locally": false,
                "tcp_nodelay": true,
                "keep_alive": 60,
                "auto_tls": true
            },
            "proxies": proxies
        })
    };

    let grouped = json!({
        "configs": [
            make_group(11, 1, "g1-"),
            make_group(22, 5, "g5-"),
            make_group(33, 100, "g100-")
        ]
    });

    let grouped_str =
        serde_json::to_string_pretty(&grouped).expect("failed to serialize grouped json");
    let list = ProxyList::from_json(&grouped_str)
        .unwrap_or_else(|e| panic!("failed to parse grouped proxy json: {}", e));

    list.export_json(&export_path)
        .await
        .expect("failed to export proxy list to json");

    let exported = tokio::fs::read_to_string(&export_path)
        .await
        .unwrap_or_else(|e| panic!("failed to read exported json: {}", e));

    let reloaded = ProxyList::from_json(&exported)
        .unwrap_or_else(|e| panic!("failed to parse exported json: {}", e));

    assert_eq!(reloaded.len(), 106, "proxy count should roundtrip");

    #[allow(unreachable_patterns)]
    fn base_ptr(proxy: &Proxy) -> *const BaseProxyConfig {
        match proxy {
            #[cfg(feature = "http")]
            Proxy::HTTP { config, .. } | Proxy::HTTPS { config, .. } => {
                config.get_base_config() as *const BaseProxyConfig
            }
            #[cfg(feature = "socks4")]
            Proxy::SOCKS4 { config, .. } | Proxy::SOCKS4A { config, .. } => {
                config.get_base_config() as *const BaseProxyConfig
            }
            #[cfg(feature = "socks5")]
            Proxy::SOCKS5 { config, .. } | Proxy::SOCKS5H { config, .. } => {
                config.get_base_config() as *const BaseProxyConfig
            }
            #[cfg(feature = "tor")]
            Proxy::Tor { config, .. } => config.get_base_config() as *const BaseProxyConfig,
            #[cfg(feature = "shadowsocks")]
            Proxy::Shadowsocks { config, .. } => config.get_base_config() as *const BaseProxyConfig,
            _ => panic!("unsupported proxy variant in test"),
        }
    }

    #[allow(unreachable_patterns)]
    fn handshake_secs(proxy: &Proxy) -> u64 {
        match proxy {
            #[cfg(feature = "http")]
            Proxy::HTTP { config, .. } | Proxy::HTTPS { config, .. } => {
                config.get_base_config().get_handshake_timeout().as_secs()
            }
            #[cfg(feature = "socks4")]
            Proxy::SOCKS4 { config, .. } | Proxy::SOCKS4A { config, .. } => {
                config.get_base_config().get_handshake_timeout().as_secs()
            }
            #[cfg(feature = "socks5")]
            Proxy::SOCKS5 { config, .. } | Proxy::SOCKS5H { config, .. } => {
                config.get_base_config().get_handshake_timeout().as_secs()
            }
            #[cfg(feature = "tor")]
            Proxy::Tor { config, .. } => config.get_base_config().get_handshake_timeout().as_secs(),
            #[cfg(feature = "shadowsocks")]
            Proxy::Shadowsocks { config, .. } => {
                config.get_base_config().get_handshake_timeout().as_secs()
            }
            _ => panic!("unsupported proxy variant in test"),
        }
    }

    let mut groups: HashMap<u64, Vec<*const BaseProxyConfig>> = HashMap::new();
    for proxy in reloaded.iter() {
        groups
            .entry(handshake_secs(proxy))
            .or_default()
            .push(base_ptr(proxy));
    }

    assert_eq!(groups.len(), 3, "expected three distinct base configs");
    assert_eq!(groups.get(&11).map(|g| g.len()), Some(1));
    assert_eq!(groups.get(&22).map(|g| g.len()), Some(5));
    assert_eq!(groups.get(&33).map(|g| g.len()), Some(100));

    for (handshake, ptrs) in groups.iter() {
        let first = ptrs[0];
        assert!(
            ptrs.iter().all(|&p| p == first),
            "base pointers for handshake {} should be shared",
            handshake
        );
    }

    let p11 = groups.get(&11).unwrap()[0];
    let p22 = groups.get(&22).unwrap()[0];
    let p33 = groups.get(&33).unwrap()[0];
    assert_ne!(p11, p22);
    assert_ne!(p11, p33);
    assert_ne!(p22, p33);
}

fn init_test_logging() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();
}

fn proxy_auto_tls(proxy: &Proxy) -> bool {
    match proxy {
        #[cfg(feature = "http")]
        Proxy::HTTP { config, .. } | Proxy::HTTPS { config, .. } => {
            config.get_base_config().is_auto_tls()
        }

        #[cfg(feature = "socks4")]
        Proxy::SOCKS4 { config, .. } | Proxy::SOCKS4A { config, .. } => {
            config.get_base_config().is_auto_tls()
        }

        #[cfg(feature = "socks5")]
        Proxy::SOCKS5 { config, .. } | Proxy::SOCKS5H { config, .. } => {
            config.get_base_config().is_auto_tls()
        }

        #[cfg(feature = "tor")]
        Proxy::Tor { config, .. } => config.get_base_config().is_auto_tls(),

        #[cfg(feature = "shadowsocks")]
        Proxy::Shadowsocks { config, .. } => config.get_base_config().is_auto_tls(),

        #[allow(unreachable_patterns)]
        _ => false,
    }
}
