# local-test-servers

Self-contained pack for running every proxy type that roxie supports against real local servers.
Drop the required binaries into `bins/`, run the startup script, then fire the integration test.

---

## Binaries

Each binary must be placed manually — they are not committed to the repo.

| Binary (Linux/Pi) | Binary (Windows) | Source |
|---|---|---|
| `bins/linux/ssserver` | `bins/windows/ssserver.exe` | [shadowsocks/shadowsocks-rust releases](https://github.com/shadowsocks/shadowsocks-rust/releases) |
| `bins/linux/hysteria-linux-arm64` | `bins/windows/hysteria-windows-amd64.exe` | [apernet/hysteria releases](https://github.com/apernet/hysteria/releases) |
| `bins/linux/3proxy` | `bins/windows/3proxy.exe` | [3proxy/3proxy releases](https://github.com/3proxy/3proxy/releases) |
| `bins/linux/xray` | `bins/windows/xray.exe` | [XTLS/Xray-core releases](https://github.com/XTLS/Xray-core/releases) |
| `bins/linux/tor` | `bins/windows/tor.exe` | [Tor Expert Bundle](https://www.torproject.org/download/tor/) |

**Linux/Pi note:** after copying binaries, mark them executable:
```
chmod +x bins/linux/*
```

---

## Tailscale requirement (Trojan + Hysteria2)

Trojan and Hysteria2 both require a valid TLS certificate. The startup script calls `tailscale cert`
automatically to obtain one for your machine's Tailscale hostname.

Before running:
1. Install and connect [Tailscale](https://tailscale.com/download)
2. Enable **HTTPS Certificates** in your Tailscale admin panel under DNS settings
3. Optionally set `TAILSCALE_HOSTNAME` if auto-detection fails:
   - Windows: `set TAILSCALE_HOSTNAME=yourhost.tail12345.ts.net`
   - Linux: `export TAILSCALE_HOSTNAME=yourhost.tail12345.ts.net`

Alternatively you could port forward like eight different ports if you hate yourself.
---

## Starting the servers

**Windows:**
```
start_servers.bat
```
Each proxy opens in its own `cmd` window. Close all windows to stop.

**Linux / Raspberry Pi:**
```bash
chmod +x start_servers.sh
./start_servers.sh
```
All proxies run as background jobs. Press `Ctrl+C` to stop everything.

### Ports

| Protocol | Port | Notes |
|---|---|---|
| Shadowsocks chacha20-ietf-poly1305 | 25565 | Minecraft port because it's what I had open at the time of making this | 
| Shadowsocks aes-128-gcm | 25566 | |
| Shadowsocks aes-256-gcm | 25567 | |
| Hysteria2 (UDP) | 8443 | needs TLS cert |
| SOCKS5 | 1080 | via 3proxy |
| SOCKS4 | 1081 | via 3proxy |
| HTTP CONNECT | 8080 | via 3proxy |
| Trojan (TLS) | 4443 | needs TLS cert, via Xray-core |
| Tor (SOCKS5) | 9050 | bootstraps ~30s after launch |

---

## Running the integration test

```bash
cargo test --test test_servers -- --ignored --nocapture
```

**Required env var:**
```
TROJAN_SERVER=yourhost.tail12345.ts.net   # must match your TLS cert's hostname
```

**Optional overrides** (all default to localhost / script defaults):
```
SS_SERVER        # Shadowsocks server IP    (default: 127.0.0.1)
SS_PASSWORD      # Shadowsocks password     (default: password123)
HY2_URL          # Full hysteria2:// URL    (default: built from SS_SERVER)
HY2_PASSWORD     # Hysteria2 password       (default: Se7RAuFZ8Lzg)
SOCKS5_SERVER    # SOCKS5 server IP         (default: SS_SERVER)
SOCKS5_PORT      # SOCKS5 port              (default: 1080)
SOCKS4_SERVER    # SOCKS4 server IP         (default: SS_SERVER)
SOCKS4_PORT      # SOCKS4 port              (default: 1081)
HTTP_SERVER      # HTTP CONNECT server IP   (default: SS_SERVER)
HTTP_PORT        # HTTP CONNECT port        (default: 8080)
TROJAN_PORT      # Trojan port              (default: 4443)
TROJAN_PASSWORD  # Trojan password          (default: password123)
TOR_SERVER       # Tor SOCKS5 server        (default: 127.0.0.1)
TOR_PORT         # Tor SOCKS5 port          (default: 9050)
```

**Tor note:** Tor takes ~30 seconds to bootstrap after launch. Wait until you see
`Bootstrapped 100% (done): Done` in the Tor window before running the test.
