#!/usr/bin/env bash
# ============================================================
# roxie proxy test server — startup script (Linux / Raspberry Pi)
# ============================================================
#
# Ports used:
#   25565  Shadowsocks  chacha20-ietf-poly1305
#   25566  Shadowsocks  aes-128-gcm
#   25567  Shadowsocks  aes-256-gcm
#   8443   Hysteria2    (UDP)
#   1080   SOCKS5       (via 3proxy)
#   1081   SOCKS4       (via 3proxy)
#   8080   HTTP CONNECT (via 3proxy)
#   4443   Trojan       (via xray, TLS)
#   9050   Tor          (SOCKS5, via tor daemon)
#
# Usage:
#   chmod +x start_servers.sh && ./start_servers.sh
#
#   Optional env overrides:
#     export TAILSCALE_HOSTNAME=myhost.tail12345.ts.net
#     export SS_PASSWORD=yourpassword
#     export HY2_PASSWORD=yourpassword
#     export TROJAN_PASSWORD=yourpassword
#
# ============================================================

set -e

# ── Configurable defaults ─────────────────────────────────
SS_PASSWORD="${SS_PASSWORD:-password123}"
HY2_PASSWORD="${HY2_PASSWORD:-Se7RAuFZ8Lzg}"
TROJAN_PASSWORD="${TROJAN_PASSWORD:-password123}"

# Resolve paths relative to this script so the pack is portable
PACK="$(cd "$(dirname "$0")" && pwd)"
BINS="$PACK/bins/linux"
CFG="$PACK/config"
CERTS="$PACK/certs"

mkdir -p "$CFG" "$CERTS"

# ── Detect Tailscale hostname ─────────────────────────────
if [ -z "$TAILSCALE_HOSTNAME" ]; then
    echo "[*] Detecting Tailscale hostname..."
    TAILSCALE_HOSTNAME=$(tailscale status --self 2>/dev/null | awk 'NR==1{print $2}') || true
fi

if [ -z "$TAILSCALE_HOSTNAME" ]; then
    echo "[!] Could not detect Tailscale hostname automatically."
    echo "[!] Set it manually:  export TAILSCALE_HOSTNAME=yourhost.tail12345.ts.net"
    echo "[!] Trojan and Hysteria2 will not start without a valid TLS cert."
    TAILSCALE_HOSTNAME="localhost"
    SKIP_TLS=1
fi

echo "[*] Tailscale hostname: $TAILSCALE_HOSTNAME"

# ── Obtain Tailscale TLS certificate ─────────────────────
if [ -z "$SKIP_TLS" ]; then
    echo "[*] Requesting Tailscale TLS certificate..."
    if tailscale cert --cert-file "$CERTS/server.crt" --key-file "$CERTS/server.key" "$TAILSCALE_HOSTNAME" 2>/dev/null; then
        echo "[*] Certificate written to $CERTS/"
    else
        echo "[!] tailscale cert failed. Trojan and Hysteria2 will not have valid TLS."
        SKIP_TLS=1
    fi
fi

# ── Write 3proxy config ───────────────────────────────────
echo "[*] Writing 3proxy config..."
cat > "$CFG/3proxy.cfg" <<EOF
nscache 65536
auth none
socks    -p1080
socks -4 -p1081
proxy    -p8080
EOF

# ── Write Hysteria2 server config ─────────────────────────
echo "[*] Writing Hysteria2 config..."
cat > "$CFG/hysteria2-server.yaml" <<EOF
listen: :8443
auth:
  type: password
  password: $HY2_PASSWORD
tls:
  cert: $CERTS/server.crt
  key:  $CERTS/server.key
EOF

# ── Write Xray Trojan server config ──────────────────────
echo "[*] Writing Xray Trojan config..."
cat > "$CFG/trojan-config.json" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "port": 4443,
    "listen": "0.0.0.0",
    "protocol": "trojan",
    "settings": {
      "clients": [{ "password": "$TROJAN_PASSWORD" }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {
        "certificates": [{
          "certificateFile": "$CERTS/server.crt",
          "keyFile": "$CERTS/server.key"
        }]
      }
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
EOF

echo ""
echo "============================================================"
echo " Starting proxy servers"
echo "============================================================"
echo ""

# Helper: launch in background, print PID
launch() {
    local label="$1"; shift
    "$@" &
    echo "[*] $label — PID $!"
}

# ── Shadowsocks ───────────────────────────────────────────
launch "Shadowsocks chacha20-ietf-poly1305 :25565" \
    "$BINS/ssserver" -s 0.0.0.0:25565 -k "$SS_PASSWORD" -m chacha20-ietf-poly1305

launch "Shadowsocks aes-128-gcm :25566" \
    "$BINS/ssserver" -s 0.0.0.0:25566 -k "$SS_PASSWORD" -m aes-128-gcm

launch "Shadowsocks aes-256-gcm :25567" \
    "$BINS/ssserver" -s 0.0.0.0:25567 -k "$SS_PASSWORD" -m aes-256-gcm

# ── Hysteria2 ─────────────────────────────────────────────
launch "Hysteria2 :8443 (UDP)" \
    "$BINS/hysteria-linux-arm64" server -c "$CFG/hysteria2-server.yaml"

# ── 3proxy ────────────────────────────────────────────────
launch "3proxy SOCKS5:1080 SOCKS4:1081 HTTP:8080" \
    "$BINS/3proxy" "$CFG/3proxy.cfg"

# ── Xray (Trojan) ─────────────────────────────────────────
launch "Xray Trojan :4443" \
    "$BINS/xray" run -c "$CFG/trojan-config.json"

# ── Tor ───────────────────────────────────────────────────
echo "[*] Writing Tor config..."
mkdir -p "$CFG/tor-data"
cat > "$CFG/torrc" <<EOF
SocksPort 9050
DataDirectory $CFG/tor-data
Log notice stdout
EOF
launch "Tor :9050" \
    "$BINS/tor" -f "$CFG/torrc"

echo ""
echo "============================================================"
echo " All servers launched.  Summary:"
echo "============================================================"
echo ""
printf "  %-30s %-6s  %s\n" "Protocol" "Port" "Password"
printf "  %-30s %-6s  %s\n" "──────────────────────────────" "──────" "────────────────────"
printf "  %-30s %-6s  %s\n" "Shadowsocks chacha20"     "25565" "$SS_PASSWORD"
printf "  %-30s %-6s  %s\n" "Shadowsocks aes-128-gcm"  "25566" "$SS_PASSWORD"
printf "  %-30s %-6s  %s\n" "Shadowsocks aes-256-gcm"  "25567" "$SS_PASSWORD"
printf "  %-30s %-6s  %s\n" "Hysteria2 (UDP)"          "8443"  "$HY2_PASSWORD"
printf "  %-30s %-6s  %s\n" "SOCKS5"                   "1080"  "(no auth)"
printf "  %-30s %-6s  %s\n" "SOCKS4"                   "1081"  "(no auth)"
printf "  %-30s %-6s  %s\n" "HTTP CONNECT"             "8080"  "(no auth)"
printf "  %-30s %-6s  %s\n" "Trojan (TLS)"             "4443"  "$TROJAN_PASSWORD"
printf "  %-30s %-6s  %s\n" "Tor (SOCKS5)"             "9050"  "(no auth)"
echo ""
echo "  Tailscale hostname: $TAILSCALE_HOSTNAME"
echo "  TLS cert: $CERTS/server.crt"
echo ""
echo "  Test env vars for cargo test:"
echo ""
TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "100.82.255.88")
echo "    export SS_SERVER=$TAILSCALE_IP"
echo "    export SS_PORT=25565"
echo "    export SS_PASSWORD=$SS_PASSWORD"
echo "    export HY2_URL=hysteria2://$HY2_PASSWORD@$TAILSCALE_IP:8443?insecure=1&sni=$TAILSCALE_HOSTNAME"
echo "    export SOCKS5_SERVER=$TAILSCALE_IP"
echo "    export SOCKS5_PORT=1080"
echo "    export SOCKS4_SERVER=$TAILSCALE_IP"
echo "    export SOCKS4_PORT=1081"
echo "    export HTTP_SERVER=$TAILSCALE_IP"
echo "    export HTTP_PORT=8080"
echo "    export TROJAN_SERVER=$TAILSCALE_HOSTNAME"
echo "    export TROJAN_PORT=4443"
echo "    export TROJAN_PASSWORD=$TROJAN_PASSWORD"
echo "    export TOR_PORT=9050"
echo ""
echo "============================================================"
echo ""
echo "  Press Ctrl+C to stop all servers."
echo ""

# Wait for all background jobs so the script stays alive
wait
