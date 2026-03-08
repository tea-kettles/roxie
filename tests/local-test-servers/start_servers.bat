@echo off
setlocal EnableDelayedExpansion

:: ============================================================
:: roxie proxy test server — startup script (Windows)
:: ============================================================
::
:: Ports used:
::   25565  Shadowsocks  chacha20-ietf-poly1305
::   25566  Shadowsocks  aes-128-gcm
::   25567  Shadowsocks  aes-256-gcm
::   8443   Hysteria2    (UDP)
::   1080   SOCKS5       (via 3proxy)
::   1081   SOCKS4       (via 3proxy)
::   8080   HTTP CONNECT (via 3proxy)
::   4443   Trojan       (via xray, TLS)
::   9050   Tor          (SOCKS5, via tor daemon)
::
:: Usage:
::   start_servers.bat
::
::   Optional env overrides:
::     set TAILSCALE_HOSTNAME=myhost.tail12345.ts.net
::     set SS_PASSWORD=yourpassword
::     set HY2_PASSWORD=yourpassword
::     set TROJAN_PASSWORD=yourpassword
::
:: ============================================================

:: ── Configurable defaults ─────────────────────────────────
if not defined SS_PASSWORD     set SS_PASSWORD=password123
if not defined HY2_PASSWORD    set HY2_PASSWORD=Se7RAuFZ8Lzg
if not defined TROJAN_PASSWORD set TROJAN_PASSWORD=password123

:: Resolve script directory so the pack is location-independent
set PACK=%~dp0
set PACK=%PACK:~0,-1%
set BINS=%PACK%\bins\windows
set CFG=%PACK%\config
set CERTS=%PACK%\certs

if not exist "%CFG%"   mkdir "%CFG%"
if not exist "%CERTS%" mkdir "%CERTS%"

:: ── Detect Tailscale hostname ─────────────────────────────
if not defined TAILSCALE_HOSTNAME (
    echo [*] Detecting Tailscale hostname...
    for /f "tokens=*" %%H in ('tailscale status --self 2^>nul ^| findstr /r "^[a-zA-Z0-9]"') do (
        if not defined TAILSCALE_HOSTNAME (
            for /f "tokens=1" %%N in ("%%H") do set TAILSCALE_HOSTNAME=%%N
        )
    )
)

if not defined TAILSCALE_HOSTNAME (
    echo [!] Could not detect Tailscale hostname automatically.
    echo [!] Set it manually:  set TAILSCALE_HOSTNAME=yourhost.tail12345.ts.net
    echo [!] Trojan and Hysteria2 will not start without a valid TLS cert.
    set TAILSCALE_HOSTNAME=localhost
    set SKIP_TLS=1
)

echo [*] Tailscale hostname: %TAILSCALE_HOSTNAME%

:: ── Obtain Tailscale TLS certificate ─────────────────────
if not defined SKIP_TLS (
    echo [*] Requesting Tailscale TLS certificate...
    tailscale cert --cert-file "%CERTS%\server.crt" --key-file "%CERTS%\server.key" %TAILSCALE_HOSTNAME% 2>nul
    if errorlevel 1 (
        echo [!] tailscale cert failed. Trojan and Hysteria2 will not have valid TLS.
        echo [!] Make sure tailscale is running and you are logged in.
        set SKIP_TLS=1
    ) else (
        echo [*] Certificate written to %CERTS%\
    )
)

:: ── Write 3proxy config ───────────────────────────────────
echo [*] Writing 3proxy config...
(
    echo nscache 65536
    echo auth none
    echo socks    -p1080
    echo socks -4 -p1081
    echo proxy    -p8080
) > "%CFG%\3proxy.cfg"

:: ── Write Hysteria2 server config ─────────────────────────
echo [*] Writing Hysteria2 config...
if not defined SKIP_TLS (
    (
        echo listen: :8443
        echo auth:
        echo   type: password
        echo   password: %HY2_PASSWORD%
        echo tls:
        echo   cert: %CERTS%\server.crt
        echo   key:  %CERTS%\server.key
    ) > "%CFG%\hysteria2-server.yaml"
) else (
    (
        echo listen: :8443
        echo auth:
        echo   type: password
        echo   password: %HY2_PASSWORD%
        echo tls:
        echo   cert: %CERTS%\server.crt
        echo   key:  %CERTS%\server.key
        echo # WARNING: cert not present — server will not start correctly
    ) > "%CFG%\hysteria2-server.yaml"
)

:: ── Write Xray Trojan server config ──────────────────────
echo [*] Writing Xray Trojan config...
(
    echo {
    echo   "log": { "loglevel": "warning" },
    echo   "inbounds": [{
    echo     "port": 4443,
    echo     "listen": "0.0.0.0",
    echo     "protocol": "trojan",
    echo     "settings": {
    echo       "clients": [{ "password": "%TROJAN_PASSWORD%" }]
    echo     },
    echo     "streamSettings": {
    echo       "network": "tcp",
    echo       "security": "tls",
    echo       "tlsSettings": {
    echo         "certificates": [{
    echo           "certificateFile": "%CERTS:\=\\%\\server.crt",
    echo           "keyFile": "%CERTS:\=\\%\\server.key"
    echo         }]
    echo       }
    echo     }
    echo   }],
    echo   "outbounds": [{ "protocol": "freedom" }]
    echo }
) > "%CFG%\trojan-config.json"

echo.
echo ============================================================
echo  Starting proxy servers
echo ============================================================
echo.

:: ── Shadowsocks ───────────────────────────────────────────
echo [*] Starting Shadowsocks chacha20-ietf-poly1305  :25565
start "SS-chacha20 :25565" cmd /k ""%BINS%\ssserver.exe" -s 0.0.0.0:25565 -k %SS_PASSWORD% -m chacha20-ietf-poly1305"

echo [*] Starting Shadowsocks aes-128-gcm             :25566
start "SS-aes128 :25566"   cmd /k ""%BINS%\ssserver.exe" -s 0.0.0.0:25566 -k %SS_PASSWORD% -m aes-128-gcm"

echo [*] Starting Shadowsocks aes-256-gcm             :25567
start "SS-aes256 :25567"   cmd /k ""%BINS%\ssserver.exe" -s 0.0.0.0:25567 -k %SS_PASSWORD% -m aes-256-gcm"

:: ── Hysteria2 ─────────────────────────────────────────────
echo [*] Starting Hysteria2                           :8443 ^(UDP^)
start "Hysteria2 :8443"    cmd /k ""%BINS%\hysteria-windows-amd64.exe" server -c "%CFG%\hysteria2-server.yaml""

:: ── 3proxy (SOCKS4 + SOCKS5 + HTTP) ──────────────────────
echo [*] Starting 3proxy  SOCKS5:1080  SOCKS4:1081  HTTP:8080
start "3proxy :1080/:1081/:8080" cmd /k ""%BINS%\3proxy.exe" "%CFG%\3proxy.cfg""

:: ── Xray (Trojan) ─────────────────────────────────────────
echo [*] Starting Xray Trojan                         :4443
start "Trojan :4443"       cmd /k ""%BINS%\xray.exe" run -c "%CFG%\trojan-config.json""

:: ── Tor ───────────────────────────────────────────────────
echo [*] Writing Tor config...
if not exist "%CFG%\tor-data" mkdir "%CFG%\tor-data"
(
    echo SocksPort 9050
    echo DataDirectory %CFG%\tor-data
    echo Log notice stdout
) > "%CFG%\torrc"
echo [*] Starting Tor                                  :9050
start "Tor :9050"          cmd /k ""%BINS%\tor.exe" -f "%CFG%\torrc""

echo.
echo ============================================================
echo  All servers launched.  Summary:
echo ============================================================
echo.
echo   Protocol                   Port   Password
echo   ─────────────────────────────────────────────────────────
echo   Shadowsocks chacha20       25565  %SS_PASSWORD%
echo   Shadowsocks aes-128-gcm    25566  %SS_PASSWORD%
echo   Shadowsocks aes-256-gcm    25567  %SS_PASSWORD%
echo   Hysteria2  (UDP)            8443  %HY2_PASSWORD%
echo   SOCKS5                      1080  (no auth)
echo   SOCKS4                      1081  (no auth)
echo   HTTP CONNECT                8080  (no auth)
echo   Trojan  (TLS)               4443  %TROJAN_PASSWORD%
echo   Tor     (SOCKS5)            9050  (no auth)
echo.
echo   Tailscale hostname: %TAILSCALE_HOSTNAME%
echo   TLS cert: %CERTS%\server.crt
echo.
echo   Test env vars for cargo test:
echo.
echo     set SS_SERVER=100.82.255.88
echo     set SS_PORT=25565
echo     set SS_PASSWORD=%SS_PASSWORD%
echo     set HY2_URL=hysteria2://%HY2_PASSWORD%@100.82.255.88:8443?insecure=1^&sni=%TAILSCALE_HOSTNAME%
echo     set SOCKS5_SERVER=100.82.255.88
echo     set SOCKS5_PORT=1080
echo     set SOCKS4_SERVER=100.82.255.88
echo     set SOCKS4_PORT=1081
echo     set HTTP_SERVER=100.82.255.88
echo     set HTTP_PORT=8080
echo     set TROJAN_SERVER=%TAILSCALE_HOSTNAME%
echo     set TROJAN_PORT=4443
echo     set TROJAN_PASSWORD=%TROJAN_PASSWORD%
echo     set TOR_PORT=9050
echo.
echo ============================================================
echo.

endlocal
