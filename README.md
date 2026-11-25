# 076one VPN (Android)

**Download v1.8.6** (versionCode 20, Android 5.0+):
- [arm64-v8a (most phones)](https://github.com/076one/076one-vpn/raw/main/release/076one-v1.8.6-arm64-v8a.apk)
- [armeabi-v7a (older 32-bit phones)](https://github.com/076one/076one-vpn/raw/main/release/076one-v1.8.6-armeabi-v7a.apk)
- [universal (both)](https://github.com/076one/076one-vpn/raw/main/release/076one-v1.8.6.apk)

SHA-256 files are next to each APK in `release/`; `release/latest.json` feeds the in-app updater. Signing certificate SHA-256: `ec956e98caa16d80234dcb3f1e9b8b66fa9e14f8a78f71702142ad0024116ee8`.

Licences of bundled components: psiphon-tunnel-core and libfpn GPL-3.0, Aether AGPL-3.0, Xray-core MPL-2.0, warp-plus MIT, Cinzel OFL — see `android/assets/licenses/`.
Build: `KS_PASS=... ./build.sh` with your own keystore at `android/o76one-release.jks` (not included).

---

# 076one — Android VPN: MASQUE (CONNECT-IP, RFC 9484) over HTTP/3 (QUIC) with automatic HTTP/2 fallback, to free Cloudflare WARP

Package `com.o76one.app`, label **076one**, minSdk 21 (Android 5.0) since v1.8.2, targetSdk 33, ABIs `arm64-v8a` + `armeabi-v7a`.

## Layout
```
src/
  build.sh                     Gradle-free build: Go core -> lib/*/libo76core.so, aapt2, javac, d8, zipalign, apksigner
  .github/workflows/build.yml  optional CI build of the same script
  android/
    AndroidManifest.xml
    java/com/o76one/app/       MainActivity (Persian RTL UI), O76VpnService (VpnService), Core (helpers)
    res/mipmap-*/ic_launcher.png
    o76one-release.jks         signing key (not included; alias o76one) - keep it to sign updates
  core/                        usque (MIT, github.com/Diniboy1123/usque @ 6aa03fc) + o76core/main.go (our CLI core)
```

## How it works
* `libo76core.so` is a Go executable (not a JNI lib) shipped in jniLibs so Android extracts it executable
  (`extractNativeLibs=true`). The app runs it as a child process and parses its stdout lines.
* `o76core register` - registers a free WARP device + enrolls an ECDSA key (usque API code) -> `config.json` (usque format).
* `o76core scan` - TLS 1.3 handshake (SNI configurable, ALPN h2, client cert, endpoint-key pinning) to
  162.159.198.2-254 x ports 443,500,1701,4443,4500,8095,8443, 64 parallel, 2.5 s timeout. Healthy ones (sorted by latency, best 60) are saved.
* `o76core test` - handshake latency, then a real MASQUE CONNECT-IP tunnel over HTTP/2 into a userspace netstack,
  then GET https://www.cloudflare.com/cdn-cgi/trace through the tunnel; success = `warp=on`.
* `o76core vpn` - VpnService builds the TUN (IPv4 + IPv6 from config, all routes, DNS 1.1.1.1/1.0.0.1, MTU 1280,
  **the app itself excluded** so the core's own TCP connection is not looped), passes the TUN fd to the core over a unix
  socket (SCM_RIGHTS); the core pumps raw IP packets <-> CONNECT-IP (usque `MaintainTunnel`, HTTP/2 mode, auto-reconnect)
  and prints byte counters every second -> live ⬇/⬆ speed in the UI.

## Build
`./build.sh` (env vars at the top of the script point to Go >= 1.26, JDK 17, android-34 android.jar, aapt2, zipalign, d8.jar, apksigner.jar).
The armeabi-v7a core is a static `linux/arm` Go binary (Go cannot build `android/arm` without cgo/NDK).

## v1.1 (versionCode 2) changes
* **Icon**: text logo "076 / one" on a navy→violet gradient; legacy square + round PNGs for all densities and an
  adaptive icon (`mipmap-anydpi-v26`). Generator: `../icon/make_icon.py`.
* **HTTP/3 first**: `vpn`/`test` take `-h3 ip:port -h3sni S -h2 ip:port -h2sni S`. QUIC is tried first; if the tunnel is not up
  within 3 s (`-fallback`) the core switches to HTTP/2 and prints `PROTO h2 …`. QUIC uses a fixed packet size of 1350
  (`-qsize`): with PMTU discovery the first full-size (1280 B) packets right after connect were dropped and the tunnel stalled.
  The app remembers the winner: after a QUIC failure it goes straight to HTTP/2 for 30 min. Setting "فقط HTTP/2" disables QUIC.
* **Scan** probes HTTP/3 on 162.159.198.1/.2 (UDP, same 7 ports) plus the HTTP/2 range, for every SNI in the SNI list;
  output `RES <h3|h2> ip:port ms sni`. Keeps best 20 h3 + 45 h2 entries.
* **probe** sub-command: parallel 1.5 s re-probe of saved entries (`-eps "proto|ip:port|sni;…"`).
* **Auto select**: on connect the app re-probes the top 4 h2 + top 3 h3 entries and uses the lowest-ping healthy one,
  unless the user pinned an entry (tap = pin/unpin, long tap = delete, "انتخاب خودکار سرور" = unpin).
* **Auto re-scan / failover**: background scan when the list is empty or older than 6 h (app start, resume, connect). The core prints
  `FAILS n` (consecutive connect failures) and `STALL s` (tunnel down >10 s); at 2 failures the service marks the server failed
  (10 min cooldown), starts a background scan and restarts the core on the next best server with the same TUN.
* **List** always sorted: healthy by ping, unknown, failed last; each row shows protocol, ping, status and SNI.
* **Settings screen** (`SettingsActivity`): SNI list add/remove/import (one per line)/reset, HTTP/2-only switch.
  Defaults: consumer-masque.cloudflareclient.com (usque default, `--sni-address`), zero-trust-client.cloudflareclient.com,
  consumer-masque-proxy.cloudflareclient.com — all three verified with a full tunnel (warp=on) over h3 and h2 in testing.

## v1.2 (versionCode 3) — getting data through Iranian DPI (HTTP/2 over TCP)
Field report (Irancell, v1.1): UDP/QUIC blocked; HTTP/2 TLS handshake passed on 1459 servers, "connected", but only
~100 KB passed and nothing loaded. The v1.1 "healthy" check was only a handshake. v1.2:

* **Real end-to-end test** (`o76core realtest -eps "h2|ip:port|sni;…"`, 4 parallel, 15 s each): MASQUE tunnel into a
  userspace netstack → GET cdn-cgi/trace (must be `warp=on`) → second GET on the same connection = **real delay** →
  250 KB download from speed.cloudflare.com = real KB/s. Output `REAL proto ep sni rttMs kbps firstMs colo` /
  `RFAIL proto ep sni stage reason`. A tunnel that handshakes but stalls is now `RFAIL … download/trace`.
  Used after every scan (12 diverse server/SNI/port combos), before connecting when nothing passed in the last 6 h
  (6 combos, 100 KB), and by "تست سرور". The list is sorted: real-passed by real delay (slow <100 KB/s penalised) →
  handshake-only → unknown → failed.
* **Connected-but-no-data watchdog (vpn)**: the core injects a tiny DNS query to 1.1.1.1 into the tunnel (and swallows
  the answer) whenever nothing came back for 2 s, and every 10 s anyway → `RTT ms` (shown as "تاخیر واقعی").
  No answer and <16 KB received for 8 s → `NODATA`; the app marks the server failed and switches to the next
  server/SNI (with a real test). A pinned server is not switched, only a warning is shown.
* **HTTP/2 PING health check** (ReadIdleTimeout 10 s, PingTimeout 5 s): a silently blackholed TCP connection is dropped
  and re-dialled in ~15 s instead of waiting for the OS TCP timeout.
* **Anti-DPI transport** (`o76core/dpi.go`, hook `api.H2DialTLS` in usque `api/masque.go`), flags on every command:
  `-frag both|tlsrec|tcp|off` (ClientHello re-split into small TLS records and/or written in small TCP segments),
  `-fragsize 10-50`, `-fragdelay 1-5` (ms), `-fp chrome|go` (uTLS Chrome ClientHello instead of Go's), `-mss 1300`
  (outer TCP_MAXSEG, for mobile paths with broken PMTUD), `-nodelay`, `-mtu 1280` (tunnel MTU; <1280 disables IPv6).
* **SNI rotation**: Cloudflare's MASQUE server accepts any SNI (auth = enrolled client cert + pinned server key), so the
  default list mixes neutral/domestic names with the official one: www.speedtest.net, consumer-masque.cloudflareclient.com,
  www.digikala.com, www.aparat.com, snapp.ir, divar.ir, cdn.jsdelivr.net, www.cloudflare.com (all verified warp=on +
  download in testing). v1.1 users' lists are migrated (their own additions kept). `scan -rotate` gives each ip:port one
  SNI, rotating with a per-port offset, so every SNI is tried on every port across the range (same scan size as 1 SNI).
  Ports list is editable.
* **Settings**: one switch "بهترین تنظیمات" (default on = the values above). Off shows manual fragmentation mode / sizes /
  delays, fingerprint, MTU (1280…1200), MSS, NODELAY, scan ports, HTTP/2-only.
* **"خروجی گزارش"** copies a diagnostic report to the clipboard (app/Android version, network type + operator, settings,
  SNI list, top 25 servers with handshake/real results, VPN state, last 400 log lines). Long base64-like strings, the
  account id, token, private key and the WARP IPv6 are scrubbed.
* Not done: HTTP/2 frame padding. Go's x/net/http2 client never pads DATA frames (no option); it would need a fork, and
  it would only change our upload direction, Cloudflare's downstream stays unpadded. Firefox fingerprint: uTLS's Firefox
  preset fails against Cloudflare ("invalid server key share"), so only Chrome/Go are offered.

## v1.3 (versionCode 4) — "پل (پروکسی)": upstream proxy bridge
Field context: on Irancell the direct TCP path to 162.159.198.x fails/stalls even with SNI rotation + ClientHello fragmentation.
v1.3 can chain **phone → public SOCKS5 / SOCKS4 / HTTP-CONNECT proxy → Cloudflare MASQUE (HTTP/2)**. The MASQUE TLS session
(enrolled client cert + pinned server key, uTLS Chrome fingerprint, TLS-record fragmentation) runs end-to-end inside the
proxied stream, so the proxy only relays ciphertext. A bridge forces HTTP/2 (no SOCKS5 UDP ASSOCIATE / HTTP/3).

* **Core** (`o76core/bridge.go`, hook `api.WithH2Dial` in `api/masque.go` = per-tunnel dialer carried in the tunnel context):
  * `-bridge URL` on test / vpn / realtest / scan / probe: `socks5://[user:pass@]ip:port`, `socks4://ip:port`,
    `http://[user:pass@]ip:port`, `auto://…` (detect: HTTP CONNECT → SOCKS5 → SOCKS4; SOCKS servers reject a CONNECT line
    at once, HTTP proxies would hang on a SOCKS greeting). SOCKS5 user/pass (RFC 1929), HTTP Basic proxy auth, SOCKS4a.
    MSS clamp/NODELAY apply to the phone→proxy TCP; TLS-record fragmentation survives the proxy (TCP-segment splitting is
    re-segmented by the proxy). Verified: first TLS record through the proxy is 21–46 bytes with `-frag both`, 1764 with `off`.
  * `bridgetest -proxies file -eps "h2|ip:port|sni;…" -n 50 -max 1000 -t 6s -real 16 -keep 10 -dl 100000`:
    stage 1 = proxy connect + MASQUE TLS handshake through it for every proxy (50 parallel) → `BHS key ms ep`, `BPROG done ok`;
    stage 2 = real tunnel (trace warp=on + RTT + 100 KB download) on the fastest → `BREAL key ep sni rttMs kbps firstMs hsMs colo`
    / `BFAIL key stage reason`; `DONE n`. Keys never contain credentials. Dedupe by ip:port.
  * `fetchlists -urls "type|url|mirror,…"`: downloads lists directly (no proxy), parses all formats, interleaves sources,
    prints `P scheme://ip:port`, `SRC ok|err n url`.
* **Default list sources** (each checked with curl on 2026-11-21, HTTP 200, plain ip:port lists; jsDelivr mirror as fallback):
  monosans/proxy-list socks5/http/socks4, proxifly/free-proxy-list socks5/http, TheSpeedX/PROXY-List socks5/http,
  hookzof/socks5_list, api.proxyscrape.com v4 socks5/http. (officialputuid/KangProxy returned 404 → not included.)
  Users can add their own list URLs.
* **App**: `Bridges.java` (storage: pasted list `files/bridges_user.txt` with credentials, downloaded pool
  `files/bridges_pool.txt`, results in prefs `bridgeRes`; each test run takes previously-working + pasted + the next slice
  of the pool, max 1000, rotating offset), `BridgeActivity` (switch off by default, test / update-lists / paste / auto-pick /
  sources / clear, list sorted by real delay: type, ip:port, delay, KB/s, colo, ✓✗, 🔑 for auth; tap = pin, long tap = delete).
  `O76VpnService`: with the bridge on, connects with `-bridge` to the best (or pinned) bridge using the endpoint/SNI it passed
  with; NODATA / 2× FAILS / STALL → mark bridge failed (10 min cooldown) and switch to the next; none left → re-test (400).
  Main screen: bridge button + status ("از طریق پل", bridge in use); an orange hint suggests the bridge when the last direct
  real test had 0 passes (within 6 h); the "تست سرور" dialog offers it too. Diagnostic log: bridge on/off, counts, fetch result,
  top 15 bridges by key — credentials never included (also regex-scrubbed).
* **Sandbox tests** (not from Iran): local SOCKS5, SOCKS4, HTTP CONNECT, SOCKS5+auth, HTTP+auth → warp=on + 250 KB download
  each; wrong password → "socks5: auth failed". Real public proxies (1000 from the lists, mixed): 116 passed stage 1
  (all on 162.159.198.2:443; 162.159.198.1:443 does not serve HTTP/2), 13 of 16 passed the full warp=on + download test
  (Cloudflare colos PHX, RIC, CDG, MIA, HKG, ICN, WRO, BEG, FRA, TIA, DME; real RTT 104–940 ms, 15–88 KB/s on 100 KB).

## v1.4 (versionCode 5) — "Worker" mode (REMOVED in v1.8.2; kept here as history) + bridge reliability
Field context (Irancell): direct MASQUE handshakes but no data, UDP/HTTP3 blocked; v1.3 works via public proxy bridges
(best ~109–458 ms, 30–60 KB/s, occasional stalls). VLESS-over-WebSocket+TLS behind Cloudflare usually works in Iran.

### Connection modes (main screen selector: «WARP مستقیم» / «پل پروکسی» / «Worker»)
Pref `mode` = `warp` | `bridge` | `worker` (v1.3 `bridgeOn` is migrated; the bridge screen switch sets the mode).
Worker mode needs no WARP account: TUN 10.76.0.2/32 + fd00:76::2/128, all routes, the app itself excluded.

### Worker script — `core/o76core/worker.js` (readable source, MIT, written from scratch for 076one)
* VLESS v0: UUID auth (constant-time compare), cmd 1 TCP via `cloudflare:sockets` `connect()`, cmd 2 UDP **port 53 only**
  answered with DNS-over-HTTPS (`fetch` to cloudflare-dns.com, `[len][packet]` framing); any other UDP/mux is refused.
* Early data from `Sec-WebSocket-Protocol` (base64url). Non-WebSocket requests get a plain `ok`.
* Optional `PROXY_IP` (or env `PROXYIP`): when a direct connect fails or closes without data (Workers cannot `connect()`
  to Cloudflare IPs), the worker retries once through it, replaying the buffered client bytes. Env `UUID` overrides.
* No telemetry, no other outbound calls. **Worker mode is a standalone tunnel** (Workers cannot connect to 162.159.x, so
  it is not chained to MASQUE); sites hosted on Cloudflare need PROXY_IP.
* **Deployed form = `worker.min.js`** (esbuild `--minify`, generated by build.sh, committed). Field finding 2026-11-22:
  Cloudflare disabled the readable script ~15 s after upload (every request → `error code: 1101`, even plain GET, no
  traffic needed) while the minified build kept working; a disabled script *name* stays dead even after re-uploading
  minified code, so redeploys always use a fresh random name (`-replace old` deletes the old script).
  The core reports `cloudflare-1101` on the WS upgrade and the app tells the user to redeploy.
* `res/raw/worker.js` (what the app shows/copies) = the minified build; placeholders `__UUID__` / `__PROXYIP__`.

### Core (Go)
* `vless.go`: VLESS over WebSocket over TLS — TCP (MSS clamp, NODELAY) + ClientHello fragmentation (`dpi.go`) + uTLS Chrome
  (ALPN http/1.1, ALPS removed), **certificate verified** for the SNI; connect to a clean IP with SNI/Host = worker domain;
  hand-written RFC 6455 client (masked frames, ping/pong, close); early data ≤ `-ed` bytes (2048) in the upgrade request;
  warm pool of 3 pre-handshaken TLS connections (max age 20 s) so a new stream costs ~1 RTT; `vless://` link parse/render.
* `wtun.go` `wvpn` (TUN fd over unix socket like `vpn`): gVisor stack, TCP forwarder → one VLESS stream per connection
  (waits ≤60 ms for the app's first bytes so they ride as early data); UDP/53 → persistent VLESS-UDP DNS session (IDs
  remapped, 60 s cache), fallback DNS-over-TCP to 8.8.8.8 through the worker after 3 UDP failures (UDP retried after 60 s);
  other UDP → ICMP port unreachable (QUIC falls back to TCP at once). Health: DNS probe through the worker every 10 s
  (2 s while idle/failing) → `RTT ms`, first success → `STATE up`; nothing for `-nodata` (12 s) → `NODATA`; probe failures
  before up → `FAILS n`; dial failures → `WERR`. `wget` = fetch one URL through the worker (CLI/debug).
* `wscan.go` `wscan`: random IPs from Cloudflare's published IPv4 ranges (one per /24) × ports 443,8443,2053,2083,2087,2096
  + `-extra` (domain:443, previous good IPs) → stage 1 TLS handshake with the worker SNI (`WHS`), stage 2 real test on the
  fastest: VLESS → `GET http://www.gstatic.com/generate_204`, a second fresh request = real delay, 100 KB ranged download
  from non-Cloudflare hosts (ovh, hetzner, thinkbroadband, in order) → `WREAL addr rtt kbps first hs colo` / `WFAIL`.
  Note: 108.162.192.0/18 answers 403 for workers.dev (filtered out by the real test).
* `deploy.go` **`deployworker`** — usable on any machine:
  ```
  CF_API_TOKEN=… o76core deployworker [-name n] [-uuid U] [-proxyip host[:port]] [-subdomain s] [-account id]
                 [-replace oldname] [-via auto|direct|bridge|masque|sysproxy] [-bridge URL] [-c config.json -h2 ip:port -h2sni S]
  o76core deployworker -uuid U -print      # just print the script with that UUID
  ```
  Token template "Edit Cloudflare Workers". Steps: `GET /accounts` → `GET/PUT /accounts/{id}/workers/subdomain` (random
  12-letter one if none) → `PUT /accounts/{id}/workers/scripts/{name}` (multipart ES module, `main_module` worker.js,
  `compatibility_date` 2025-06-01, UUID embedded) → `POST …/scripts/{name}/subdomain {"enabled":true}` → optional delete of
  `-replace`. Output `DSTEP …`, `DOK host uuid name account subdomain`, `LINK vless://…`. Transports tried in order:
  direct (fragmented ClientHello, verified TLS) → `-bridge` proxy → MASQUE WARP tunnel (`-c/-h2`, optionally via the bridge);
  `sysproxy` = environment HTTPS_PROXY (used from the build sandbox). The token is read from env/flag and never printed.
* `uuid` prints a random v4 UUID.

### App
* `Workers.java` (prefs `wHost wSni wPath wUuid wEd wProxyIp wName wSub wToken wPorts`, results `wRes` with success/fail
  counters), `WorkerActivity` (Persian RTL): token field (password input, stored only in app prefs) + «استقرار خودکار»
  (deploy → auto-fill host/UUID → 400-IP clean scan → offer to switch mode), host field, `vless://` import / copy,
  UUID + regenerate, PROXY_IP, clean-IP list (sorted by real delay; long tap = delete), manual guide (dash.cloudflare.com →
  Workers & Pages → Create → Hello World → Edit code → paste → Deploy → copy *.workers.dev) with copy/show script.
  The deploy goes direct, else via the best tested bridge, else via a WARP tunnel on the best real-tested server.
* `O76VpnService` worker branch: plan = best clean IP (quick 250-IP scan first if none, domain itself as last resort);
  `NODATA` / 2× `FAILS` → mark IP failed (10 min cooldown) → next IP with the same TUN.
* Diagnostic log: `mode:` line and worker host; UUIDs (any) and the API token are scrubbed.

### Bridge improvements
* Core `vpn -bridges url,url`: 2–3 other tested bridges kept **warm** (proxy + MASQUE TLS handshake every 60 s → `BWARM`);
  on NODATA / 2× FAILS / STALL the core switches to the next warm one **without restarting** (closes the HTTP/2 conn,
  MaintainTunnel re-dials through the new bridge) → `BSWITCH old new reason`; only when no warm standby is left does the
  app re-plan. stdin `BRIDGES url,url` replaces the standby set. Never used with a pinned bridge; nothing auto-pins.
* While connected via a bridge the service re-tests known-good bridges + 30 new pool entries every 20 min and pushes the
  fresh warm set to the core.
* Score = (real RTT + slow-download penalty) ÷ smoothed success rate `(sc+1)/(sc+fc+2)` + colo penalty
  (0 for FRA/AMS/IST/VIE/… near Iran, +80 ms otherwise, +40 unknown). Same scoring for Worker clean IPs.
* No automatic direct-MASQUE scans in Worker mode, or in bridge mode after the last direct real tests all failed.
* connect-ip "datagram Hop Limit/TTL too small" lines are counted (`TTLDROPS n` at most once a minute, shown as
  `ttlDrops=` in the diagnostic log) instead of logged one by one.

### Tests (sandbox, not from Iran)
* Real `worker.js` / `worker.min.js` in **workerd 1.20261121.1** (HTTPS socket, self-signed cert): TCP, wrong UUID
  rejected, early data on/off, PROXY_IP fallback, `wvpn` through a socketpair "TUN" (`core/tools/wvpnharness`):
  DNS via VLESS-UDP→DoH, HTTP/HTTPS fetches, worker killed → `NODATA` in 12 s.
* Bridge failover: 3 local proxies, primary killed mid-session → `BSWITCH … FAILS-2`, traffic resumed in ~3 s, no restart.
* `deployworker` against a mock API (`test/mock_cf_api.py`): new/existing subdomain, bad token, bridge transport, fallback
  chain; against the real API: token errors via direct and via MASQUE; real deploy on the user's account (o76x).
* Real deployment: a workers.dev subdomain (removed) — VLESS-WS via the domain and via clean IPs (e.g. 104.17.79.201:2053,
  104.21.68.150:8443), exit IP 104.28.x (Cloudflare), 10 MB at ~5 MB/s through the full TUN path from the sandbox.

## v1.5 (versionCode 6)
* **Worker fixes** — deploy/connect fixes for the Cloudflare Worker mode; minified `worker.min.js` is what ships.
* **WLOG** — Worker-side diagnostic lines surfaced in the app log.
* **Worker-over-bridge** — Worker (VLESS-WS) traffic can be carried through a tested bridge proxy.
* **IR-only proxies** — bridge pool limited to Iran-reachable proxies.
* **International connectivity test** — checks real reachability of foreign hosts after connecting.
* **Persistent log + export** — diagnostic log survives restarts and can be exported/shared.
* **Server panel fixed**, **scroll fix** in the main screen.
* **New launcher icons** — adaptive foreground is a full-bleed square crop of the portrait (`icon/make_icon_v15.py`,
  preview `icon/preview-v15.png`); legacy rounded-square and circle icons are full-bleed too.
* Build tools used (aarch64 host): Go 1.27.4 linux-arm64, d8/apksigner from build-tools r34, aapt2/zipalign static aarch64
  from lzhiyong/android-sdk-tools 35.0.2.

## v1.5.1 (versionCode 7)

- **WARP registration over several routes** (`o76core register`): direct with fragmented ClientHello + Chrome TLS
  (same anti-DPI flags as the tunnel; private/blackhole DNS answers ignored, fallback API IPs `-apiips`), then the
  best working bridges that reach abroad (`-bridges`, intl=1 first, Iranian list included), then the user's Worker
  (`-wlink`, `-waddrs`: VLESS stream to api.cloudflareclient.com:443, TLS end to end). One Persian log line per
  route. The app writes to `config.new.json` and only replaces `config.json` after `OK` (old one kept as
  `config.prev.json`); a failed registration never touches the existing account. The log now names why a
  registration started (automatic: no account / button), and with an account the button reads "ثبت‌نام دوباره"
  behind a clear dialog.
- **Worker on networks that reset a clean IP after a burst of handshakes** (TCI field log): `wvpn -waddrs a,b,c`
  (app passes the top 4 working clean IPs; stdin `WADDRS …` updates them), round-robin dials, 60 s cooldown after 2
  failures in a row (`WLOG cooldown …`), at most 2 TLS handshakes per IP and 4 overall (rest queue), warm pool 1
  (was 3) with 40 s reuse window, port 443/8443 preferred over 2053/2083/2087/2096 when about equal, and when every
  IP is cooling down a direct Worker falls back to an intl=1 bridge (`-wfallback`, `WFALLBACK` / `WLOG fallback`).
- **UI**: one button system (`MainActivity.Ui`): icon+label centred as one block, 8 dp gap, one-line labels that
  shrink to fit, rows never baseline-aligned or clipped, equal weight + 4 dp margins; mode buttons 52 dp with the
  icon above the label and identical stroke/padding selected or not; text buttons 48 dp with a 20 dp icon; icon-only
  buttons 44 dp square with a 24 dp icon; list-row icons 18 dp centred on the text line. All 23 `ic_*.xml`
  regenerated by `icon/icons_check.py --fix`: 24x24 viewport, 2 px stroke, uniform 1-unit margin, ink box centred
  (grid: `icon/icons-grid.png`). Static audit: `test/v151/ui_audit.py`.
- Tests: `go test ./o76core` (route order/fallback, dead address fall-through, an IP that RSTs after 3 handshakes
  while traffic continues on the other IPs, handshake caps, cooldown + fallback hook); register through a local
  HTTP and SOCKS5 proxy against the real API, with a blackholed direct route falling through to the proxy.

## v1.6 (versionCode 8) — "Aether" connection mode (4th mode, arm64 only)

The 4th mode runs **Aether v2.4.0** by CluvexStudio (https://github.com/CluvexStudio/Aether, AGPL-3.0) as a separate
process: it scans for a Cloudflare WARP gateway, opens a MASQUE / WireGuard / gool tunnel with its own anti-DPI and
end-to-end validation, and serves it as a local SOCKS5 proxy. `o76core svpn` carries the phone's TUN into that port.

### What ships
* `lib/arm64-v8a/libaether.so` = the official `aether-linux-aarch64-musl` release binary, unmodified, static musl (runs on
  every API level from 24; the bionic Android build needs API 28+). sha256 `a9d5e80e…634baf`, checked by `build.sh`.
  Kept in `android/jniLibs/arm64-v8a/`. **No** `pt/` (tor/psiphon) helpers, **no** armv7 Aether.
* `armeabi-v7a` has only `libo76core.so`; there the Aether mode button, the Aether screen and the mode itself are hidden
  (`Aether.available()` = libaether.so exists in nativeLibraryDir; `Core.mode()` falls back to WARP).
* `assets/licenses/`: `aether-LICENSE.txt` (AGPL-3.0), `aether-THIRD-PARTY-NOTICES.txt`, `NOTICE-aether.txt`
  (version, hashes, source links for v2.4.0). Settings → «درباره» names Aether v2.4.0 by CluvexStudio with its repo URL and
  opens these texts. The mode is named after the core it runs; no endorsement implied (Aether TRADEMARK.md).

### Core (Go)
* `o76core svpn -sock path -socks 127.0.0.1:PORT [-nodata 30s] [-mtu 1280]` (`svpn.go`, adapted from Worker mode
  `wtun.go`): TUN fd → gVisor netstack → one SOCKS5 CONNECT (`socks5Connect` from `bridge.go`) per TCP flow;
  UDP/53 → DNS-over-TCP through the SOCKS port (1.1.1.1, 8.8.8.8 after a 2.5 s hedge, 60 s cache); every other UDP is
  refused (ICMP unreachable, QUIC falls back to TCP). Same output as `wvpn`: READY, STATE connecting|up|down,
  STAT rx tx, RTT, NODATA, FAILS, WLOG, WERR.
* `o76core aetherid -in config.json -out masque.toml` (`aetherid.go`, ported from aether-prep/usque2aether): turns our
  existing WARP account into an Aether identity (same device id/token, self-signed cert from the same enrolled EC key),
  so Aether registers nothing.
* Fix (also in `wtun.go`): after NODATA the health loop no longer re-arms "STATE up" by itself.
* Tests: `svpn_test.go` (netstack ↔ socketpair ↔ fake SOCKS5: HTTP flow, UDP DNS over TCP-through-SOCKS, UDP/443
  refused, STATE up; dead SOCKS → FAILS + NODATA, never up; aetherid key/cert match). `svpn_live_test.go`: real binary
  against a running Aether (set `O76_SVPN_BIN`, `O76_SVPN_SOCKS`).

### App
* Main screen: 4th mode button «Aether» (layers icon, same choice-button style) + «Aether (پروتکل، SNI، پل)» button →
  `AetherActivity`: protocol HTTP/2 (default) / HTTP/3 / WireGuard / gool; SNI (default = first SNI of the app's list,
  plus www.cloudflare.com); «از طریق پل» = the best working bridge with intl=1 as `AETHER_UPSTREAM` (HTTP/2 only; env,
  not argv, because it may carry credentials); «خروجی غیر ایران» = `--exit-loc !IR`.
* Service (`O76VpnService` + `Aether.java`): kill stale aether processes → identity (`aetherid` when masque.toml is
  missing / older than config.json / >300 days; for wg / gool a one-time `--register wg|gool` via the best intl=1 bridge,
  kept in `filesDir/aether/`) → start libaether.so from nativeLibraryDir, cwd filesDir/aether, stdin closed (EOF),
  `AETHER_REPROVISION=0`, `--bind 127.0.0.1:<free port> --scan balanced -4 --quick-reconnect --startup-secs 30
  --reconnect-secs 2 --dns 1.1.1.1,1.0.0.1 --api-address 162.159.137.105 --stats --stats-secs 5`, HTTP/2 adds
  `--noize firewall --fragment --fragment-size 8-16 --fragment-delay 2-10`. Output lines → persistent log as
  «Aether: …» (stats once a minute). Waits for both «tunnel validated» and «socks5 server listening», then establishes
  the TUN and starts `svpn`.
* Watchdog: no validation 60 s after start → kill, log, error (a scan that already found answering gateways but has
  not selected one yet gets up to 120 s, Aether's balanced scan budget). While connected: Aether exits, or no
  re-validation 30 s after «tunnel ended» → restart Aether + svpn; svpn NODATA/FAILS(3) → same; more than 3 restarts
  without 60 s of working time → error («try another protocol/SNI or mode»). Stop / disconnect kills both (SIGTERM,
  then SIGKILL after 1.5 s).
* Diagnostics export: `aether:` line (proto, sni, bridge, exit, which identities exist).

### Not verified
Real Android device (exec of the musl binary from nativeLibraryDir, no resolv.conf), Iranian networks, wg/gool
registration through a public bridge. Sandbox: HTTP/2 tunnel with a converted identity + svpn path (see above).

## v1.6.1 (versionCode 9) — Aether watchdog + exit-location fix
Field log (Iran, TCI, v1.6): Aether worked, the app killed it — (1) the flat 60 s watchdog fired one second into
data-plane validation (gateway selected at 39 s, tls ok, connect-ip 200), (2) with «خروجی غیر ایران» on, every validated
tunnel was rejected: Cloudflare WARP's exit for Iranian users geolocates as IR (`masque exit: 104.28.x, IR via FRA`)
although traffic leaves at a foreign colo, unfiltered; then a reconnect loop and the watchdog kill.
* **Watchdog** (`AetherWatch.java`, pure Java): progress lines (candidate ok, selected gateway / cloudflare edge / cached
  gateway still works, tls established, connect-ip request/status, validating data-plane, tunnel validated, socks
  listening) reset the idle timer; idle kill after 60 s **only** while nothing is happening (no candidate yet, or after a
  tunnel attempt ended) — never mid-scan with candidates or mid-handshake/validation; hard cap 240 s without
  «tunnel validated»; a validation followed by a non-fatal reconnect (tunnel ended / exit rejected) gets another 120 s.
  While connected: re-validation within 120 s of a drop (30 s if Aether shows no progress and is not mid-handshake).
* **Up** = «tunnel validated» + «socks5 server listening»; the exit line is not waited for.
* **Exit ≠ IR**: default OFF, and switched off once for v1.6 users who had it on (`aExitMig161`). Two
  «exit location IR rejected» (or «changed to IR») → the option is turned off, a Persian explanation is logged and Aether
  restarts without `--exit-loc` (startup and while connected). The text under the switch explains the IR geolocation
  and suggests gool for a non-Iran exit.
* Test: `test/aetherwatch/run.sh` replays the field log lines (34 checks).

## v1.8.2 (versionCode 16) — Worker mode removed, "Config + Psiphon" mode, Android 5.0+
* **Worker mode removed completely** (it got the user's Cloudflare account banned): Workers.java, WorkerActivity, res/raw/worker.js,
  core deploy.go / worker.js / worker.min.js / vless.go / wscan.go / wtun.go / waddrs.go(+test), the `wvpn`, `wscan`, `wget`,
  `deployworker`, `uuid` commands, register `-wlink/-waddrs`, the Worker bridge-test kind. No Cloudflare API / token code remains;
  stored Worker prefs (incl. any API token) are deleted at app start. A saved mode "worker" becomes "chain" when a config is
  saved, else WARP. WARP registration: direct, then bridges. Bridge test without a WARP account says "register WARP first".
  The few helpers svpn/register still need moved to `core/o76core/common.go`.
* **«کانفیگ + سایفون» / Config + Psiphon** (mode id `chain`, in Worker's slot): `chain/` builds `lib/<abi>/libchain.so`, one Go
  binary with Xray-core v26.3.27 (MPL-2.0, unmodified) + psiphon-tunnel-core 6f412a9e0c31 (GPL-3.0), Go 1.26.10 (`GO126`).
  `libchain run -link @file [-psiphon] [-region XX] -socks PORT -dir D -dns …`: Xray runs the link as SOCKS5 on 127.0.0.1:<random>
  (noauth, loopback), verified with a real request (CONFIG_OK / CONFIG_ERR); with Psiphon, psiphon-tunnel-core runs with
  UpstreamProxyURL=socks5://127.0.0.1:<xray port> and serves SOCKS5 on PORT; READY → `o76core svpn` carries the TUN into PORT.
  `libchain test -file` (parallel real test → latency), `libchain sub -url` (base64 / plain subscription), `libchain parse`.
  Links: vless (tcp/raw incl. http header, ws, grpc, httpupgrade, xhttp; tls / reality incl. pqv), vmess (v2rayN JSON), trojan,
  ss (SIP002, legacy, 2022). Xray removed `allowInsecure` (after 2026-06-01) → ignored with a warning; `pcs`/`vcn` supported.
  Two tiny local patches (third_party/qpack, third_party/tsnetlink) let both projects link into one binary; see
  assets/licenses/NOTICE-chain.txt.
* **minSdk 21**: manifest, aapt2, d8, apksigner; `tools/apicheck.py` audits compiled classes against api-versions.xml.
  Replaced: java.util.function (Core.Cancel / Core.Fn), Files.readAllBytes, ThreadLocal.withInitial, LinkedHashMap.putIfAbsent,
  getSystemService(Class); guarded getActiveNetwork (API 21-22 fallback via getAllNetworks). v1+v2+v3 signing, v4 off.

## v1.8.3 (versionCode 17) — Config + Psiphon stability (chain mode only)
Driven by a field log from Iran (v1.8.2, ss config Frankfurt + Psiphon): config up in 0.1–0.6 s, Psiphon in 2–7 s, but the svpn
DNS probe saw ~30 s stalls that recovered on their own; every NODATA killed and restarted the whole chain and after 3 restarts the
app gave up. Psiphon refused IPv6 destinations (SOCKS reply 5), so apps stalled on v6 first. WARP / Firefox / Aether / warp+ /
bridge behaviour is unchanged (shared code is guarded by chain-only flags).
1. **IPv6 off in chain mode**: no IPv6 address / `::/0` route on the VpnService builder → Android blocks v6 for apps at once
   (VpnService.Builder.allowFamily semantics, API 21+), so they use IPv4 immediately. `svpn -chain` also RSTs any v6 TCP flow
   (`-no6`), answers AAAA questions with an empty NOERROR locally, and RSTs private/reserved IPv4 destinations at once
   (`-fastfail`: 0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0/24, 192.168/16, 198.18/15, 224/3).
2. **Stall tolerance** (`svpn -chain`): NODATA only after 50 s without any success **and** 3 failed probes in a row; any byte
   relayed to an app counts as liveness (counted while it flows, not at connection end); DNS probe timeout 5 s (2nd resolver
   hedged at 1.5 s), up to 3 probes in flight so a slow probe never delays the next; no `FAILS` lines in chain mode.
3. **Partial restart**: on NODATA the app sends `RECOVER` on libchain's stdin. libchain checks the config leg through Xray's
   SOCKS port; only if that fails it restarts the Xray instance in-process on the same port; then it stops and starts the
   Psiphon controller in-process (same local SOCKS port, same data store) and verifies with a real request →
   `RECOVER_OK ms` / `RECOVER_FAIL reason`. svpn and the TUN stay up. Only a failed (or data-less) partial recovery, or the
   core exiting, triggers the full restart (which also keeps the TUN). libchain also restarts the Psiphon controller
   in-process by itself if it ever exits (e.g. establish timeout after a long outage) instead of exiting. Other control
   lines: `XRAY_RESTART`, `PING` (→ `PONG <tunnels>`); EOF on stdin still exits.
4. **Never gives up**: the 3-restart limit is gone in chain mode; full restarts back off 2, 5, 10, 20, 30 s (cap), shown as
   «اتصال دوباره #n — x ثانیه دیگر» / "reconnecting #n"; counters reset when data flows (svpn `STATE up`). The initial connect
   retries the same way. svpn exiting by itself is one more restart.
5. **Failover**: after 2 failed recoveries in a row on one config, the next config that passed its last test (lowest latency
   first) is used for this session (not saved), logged as «تعویض خودکار کانفیگ». When every tested config failed, a new round
   starts from the best one — or, only if the new setting **«جایگزین خودکار بدون سایفون» / Auto fallback without Psiphon /
   无 Psiphon 自动回退** (Config + Psiphon screen, default off) is on, the best config is tried without Psiphon.
6. **Psiphon tuning**: `TunnelPoolSize 2` (warm standby tunnel; port forwards keep flowing on the other one;
   `libchain run -psipool N`), `EstablishTunnelPausePeriodSeconds 1`, SSH keep-alive every 20–25 s with a 15 s timeout (a
   dead tunnel is detected and re-established by Psiphon itself much sooner than the 60–120 s / 30 s defaults), establish
   timeout 180 s initially, 75 s for an in-process restart. The data store stays in `files/chain/psiphon` (app files dir,
   not cache), so server affinity / the last good server survive restarts.
7. **Keep-alive**: Xray outbound `sockopt.tcpKeepAliveIdle 20 / tcpKeepAliveInterval 10` (TCP sockets only; values in the link
   win); Psiphon SSH keep-alive 20–25 s through the whole chain; libchain sends a tiny DNS-over-TCP request through the
   chain every 22 s (`-keepalive`, logged only on failure / recovery); svpn's own 10 s probe keeps going.
8. **Logging**: every step is a `WLOG` line: svpn (`no data for Ns and N probes failed in a row -> NODATA`, `ipv6 … refused at
   once`, `dns ok … after N failed probes`), libchain (`recover #n: step 1/2/3 …`, `psiphon lost its tunnel(s)`, `keepalive …`,
   `PSI_TUNNELS n`), app (`chain recover #n …`, `full restart #n`, `reconnect #n in Ns`, `failover …`, `data flows again`).
Tests: `go test ./o76core` (new `TestChainHealthToleratesShortStall`, `TestChainFastFail`), `go test ./chain`
(`TestKeepAliveSockopt`), and the env-gated live stall test `TestChainStallLive` (real libchain + svpn, a local Xray
shadowsocks server paused with SIGSTOP/SIGCONT). Toolchain: `setup-toolchain.sh` now also fetches Go 1.26.10 (`/tmp/t/go126`).

## v1.8.4 (versionCode 18) — Bridge + Psiphon («با زدن تیک سایفون یا وارپ از پروکسی عبور کنه»)
The Bridge screen («پل (پروکسی)») gets a two-option selector **«از طریق پروکسی:» WARP | سایفون** (Through the proxy / 通过代理运行),
saved in prefs `bridgeVia` (`warp` default, `psiphon`). The bridge lists (pasted, downloaded, sources, IR-only) are shared;
test results are kept apart (`bridgeRes` for WARP, `bridgeResPsi` for Psiphon) because a pass of one kind says nothing about
the other.
- **WARP** (default): unchanged — phone → public SOCKS5/SOCKS4/HTTP proxy → Cloudflare MASQUE (HTTP/2); the test keeps its
  «register WARP first» check. Main screen shows «حالت: پل + WARP».
- **Psiphon** (new): phone → public proxy → Psiphon; the exit is a Psiphon server. No WARP account needed (no auto
  registration on launch, no WARP check on connect or test). Main screen shows «حالت: پل + سایفون — <bridge>», the stage and
  «خروجی: سایفون <region> از طریق <bridge>».
Runtime: `libchain run -upstream @file` (new; Psiphon only, no Xray). The bridge URL is written to an app-private file (never
in argv). libchain checks the proxy first (proxy handshake + TLS handshake to 1.1.1.1 / 8.8.8.8 / www.google.com through it;
`auto` proxies are detected SOCKS5 → HTTP → SOCKS4) → `CONFIG_OK`, then Psiphon runs with `UpstreamProxyURL` = the bridge
(`NetworkID 076one-bridge`, same data store, pool 2, keep-alives, in-process restart). The phone's traffic reaches Psiphon's
local SOCKS through `o76core svpn -chain`, so everything from v1.8.3 chain mode applies unchanged: no IPv6 route, v6/private
fast-fail, empty AAAA, 50 s + 3 probes stall tolerance, `RECOVER` partial restart (step 1 now checks the bridge proxy instead of
Xray; a dead bridge fails the recovery at once), unlimited reconnects with 2/5/10/20/30 s backoff.
- **Proxy schemes** (psiphon-tunnel-core `psiphon/upstreamproxy`): `socks5`/`socks5h` (user:password), `http` CONNECT
  (Basic / Digest / NTLM via the proxy's 407 challenge) go straight to Psiphon. Psiphon's own `socks4a` dialer sends host names
  to the proxy, which plain SOCKS4 proxies reject (and the server-list download uses a host name), so **socks4** bridges run
  through a small local adapter in libchain: SOCKS5 (no auth) on 127.0.0.1:<random> → plain SOCKS4 upstream, names resolved
  locally (IPv4; IPv6 refused). Credentials are URL-encoded for Psiphon (`url.UserPassword`) and redacted from every libchain
  output line; results show only `scheme://ip:port`.
- **Failover**: after 2 failed recoveries in a row through the current bridge, the next bridge that passed the last Psiphon
  test (best first, not yet tried this round) is used — session only (`Bridges.sessionKey`); the pinned bridge and saved
  results are not changed. When all were tried, a new round starts from the best. With no usable bridge at connect time the
  lists are fetched (if empty) and the Psiphon test runs once first.
- **Test** (Psiphon selected): `libchain ptest` — stage 1 proxy handshake (+TLS abroad) on up to 300 proxies, 60 at a time,
  6 s each; stage 2 a real Psiphon connect through the 6 fastest, 3 in parallel (child `libchain run -upstream`, own data dir
  `files/chain/ptest/<slot>`, 75 s timeout) plus one HTTPS request through it; stops starting new ones after 3 passes. Each
  proxy shows its latency and Psiphon region, or its error («هندشیک: …» / «سایفون: …»). Background re-tests while
  connected stay WARP-only.
- Psiphon region: the Config + Psiphon screen's region setting is used for both Psiphon modes. libchain now reports the exit
  region from Psiphon's `ConnectedServerRegion` notice (also fixes the region in Config + Psiphon mode).
Tests: `go test ./chain` (new `TestParseUpstream`, `TestUpstreamDialers`: HTTP CONNECT with auth, SOCKS4, the SOCKS4
adapter), `go test ./o76core`; the live test `TestChainStallLive` now also takes `O76_CHAIN_UPSTREAM=<proxy url>` (Bridge +
Psiphon; `O76_SS_PID` = the proxy's pid). `test/testproxy.py` now sends `Proxy-Authenticate` + `Connection: close` with its 407.

## v1.8.6 (versionCode 20) — Quick Settings tile, problem reports, Firefox quota refresh

- Quick Settings tile "01" (Android 7+): tap connects with the last-used mode or disconnects; long-press opens the app; the subtitle shows the state and mode (Android 10+). If VPN permission is missing, the tile opens the app.
- "Report a problem" in Settings and in the log menu: opens a prefilled GitHub issue in the browser.
- Firefox mode: the remaining monthly data was read only once at connect, so the app showed a frozen number. libfpn now asks the service every 10 minutes and reports each change.

## v1.8.5 (versionCode 19) — bridge stall switch, Firefox tolerance, in-app updater
Driven by a phone log from Iran (2026-11-24, v1.8.4): through Bridge + Psiphon the public proxy stalled ~75 s (keep-alive
and DNS probe failing, Psiphon tunnels down to 0, then recovered by itself) and failover never triggered (it needed 2 failed
recoveries); the bridge's proxy check refused twice before answering; Firefox mode saw NODATA every 1–2 min and gave up
after 3 reconnects.
1. **Bridge + Psiphon stall switch**: svpn runs with `-chain -nodata 40s` (3 failed probes still required). On NODATA, when
   libchain's own keep-alive has failed too (new `KA n` line = consecutive keep-alive failures; keep-alive every 15 s in
   bridge mode) or Psiphon has 0 tunnels, the app switches **at once, without backoff** to the next bridge: the **warm
   standby** if its check is < 3 min old, else the next bridge that passed the last Psiphon test (not tried this round),
   else any passed one. Otherwise (keep-alive still passing / no other bridge) the v1.8.3/1.8.4 Psiphon recovery runs.
   Logged as «تعویض فوری پل (بدون داده ۴۰ ثانیه)» / `WLOG bridge+psiphon stall switch …`. Session only
   (`Bridges.sessionKey`); the pin and saved results are unchanged.
   - **Warm standby**: every 60 s (15 s after connect, 10 s after a switch) a proxy handshake + TLS abroad check of up to 3
     other passed bridges (`libchain ptest -real 0`, stage 1 only, 6 s); the fastest that answers is the standby
     (`WLOG bridge+psiphon standby: …`). A pre-started second Psiphon was judged too costly (a second controller with its
     own pool, data and battery); Psiphon's data store keeps server affinity, so the restart on the standby is a few seconds.
   - **Refusing bridges are skipped**: `libchain run -upstream … -uptries 1` (new flag, default 3) checks the proxy once,
     and a "connection refused" is never retried even with more tries. A CONFIG_ERR at connect time
     (`Chain.BridgeRefused`) puts the bridge on this session's skip list and the next healthy bridge starts at once
     (no backoff). When no healthy bridge is left the skip list is cleared and the normal backoff/failover applies.
2. **Firefox mode tolerance** (libfpn, Predator core): svpn `-tolerant` (new): NODATA only after 50 s without data **and** 3
   failed probes in a row, overlapping 8 s probes, any relayed byte = liveness, no FAILS lines; IPv6 kept (unlike `-chain`).
   libfpn `run -keepalive 20s` (new): TLS handshake to 1.1.1.1:443 through its own SOCKS port (logged only on failure /
   recovery). **Never gives up**: on NODATA or libfpn exiting only libfpn is restarted, **on the same SOCKS port** (svpn and
   the TUN keep running; `Fox.stopWait` kills the old process within ~1 s), after the backoff 2/5/10/20/30 s shown as
   «Firefox: اتصال دوباره #n — x ثانیه دیگر»; a failed libfpn-only restart falls back to the full restart (libfpn + svpn,
   TUN kept), which also never gives up. The counters reset when data flows (`STATE up`). Only a signed-out account (or an
   empty monthly quota) stops it with an error. The initial connect retries the same way.
3. **In-app updater** (`Updater.java`, `UpdCore.java`, `ApkProvider.java`): Settings → «بررسی به‌روزرسانی» / Check for update /
   检查更新, plus a quiet check at app start at most once a day (checkbox in Settings, default on; a dialog only when a newer
   version exists). Manifest `https://github.com/076one/076one-vpn/raw/main/release/latest.json` (redirects to
   raw.githubusercontent.com). While the VPN is up in a mode with a local SOCKS5 port (Config/Bridge + Psiphon, Firefox,
   Aether, warp+) the manifest and APK are fetched **through the app's own tunnel** (own SOCKS5 client, host name sent to the
   proxy, HTTP/1.1 with redirects / chunked); otherwise, or if that fails, directly. WARP / Bridge + WARP modes have no local
   SOCKS port, so the download goes direct there (the app is excluded from its own VPN). The APK for the phone is picked
   from `Build.SUPPORTED_ABIS`: arm64-v8a → arm64 file, else armeabi-v7a file, universal as fallback. Before installing:
   size, **SHA-256** from latest.json, full **v1 (JAR) signature verification** with the signer certificate equal to the
   installed app's own (PackageManager GET_SIGNING_CERTIFICATES on 28+, GET_SIGNATURES before), package name and
   versionCode. Then the system installer: `content://com.o76one.app.apk/update/<file>` (own minimal read-only provider
   instead of androidx FileProvider, read grant only) on Android 7+, `file://` from the external cache on 5–6; on 8+ the
   «install unknown apps» permission is asked for first (the verified download is reused when the user comes back).
   Permission `REQUEST_INSTALL_PACKAGES`. Progress (bytes, speed, route) and clear errors in dialogs.
   - **latest.json** (written by `tools/latest_json.py`, notes in `tools/notes-<ver>.json`):
     `{versionCode, versionName, minSdk, apk, url, size, sha256 (universal at top level), signerSha256,
     apks: [{abi: universal|arm64-v8a|armeabi-v7a, apk: "release/<file>", url, size, sha256}], notes: {fa, en, zh}}`.
     Release files go to `release/076one-v<ver>[-<abi>].apk` + `release/latest.json` on branch main.
4. **Per-ABI APKs**: build.sh now also writes `076one-v<ver>-arm64-v8a.apk` (arm64 libs + Aether) and
   `076one-v<ver>-armeabi-v7a.apk` (armv7 libs only; Aether is hidden because libaether.so is absent) from the same build,
   same signer and versionCode, each with `.sha256`; `SPLITS=0` skips them. No v4 / `.idsig`.
Tests: `go test ./o76core` (new `TestTolerantOpts`), `go test ./chain` (new `TestIsRefusedBridge`); live
`TestBridgeSwitchLive` (env-gated: two local proxies + a refused port, real libchain + svpn + Psiphon; SIGSTOP of bridge A;
checks the warm-standby check, the refused-bridge fast fail, NODATA timing with failed keep-alive, and data through bridge B
on the same TUN); `../test/updater/` (desktop JVM: latest.json parse + ABI pick, HTTP redirect / chunked / SOCKS5 download
from a local server, SHA-256 and v1 signer checks incl. tampered APK).
