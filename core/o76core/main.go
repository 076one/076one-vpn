// o76core: small command-line core for the 076one Android app.
// It reuses usque (MIT, github.com/Diniboy1123/usque) for Cloudflare WARP
// registration and MASQUE (CONNECT-IP over HTTP/2) tunnelling.
//
// Sub-commands (output is line based, parsed by the Android app):
//
//	register -c cfg.json                                   -> "OK" | "ERR <msg>"
//	scan  -c cfg.json -snis a,b -proto auto|h2 ...         -> "RES <h3|h2> ip:port ms sni" per healthy endpoint, "PROG n", "DONE n"
//	probe -c cfg.json -eps "h3|ip:port|sni;h2|..."         -> "RES ..." / "FAIL proto ip:port sni", "DONE n"
//	test  -c cfg.json -h3 ip:port -h3sni S -h2 ip:port -h2sni S
//	      tries HTTP/3 first, falls back to HTTP/2 after -fallback (3s) -> "HS ..", "PROTO p ..", "UP p ms", "TRACE ..", "OK"|"ERR"
//	vpn   (same endpoint flags) -sock path
//	      receives the Android TUN fd over a unix socket (SCM_RIGHTS), then pumps packets through MASQUE.
//	      Prints "PROTO p ep sni", "STATE up|down", "FAILS n" (consecutive connect failures) and "STAT <rx> <tx>" each second.
//	realtest / bridgetest / fetchlists: see real.go and bridge.go. Every tunnel command takes -bridge URL (upstream proxy).
//	v1.4: vpn -bridges (warm standby bridges, bridgeset.go); uuid. (v1.8.2: Worker mode and deployworker removed.)
//	v1.6 Aether mode: svpn (TUN -> local SOCKS5 of the Aether core, svpn.go); aetherid (identity -> Aether TOML).
//
// Every command exits when stdin is closed (i.e. the parent app died).
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/quic-go/quic-go"
	_ "golang.org/x/crypto/x509roots/fallback" // CA roots when system roots are not found
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var outMu sync.Mutex

func out(format string, a ...interface{}) {
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Fprintf(os.Stdout, format+"\n", a...)
}

func fail(format string, a ...interface{}) {
	out("ERR "+format, a...)
	os.Exit(1)
}

// setupResolver makes Go resolve names via given DNS servers (Android has no /etc/resolv.conf).
func setupResolver(servers []string) {
	var list []string
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			list = append(list, net.JoinHostPort(s, "53"))
		}
	}
	list = append(list, "1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53")
	var idx uint32
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			var lastErr error
			start := int(atomic.AddUint32(&idx, 1))
			for i := 0; i < len(list); i++ {
				c, err := d.DialContext(ctx, network, list[(start+i)%len(list)])
				if err == nil {
					return c, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
}

// exitOnStdinClose kills the process when the parent closes our stdin.
func exitOnStdinClose() {
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}()
}

// logWatcher forwards log lines to stderr and turns tunnel events into STATE lines.
type logWatcher struct{}

var quietLog atomic.Bool

// ttlDrops counts "datagram Hop Limit/TTL too small" errors (reported as "TTLDROPS n" at most once a minute)
var ttlDrops atomic.Int64

func ttlDropReporter() {
	var last int64
	for range time.Tick(60 * time.Second) {
		if n := ttlDrops.Load(); n != last {
			last = n
			out("TTLDROPS %d", n)
		}
	}
}

func (logWatcher) Write(p []byte) (int, error) {
	if quietLog.Load() {
		if debugOn {
			_, _ = os.Stderr.Write(p)
		}
		return len(p), nil
	}
	s := string(p)
	if strings.Contains(s, "Hop Limit too small") || strings.Contains(s, "TTL too small") {
		// harmless (a packet whose TTL/hop limit ran out, e.g. traceroute or a routing loop probe); counted, not logged
		ttlDrops.Add(1)
		return len(p), nil
	}
	switch {
	case strings.Contains(s, "Connected to MASQUE server"):
		atomic.StoreInt32(&failCount, 0)
		tunUp.Store(true)
		signalConnected()
		out("STATE up")
	case strings.Contains(s, "Failed to connect tunnel"), strings.Contains(s, "Tunnel connection failed"):
		if tunUp.Swap(false) {
			downSince.Store(time.Now().UnixNano())
		}
		out("STATE down")
		n := atomic.AddInt32(&failCount, 1)
		if atomic.LoadInt32(&inTrial) == 0 { // QUIC trial failures are handled by the fallback
			if n >= 2 && bridges != nil && bridges.switchNext(fmt.Sprintf("FAILS-%d", n)) {
				atomic.StoreInt32(&failCount, 0)
			} else {
				out("FAILS %d", n)
			}
		}
	case strings.Contains(s, "Tunnel connection lost"):
		tunUp.Store(false)
		downSince.Store(time.Now().UnixNano())
		out("STATE down")
	}
	_, _ = os.Stderr.Write(p)
	return len(p), nil
}

func loadCfg(path string) {
	if err := config.LoadConfig(path); err != nil {
		fail("config: %v", err)
	}
}

func buildTLS(sni string) *tls.Config {
	privKey, err := config.AppConfig.GetEcPrivateKey()
	if err != nil {
		fail("private key: %v", err)
	}
	peerPubKey, err := config.AppConfig.GetEcEndpointPublicKey()
	if err != nil {
		fail("endpoint pubkey: %v", err)
	}
	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		fail("cert: %v", err)
	}
	tlsCfg, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, sni, false)
	if err != nil {
		fail("tls: %v", err)
	}
	return tlsCfg
}

// handshakeH2 does TCP + TLS (ALPN h2) and returns latency.
func handshakeH2(ep string, base *tls.Config, timeout time.Duration) (time.Duration, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, alpn, err := dialH2TLS(ctx, "tcp", ep, base, dpi)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	if alpn != "h2" {
		return 0, fmt.Errorf("alpn %q", alpn)
	}
	return time.Since(start), nil
}

// handshakeH3 does a QUIC handshake (ALPN h3, same transport settings as usque) and returns latency.
func handshakeH3(ep string, base *tls.Config, timeout time.Duration) (time.Duration, error) {
	addr, err := net.ResolveUDPAddr("udp", ep)
	if err != nil {
		return 0, err
	}
	cfg := base.Clone()
	cfg.NextProtos = []string{"h3"}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return 0, err
	}
	defer udp.Close()
	tr := &quic.Transport{Conn: udp, ConnectionIDLength: 20}
	defer tr.Close()
	qc := internal.DefaultQuicConfig(30*time.Second, uint16(quicPacketSize))
	qc.HandshakeIdleTimeout = timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	conn, err := tr.Dial(ctx, addr, cfg, qc)
	if err != nil {
		return 0, err
	}
	lat := time.Since(start)
	_ = conn.CloseWithError(0, "probe")
	return lat, nil
}

func handshake(proto, ep string, base *tls.Config, timeout time.Duration) (time.Duration, error) {
	if proto == "h3" {
		return handshakeH3(ep, base, timeout)
	}
	return handshakeH2(ep, base, timeout)
}

// applyDPI installs the anti-DPI dialer and HTTP/2 PING health checks into usque.
func applyDPI() {
	o := dpi
	api.H2DialTLS = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		c, alpn, err := dialH2TLS(ctx, network, addr, cfg, o)
		if err != nil {
			return nil, err
		}
		if alpn != "h2" {
			c.Close()
			return nil, errALPN
		}
		return c, nil
	}
	// a TCP connection that DPI silently blackholes after the handshake is detected in ~15 s
	// (no frame for 10 s -> PING, no answer in 5 s -> reconnect) instead of minutes.
	api.H2ReadIdleTimeout = 10 * time.Second
	api.H2PingTimeout = 5 * time.Second
}

// tlsCache builds one TLS config per SNI (with client cert when a config exists).
type tlsCache struct {
	mu     sync.Mutex
	hasCfg bool
	m      map[string]*tls.Config
}

func newTLSCache(cfgPath string) *tlsCache {
	tc := &tlsCache{m: map[string]*tls.Config{}}
	if _, err := os.Stat(cfgPath); err == nil {
		loadCfg(cfgPath)
		tc.hasCfg = true
	}
	return tc
}

func (t *tlsCache) get(sni string) *tls.Config {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c, ok := t.m[sni]; ok {
		return c
	}
	var c *tls.Config
	if t.hasCfg {
		c = buildTLS(sni)
	} else {
		c = &tls.Config{ServerName: sni, InsecureSkipVerify: true}
	}
	t.m[sni] = c
	return c
}

func splitList(s string) []string {
	var r []string
	for _, x := range strings.FieldsFunc(s, func(c rune) bool { return c == ',' || c == '\n' || c == ' ' }) {
		if x = strings.TrimSpace(x); x != "" {
			r = append(r, x)
		}
	}
	return r
}

// register: see register.go (v1.5.1: multi-route)

// ---------------- scan ----------------
type target struct{ proto, ep, sni string }

func runProbes(targets []target, tc *tlsCache, conc int, timeout time.Duration, reportFail bool) int32 {
	ch := make(chan target)
	var wg sync.WaitGroup
	var found, done int32
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range ch {
				lat, err := handshake(t.proto, t.ep, tc.get(t.sni), timeout)
				if err == nil {
					atomic.AddInt32(&found, 1)
					ms := lat.Milliseconds()
					if ms < 1 {
						ms = 1
					}
					out("RES %s %s %d %s", t.proto, t.ep, ms, t.sni)
				} else if reportFail {
					out("FAIL %s %s %s", t.proto, t.ep, t.sni)
				}
				d := atomic.AddInt32(&done, 1)
				if d%25 == 0 {
					out("PROG %d", d)
				}
			}
		}()
	}
	for _, t := range targets {
		ch <- t
	}
	close(ch)
	wg.Wait()
	return found
}

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	cfgPath := fs.String("c", "config.json", "config path")
	sni := fs.String("sni", "", "single SNI (alias of -snis)")
	snis := fs.String("snis", internal.ConnectSNI, "comma/newline separated SNI list")
	prefix := fs.String("prefix", "162.159.198.", "first three octets (HTTP/2 range)")
	ips := fs.String("ips", "2-254", "HTTP/2 last octet range a-b")
	ports := fs.String("ports", "443,500,1701,4443,4500,8095,8443", "HTTP/2 ports")
	h3ips := fs.String("h3ips", "162.159.198.1,162.159.198.2", "HTTP/3 (QUIC) endpoints")
	h3ports := fs.String("h3ports", "443,500,1701,4443,4500,8095,8443", "HTTP/3 UDP ports")
	proto := fs.String("proto", "auto", "auto (h3+h2) | h2 | h3")
	conc := fs.Int("n", 96, "concurrency")
	timeout := fs.Duration("t", 2500*time.Millisecond, "timeout")
	rotate := fs.Bool("rotate", true, "rotate SNIs over the HTTP/2 targets (each ip:port gets one SNI) instead of every SNI x every target")
	addDPIFlags(fs)
	_ = fs.Parse(args)
	runPostParse()
	applyDPI()

	sniList := splitList(*snis)
	if *sni != "" {
		sniList = splitList(*sni)
	}
	if len(sniList) == 0 {
		sniList = []string{internal.ConnectSNI}
	}
	tc := newTLSCache(*cfgPath)

	var targets []target
	for _, s := range sniList {
		if *proto != "h2" {
			for _, ip := range splitList(*h3ips) {
				for _, p := range splitList(*h3ports) {
					targets = append(targets, target{"h3", net.JoinHostPort(ip, p), s})
				}
			}
		}
	}
	if *proto != "h3" {
		var a, b int
		if _, err := fmt.Sscanf(*ips, "%d-%d", &a, &b); err != nil {
			a, _ = strconv.Atoi(*ips)
			b = a
		}
		portList := splitList(*ports)
		k := 0
		if *rotate {
			// one SNI per ip:port, rotating; a different starting offset per port so every
			// SNI is tried on every port and across the whole IP range
			for i := a; i <= b; i++ {
				for pi, p := range portList {
					s := sniList[(k+pi)%len(sniList)]
					targets = append(targets, target{"h2", net.JoinHostPort(fmt.Sprintf("%s%d", *prefix, i), p), s})
				}
				k++
			}
		} else {
			for _, s := range sniList {
				for i := a; i <= b; i++ {
					for _, p := range portList {
						targets = append(targets, target{"h2", net.JoinHostPort(fmt.Sprintf("%s%d", *prefix, i), p), s})
					}
				}
			}
		}
	}
	out("TOTAL %d", len(targets))
	found := runProbes(targets, tc, *conc, *timeout, false)
	out("DONE %d", found)
}

// ---------------- probe ----------------
// probe -c cfg -eps "h3|1.2.3.4:443|sni;h2|..." : quick re-probe of saved endpoints.
func cmdProbe(args []string) {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	cfgPath := fs.String("c", "config.json", "config path")
	eps := fs.String("eps", "", "proto|ip:port|sni;...")
	timeout := fs.Duration("t", 1500*time.Millisecond, "timeout")
	addDPIFlags(fs)
	_ = fs.Parse(args)
	runPostParse()
	applyDPI()
	tc := newTLSCache(*cfgPath)
	var targets []target
	for _, item := range strings.Split(*eps, ";") {
		p := strings.Split(strings.TrimSpace(item), "|")
		if len(p) != 3 {
			continue
		}
		targets = append(targets, target{p[0], p[1], p[2]})
	}
	n := len(targets)
	if n == 0 {
		fail("no endpoints")
	}
	found := runProbes(targets, tc, n, *timeout, true)
	out("DONE %d", found)
}

// ---------------- tunnel helpers ----------------
var (
	connMu     sync.Mutex
	connSignal chan struct{}
	failCount  int32
	inTrial    int32
	tunUp      atomic.Bool
	downSince  atomic.Int64
	// activeCancel stops the HTTP/3 tunnel that won (kept so it is not garbage)
	activeCancel context.CancelFunc
)

func armConnected() chan struct{} {
	connMu.Lock()
	defer connMu.Unlock()
	connSignal = make(chan struct{})
	return connSignal
}

func signalConnected() {
	connMu.Lock()
	defer connMu.Unlock()
	if connSignal != nil {
		close(connSignal)
		connSignal = nil
	}
}

var quicPacketSize = 1350

type tunSpec struct {
	h3EP, h3SNI, h2EP, h2SNI string
}

func parseTunFlags(fs *flag.FlagSet) *tunSpec {
	t := &tunSpec{}
	fs.StringVar(&t.h3EP, "h3", "", "HTTP/3 endpoint ip:port (empty = skip QUIC)")
	fs.StringVar(&t.h3SNI, "h3sni", internal.ConnectSNI, "SNI for HTTP/3 endpoint")
	fs.StringVar(&t.h2EP, "h2", "", "HTTP/2 endpoint ip:port (fallback)")
	fs.StringVar(&t.h2SNI, "h2sni", internal.ConnectSNI, "SNI for HTTP/2 endpoint")
	fs.IntVar(&quicPacketSize, "qsize", 1350, "QUIC packet size for HTTP/3 (0 = PMTU discovery)")
	return t
}

// runTunnel tries HTTP/3 first (if given) and falls back to HTTP/2 when the QUIC tunnel
// is not up within fallbackAfter. It returns after the tunnel is up (the tunnel keeps
// running in background until ctx is cancelled) or an error if nothing came up.
func runTunnel(ctx context.Context, t *tunSpec, dev api.TunnelDevice, fallbackAfter, h2Wait time.Duration) (string, error) {
	mk := func(useH2 bool, ep, sni string) api.MaintainTunnelConfig {
		c, err := mkTunnelCfg(useH2, ep, sni, dev)
		if err != nil {
			fail("bad endpoint %q: %v", ep, err)
		}
		return c
	}
	if dpi.bridge != nil && t.h3EP != "" {
		// a bridge carries TCP only: force HTTP/2
		if t.h2EP == "" {
			t.h2EP, t.h2SNI = t.h3EP, t.h3SNI
		}
		t.h3EP = ""
	}
	if t.h3EP != "" {
		out("TRY h3 %s %s", t.h3EP, t.h3SNI)
		atomic.StoreInt32(&inTrial, 1)
		sig := armConnected()
		c3, cancel3 := context.WithCancel(ctx)
		done3 := make(chan struct{})
		go func() { api.MaintainTunnel(c3, mk(false, t.h3EP, t.h3SNI)); close(done3) }()
		select {
		case <-sig:
			atomic.StoreInt32(&inTrial, 0)
			out("PROTO h3 %s %s", t.h3EP, t.h3SNI)
			activeCancel = cancel3 // tunnel keeps running until the process exits
			return "h3", nil
		case <-time.After(fallbackAfter):
			cancel3()
			select {
			case <-done3:
			case <-time.After(time.Second):
			}
			atomic.StoreInt32(&inTrial, 0)
			out("H3FAIL")
		}
	}
	if t.h2EP == "" {
		return "", errors.New("HTTP/3 did not connect and no HTTP/2 endpoint given")
	}
	out("TRY h2 %s %s", t.h2EP, t.h2SNI)
	atomic.StoreInt32(&failCount, 0)
	sig := armConnected()
	go api.MaintainTunnel(ctx, mk(true, t.h2EP, t.h2SNI))
	if h2Wait <= 0 {
		go func() {
			<-sig
			out("PROTO h2 %s %s", t.h2EP, t.h2SNI)
		}()
		return "h2", nil
	}
	select {
	case <-sig:
		out("PROTO h2 %s %s", t.h2EP, t.h2SNI)
		return "h2", nil
	case <-time.After(h2Wait):
		return "", errors.New("HTTP/2 tunnel did not come up")
	}
}

var copyPkts = os.Getenv("O76_COPY") != ""

// countDev counts packets in both directions (debug aid).
type countDev struct {
	d      api.TunnelDevice
	rx, tx atomic.Uint64
}

func (c *countDev) ReadPacket(b []byte) (int, error) {
	n, err := c.d.ReadPacket(b)
	if err == nil {
		c.tx.Add(1)
	}
	return n, err
}

func (c *countDev) WritePacket(p []byte) error {
	c.rx.Add(1)
	if copyPkts {
		p = append([]byte(nil), p...)
	}
	return c.d.WritePacket(p)
}

// ---------------- test ----------------
func cmdTest(args []string) {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	cfgPath := fs.String("c", "config.json", "config path")
	t := parseTunFlags(fs)
	url := fs.String("url", "https://www.cloudflare.com/cdn-cgi/trace", "trace url")
	fb := fs.Duration("fallback", 3*time.Second, "fall back to HTTP/2 if QUIC is not up after this")
	dl := fs.Int("dl", 250000, "download size for the throughput test (0 = skip)")
	addDPIFlags(fs)
	_ = fs.Parse(args)
	runPostParse()
	applyDPI()
	loadCfg(*cfgPath)
	out("OPTS %s", dpi)
	if t.h3EP == "" && t.h2EP == "" {
		t.h2EP = config.DefaultEndpointH2V4 + ":443"
	}

	// handshake latency of the first candidate
	if dpi.bridge != nil && t.h3EP != "" {
		if t.h2EP == "" {
			t.h2EP, t.h2SNI = t.h3EP, t.h3SNI
		}
		t.h3EP = ""
	}
	if t.h3EP != "" && os.Getenv("O76_NOHS") == "" {
		if lat, err := handshakeH3(t.h3EP, buildTLS(t.h3SNI), 4*time.Second); err == nil {
			out("HS h3 %d", lat.Milliseconds())
		} else {
			out("HSFAIL h3 %v", err)
		}
	}
	if t.h2EP != "" {
		if lat, err := handshakeH2(t.h2EP, buildTLS(t.h2SNI), 6*time.Second); err == nil {
			out("HS h2 %d", lat.Milliseconds())
		} else {
			out("HSFAIL h2 %v", err)
		}
	}

	local := localAddrs()
	dnsAddrs := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}
	tunDev, tunNet, err := netstack.CreateNetTUN(local, dnsAddrs, dpi.mtu)
	if err != nil {
		fail("netstack: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	upStart := time.Now()
	cdev := &countDev{d: api.NewNetstackAdapter(tunDev)}
	if os.Getenv("O76_DEBUG") != "" {
		go func() {
			for range time.Tick(2 * time.Second) {
				out("DBG toTunnel=%d fromTunnel=%d", cdev.tx.Load(), cdev.rx.Load())
			}
		}()
	}
	proto, err := runTunnel(ctx, t, cdev, *fb, 10*time.Second)
	if err != nil {
		fail("tunnel: %v", err)
	}
	out("UP %s %d", proto, time.Since(upStart).Milliseconds())
	// a stalled tunnel can block gVisor (even Close); never hang the test on it
	time.AfterFunc(40*time.Second, func() { fail("timeout: tunnel up but no data passes (stall)") })
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tunNet.DialContext(ctx, network, addr)
			},
			ForceAttemptHTTP2: true,
		},
	}
	start := time.Now()
	var body []byte
	var lastErr error
	for i := 0; i < 2; i++ {
		resp, err := client.Get(*url)
		if err != nil {
			lastErr = err
			time.Sleep(time.Second)
			continue
		}
		body, _ = io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		lastErr = nil
		break
	}
	if lastErr != nil {
		fail("trace: %v", lastErr)
	}
	kv := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			kv[k] = v
		}
	}
	out("TRACE %d warp=%s ip=%s colo=%s loc=%s proto=%s", time.Since(start).Milliseconds(), kv["warp"], kv["ip"], kv["colo"], kv["loc"], proto)
	if kv["warp"] != "on" && kv["warp"] != "plus" {
		fail("warp=%s", kv["warp"])
	}
	// real round-trip: a second request on the already open connection
	s2 := time.Now()
	if resp, err := client.Get(*url); err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		out("RTT %d", max64(time.Since(s2).Milliseconds(), 1))
	} else {
		fail("rtt: %v (tunnel up but data stalls)", err)
	}
	if *dl > 0 {
		s3 := time.Now()
		resp, err := client.Get(fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", *dl))
		if err != nil {
			fail("download: %v (tunnel up but data stalls)", err)
		}
		n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, int64(*dl)+1))
		resp.Body.Close()
		ms := max64(time.Since(s3).Milliseconds(), 1)
		out("DL %d %d %d", n, ms, n*1000/1024/ms)
		if err != nil || n < int64(*dl)*9/10 {
			fail("download stalled after %d bytes: %v", n, err)
		}
	}
	out("OK")
}

// ---------------- vpn ----------------
type fdDevice struct {
	fd     int
	rx, tx atomic.Uint64
}

func (d *fdDevice) ReadPacket(buf []byte) (int, error) {
	for {
		n, err := syscall.Read(d.fd, buf)
		if err == syscall.EINTR || err == syscall.EAGAIN {
			if err == syscall.EAGAIN {
				time.Sleep(2 * time.Millisecond)
			}
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, io.EOF
		}
		d.tx.Add(uint64(n))
		return n, nil
	}
}

func (d *fdDevice) WritePacket(pkt []byte) error {
	for {
		_, err := syscall.Write(d.fd, pkt)
		if err == syscall.EINTR || err == syscall.EAGAIN {
			continue
		}
		if err == nil {
			d.rx.Add(uint64(len(pkt)))
		}
		return err
	}
}

func receiveFd(sockPath string) (int, error) {
	_ = os.Remove(sockPath)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		return -1, err
	}
	defer ln.Close()
	_ = ln.SetDeadline(time.Now().Add(20 * time.Second))
	out("READY")
	c, err := ln.AcceptUnix()
	if err != nil {
		return -1, err
	}
	defer c.Close()
	buf := make([]byte, 16)
	oob := make([]byte, syscall.CmsgSpace(4*4))
	_, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil {
		return -1, err
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, err
	}
	for _, m := range msgs {
		fds, err := syscall.ParseUnixRights(&m)
		if err == nil && len(fds) > 0 {
			return fds[0], nil
		}
	}
	return -1, errors.New("no fd received")
}

func cmdVPN(args []string) {
	fs := flag.NewFlagSet("vpn", flag.ExitOnError)
	cfgPath := fs.String("c", "config.json", "config path")
	t := parseTunFlags(fs)
	sock := fs.String("sock", "", "unix socket path to receive TUN fd")
	fb := fs.Duration("fallback", 3*time.Second, "fall back to HTTP/2 if QUIC is not up after this")
	noData := fs.Duration("nodata", 8*time.Second, "report NODATA when the tunnel is up but nothing comes back for this long (0 = off)")
	standby := fs.String("bridges", "", "standby bridges (comma separated) kept warm for instant failover; needs -bridge")
	addDPIFlags(fs)
	_ = fs.Parse(args)
	runPostParse()
	applyDPI()
	loadCfg(*cfgPath)
	out("OPTS %s", dpi)
	if t.h3EP == "" && t.h2EP == "" {
		t.h2EP = config.DefaultEndpointH2V4 + ":443"
	}
	go ttlDropReporter()
	if dpi.bridge != nil && *standby != "" {
		ep, sni := t.h2EP, t.h2SNI
		if ep == "" {
			ep, sni = t.h3EP, t.h3SNI
		}
		bridges = newBset(dpi.bridge, *standby, ep, sni)
		api.H2DialTLS = bridges.dial
		go bridges.warmLoop(newTLSCache(*cfgPath))
	}
	// validate TLS material early
	_ = buildTLS(t.h2SNI)

	fd, err := receiveFd(*sock)
	if err != nil {
		fail("tun fd: %v", err)
	}
	_ = syscall.SetNonblock(fd, false)
	dev := &fdDevice{fd: fd}
	out("STATE connecting")

	go func() {
		for range time.Tick(time.Second) {
			out("STAT %d %d", dev.rx.Load(), dev.tx.Load())
		}
	}()
	var tdev api.TunnelDevice = dev
	var pd *probeDev
	if v4, err := netip.ParseAddr(config.AppConfig.IPv4); err == nil && v4.Is4() && *noData > 0 {
		pd = newProbeDev(dev, v4)
		tdev = pd
		go noDataWatch(pd, dev, *noData)
	}
	if _, err := runTunnel(context.Background(), t, tdev, *fb, 0); err != nil {
		fail("%v", err)
	}
	// watchdog: a tunnel that stays down (e.g. a blackholed TCP connect that never errors)
	// is reported as "STALL <seconds>" every 10 s so the app can switch servers.
	downSince.Store(time.Now().UnixNano())
	for range time.Tick(time.Second) {
		if tunUp.Load() {
			continue
		}
		d := time.Since(time.Unix(0, downSince.Load()))
		if d > 10*time.Second {
			if bridges != nil && bridges.switchNext(fmt.Sprintf("STALL-%d", int(d.Seconds()))) {
				downSince.Store(time.Now().UnixNano())
				continue
			}
			out("STALL %d", int(d.Seconds()))
			downSince.Store(time.Now().UnixNano())
		}
	}
}

// noDataWatch: while the tunnel is "up", inject a DNS probe whenever nothing arrived for 2 s (and every
// 10 s anyway, for the real-delay display). If neither a probe answer nor >=16 KB of data came back for
// `limit`, print "NODATA <s>" so the app switches server/SNI (DPI that lets the handshake through but
// stalls the stream).
func noDataWatch(pd *probeDev, dev *fdDevice, limit time.Duration) {
	var upAt time.Time
	var lastGood time.Time
	var lastRx uint64
	var lastProbe time.Time
	wasUp := false
	for range time.Tick(500 * time.Millisecond) {
		now := time.Now()
		if !tunUp.Load() {
			wasUp = false
			continue
		}
		if !wasUp {
			wasUp = true
			upAt = now
			lastGood = now
			lastRx = dev.rx.Load()
			pd.sendProbe()
			lastProbe = now
			continue
		}
		if g := pd.gotAt.Load(); g > 0 && time.Unix(0, g).After(lastGood) {
			lastGood = time.Unix(0, g)
		}
		if rx := dev.rx.Load(); rx-lastRx >= 16*1024 {
			lastGood = now
			lastRx = rx
		}
		idle := now.Sub(lastGood)
		if (idle > 2*time.Second && now.Sub(lastProbe) > 2*time.Second) || now.Sub(lastProbe) > 10*time.Second {
			pd.sendProbe()
			lastProbe = now
		}
		if idle > limit && bridges != nil && bridges.switchNext("NODATA") {
			lastGood = now
			continue
		}
		if idle > limit {
			out("NODATA %d %d", int(idle.Seconds()), int(now.Sub(upAt).Seconds()))
			lastGood = now // report again after another `limit`
		}
	}
}

func main() {
	// never route the MASQUE connection through an environment proxy
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		_ = os.Unsetenv(k)
	}
	_ = os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	log.SetFlags(log.Ltime)
	log.SetOutput(logWatcher{})
	if len(os.Args) < 2 {
		fmt.Println("usage: o76core register|scan|test|vpn ...")
		os.Exit(2)
	}
	if os.Getenv("O76_WATCH_STDIN") == "1" {
		if os.Args[1] == "vpn" || os.Args[1] == "svpn" {
			stdinCommands()
		} else {
			exitOnStdinClose()
		}
	}
	debugOn = os.Getenv("O76_DEBUG") != ""
	setupResolver(strings.Split(os.Getenv("O76_DNS"), ","))
	switch os.Args[1] {
	case "register":
		cmdRegister(os.Args[2:])
	case "scan":
		cmdScan(os.Args[2:])
	case "test":
		cmdTest(os.Args[2:])
	case "probe":
		cmdProbe(os.Args[2:])
	case "vpn":
		cmdVPN(os.Args[2:])
	case "realtest":
		cmdRealtest(os.Args[2:])
	case "bridgetest":
		cmdBridgetest(os.Args[2:])
	case "fetchlists":
		cmdFetchlists(os.Args[2:])
	case "ipfilter":
		cmdIPFilter(os.Args[2:])
	case "svpn":
		cmdSVPN(os.Args[2:])
	case "aetherid":
		cmdAetherID(os.Args[2:])
	default:
		fail("unknown command %s", os.Args[1])
	}
}
