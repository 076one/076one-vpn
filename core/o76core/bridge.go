// Upstream proxy "bridge": phone -> public SOCKS5 / SOCKS4 / HTTP-CONNECT proxy -> Cloudflare MASQUE (HTTP/2 over TCP).
// The MASQUE TLS session (client cert + pinned server key, uTLS fingerprint, ClientHello TLS-record
// fragmentation) runs end-to-end *inside* the proxied stream, so the proxy only sees an opaque TLS stream.
//
//	-bridge URL           on test / vpn / realtest / scan / probe: dial every HTTP/2 connection through this proxy
//	bridgetest            test many proxies in parallel: proxy handshake + MASQUE TLS through it, then a real
//	                      tunnel test (trace warp=on + small download) on the best ones
//	fetchlists            download public proxy lists, print one normalised proxy per line
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Diniboy1123/usque/api"
)

type bridge struct {
	scheme     string // socks5 | socks4 | http | auto (unknown: detect)
	host, port string
	user, pass string
}

func (b *bridge) addr() string { return net.JoinHostPort(b.host, b.port) }

// key is the proxy identity printed to the app: never contains credentials.
func (b *bridge) key() string { return b.scheme + "://" + b.addr() }

func (b *bridge) String() string {
	if b == nil {
		return "none"
	}
	if b.user != "" {
		return b.key() + " (auth)"
	}
	return b.key()
}

// parseBridge accepts socks5://[u:p@]h:p, socks4://h:p, http://h:p, https?->http, socks5h, [u:p@]h:p, h:p:u:p.
// A bare ip:port gets defScheme ("auto" = detect while testing).
func parseBridge(line, defScheme string) (*bridge, error) {
	s := strings.TrimSpace(line)
	if i := strings.IndexAny(s, " \t#"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return nil, errors.New("empty")
	}
	scheme := defScheme
	if i := strings.Index(s, "://"); i >= 0 {
		scheme = strings.ToLower(s[:i])
		s = s[i+3:]
	}
	switch scheme {
	case "socks5h", "socks":
		scheme = "socks5"
	case "socks4a":
		scheme = "socks4"
	case "https":
		scheme = "http"
	case "socks5", "socks4", "http", "auto":
	default:
		return nil, fmt.Errorf("unknown scheme %q", scheme)
	}
	s = strings.TrimSuffix(s, "/")
	b := &bridge{scheme: scheme}
	if at := strings.LastIndex(s, "@"); at >= 0 {
		cred := s[:at]
		s = s[at+1:]
		if u, err := url.PathUnescape(cred); err == nil {
			cred = u
		}
		b.user, b.pass, _ = strings.Cut(cred, ":")
	} else if parts := strings.Split(s, ":"); len(parts) == 4 && !strings.Contains(s, "[") {
		// host:port:user:pass
		s = parts[0] + ":" + parts[1]
		b.user, b.pass = parts[2], parts[3]
	} else if len(parts) == 3 && net.ParseIP(parts[0]) != nil {
		// ip:port:Country (hideip.me style)
		s = parts[0] + ":" + parts[1]
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	pn, err := strconv.Atoi(p)
	if err != nil || pn <= 0 || pn > 65535 || h == "" {
		return nil, fmt.Errorf("bad port %q", p)
	}
	if ip := net.ParseIP(h); ip != nil {
		if ip.IsLoopback() && os.Getenv("O76_ALLOW_LOCAL") == "" || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, errors.New("bad ip")
		}
	}
	b.host, b.port = h, p
	return b, nil
}

// dialBridge connects to target (ip:port) through the proxy and returns the tunnelled stream.
func dialBridge(ctx context.Context, b *bridge, target string, o dpiOpts) (net.Conn, string, error) {
	o.bridge = nil
	schemes := []string{b.scheme}
	if b.scheme == "auto" {
		schemes = []string{"http", "socks5", "socks4"} // SOCKS servers reject a CONNECT line at once; HTTP proxies would wait on a SOCKS greeting
	}
	var lastErr error
	for i, sc := range schemes {
		c, err := dialTCP(ctx, "tcp", b.addr(), o)
		if err != nil {
			return nil, "", err // proxy unreachable: no point trying other protocols
		}
		dl, ok := ctx.Deadline()
		if !ok {
			dl = time.Now().Add(15 * time.Second)
		}
		if i < len(schemes)-1 {
			// auto-detect: a proxy of another type usually just waits for more bytes; don't let that eat the budget
			if d := time.Now().Add(1500 * time.Millisecond); d.Before(dl) {
				dl = d
			}
		}
		_ = c.SetDeadline(dl)
		switch sc {
		case "socks5":
			err = socks5Connect(c, b, target)
		case "socks4":
			err = socks4Connect(c, b, target)
		default:
			err = httpConnect(c, b, target)
		}
		if err == nil {
			_ = c.SetDeadline(time.Time{})
			return c, sc, nil
		}
		c.Close()
		lastErr = fmt.Errorf("%s: %w", sc, err)
		if len(schemes) == 1 {
			// v1.5: the proxy itself is reachable but did not get us to the target (refused / timed out)
			lastErr = &proxyTargetErr{lastErr}
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, "", lastErr
}

// proxyTargetErr (v1.5): proxy reachable, target not (for a known proxy type). In the international-reach test this
// means "domestic only" (intl=0) rather than "dead proxy".
type proxyTargetErr struct{ err error }

func (e *proxyTargetErr) Error() string { return e.err.Error() }
func (e *proxyTargetErr) Unwrap() error { return e.err }

func isProxyTargetErr(err error) bool {
	var pe *proxyTargetErr
	return errors.As(err, &pe)
}

func splitTarget(target string) (net.IP, string, uint16, error) {
	h, p, err := net.SplitHostPort(target)
	if err != nil {
		return nil, "", 0, err
	}
	pn, err := strconv.Atoi(p)
	if err != nil {
		return nil, "", 0, err
	}
	return net.ParseIP(h), h, uint16(pn), nil
}

func socks5Connect(c net.Conn, b *bridge, target string) error {
	ip, host, port, err := splitTarget(target)
	if err != nil {
		return err
	}
	methods := []byte{0x00}
	if b.user != "" {
		methods = []byte{0x02, 0x00}
	}
	if _, err := c.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return err
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(c, rep); err != nil {
		return err
	}
	if rep[0] != 0x05 {
		return errors.New("not socks5")
	}
	switch rep[1] {
	case 0x00:
	case 0x02:
		if b.user == "" {
			return errors.New("auth required")
		}
		m := []byte{0x01, byte(len(b.user))}
		m = append(m, b.user...)
		m = append(m, byte(len(b.pass)))
		m = append(m, b.pass...)
		if _, err := c.Write(m); err != nil {
			return err
		}
		if _, err := io.ReadFull(c, rep); err != nil {
			return err
		}
		if rep[1] != 0x00 {
			return errors.New("auth failed")
		}
	default:
		return errors.New("no acceptable auth")
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip4 := ip.To4(); ip4 != nil {
		req = append(req, 0x01)
		req = append(req, ip4...)
	} else if ip != nil {
		req = append(req, 0x04)
		req = append(req, ip.To16()...)
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := c.Write(req); err != nil {
		return err
	}
	h := make([]byte, 4)
	if _, err := io.ReadFull(c, h); err != nil {
		return err
	}
	if h[1] != 0x00 {
		return fmt.Errorf("connect refused (code %d)", h[1])
	}
	var skip int
	switch h[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return err
		}
		skip = int(l[0])
	default:
		return errors.New("bad reply")
	}
	_, err = io.ReadFull(c, make([]byte, skip+2))
	return err
}

func socks4Connect(c net.Conn, b *bridge, target string) error {
	ip, host, port, err := splitTarget(target)
	if err != nil {
		return err
	}
	req := []byte{0x04, 0x01}
	req = binary.BigEndian.AppendUint16(req, port)
	if ip4 := ip.To4(); ip4 != nil {
		req = append(req, ip4...)
		req = append(req, b.user...)
		req = append(req, 0)
	} else {
		req = append(req, 0, 0, 0, 1) // SOCKS4a
		req = append(req, b.user...)
		req = append(req, 0)
		req = append(req, host...)
		req = append(req, 0)
	}
	if _, err := c.Write(req); err != nil {
		return err
	}
	rep := make([]byte, 8)
	if _, err := io.ReadFull(c, rep); err != nil {
		return err
	}
	if rep[1] != 0x5a {
		return fmt.Errorf("rejected (code %d)", rep[1])
	}
	return nil
}

func httpConnect(c net.Conn, b *bridge, target string) error {
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if b.user != "" {
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(b.user+":"+b.pass)) + "\r\n"
	}
	req += "\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		return err
	}
	// read the response head byte by byte so no tunnelled bytes are swallowed
	var head []byte
	one := make([]byte, 1)
	for !strings.HasSuffix(string(head), "\r\n\r\n") && !strings.HasSuffix(string(head), "\n\n") {
		if _, err := c.Read(one); err != nil {
			return err
		}
		head = append(head, one[0])
		if len(head) > 8192 {
			return errors.New("response too long")
		}
	}
	line, _, _ := strings.Cut(string(head), "\n")
	f := strings.Fields(line)
	if len(f) < 2 || !strings.HasPrefix(f[0], "HTTP/") {
		return errors.New("not an http proxy")
	}
	if f[1] != "200" {
		return fmt.Errorf("status %s", f[1])
	}
	return nil
}

// ---------------- bridgetest ----------------

type bres struct {
	b      *bridge
	idx    int
	scheme string
	hsMs   int64
	err    error
	stage  string
	r      realResult
	realOK bool
}

// bridgeDialer returns a per-tunnel HTTP/2 dialer that goes through b with the global anti-DPI options.
func bridgeDialer(b *bridge) api.H2DialFunc {
	o := dpi
	o.bridge = b
	return func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
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
}

func readProxyFile(path, def string) []*bridge {
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			fail("proxies: %v", err)
		}
		defer f.Close()
		r = f
	}
	seen := map[string]bool{}
	var list []*bridge
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		b, err := parseBridge(sc.Text(), def)
		if err != nil {
			continue
		}
		k := b.addr()
		if seen[k] {
			continue
		}
		seen[k] = true
		list = append(list, b)
	}
	return list
}

// bridgetest -c cfg -proxies file -eps "h2|ip:port|sni;..." : stage 1 proxy+MASQUE TLS handshake for every proxy
// (-n parallel, -t timeout), stage 2 real tunnel test through the -real fastest.
// Output: "BTOTAL n", "BPROG done ok", "BHS scheme://ip:port ms" (stage 1 pass),
// "BREAL scheme://ip:port ep rttMs kbps firstMs colo", "BFAIL scheme://ip:port stage reason" (stage 2), "DONE n".
func cmdBridgetest(args []string) {
	fs := flag.NewFlagSet("bridgetest", flag.ExitOnError)
	cfgPath := fs.String("c", "config.json", "config path")
	pf := fs.String("proxies", "-", "proxy list file, one per line ('-' = stdin)")
	def := fs.String("def", "auto", "type for bare ip:port lines: auto|socks5|socks4|http")
	eps := fs.String("eps", "h2|162.159.198.2:443|consumer-masque.cloudflareclient.com", "MASQUE HTTP/2 endpoints proto|ip:port|sni;... (rotated over proxies)")
	conc := fs.Int("n", 50, "parallel stage-1 tests")
	maxN := fs.Int("max", 1000, "max proxies tested")
	hsTimeout := fs.Duration("t", 6*time.Second, "stage-1 timeout (proxy connect + MASQUE TLS)")
	realN := fs.Int("real", 12, "proxies given the real tunnel test (fastest stage-1 first)")
	realConc := fs.Int("rn", 4, "parallel real tests")
	realTimeout := fs.Duration("rt", 15*time.Second, "real test timeout")
	keep := fs.Int("keep", 8, "stop real-testing after this many proxies passed")
	dl := fs.Int("dl", 100000, "download bytes in the real test")
	addDPIFlags(fs)
	_ = fs.Parse(args)
	runPostParse()
	dpi.bridge = nil
	applyDPI()
	quietLog.Store(true)
	loadCfg(*cfgPath)

	var targets []target
	for _, item := range strings.Split(*eps, ";") {
		p := strings.Split(strings.TrimSpace(item), "|")
		if len(p) == 3 && p[0] == "h2" {
			targets = append(targets, target{p[0], p[1], p[2]})
		}
	}
	if len(targets) == 0 {
		fail("no h2 endpoints")
	}
	list := readProxyFile(*pf, *def)
	if len(list) > *maxN {
		list = list[:*maxN]
	}
	out("BTOTAL %d", len(list))
	tc := newTLSCache(*cfgPath)

	// stage 1
	results := make([]*bres, len(list))
	ch := make(chan int)
	var wg sync.WaitGroup
	var done, okN int32
	for w := 0; w < *conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range ch {
				b := list[i]
				t := targets[i%len(targets)]
				res := &bres{b: b, idx: i}
				o := dpi
				o.bridge = b
				ctx, cancel := context.WithTimeout(context.Background(), *hsTimeout)
				start := time.Now()
				var proxyOK atomic.Bool
				o.onProxyOK = func() { proxyOK.Store(true) }
				c, alpn, sc, err := dialH2TLSBridge(ctx, t.ep, tc.get(t.sni), o)
				cancel()
				if err == nil {
					out("BINTL %s 1", b.key())
				} else if proxyOK.Load() {
					out("BINTL %s 0", b.key())
				}
				if err == nil {
					c.Close()
					if alpn != "h2" {
						err = errALPN
					}
				}
				res.scheme = sc
				if err == nil {
					res.hsMs = max64(time.Since(start).Milliseconds(), 1)
					if b.scheme == "auto" {
						b.scheme = sc
					}
					atomic.AddInt32(&okN, 1)
					out("BHS %s %d %s", b.key(), res.hsMs, t.ep)
				} else {
					res.err = err
				}
				results[i] = res
				d := atomic.AddInt32(&done, 1)
				if d%50 == 0 {
					out("BPROG %d %d", d, atomic.LoadInt32(&okN))
				}
			}
		}()
	}
	for i := range list {
		ch <- i
	}
	close(ch)
	wg.Wait()
	out("BPROG %d %d", done, okN)

	var good []*bres
	for _, r := range results {
		if r != nil && r.err == nil {
			good = append(good, r)
		}
	}
	sort.Slice(good, func(i, j int) bool { return good[i].hsMs < good[j].hsMs })
	if len(good) > *realN {
		good = good[:*realN]
	}
	out("BSTAGE2 %d", len(good))

	// stage 2: real tunnel through the proxy
	var passed int32
	ch2 := make(chan *bres)
	var wg2 sync.WaitGroup
	for w := 0; w < *realConc; w++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			for r := range ch2 {
				if atomic.LoadInt32(&passed) >= int32(*keep) {
					continue
				}
				t := targets[r.idx%len(targets)]
				rr := realOneVia(t.proto, t.ep, t.sni, *realTimeout, *dl, r.b)
				if rr.ok() {
					atomic.AddInt32(&passed, 1)
					out("BREAL %s %s %s %d %d %d %d %s", r.b.key(), t.ep, t.sni, max64(rr.rttMs, 1), rr.kbps, rr.firstMs, r.hsMs, rr.colo)
				} else {
					reason := "warp=" + rr.warp
					if rr.err != nil {
						reason = rr.err.Error()
					}
					out("BFAIL %s %s %s", r.b.key(), rr.stage, strings.ReplaceAll(reason, "\n", " "))
				}
			}
		}()
	}
	for _, r := range good {
		ch2 <- r
	}
	close(ch2)
	wg2.Wait()
	out("DONE %d", passed)
}

// dialH2TLSBridge is dialH2TLS through o.bridge, also returning the detected proxy protocol.
func dialH2TLSBridge(ctx context.Context, ep string, cfg *tls.Config, o dpiOpts) (net.Conn, string, string, error) {
	var sc string
	o.rawDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, s, err := dialBridge(ctx, o.bridge, addr, o)
		sc = s
		if (err == nil || isProxyTargetErr(err)) && o.onProxyOK != nil {
			o.onProxyOK()
		}
		return c, err
	}
	c, alpn, err := dialH2TLS(ctx, "tcp", ep, cfg, o)
	return c, alpn, sc, err
}

// ---------------- fetchlists ----------------

// fetchlists -urls "type|url|mirror,..." -max N : download proxy lists (direct), print "P scheme://ip:port" lines
// interleaved across sources, "SRC ok|err count url", "DONE n".
func cmdFetchlists(args []string) {
	fs := flag.NewFlagSet("fetchlists", flag.ExitOnError)
	urls := fs.String("urls", "", "comma/newline separated type|url[|mirror] (type: socks5|socks4|http|auto)")
	maxN := fs.Int("max", 3000, "max proxies printed")
	per := fs.Int("per", 1500, "max proxies taken from one source")
	timeout := fs.Duration("t", 20*time.Second, "per source timeout")
	country := fs.String("country", "", "v1.5: keep only proxies in this country (IR): sources typed \"type@IR\" are trusted, every other entry is checked against the bundled IP ranges")
	_ = fs.Parse(args)
	cc := strings.ToUpper(strings.TrimSpace(*country))
	var srcs [][]string
	for _, s := range strings.FieldsFunc(*urls, func(c rune) bool { return c == ',' || c == '\n' || c == ' ' }) {
		p := strings.Split(strings.TrimSpace(s), "|")
		if len(p) == 1 {
			p = []string{"auto", p[0]}
		}
		if len(p) >= 2 {
			srcs = append(srcs, p)
		}
	}
	client := &http.Client{Timeout: *timeout, Transport: &http.Transport{Proxy: nil, ForceAttemptHTTP2: true}}
	lists := make([][]*bridge, len(srcs))
	var wg sync.WaitGroup
	for i, s := range srcs {
		wg.Add(1)
		go func(i int, s []string) {
			defer wg.Done()
			var lastErr error
			for _, u := range s[1:] {
				if !strings.HasPrefix(u, "http") {
					continue
				}
				resp, err := client.Get(u)
				if err != nil {
					lastErr = err
					continue
				}
				body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
				resp.Body.Close()
				if err != nil || resp.StatusCode != 200 {
					lastErr = fmt.Errorf("http %d %v", resp.StatusCode, err)
					continue
				}
				// v1.5: "type@CC" = the source itself is already filtered to that country
				typ, srcCC, _ := strings.Cut(s[0], "@")
				trusted := cc != "" && strings.EqualFold(srcCC, cc)
				keep := func(b *bridge, itemCC string) bool {
					if cc == "" {
						return true
					}
					return trusted || strings.EqualFold(itemCC, cc) || inCountry(b.host, cc)
				}
				var l []*bridge
				if js := strings.TrimSpace(string(body)); strings.HasPrefix(js, "{") {
					// geonode-style JSON: {"data":[{"ip":..,"port":..,"protocols":["socks5",..],"country":"IR"}]}
					var g struct {
						Data []struct {
							IP        string   `json:"ip"`
							Port      string   `json:"port"`
							Protocols []string `json:"protocols"`
							Country   string   `json:"country"`
						} `json:"data"`
					}
					if json.Unmarshal([]byte(js), &g) == nil {
						for _, d := range g.Data {
							for _, pr := range d.Protocols {
								if b, err := parseBridge(pr+"://"+net.JoinHostPort(d.IP, d.Port), typ); err == nil && net.ParseIP(b.host) != nil && keep(b, d.Country) {
									l = append(l, b)
								}
							}
						}
					}
				} else {
					for _, line := range strings.Split(string(body), "\n") {
						if b, err := parseBridge(line, typ); err == nil && net.ParseIP(b.host) != nil && keep(b, "") {
							l = append(l, b)
						}
					}
				}
				if len(l) == 0 {
					lastErr = errors.New("no proxies in response")
					continue
				}
				if len(l) > *per {
					l = l[:*per]
				}
				lists[i] = l
				out("SRC ok %d %s", len(l), u)
				return
			}
			out("SRC err 0 %s %v", s[1], strings.ReplaceAll(fmt.Sprint(lastErr), "\n", " "))
		}(i, s)
	}
	wg.Wait()
	// interleave sources so a cap keeps a mix of all of them
	seen := map[string]bool{}
	n := 0
	for k := 0; n < *maxN; k++ {
		any := false
		for _, l := range lists {
			if k < len(l) {
				any = true
				b := l[k]
				if seen[b.addr()] {
					continue
				}
				seen[b.addr()] = true
				out("P %s", b.key())
				n++
				if n >= *maxN {
					break
				}
			}
		}
		if !any {
			break
		}
	}
	out("DONE %d", n)
}
