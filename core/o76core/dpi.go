// Anti-DPI transport for the HTTP/2 (TCP+TLS) MASQUE connection:
//   - TLS ClientHello fragmentation: the handshake record is re-split into several small TLS records
//     ("tlsrec") and/or written to the socket in small TCP chunks with short pauses ("tcp"), so a DPI box
//     that only inspects the first segment / first record does not see the whole SNI.
//   - browser TLS fingerprint (uTLS Chrome/Firefox) instead of Go's distinctive ClientHello.
//   - TCP tweaks: TCP_NODELAY, outer TCP MSS clamp (TCP_MAXSEG) for mobile paths with broken PMTUD,
//     TCP keepalive.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
)

type dpiOpts struct {
	frag             string // off | tcp | tlsrec | both
	sizeMin, sizeMax int    // fragment sizes (bytes)
	delayMin         int    // ms between TCP chunks
	delayMax         int
	fp               string // chrome | firefox | go
	noDelay          bool
	mss              int     // outer TCP MSS clamp, 0 = system
	mtu              int     // tunnel MTU
	bridge           *bridge // upstream proxy for every HTTP/2 connection (nil = direct)
	onProxyOK        func()  // v1.5 bridge test: called when the proxy itself accepted the CONNECT (intl test)
	rawDial          func(ctx context.Context, network, addr string) (net.Conn, error)
}

var dpi = dpiOpts{frag: "both", sizeMin: 10, sizeMax: 50, delayMin: 1, delayMax: 5, fp: "chrome", noDelay: true, mss: 1300, mtu: 1280}

// addDPIFlags registers the anti-DPI flags on a FlagSet (defaults = "best settings").
func addDPIFlags(fs *flag.FlagSet) {
	fs.StringVar(&dpi.frag, "frag", dpi.frag, "ClientHello fragmentation: off|tcp|tlsrec|both")
	fragSize := fs.String("fragsize", "10-50", "fragment size range in bytes (1-100)")
	fragDelay := fs.String("fragdelay", "1-5", "delay between TCP fragments in ms (0-10)")
	fs.StringVar(&dpi.fp, "fp", dpi.fp, "TLS fingerprint: chrome|go (firefox: uTLS key-share bug with Cloudflare, not offered)")
	fs.BoolVar(&dpi.noDelay, "nodelay", dpi.noDelay, "TCP_NODELAY on the MASQUE connection")
	fs.IntVar(&dpi.mss, "mss", dpi.mss, "outer TCP MSS clamp (0 = system default)")
	fs.IntVar(&dpi.mtu, "mtu", dpi.mtu, "tunnel MTU (1200-1400)")
	bridgeURL := fs.String("bridge", "", "upstream proxy for HTTP/2: socks5://[user:pass@]ip:port | socks4://ip:port | http://[user:pass@]ip:port")
	postParse = append(postParse, func() {
		if *bridgeURL != "" {
			b, err := parseBridge(*bridgeURL, "socks5")
			if err != nil {
				fail("bridge: %v", err)
			}
			dpi.bridge = b
		}
		dpi.sizeMin, dpi.sizeMax = parseRange(*fragSize, 10, 50, 1, 1000)
		dpi.delayMin, dpi.delayMax = parseRange(*fragDelay, 1, 5, 0, 50)
		if dpi.mtu < 1200 {
			dpi.mtu = 1200
		}
		if dpi.mtu > 1400 {
			dpi.mtu = 1400
		}
	})
}

var postParse []func()

func runPostParse() {
	for _, f := range postParse {
		f()
	}
}

func parseRange(s string, defA, defB, lo, hi int) (int, int) {
	var a, b int
	if n, _ := fmt.Sscanf(strings.TrimSpace(s), "%d-%d", &a, &b); n == 2 {
	} else if n, _ := fmt.Sscanf(strings.TrimSpace(s), "%d", &a); n == 1 {
		b = a
	} else {
		return defA, defB
	}
	if a < lo {
		a = lo
	}
	if b > hi {
		b = hi
	}
	if b < a {
		b = a
	}
	return a, b
}

func (o dpiOpts) String() string {
	return fmt.Sprintf("frag=%s size=%d-%d delay=%d-%dms fp=%s nodelay=%v mss=%d mtu=%d bridge=%s",
		o.frag, o.sizeMin, o.sizeMax, o.delayMin, o.delayMax, o.fp, o.noDelay, o.mss, o.mtu, o.bridge)
}

var rndMu sync.Mutex
var rnd = rand.New(rand.NewSource(time.Now().UnixNano()))

func rint(a, b int) int {
	if b <= a {
		return a
	}
	rndMu.Lock()
	defer rndMu.Unlock()
	return a + rnd.Intn(b-a+1)
}

// fragConn fragments the first write (the TLS ClientHello).
type fragConn struct {
	net.Conn
	once bool
	o    dpiOpts
}

func (c *fragConn) Write(b []byte) (int, error) {
	if c.once || c.o.frag == "off" || c.o.frag == "" || len(b) < 6 || b[0] != 0x16 {
		return c.Conn.Write(b)
	}
	c.once = true
	recLen := int(b[3])<<8 | int(b[4])
	if 5+recLen > len(b) {
		return c.Conn.Write(b)
	}
	data := b[:5+recLen]
	rest := b[5+recLen:]
	var pieces [][]byte
	if c.o.frag == "tlsrec" || c.o.frag == "both" {
		// re-split the handshake payload into several TLS records (valid per RFC 8446 5.1)
		payload := data[5:]
		for len(payload) > 0 {
			n := rint(c.o.sizeMin, c.o.sizeMax)
			if n > len(payload) {
				n = len(payload)
			}
			rec := make([]byte, 5+n)
			copy(rec, data[:3])
			rec[3], rec[4] = byte(n>>8), byte(n)
			copy(rec[5:], payload[:n])
			pieces = append(pieces, rec)
			payload = payload[n:]
		}
	} else {
		pieces = [][]byte{data}
	}
	tcp := c.o.frag == "tcp" || c.o.frag == "both"
	first := true
	for _, p := range pieces {
		if !tcp {
			if _, err := c.Conn.Write(p); err != nil {
				return 0, err
			}
			continue
		}
		for len(p) > 0 {
			n := rint(c.o.sizeMin, c.o.sizeMax)
			if n > len(p) {
				n = len(p)
			}
			if !first {
				if d := rint(c.o.delayMin, c.o.delayMax); d > 0 {
					time.Sleep(time.Duration(d) * time.Millisecond)
				}
			}
			first = false
			if _, err := c.Conn.Write(p[:n]); err != nil {
				return 0, err
			}
			p = p[n:]
		}
	}
	if len(rest) > 0 {
		if _, err := c.Conn.Write(rest); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

// dialTCP dials with keepalive and an optional MSS clamp set before connect().
func dialTCP(ctx context.Context, network, addr string, o dpiOpts) (net.Conn, error) {
	d := net.Dialer{KeepAlive: 15 * time.Second}
	if o.mss > 0 {
		mss := o.mss
		d.Control = func(_, _ string, rc syscall.RawConn) error {
			var serr error
			_ = rc.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, mss)
			})
			if serr != nil {
				debugf("TCP_MAXSEG: %v", serr)
			}
			return nil
		}
	}
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		// fragmentation needs NODELAY so every small write leaves as its own segment
		_ = tc.SetNoDelay(true)
	}
	return c, nil
}

// h2Conn hides the uTLS connection state type from x/net/http2 (it only accepts crypto/tls's).
type h2Conn struct{ net.Conn }

// dialH2TLS: TCP dial + (fragmented) TLS handshake with ALPN h2 and the configured fingerprint.
func dialH2TLS(ctx context.Context, network, addr string, cfg *tls.Config, o dpiOpts) (net.Conn, string, error) {
	var raw net.Conn
	var err error
	switch {
	case o.rawDial != nil:
		raw, err = o.rawDial(ctx, network, addr)
	case o.bridge != nil:
		raw, _, err = dialBridge(ctx, o.bridge, addr, o)
	default:
		raw, err = dialTCP(ctx, network, addr, o)
	}
	if err != nil {
		return nil, "", err
	}
	fc := &fragConn{Conn: raw, o: o}
	setNoDelay := func() {
		if tc, ok := raw.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(o.noDelay)
		}
	}
	if o.fp == "go" || o.fp == "" {
		c := cfg.Clone()
		c.NextProtos = []string{"h2"}
		tc := tls.Client(fc, c)
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, "", err
		}
		setNoDelay()
		return tc, tc.ConnectionState().NegotiatedProtocol, nil
	}
	uc := &utls.Config{
		ServerName:            cfg.ServerName,
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: cfg.VerifyPeerCertificate,
		NextProtos:            []string{"h2"},
	}
	for _, c := range cfg.Certificates {
		uc.Certificates = append(uc.Certificates, utls.Certificate{Certificate: c.Certificate, PrivateKey: c.PrivateKey})
	}
	id := utls.HelloChrome_Auto
	if o.fp == "firefox" {
		id = utls.HelloFirefox_Auto
	}
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		raw.Close()
		return nil, "", err
	}
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.ALPNExtension:
			e.AlpnProtocols = []string{"h2"}
		case *utls.ApplicationSettingsExtension:
			e.SupportedProtocols = []string{"h2"}
		case *utls.ApplicationSettingsExtensionNew:
			e.SupportedProtocols = []string{"h2"}
		}
	}
	u := utls.UClient(fc, uc, utls.HelloCustom)
	if err := u.ApplyPreset(&spec); err != nil {
		raw.Close()
		return nil, "", err
	}
	if err := u.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, "", err
	}
	setNoDelay()
	return &h2Conn{u}, u.ConnectionState().NegotiatedProtocol, nil
}

var errALPN = errors.New("server did not negotiate h2")

var debugOn bool

func debugf(f string, a ...interface{}) {
	if debugOn {
		out("DBG "+f, a...)
	}
}
