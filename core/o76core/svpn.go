// v1.6 Aether mode tunnel: Android TUN -> gVisor userspace TCP/IP stack -> one SOCKS5 CONNECT per TCP flow to a
// local SOCKS5 server (the Aether core on 127.0.0.1:PORT). DNS (UDP/53) is answered with DNS-over-TCP through the
// same SOCKS port (1.1.1.1, then 8.8.8.8). Other UDP (e.g. QUIC) is refused with ICMP port unreachable so apps fall
// back to TCP at once. Adapted from Worker mode (wtun.go).
//
//	svpn -sock path -socks 127.0.0.1:PORT [-nodata 30s] [-mtu 1280] [-chain]
//	  prints READY, "STATE connecting|up|down", "STAT rx tx", "RTT ms", "NODATA s", "FAILS n", "WLOG …", "WERR reason".
//
// v1.8.3 -chain (Config + Psiphon mode): NODATA only after -nodata (default 50 s there) without any success AND
// -needfails consecutive failed probes; any relayed byte counts as liveness; each DNS probe has its own short
// timeout (-probeto) and probes overlap, so one slow probe never delays the next; no "FAILS" lines (the app
// recovers on NODATA); IPv6 TCP and private/reserved IPv4 destinations get an RST at once (-no6, -fastfail) and
// AAAA questions get an empty answer, so apps use IPv4 immediately.
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// packetDev is the TUN side (fdDevice in the app, a socketpair in tests).
type packetDev interface {
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) error
}

type stun struct {
	socks     *bridge
	resolvers []string
	s         *stack.Stack
	ep        *channel.Endpoint
	dev       packetDev
	conns     atomic.Int32
	dialOK    atomic.Int64
	dialFails atomic.Int32
	relayOK   atomic.Int64
	probeOK   atomic.Int64
	rxApp     atomic.Uint64
	rxAt      atomic.Int64 // v1.8.3: last time any relayed byte reached an app
	no6       bool         // v1.8.3: refuse IPv6 TCP at once (RST) and answer AAAA with no records
	fastFail  bool         // v1.8.3: refuse private/reserved IPv4 destinations at once (RST)
	ho        healthOpts
	nRelay    atomic.Int32
	cacheMu   sync.Mutex
	cache     map[string]dnsCacheEnt
	logMu     sync.Mutex
	logCount  map[string]int
	dohOnce   sync.Once
	doh       *http.Client
}

func (t *stun) slog(key, f string, a ...interface{}) {
	t.logMu.Lock()
	n := t.logCount[key]
	t.logCount[key] = n + 1
	t.logMu.Unlock()
	if n < 3 || (n+1)%25 == 0 {
		out("WLOG "+f, a...)
	}
}

func newSTun(socksAddr string, dev packetDev, mtu int) (*stun, error) {
	host, port, err := net.SplitHostPort(socksAddr)
	if err != nil {
		return nil, fmt.Errorf("-socks: %v", err)
	}
	t := &stun{socks: &bridge{scheme: "socks5", host: host, port: port}, dev: dev,
		resolvers: []string{"1.1.1.1:53", "8.8.8.8:53"}, cache: map[string]dnsCacheEnt{}, logCount: map[string]int{}}
	t.s = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	sack := tcpip.TCPSACKEnabled(true)
	_ = t.s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	t.ep = channel.New(1024, uint32(mtu), "")
	if err := t.s.CreateNIC(1, t.ep); err != nil {
		return nil, fmt.Errorf("nic: %v", err)
	}
	t.s.SetPromiscuousMode(1, true)
	t.s.SetSpoofing(1, true)
	t.s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})
	tf := tcp.NewForwarder(t.s, 0, 2048, t.onTCP)
	t.s.SetTransportProtocolHandler(tcp.ProtocolNumber, tf.HandlePacket)
	uf := udp.NewForwarder(t.s, t.onUDP)
	t.s.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		if id.LocalPort != 53 {
			return false // ICMP port unreachable: QUIC etc. fall back to TCP at once
		}
		return uf.HandlePacket(id, pkt)
	})
	return t, nil
}

// dial opens one SOCKS5 CONNECT stream to dst through the local SOCKS server.
func (t *stun) dial(ctx context.Context, dst string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", t.socks.addr())
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if err := socks5Connect(c, t.socks, dst); err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

// pump moves packets TUN <-> stack until the TUN fails; returns the read error.
func (t *stun) pump() error {
	go func() {
		ctx := context.Background()
		for {
			pkt := t.ep.ReadContext(ctx)
			if pkt == nil {
				continue
			}
			v := pkt.ToView()
			pkt.DecRef()
			_ = t.dev.WritePacket(v.AsSlice())
			v.Release()
		}
	}()
	buf := make([]byte, 65536)
	for {
		n, err := t.dev.ReadPacket(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		p := make([]byte, n)
		copy(p, buf[:n])
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
		switch p[0] >> 4 {
		case 4:
			t.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			t.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			pkb.DecRef()
		}
	}
}

// reservedV4: destinations a remote proxy can never reach (Psiphon refuses them after a round trip).
func reservedV4(ip net.IP) bool {
	ip = ip.To4()
	if ip == nil {
		return false
	}
	switch {
	case ip[0] == 0, ip[0] == 10, ip[0] == 127, ip[0] >= 224,
		ip[0] == 100 && ip[1]&0xc0 == 64, // 100.64/10 carrier-grade NAT
		ip[0] == 169 && ip[1] == 254,
		ip[0] == 172 && ip[1]&0xf0 == 16,
		ip[0] == 192 && ip[1] == 168,
		ip[0] == 192 && ip[1] == 0 && ip[2] == 0,
		ip[0] == 198 && ip[1]&0xfe == 18: // 198.18/15 benchmarking
		return true
	}
	return false
}

func (t *stun) onTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	if t.no6 && id.LocalAddress.Len() == 16 {
		r.Complete(true) // RST: the app falls back to IPv4 at once
		t.slog("v6rst", "ipv6 [%s]:%d refused at once (RST)", net.IP(id.LocalAddress.AsSlice()), id.LocalPort)
		return
	}
	if t.fastFail && reservedV4(net.IP(id.LocalAddress.AsSlice())) {
		r.Complete(true)
		t.slog("privrst", "private/reserved %s:%d refused at once (RST)", net.IP(id.LocalAddress.AsSlice()), id.LocalPort)
		return
	}
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	ep.SocketOptions().SetKeepAlive(true)
	c := gonet.NewTCPConn(&wq, ep)
	dst := net.JoinHostPort(net.IP(id.LocalAddress.AsSlice()).String(), fmt.Sprint(id.LocalPort))
	go t.relay(c, dst)
}

func (t *stun) relay(c *gonet.TCPConn, dst string) {
	defer c.Close()
	t.conns.Add(1)
	defer t.conns.Add(-1)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t0 := time.Now()
	rc, err := t.dial(ctx, dst)
	cancel()
	if err != nil {
		f := t.dialFails.Add(1)
		t.slog("relayfail", "relay fail %s after %d ms: %s", dst, time.Since(t0).Milliseconds(), errLine(err))
		if f == 3 || f%10 == 0 {
			out("WERR %s", strings.ReplaceAll(err.Error(), "\n", " "))
		}
		return
	}
	t.dialFails.Store(0)
	t.dialOK.Store(time.Now().UnixNano())
	defer rc.Close()
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(rc, c)
		if cw, ok := rc.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		var nn int64
		fb := make([]byte, 32*1024)
		if k, err := rc.Read(fb); k > 0 {
			t.relayOK.Store(time.Now().UnixNano())
			if t.nRelay.Add(1) == 1 {
				out("WLOG first relay ok %s %d ms", dst, time.Since(t0).Milliseconds())
			}
			t.rxApp.Add(uint64(k))
			t.rxAt.Store(time.Now().UnixNano())
			if _, werr := c.Write(fb[:k]); werr == nil && err == nil {
				nn, _ = io.Copy(rxCounter{c, t}, rc) // counted as it flows (a long download is liveness too)
			}
		} else if err != nil && err != io.EOF {
			t.slog("relayread", "relay %s: no answer after %d ms: %s", dst, time.Since(t0).Milliseconds(), errLine(err))
		}
		_ = nn
		_ = c.CloseWrite()
		done <- struct{}{}
	}()
	<-done
	select {
	case <-done:
	case <-time.After(30 * time.Second):
	}
}

// rxCounter counts bytes relayed to the app while they flow.
type rxCounter struct {
	w io.Writer
	t *stun
}

func (r rxCounter) Write(p []byte) (int, error) {
	n, err := r.w.Write(p)
	if n > 0 {
		r.t.rxApp.Add(uint64(n))
		r.t.rxAt.Store(time.Now().UnixNano())
	}
	return n, err
}

// dnsTCP sends one DNS message as DNS-over-TCP through SOCKS to the given resolver.
func (t *stun) dnsTCP(q []byte, resolver string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := t.dial(ctx, resolver)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	m := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(m, uint16(len(q)))
	copy(m[2:], q)
	if _, err := c.Write(m); err != nil {
		return nil, err
	}
	var lb [2]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		return nil, err
	}
	a := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(c, a); err != nil {
		return nil, err
	}
	if len(a) < 12 {
		return nil, errors.New("short dns answer")
	}
	return a, nil
}

// dnsSocksUDP (v1.7, Firefox mode): one DNS query through SOCKS5 UDP ASSOCIATE on the same local SOCKS server
// (the Firefox core answers port 53 with encrypted DNS inside its tunnel, so no raw TCP/53 CONNECT is needed).
func (t *stun) dnsSocksUDP(q []byte, resolver string) ([]byte, error) {
	rh, rp, err := net.SplitHostPort(resolver)
	if err != nil {
		return nil, err
	}
	rip := net.ParseIP(rh).To4()
	if rip == nil {
		return nil, errors.New("udp dns: ipv4 resolver required")
	}
	var port uint16
	fmt.Sscanf(rp, "%d", &port)
	c, err := net.DialTimeout("tcp", t.socks.addr(), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = c.Write([]byte{5, 1, 0}); err != nil {
		return nil, err
	}
	var g [2]byte
	if _, err = io.ReadFull(c, g[:]); err != nil || g[0] != 5 || g[1] != 0 {
		return nil, errors.New("udp dns: socks greeting refused")
	}
	if _, err = c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, err
	}
	var h [4]byte
	if _, err = io.ReadFull(c, h[:]); err != nil {
		return nil, err
	}
	if h[1] != 0 {
		return nil, fmt.Errorf("udp dns: associate refused (%d)", h[1])
	}
	var bnd net.IP
	switch h[3] {
	case 1:
		b := make([]byte, 4)
		if _, err = io.ReadFull(c, b); err != nil {
			return nil, err
		}
		bnd = net.IP(b)
	case 4:
		b := make([]byte, 16)
		if _, err = io.ReadFull(c, b); err != nil {
			return nil, err
		}
		bnd = net.IP(b)
	default:
		return nil, errors.New("udp dns: unsupported bind address")
	}
	var pb [2]byte
	if _, err = io.ReadFull(c, pb[:]); err != nil {
		return nil, err
	}
	if bnd.IsUnspecified() {
		bnd = net.IPv4(127, 0, 0, 1)
	}
	u, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: bnd, Port: int(binary.BigEndian.Uint16(pb[:]))})
	if err != nil {
		return nil, err
	}
	defer u.Close()
	_ = u.SetDeadline(time.Now().Add(8 * time.Second))
	pkt := append([]byte{0, 0, 0, 1, rip[0], rip[1], rip[2], rip[3], byte(port >> 8), byte(port)}, q...)
	if _, err = u.Write(pkt); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := u.Read(buf)
	if err != nil {
		return nil, err
	}
	off := 0
	if n >= 4 {
		switch buf[3] {
		case 1:
			off = 10
		case 4:
			off = 22
		case 3:
			if n > 4 {
				off = 7 + int(buf[4])
			}
		}
	}
	if off == 0 || n-off < 12 {
		return nil, errors.New("short udp dns answer")
	}
	return append([]byte(nil), buf[off:n]...), nil
}

// v1.8.1: DNS-over-HTTPS (HTTP/2, port 443) through the SOCKS port. Some upstreams (the Firefox proxy) refuse
// TCP/53 and UDP, so plain DNS through them times out and apps fall back to the ISP's poisoned resolver.
func (t *stun) dnsDoH(q []byte, u string) ([]byte, error) {
	t.dohOnce.Do(func() {
		tr := &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) { return t.dial(ctx, addr) },
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 8 * time.Second,
		}
		t.doh = &http.Client{Transport: tr, Timeout: 9 * time.Second}
	})
	req, err := http.NewRequest("POST", u, bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := t.doh.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("doh %s: %s", u, resp.Status)
	}
	a, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	if len(a) < 12 {
		return nil, errors.New("short doh answer")
	}
	return a, nil
}

// poisoned reports an answer that carries Iran's filtering addresses (10.10.34.34-36, 2001:4188:2:600:10:10:34:3x).
func poisoned(a []byte) bool {
	for _, p := range [][]byte{{10, 10, 34, 34}, {10, 10, 34, 35}, {10, 10, 34, 36},
		{0x20, 0x01, 0x41, 0x88, 0, 2, 6, 0, 0, 0x10, 0, 0x10, 0, 0x34, 0, 0x35},
		{0x20, 0x01, 0x41, 0x88, 0, 2, 6, 0, 0, 0x10, 0, 0x10, 0, 0x34, 0, 0x34},
		{0x20, 0x01, 0x41, 0x88, 0, 2, 6, 0, 0, 0x10, 0, 0x10, 0, 0x34, 0, 0x36}} {
		if len(a) > 12 && bytes.Contains(a[12:], p) {
			return true
		}
	}
	return false
}

// dnsQuery resolves q (cache 60 s); the first resolver gets a 2.5 s head start, then the second one races it.
func (t *stun) dnsQuery(q []byte, useCache bool) ([]byte, error) {
	return t.dnsQueryT(q, useCache, 12*time.Second, 2500*time.Millisecond)
}

// emptyAAAA: v1.8.3 (-no6) a NOERROR answer with no records for an AAAA question, nil for anything else.
func emptyAAAA(q []byte) []byte {
	if len(q) < 12 || binary.BigEndian.Uint16(q[4:]) != 1 || q[2]&0x80 != 0 {
		return nil
	}
	i := 12
	for i < len(q) && q[i] != 0 {
		if q[i]&0xc0 != 0 {
			return nil
		}
		i += int(q[i]) + 1
	}
	if i+5 > len(q) || binary.BigEndian.Uint16(q[i+1:]) != 28 {
		return nil
	}
	a := append([]byte(nil), q[:i+5]...)
	a[2] = 0x80 | (q[2] & 0x79) // QR, keep opcode + RD
	a[3] = 0x80                 // RA, NOERROR
	binary.BigEndian.PutUint16(a[6:], 0)
	binary.BigEndian.PutUint16(a[8:], 0)
	binary.BigEndian.PutUint16(a[10:], 0)
	return a
}

func (t *stun) dnsQueryT(q []byte, useCache bool, totalTO, hedgeAfter time.Duration) ([]byte, error) {
	if len(q) < 12 {
		return nil, errors.New("short dns")
	}
	key := string(q[2:])
	if useCache {
		t.cacheMu.Lock()
		e, ok := t.cache[key]
		t.cacheMu.Unlock()
		if ok && time.Now().Before(e.exp) {
			a := append([]byte(nil), e.ans...)
			copy(a[:2], q[:2])
			return a, nil
		}
	}
	type res struct {
		a   []byte
		err error
	}
	ch := make(chan res, len(t.resolvers))
	start := func(r string) {
		go func() {
			var a []byte
			var err error
			if strings.HasPrefix(r, "doh:") {
				a, err = t.dnsDoH(q, strings.TrimPrefix(r, "doh:"))
			} else if strings.HasPrefix(r, "udp:") {
				a, err = t.dnsSocksUDP(q, strings.TrimPrefix(r, "udp:"))
			} else {
				a, err = t.dnsTCP(q, r)
			}
			ch <- res{a, err}
		}()
	}
	start(t.resolvers[0])
	running, next := 1, 1
	hedge := time.NewTimer(hedgeAfter)
	defer hedge.Stop()
	total := time.NewTimer(totalTO)
	defer total.Stop()
	var errs []string
	for running > 0 || next < len(t.resolvers) {
		select {
		case r := <-ch:
			running--
			if r.err == nil && poisoned(r.a) {
				r.err = errors.New("poisoned answer (filtering address)")
			}
			if r.err == nil {
				copy(r.a[:2], q[:2])
				if useCache && r.a[3]&0x0f == 0 && binary.BigEndian.Uint16(r.a[6:]) > 0 {
					t.cacheMu.Lock()
					if len(t.cache) > 2000 {
						t.cache = map[string]dnsCacheEnt{}
					}
					t.cache[key] = dnsCacheEnt{append([]byte(nil), r.a...), time.Now().Add(60 * time.Second)}
					t.cacheMu.Unlock()
				}
				return r.a, nil
			}
			errs = append(errs, r.err.Error())
			if next < len(t.resolvers) {
				start(t.resolvers[next])
				next++
				running++
			}
		case <-hedge.C:
			if next < len(t.resolvers) {
				start(t.resolvers[next])
				next++
				running++
			}
		case <-total.C:
			return nil, fmt.Errorf("dns via socks: timeout %v %s", totalTO, strings.Join(errs, "; "))
		}
	}
	return nil, errors.New("dns via socks: " + strings.Join(errs, "; "))
}

func (t *stun) onUDP(r *udp.ForwarderRequest) bool {
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		return true
	}
	c := gonet.NewUDPConn(&wq, ep)
	go func() {
		defer c.Close()
		buf := make([]byte, 4096)
		for {
			_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			if t.no6 {
				if a := emptyAAAA(q); a != nil {
					_, _ = c.Write(a)
					continue
				}
			}
			go func() {
				a, err := t.dnsQuery(q, true)
				if err != nil {
					debugf("dns: %v", err)
					return
				}
				_, _ = c.Write(a)
			}()
		}
	}()
	return true
}

// healthOpts: v1.8.3. The zero value is the pre-1.8.3 behaviour (all modes except Config + Psiphon).
type healthOpts struct {
	needFails    int           // NODATA also needs this many consecutive failed probes (0 = not required)
	probeTimeout time.Duration // per-probe timeout (0 = 12 s, first resolver 2.5 s ahead)
	maxInflight  int           // probes allowed in flight at once (0 = 1: a slow probe delays the next)
	anyRx        bool          // any relayed byte counts as liveness (else 16 KB steps)
	quietFails   bool          // log failed probes as WLOG instead of "FAILS n" (the app acts on NODATA only)
}

// health: same contract as Worker mode. "STATE up" on the first DNS probe or relay success; NODATA after `limit`
// without any success; "FAILS n" for every 3 failed probes while nothing else worked.
func (t *stun) health(limit time.Duration, stop <-chan struct{}) {
	o := t.ho
	start := time.Now()
	var lastGood, lastProbe, nodataAt time.Time
	up := false
	var lastRx uint64
	var inflight atomic.Int32
	var fails atomic.Int32
	var seq atomic.Uint32
	maxIn := int32(max(1, o.maxInflight))
	probeTO, hedge := 12*time.Second, 2500*time.Millisecond
	if o.probeTimeout > 0 {
		probeTO, hedge = o.probeTimeout, o.probeTimeout*3/10
	}
	probe := func() {
		defer inflight.Add(-1)
		s := time.Now()
		_, err := t.dnsQueryT(dnsQuestion("www.google.com", 1, uint16(seq.Add(1))), false, probeTO, hedge)
		ms := max64(time.Since(s).Milliseconds(), 1)
		if err == nil {
			t.probeOK.Store(time.Now().UnixNano())
			if f := fails.Swap(0); f > 0 || seq.Load() == 1 {
				if f > 0 {
					out("WLOG dns ok via socks %d ms (after %d failed probes)", ms, f)
				} else {
					out("WLOG dns ok via socks %d ms", ms)
				}
			}
			out("RTT %d", ms)
			return
		}
		f := fails.Add(1)
		t.slog("dnsfail", "dns probe fail #%d after %d ms: %s", f, ms, errLine(err))
		recent := func(ns int64) bool { return ns > 0 && time.Since(time.Unix(0, ns)) < limit }
		if !up && f%3 == 0 && !recent(t.dialOK.Load()) && !recent(t.relayOK.Load()) {
			if o.quietFails {
				out("WLOG %d probes failed in a row (no recent relay); waiting for the %v no-data window", f, limit)
			} else {
				out("FAILS %d", f/3)
			}
		}
	}
	tk := time.NewTicker(500 * time.Millisecond)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tk.C:
		}
		now := time.Now()
		if rx := t.rxApp.Load(); rx-lastRx >= 16*1024 {
			lastRx = rx
			lastGood = now
		}
		live := []int64{t.relayOK.Load(), t.probeOK.Load()}
		if o.anyRx {
			live = append(live, t.rxAt.Load())
		}
		for _, ns := range live {
			if ns > 0 && time.Unix(0, ns).After(lastGood) {
				lastGood = time.Unix(0, ns)
			}
		}
		if !up && !lastGood.IsZero() && now.Sub(lastGood) < limit {
			up = true
			out("WLOG up after %d ms", now.Sub(start).Milliseconds())
			out("STATE up")
		}
		every := 10 * time.Second
		if lastGood.IsZero() || now.Sub(lastGood) > 3*time.Second {
			every = 3 * time.Second
		}
		if inflight.Load() < maxIn && (lastProbe.IsZero() || now.Sub(lastProbe) >= every) {
			lastProbe = now
			inflight.Add(1)
			go probe()
		}
		ref := lastGood
		if ref.IsZero() {
			ref = start
		}
		if nodataAt.After(ref) {
			ref = nodataAt
		}
		if now.Sub(ref) > limit && (o.needFails <= 0 || int(fails.Load()) >= o.needFails) {
			if o.needFails > 0 {
				out("WLOG no data for %ds and %d probes failed in a row -> NODATA", int(now.Sub(ref).Seconds()), fails.Load())
			}
			out("NODATA %d %d", int(now.Sub(ref).Seconds()), int(now.Sub(start).Seconds()))
			nodataAt = now
			if up {
				up = false
				out("STATE down")
			}
		}
	}
}

// tolerantOpts: v1.8.5 -tolerant (Firefox mode): the v1.8.3 chain-mode health rules (3 failed probes in a row on
// top of the no-data window, overlapping probes, any relayed byte = liveness, no FAILS lines) without the chain-only
// IPv6 / private-destination refusals. The probe timeout is 8 s (DoH through the Firefox proxy needs a TLS handshake).
func tolerantOpts(ho healthOpts, set map[string]bool) healthOpts {
	if !set["needfails"] {
		ho.needFails = 3
	}
	if !set["probeto"] {
		ho.probeTimeout = 8 * time.Second
	}
	ho.maxInflight, ho.anyRx, ho.quietFails = 3, true, true
	return ho
}

func cmdSVPN(args []string) {
	fs := flag.NewFlagSet("svpn", flag.ExitOnError)
	sock := fs.String("sock", "", "unix socket path to receive TUN fd")
	socks := fs.String("socks", "", "local SOCKS5 server (the Aether core), e.g. 127.0.0.1:18080")
	noData := fs.Duration("nodata", 30*time.Second, "NODATA after this long without any successful data")
	mtu := fs.Int("mtu", 1280, "tunnel MTU")
	dnsUDP := fs.Bool("dnsudp", false, "v1.7: DNS via SOCKS5 UDP ASSOCIATE first (Firefox mode), DNS-over-TCP as hedge")
	chain := fs.Bool("chain", false, "v1.8.3 Config + Psiphon tuning: -nodata 50s -needfails 3 -probeto 5s -no6 -fastfail, overlapping probes, any rx = liveness")
	needFails := fs.Int("needfails", 0, "NODATA also needs this many consecutive failed DNS probes")
	probeTO := fs.Duration("probeto", 0, "per DNS probe timeout (0 = 12s)")
	no6 := fs.Bool("no6", false, "refuse IPv6 TCP at once (RST) and answer AAAA with no records")
	fastFail := fs.Bool("fastfail", false, "refuse private/reserved IPv4 destinations at once (RST)")
	tolerant := fs.Bool("tolerant", false, "v1.8.5 Firefox mode: chain-style stall tolerance (-nodata 50s -needfails 3 -probeto 8s, overlapping probes, any rx = liveness, no FAILS lines) without -no6/-fastfail")
	_ = fs.Parse(args)
	if *socks == "" {
		fail("-socks required")
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	ho := healthOpts{needFails: *needFails, probeTimeout: *probeTO}
	if *chain {
		if !set["nodata"] {
			*noData = 50 * time.Second
		}
		if !set["needfails"] {
			ho.needFails = 3
		}
		if !set["probeto"] {
			ho.probeTimeout = 5 * time.Second
		}
		if !set["no6"] {
			*no6 = true
		}
		if !set["fastfail"] {
			*fastFail = true
		}
		ho.maxInflight, ho.anyRx, ho.quietFails = 3, true, true
	} else if *tolerant {
		ho = tolerantOpts(ho, set)
		if !set["nodata"] {
			*noData = 50 * time.Second
		}
	}
	out("OPTS svpn socks=%s mtu=%d nodata=%v dnsudp=%v chain=%v tolerant=%v needfails=%d probeto=%v no6=%v fastfail=%v",
		*socks, *mtu, *noData, *dnsUDP, *chain, *tolerant, ho.needFails, ho.probeTimeout, *no6, *fastFail)
	fd, err := receiveFd(*sock)
	if err != nil {
		fail("tun fd: %v", err)
	}
	_ = syscall.SetNonblock(fd, false)
	dev := &fdDevice{fd: fd}
	out("STATE connecting")
	t, err := newSTun(*socks, dev, *mtu)
	if err != nil {
		fail("%v", err)
	}
	t.no6, t.fastFail, t.ho = *no6, *fastFail, ho
	if *dnsUDP {
		// v1.8.1: DoH on 443 first (the Firefox proxy refuses port 53), UDP ASSOCIATE and TCP/53 as hedges
		t.resolvers = []string{"doh:https://1.1.1.1/dns-query", "doh:https://8.8.8.8/dns-query", "udp:1.1.1.1:53", "1.1.1.1:53"}
	}
	go func() {
		for range time.Tick(time.Second) {
			out("STAT %d %d", dev.rx.Load(), dev.tx.Load())
		}
	}()
	go t.health(*noData, nil)
	if err := t.pump(); err != nil {
		fail("tun read: %v", err)
	}
}
