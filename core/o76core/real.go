// Real end-to-end checks: data actually flowing through the MASQUE tunnel, not just a TLS handshake.
//   - realOne: tunnel into a userspace netstack, GET cdn-cgi/trace (warp=on), a second GET on the same
//     connection = real round-trip time, then a download (default 250 KB) = real throughput.
//   - probeDev (vpn mode): injects a tiny DNS query to 1.1.1.1 into the tunnel every few seconds and swallows
//     the answer -> real in-tunnel RTT ("RTT ms") and "NODATA s" when nothing comes back.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const traceURL = "https://www.cloudflare.com/cdn-cgi/trace"

type realResult struct {
	warp    string
	firstMs int64 // first request (tunnel up + TCP + TLS inside the tunnel)
	rttMs   int64 // second request on the same connection
	kbps    int64 // download throughput, KB/s
	dlBytes int64
	colo    string
	err     error
	stage   string
}

func mkTunnelCfg(useH2 bool, ep, sni string, dev api.TunnelDevice) (api.MaintainTunnelConfig, error) {
	var addr net.Addr
	if useH2 {
		a, err := net.ResolveTCPAddr("tcp", ep)
		if err != nil {
			return api.MaintainTunnelConfig{}, err
		}
		addr = a
	} else {
		a, err := net.ResolveUDPAddr("udp", ep)
		if err != nil {
			return api.MaintainTunnelConfig{}, err
		}
		addr = a
	}
	return api.MaintainTunnelConfig{
		TLSConfig:         buildTLS(sni),
		KeepalivePeriod:   15 * time.Second,
		Endpoint:          addr,
		Device:            dev,
		MTU:               dpi.mtu,
		ReconnectDelay:    1 * time.Second,
		AlwaysReconnect:   true,
		UseHTTP2:          useH2,
		InitialPacketSize: uint16(quicPacketSize),
	}, nil
}

func localAddrs() []netip.Addr {
	var local []netip.Addr
	if v4, err := netip.ParseAddr(config.AppConfig.IPv4); err == nil {
		local = append(local, v4)
	}
	// IPv6 needs an MTU of at least 1280 (same rule as the Android TUN)
	if v6, err := netip.ParseAddr(config.AppConfig.IPv6); err == nil && dpi.mtu >= 1280 {
		local = append(local, v6)
	}
	return local
}

// realOne brings up a private tunnel to proto/ep/sni and measures real data through it.
// The measurement runs in its own goroutine: a stalled tunnel can leave gVisor blocked on a full
// queue (even Close blocks), so the caller simply stops waiting at the deadline.
func realOne(proto, ep, sni string, timeout time.Duration, dlBytes int) realResult {
	return realOneVia(proto, ep, sni, timeout, dlBytes, nil)
}

// realOneVia is realOne through an upstream proxy (nil = global settings).
func realOneVia(proto, ep, sni string, timeout time.Duration, dlBytes int, b *bridge) realResult {
	ch := make(chan realResult, 1)
	stage := &atomic.Value{}
	stage.Store("start")
	go func() { ch <- realOneInner(proto, ep, sni, timeout, dlBytes, stage, b) }()
	select {
	case r := <-ch:
		return r
	case <-time.After(timeout + time.Second):
		return realResult{stage: stage.Load().(string), err: fmt.Errorf("timeout: no data through tunnel")}
	}
}

func realOneInner(proto, ep, sni string, timeout time.Duration, dlBytes int, stage *atomic.Value, b *bridge) realResult {
	r := realResult{stage: "netstack"}
	dns := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}
	tdev, tnet, err := netstack.CreateNetTUN(localAddrs(), dns, dpi.mtu)
	if err != nil {
		r.err = err
		return r
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	tctx := ctx
	if dpi.bridge != nil {
		proto = "h2"
	}
	if b != nil {
		proto = "h2"
		tctx = api.WithH2Dial(ctx, bridgeDialer(b))
	}
	cfg, err := mkTunnelCfg(proto != "h3", ep, sni, api.NewNetstackAdapter(tdev))
	if err != nil {
		r.err = err
		return r
	}
	done := make(chan struct{})
	go func() { api.MaintainTunnel(tctx, cfg); close(done) }()
	defer func() {
		cancel()
		// tdev is deliberately not closed: closing it while netstack's resolver goroutines are still
		// running panics (send on closed channel). realtest is a short-lived process.
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tnet.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 2,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	get := func(url string, limit int64) ([]byte, int64, error) {
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
		return b, time.Since(start).Milliseconds(), err
	}
	r.stage = "trace"
	stage.Store(r.stage)
	start := time.Now()
	var body []byte
	for {
		body, _, err = get(traceURL, 8192)
		if err == nil || ctx.Err() != nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err != nil {
		r.err = err
		return r
	}
	r.firstMs = time.Since(start).Milliseconds()
	for _, line := range strings.Split(string(body), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			switch k {
			case "warp":
				r.warp = v
			case "colo":
				r.colo = v
			}
		}
	}
	r.stage = "rtt"
	stage.Store(r.stage)
	if _, ms, err := get(traceURL, 8192); err == nil {
		r.rttMs = ms
	} else {
		r.err = err
		return r
	}
	if dlBytes > 0 {
		r.stage = "download"
		stage.Store(r.stage)
		b, ms, err := get(fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", dlBytes), int64(dlBytes)+1)
		r.dlBytes = int64(len(b))
		if ms < 1 {
			ms = 1
		}
		r.kbps = r.dlBytes * 1000 / 1024 / ms
		if err != nil {
			r.err = err
			return r
		}
		if r.dlBytes < int64(dlBytes)*9/10 {
			r.err = fmt.Errorf("short download %d/%d", r.dlBytes, dlBytes)
			return r
		}
	}
	r.stage = "ok"
	return r
}

func (r realResult) ok() bool { return r.err == nil && (r.warp == "on" || r.warp == "plus") }

// realtest -eps "h2|ip:port|sni;..." -> "REAL proto ep sni rttMs kbps firstMs colo" | "RFAIL proto ep sni stage reason"
func cmdRealtest(args []string) {
	fs := flag.NewFlagSet("realtest", flag.ExitOnError)
	cfgPath := fs.String("c", "config.json", "config path")
	eps := fs.String("eps", "", "proto|ip:port|sni;...")
	timeout := fs.Duration("t", 15*time.Second, "per endpoint timeout")
	dl := fs.Int("dl", 250000, "download size in bytes (0 = skip)")
	conc := fs.Int("n", 4, "parallel tests")
	addDPIFlags(fs)
	_ = fs.Parse(args)
	runPostParse()
	applyDPI()
	loadCfg(*cfgPath)
	quietLog.Store(true)
	var targets []target
	for _, item := range strings.Split(*eps, ";") {
		p := strings.Split(strings.TrimSpace(item), "|")
		if len(p) == 3 {
			targets = append(targets, target{p[0], p[1], p[2]})
		}
	}
	if len(targets) == 0 {
		fail("no endpoints")
	}
	ch := make(chan target)
	var wg sync.WaitGroup
	var okN int32
	for w := 0; w < *conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range ch {
				r := realOne(t.proto, t.ep, t.sni, *timeout, *dl)
				if r.ok() {
					atomic.AddInt32(&okN, 1)
					out("REAL %s %s %s %d %d %d %s", t.proto, t.ep, t.sni, max64(r.rttMs, 1), r.kbps, r.firstMs, r.colo)
				} else {
					reason := "warp=" + r.warp
					if r.err != nil {
						reason = r.err.Error()
					}
					reason = strings.ReplaceAll(reason, "\n", " ")
					out("RFAIL %s %s %s %s %s", t.proto, t.ep, t.sni, r.stage, reason)
				}
			}
		}()
	}
	for _, t := range targets {
		ch <- t
	}
	close(ch)
	wg.Wait()
	out("DONE %d", okN)
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// ---------------- in-tunnel probe for vpn mode ----------------

const probePort = 53531

type probeDev struct {
	d       *fdDevice
	pkts    chan []byte
	inject  chan []byte
	errc    chan error
	src     [4]byte
	seq     atomic.Uint32
	sentAt  sync.Map // txid -> time.Time
	lastRTT atomic.Int64
	gotAt   atomic.Int64 // unix nanos of last probe answer
	pool    sync.Pool
}

func newProbeDev(d *fdDevice, src netip.Addr) *probeDev {
	p := &probeDev{d: d, pkts: make(chan []byte, 256), inject: make(chan []byte, 4), errc: make(chan error, 1)}
	p.src = src.As4()
	p.pool.New = func() interface{} { return make([]byte, 65536) }
	go func() {
		for {
			buf := p.pool.Get().([]byte)
			n, err := d.ReadPacket(buf)
			if err != nil {
				p.errc <- err
				return
			}
			p.pkts <- buf[:n]
		}
	}()
	return p
}

func (p *probeDev) ReadPacket(buf []byte) (int, error) {
	select {
	case b := <-p.inject:
		return copy(buf, b), nil
	case b := <-p.pkts:
		n := copy(buf, b)
		p.pool.Put(b[:cap(b)])
		return n, nil
	case err := <-p.errc:
		p.errc <- err
		return 0, err
	}
}

func (p *probeDev) WritePacket(pkt []byte) error {
	// swallow answers to our probe: IPv4/UDP from 1.1.1.1:53 to probePort
	if len(pkt) >= 28 && pkt[0]>>4 == 4 && pkt[9] == 17 {
		ihl := int(pkt[0]&0x0f) * 4
		if len(pkt) >= ihl+12 && binary.BigEndian.Uint16(pkt[ihl:]) == 53 && binary.BigEndian.Uint16(pkt[ihl+2:]) == probePort {
			id := uint32(binary.BigEndian.Uint16(pkt[ihl+8:]))
			if v, ok := p.sentAt.LoadAndDelete(id); ok {
				rtt := time.Since(v.(time.Time)).Milliseconds()
				if rtt < 1 {
					rtt = 1
				}
				p.lastRTT.Store(rtt)
				p.gotAt.Store(time.Now().UnixNano())
				out("RTT %d", rtt)
			}
			return nil
		}
	}
	return p.d.WritePacket(pkt)
}

// sendProbe injects a DNS A query for www.cloudflare.com to 1.1.1.1.
func (p *probeDev) sendProbe() {
	id := uint16(p.seq.Add(1))
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split("www.cloudflare.com", ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	udpLen := 8 + len(q)
	pkt := make([]byte, 20+udpLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:], id)
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], p.src[:])
	copy(pkt[16:20], []byte{1, 1, 1, 1})
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(pkt[10:], ^uint16(sum))
	binary.BigEndian.PutUint16(pkt[20:], probePort)
	binary.BigEndian.PutUint16(pkt[22:], 53)
	binary.BigEndian.PutUint16(pkt[24:], uint16(udpLen)) // checksum 0 = none (IPv4)
	copy(pkt[28:], q)
	p.sentAt.Store(uint32(id), time.Now())
	select {
	case p.inject <- pkt:
	default:
	}
}
