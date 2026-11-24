package main

// v1.8.3 Config + Psiphon (-chain) svpn behaviour: short stalls are tolerated, long ones give NODATA and then
// recover by themselves; IPv6 and private destinations fail at once; AAAA gets an empty answer.

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
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
)

// stallProxy forwards to target; while stalled it accepts connections and swallows them (like a black-holed
// upstream: SOCKS handshakes time out), exactly what the Iran log showed ("read ... i/o timeout").
type stallProxy struct {
	ln      net.Listener
	target  string
	stalled atomic.Bool
}

func (p *stallProxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		if p.stalled.Load() {
			go func() { time.Sleep(20 * time.Second); c.Close() }()
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			u, err := net.Dial("tcp", p.target)
			if err != nil {
				return
			}
			defer u.Close()
			go io.Copy(u, c)
			io.Copy(c, u)
		}(c)
	}
}

func captureOut(t *testing.T) chan string {
	r, w, _ := os.Pipe()
	oldOut := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = oldOut })
	lines := make(chan string, 4000)
	go func() {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	return lines
}

func chainOpts() healthOpts {
	return healthOpts{needFails: 3, probeTimeout: time.Second, maxInflight: 3, anyRx: true, quietFails: true}
}

func TestChainHealthToleratesShortStall(t *testing.T) {
	sln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer sln.Close()
	fs := &fakeSocks{ln: sln, httpAddr: "127.0.0.1:9", dnsAddr: tcpDNS(t)}
	go fs.serve()
	pln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer pln.Close()
	px := &stallProxy{ln: pln, target: sln.Addr().String()}
	go px.serve()
	lines := captureOut(t)

	fds, _ := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	st, err := newSTun(pln.Addr().String(), sockDev{fds[0]}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	st.ho = chainOpts()
	stop := make(chan struct{})
	defer close(stop)
	const limit = 8 * time.Second
	go st.health(limit, stop)

	expect := func(what string, pred func(string) bool, forbid func(string) bool, d time.Duration) {
		t.Helper()
		to := time.After(d)
		for {
			select {
			case l := <-lines:
				t.Log(l)
				if forbid != nil && forbid(l) {
					t.Fatalf("%s: unexpected %q", what, l)
				}
				if pred != nil && pred(l) {
					return
				}
			case <-to:
				if pred == nil {
					return
				}
				t.Fatalf("%s: timed out", what)
			}
		}
	}
	isNodata := func(l string) bool { return strings.HasPrefix(l, "NODATA") || strings.HasPrefix(l, "FAILS") }
	expect("up", func(l string) bool { return l == "STATE up" }, isNodata, 6*time.Second)

	// stall shorter than the window: probes fail, but no NODATA / FAILS / STATE down
	px.stalled.Store(true)
	expect("short stall", nil, func(l string) bool { return isNodata(l) || l == "STATE down" }, 6*time.Second)
	px.stalled.Store(false)
	expect("recovers", func(l string) bool { return strings.HasPrefix(l, "RTT ") }, isNodata, 8*time.Second)

	// a long stall gives NODATA once the window passed AND probes failed in a row, then recovers by itself
	px.stalled.Store(true)
	t0 := time.Now()
	expect("nodata", func(l string) bool { return strings.HasPrefix(l, "NODATA ") }, func(l string) bool { return strings.HasPrefix(l, "FAILS") }, 20*time.Second)
	if el := time.Since(t0); el < limit-time.Second {
		t.Fatalf("NODATA after %v, window is %v", el, limit)
	}
	px.stalled.Store(false)
	expect("up again", func(l string) bool { return l == "STATE up" }, nil, 10*time.Second)
}

// clientStack46 is the phone side with both IPv4 and IPv6.
func clientStack46(t *testing.T, fd int) *stack.Stack {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(256, 1280, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal(err)
	}
	s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4([4]byte{10, 9, 0, 2}).WithPrefix()}, stack.AddressProperties{})
	s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom16Slice(net.ParseIP("fd00:76::2").To16()).WithPrefix()}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	go func() {
		for {
			pkt := ep.ReadContext(context.Background())
			if pkt == nil {
				continue
			}
			v := pkt.ToView()
			pkt.DecRef()
			syscall.Write(fd, v.AsSlice())
			v.Release()
		}
	}()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := syscall.Read(fd, buf)
			if err != nil {
				return
			}
			p := append([]byte(nil), buf[:n]...)
			proto := header.IPv4ProtocolNumber
			if p[0]>>4 == 6 {
				proto = header.IPv6ProtocolNumber
			}
			ep.InjectInbound(proto, stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)}))
		}
	}()
	return s
}

func TestChainFastFail(t *testing.T) {
	sln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer sln.Close()
	fs := &fakeSocks{ln: sln, httpAddr: "127.0.0.1:9", dnsAddr: tcpDNS(t)}
	go fs.serve()
	fds, _ := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	st, err := newSTun(sln.Addr().String(), sockDev{fds[0]}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	st.no6, st.fastFail = true, true
	go st.pump()
	cs := clientStack46(t, fds[1])

	dial := func(addr tcpip.Address, proto tcpip.NetworkProtocolNumber, port uint16) (time.Duration, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		t0 := time.Now()
		c, err := gonet.DialContextTCP(ctx, cs, tcpip.FullAddress{NIC: 1, Addr: addr, Port: port}, proto)
		if c != nil {
			c.Close()
		}
		return time.Since(t0), err
	}
	v6 := tcpip.AddrFrom16Slice(net.ParseIP("2001:4860:4840:400::").To16())
	if d, err := dial(v6, ipv6.ProtocolNumber, 443); err == nil || d > time.Second {
		t.Fatalf("ipv6 dial: err=%v after %v (want refused at once)", err, d)
	} else {
		t.Logf("ipv6 refused in %v: %v", d, err)
	}
	for _, ip := range [][4]byte{{10, 10, 34, 35}, {192, 168, 1, 1}, {172, 20, 0, 1}, {169, 254, 1, 1}} {
		if d, err := dial(tcpip.AddrFrom4(ip), ipv4.ProtocolNumber, 443); err == nil || d > time.Second {
			t.Fatalf("private %v dial: err=%v after %v (want refused at once)", ip, err, d)
		}
	}
	fs.mu.Lock()
	tg := strings.Join(fs.targets, ",")
	fs.mu.Unlock()
	if tg != "" {
		t.Fatalf("refused destinations reached the SOCKS server: %s", tg)
	}
	if !reservedV4(net.IPv4(100, 64, 1, 1)) || reservedV4(net.IPv4(8, 8, 8, 8)) || reservedV4(net.IPv4(172, 32, 0, 1)) || reservedV4(net.IPv4(1, 1, 1, 1)) {
		t.Fatal("reservedV4 table")
	}
	// public IPv4 still goes through the SOCKS server
	if _, err := dial(tcpip.AddrFrom4([4]byte{93, 184, 216, 34}), ipv4.ProtocolNumber, 80); err != nil {
		t.Logf("public dial: %v (upstream is a dead port; only the SOCKS target matters)", err)
	}
	time.Sleep(300 * time.Millisecond)
	fs.mu.Lock()
	tg = strings.Join(fs.targets, ",")
	fs.mu.Unlock()
	if !strings.Contains(tg, "93.184.216.34:80") {
		t.Fatalf("public destination did not reach SOCKS: %q", tg)
	}

	// AAAA through the TUN resolver: empty NOERROR answer without touching the SOCKS server
	uc, err := gonet.DialUDP(cs, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}), Port: 53}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	uc.Write(dnsQuestion("www.google.com", 28, 0x5151))
	uc.SetReadDeadline(time.Now().Add(3 * time.Second))
	ab := make([]byte, 1500)
	n, err := uc.Read(ab)
	if err != nil || n < 12 || binary.BigEndian.Uint16(ab) != 0x5151 || ab[2]&0x80 == 0 || ab[3]&0x0f != 0 || binary.BigEndian.Uint16(ab[6:]) != 0 {
		t.Fatalf("AAAA answer: n=%d err=%v %x", n, err, ab[:n])
	}
	if emptyAAAA(dnsQuestion("www.google.com", 1, 1)) != nil {
		t.Fatal("A question must not be answered locally")
	}
}
