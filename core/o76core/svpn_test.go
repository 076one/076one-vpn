package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// fakeSocks is a minimal SOCKS5 (no auth, CONNECT) server that sends port-53 targets to dnsAddr and every
// other target to httpAddr, recording what was asked for.
type fakeSocks struct {
	ln                net.Listener
	httpAddr, dnsAddr string
	mu                sync.Mutex
	targets           []string
}

func (f *fakeSocks) serve() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			h := make([]byte, 2)
			if _, err := io.ReadFull(c, h); err != nil || h[0] != 5 {
				return
			}
			io.ReadFull(c, make([]byte, h[1]))
			c.Write([]byte{5, 0})
			r := make([]byte, 4)
			if _, err := io.ReadFull(c, r); err != nil || r[1] != 1 {
				return
			}
			var host string
			switch r[3] {
			case 1:
				b := make([]byte, 4)
				io.ReadFull(c, b)
				host = net.IP(b).String()
			case 4:
				b := make([]byte, 16)
				io.ReadFull(c, b)
				host = net.IP(b).String()
			case 3:
				l := make([]byte, 1)
				io.ReadFull(c, l)
				b := make([]byte, l[0])
				io.ReadFull(c, b)
				host = string(b)
			}
			pb := make([]byte, 2)
			io.ReadFull(c, pb)
			port := binary.BigEndian.Uint16(pb)
			tgt := net.JoinHostPort(host, itoa(int(port)))
			f.mu.Lock()
			f.targets = append(f.targets, tgt)
			f.mu.Unlock()
			up := f.httpAddr
			if port == 53 {
				up = f.dnsAddr
			}
			u, err := net.Dial("tcp", up)
			if err != nil {
				c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
				return
			}
			defer u.Close()
			c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
			go io.Copy(u, c)
			io.Copy(c, u)
		}(c)
	}
}

func itoa(i int) string { return fmtInt(i) }
func fmtInt(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
}

// tcpDNS answers every DNS-over-TCP query with one A record 93.184.216.34.
func tcpDNS(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var lb [2]byte
				if _, err := io.ReadFull(c, lb[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(lb[:]))
				io.ReadFull(c, q)
				a := append([]byte(nil), q...)
				a[2], a[3] = 0x81, 0x80
				binary.BigEndian.PutUint16(a[6:], 1)
				a = append(a, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34)
				m := make([]byte, 2+len(a))
				binary.BigEndian.PutUint16(m, uint16(len(a)))
				copy(m[2:], a)
				c.Write(m)
			}(c)
		}
	}()
	return ln.Addr().String()
}

type sockDev struct{ fd int }

func (d sockDev) ReadPacket(b []byte) (int, error) { return syscall.Read(d.fd, b) }
func (d sockDev) WritePacket(p []byte) error      { _, err := syscall.Write(d.fd, p); return err }

// clientStack is the "phone apps" side: a gVisor stack whose packets go through the socketpair to svpn.
func clientStack(t *testing.T, fd int) *stack.Stack {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(256, 1280, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal(err)
	}
	s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4([4]byte{10, 9, 0, 2}).WithPrefix()}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
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
			ep.InjectInbound(header.IPv4ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)}))
		}
	}()
	return s
}

func TestSVPNThroughSocks(t *testing.T) {
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello-svpn "+r.Host)
	}))
	defer hs.Close()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	fs := &fakeSocks{ln: ln, httpAddr: strings.TrimPrefix(hs.URL, "http://"), dnsAddr: tcpDNS(t)}
	go fs.serve()

	// capture STATE/WLOG lines
	r, w, _ := os.Pipe()
	oldOut := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = oldOut }()
	lines := make(chan string, 1000)
	go func() {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	st, err := newSTun(ln.Addr().String(), sockDev{fds[0]}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	go st.pump()
	stop := make(chan struct{})
	defer close(stop)
	go st.health(5*time.Second, stop)
	cs := clientStack(t, fds[1])

	// 1. TCP flow -> SOCKS CONNECT 10.0.0.5:80 -> local HTTP server
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, cs, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 0, 0, 5}), Port: 80}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("tcp dial: %v", err)
	}
	c.Write([]byte("GET / HTTP/1.0\r\nHost: example.test\r\n\r\n"))
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	body, _ := io.ReadAll(c)
	c.Close()
	if !strings.Contains(string(body), "hello-svpn example.test") {
		t.Fatalf("http through svpn: %q", body)
	}

	// 2. UDP DNS to the TUN resolver -> DNS-over-TCP through SOCKS
	uc, err := gonet.DialUDP(cs, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}), Port: 53}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	uc.Write(dnsQuestion("example.com", 1, 0x4242))
	uc.SetReadDeadline(time.Now().Add(10 * time.Second))
	ab := make([]byte, 1500)
	n, err := uc.Read(ab)
	uc.Close()
	if err != nil || n < 16 || binary.BigEndian.Uint16(ab) != 0x4242 || !strings.HasSuffix(string(ab[:n]), string([]byte{93, 184, 216, 34})) {
		t.Fatalf("dns answer: n=%d err=%v %x", n, err, ab[:n])
	}

	// 3. other UDP (QUIC) is refused: no answer, and it never reaches the SOCKS server
	qc, _ := gonet.DialUDP(cs, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{8, 8, 4, 4}), Port: 443}, ipv4.ProtocolNumber)
	qc.Write([]byte("quic-initial"))
	qc.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := qc.Read(ab); err == nil {
		t.Fatalf("udp/443 got an answer")
	}
	qc.Close()

	fs.mu.Lock()
	tg := strings.Join(fs.targets, ",")
	fs.mu.Unlock()
	if !strings.Contains(tg, "10.0.0.5:80") || !strings.Contains(tg, "1.1.1.1:53") || strings.Contains(tg, ":443") {
		t.Fatalf("socks targets %s", tg)
	}

	// 4. health reports STATE up
	deadline := time.After(8 * time.Second)
	for {
		select {
		case l := <-lines:
			if l == "STATE up" {
				t.Logf("socks targets: %s", tg)
				return
			}
		case <-deadline:
			t.Fatal("no STATE up")
		}
	}
}

func TestSVPNNodataWhenSocksDead(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // nothing listens: every dial fails
	r, w, _ := os.Pipe()
	oldOut := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = oldOut }()
	lines := make(chan string, 1000)
	go func() {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	fds, _ := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	st, _ := newSTun(addr, sockDev{fds[0]}, 1280)
	stop := make(chan struct{})
	defer close(stop)
	go st.health(3*time.Second, stop)
	var gotFails, gotNodata bool
	deadline := time.After(15 * time.Second)
	for !(gotFails && gotNodata) {
		select {
		case l := <-lines:
			gotFails = gotFails || strings.HasPrefix(l, "FAILS ")
			gotNodata = gotNodata || strings.HasPrefix(l, "NODATA ")
			t.Log(l)
			if l == "STATE up" {
				t.Fatal("STATE up with a dead SOCKS server")
			}
		case <-deadline:
			t.Fatalf("fails=%v nodata=%v", gotFails, gotNodata)
		}
	}
}

func TestAetherIdentity(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(k)
	cfg := `{"private_key":"` + base64.StdEncoding.EncodeToString(der) + `","id":"dev-1","access_token":"tok\"x","ipv4":"172.16.0.2","ipv6":"2606::1"}`
	b, err := aetherIdentity([]byte(cfg), time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`device_id = "dev-1"`, `access_token = "tok\"x"`, "cert_issued_at = 1700000000", `ipv4 = "172.16.0.2"`, "wg_peer_public_key = "} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in\n%s", want, s)
		}
	}
	cb, rest := pem.Decode([]byte(s[strings.Index(s, "-----BEGIN CERTIFICATE"):]))
	crt, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := pem.Decode(rest)
	pk, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !pk.(*ecdsa.PrivateKey).PublicKey.Equal(crt.PublicKey) || !pk.(*ecdsa.PrivateKey).Equal(k) {
		t.Fatal("cert/key do not match the WARP key")
	}
	if _, err := aetherIdentity([]byte(`{"id":"x"}`), time.Now()); err == nil {
		t.Fatal("empty identity accepted")
	}
}
