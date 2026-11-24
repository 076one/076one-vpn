package main

// Live smoke test of the real o76core binary in svpn mode against a running SOCKS5 server (the Aether core).
// Skipped unless O76_SVPN_BIN (o76core binary) and O76_SVPN_SOCKS (127.0.0.1:PORT) are set. The "TUN" is one end of
// a SOCK_DGRAM socketpair handed to the binary over -sock exactly as the app does (SCM_RIGHTS); the other end is a
// gVisor stack playing the phone's apps: UDP DNS, plain HTTP and HTTPS go through TUN -> svpn -> SOCKS -> tunnel.

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func TestSVPNLiveBinary(t *testing.T) {
	bin, socks := os.Getenv("O76_SVPN_BIN"), os.Getenv("O76_SVPN_SOCKS")
	if bin == "" || socks == "" {
		t.Skip("set O76_SVPN_BIN and O76_SVPN_SOCKS")
	}
	sock := filepath.Join(t.TempDir(), "tun.sock")
	cmd := exec.Command(bin, "svpn", "-sock", sock, "-socks", socks, "-nodata", "30s", "-mtu", "1280")
	cmd.Env = append(os.Environ(), "O76_WATCH_STDIN=1")
	stdin, _ := cmd.StdinPipe()
	defer stdin.Close()
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	fds, _ := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	lines := make(chan string, 4096)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	var all []string
	wait := func(pred func(string) bool, d time.Duration) string {
		to := time.After(d)
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					t.Fatalf("svpn exited; output:\n%s", strings.Join(all, "\n"))
				}
				all = append(all, l)
				if !strings.HasPrefix(l, "STAT ") {
					t.Logf("svpn: %s", l)
				}
				if pred(l) {
					return l
				}
			case <-to:
				t.Fatalf("timeout; output:\n%s", strings.Join(all, "\n"))
			}
		}
	}
	wait(func(l string) bool { return l == "READY" }, 10*time.Second)
	uc, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := uc.WriteMsgUnix([]byte{42}, syscall.UnixRights(fds[0]), nil); err != nil {
		t.Fatal(err)
	}
	uc.Close()
	syscall.Close(fds[0])
	cs := clientStack(t, fds[1])
	wait(func(l string) bool { return l == "STATE up" }, 30*time.Second)

	// 1. DNS (UDP/53 in the TUN -> DNS-over-TCP through SOCKS)
	dc, _ := gonet.DialUDP(cs, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}), Port: 53}, ipv4.ProtocolNumber)
	dc.Write(dnsQuestion("www.cloudflare.com", 1, 0x1234))
	dc.SetReadDeadline(time.Now().Add(15 * time.Second))
	ab := make([]byte, 1500)
	n, err := dc.Read(ab)
	dc.Close()
	if err != nil {
		t.Fatalf("dns: %v", err)
	}
	ip := firstA(ab[:n])
	if ip == nil {
		t.Fatalf("no A record: %x", ab[:n])
	}
	t.Logf("DNS www.cloudflare.com -> %s", ip)
	dial := func(ip net.IP, port uint16) net.Conn {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		var a [4]byte
		copy(a[:], ip.To4())
		c, err := gonet.DialContextTCP(ctx, cs, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(a), Port: port}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("tcp %s:%d: %v", ip, port, err)
		}
		return c
	}
	// 2. plain HTTP: Cloudflare trace says whether the exit is WARP
	c := dial(ip, 80)
	c.Write([]byte("GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n"))
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	body, _ := io.ReadAll(c)
	c.Close()
	if !strings.Contains(string(body), "warp=on") {
		t.Fatalf("trace: %q", body)
	}
	for _, l := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(l, "ip=") || strings.HasPrefix(l, "colo=") || strings.HasPrefix(l, "warp=") || strings.HasPrefix(l, "loc=") {
			t.Logf("trace %s", strings.TrimSpace(l))
		}
	}
	// 3. HTTPS (TLS end to end through TUN -> svpn -> SOCKS -> WARP)
	tc := tls.Client(dial(ip, 443), &tls.Config{ServerName: "www.cloudflare.com"})
	tc.SetDeadline(time.Now().Add(20 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("tls: %v", err)
	}
	tc.Write([]byte("GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n"))
	body, _ = io.ReadAll(tc)
	tc.Close()
	if !strings.Contains(string(body), "warp=on") {
		t.Fatalf("https trace: %q", body)
	}
	t.Logf("HTTPS ok (%d bytes, cert verified for www.cloudflare.com)", len(body))
	// 4. a 2 MB HTTPS download from speed.cloudflare.com (resolved through the tunnel too)
	dc, _ = gonet.DialUDP(cs, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}), Port: 53}, ipv4.ProtocolNumber)
	dc.Write(dnsQuestion("speed.cloudflare.com", 1, 0x2345))
	dc.SetReadDeadline(time.Now().Add(15 * time.Second))
	n, _ = dc.Read(ab)
	dc.Close()
	sip := firstA(ab[:n])
	if sip == nil {
		t.Fatalf("speed.cloudflare.com: no A")
	}
	s := time.Now()
	sc := tls.Client(dial(sip, 443), &tls.Config{ServerName: "speed.cloudflare.com"})
	sc.SetDeadline(time.Now().Add(60 * time.Second))
	sc.Write([]byte("GET /__down?bytes=2000000 HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: o76test\r\nConnection: close\r\n\r\n"))
	nn, err := io.Copy(io.Discard, sc)
	sc.Close()
	ms := time.Since(s).Milliseconds()
	if nn < 2000000 {
		t.Fatalf("download %d bytes: %v", nn, err)
	}
	t.Logf("HTTPS download speed.cloudflare.com (%s): %d bytes in %d ms = %d KB/s", sip, nn, ms, nn*1000/1024/max64(ms, 1))
	wait(func(l string) bool { return strings.HasPrefix(l, "STAT ") && l != "STAT 0 0" }, 5*time.Second)
	t.Logf("last STAT: %s", func() string {
		for i := len(all) - 1; i >= 0; i-- {
			if strings.HasPrefix(all[i], "STAT ") {
				return all[i]
			}
		}
		return ""
	}())
}

// firstA returns the first A record of a DNS answer.
func firstA(m []byte) net.IP {
	if len(m) < 12 {
		return nil
	}
	qd, an := int(binary.BigEndian.Uint16(m[4:])), int(binary.BigEndian.Uint16(m[6:]))
	p := 12
	skip := func() {
		for p < len(m) {
			l := int(m[p])
			if l == 0 {
				p++
				return
			}
			if l&0xc0 == 0xc0 {
				p += 2
				return
			}
			p += 1 + l
		}
	}
	for i := 0; i < qd; i++ {
		skip()
		p += 4
	}
	for i := 0; i < an && p+10 <= len(m); i++ {
		skip()
		typ := binary.BigEndian.Uint16(m[p:])
		rdl := int(binary.BigEndian.Uint16(m[p+8:]))
		p += 10
		if typ == 1 && rdl == 4 && p+4 <= len(m) {
			return net.IP(m[p : p+4])
		}
		p += rdl
	}
	return nil
}
