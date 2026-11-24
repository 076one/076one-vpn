// Test harness for "o76core wvpn" without a real TUN: a SOCK_DGRAM socketpair stands in for the Android TUN fd;
// the "phone apps" side is a userspace netstack (wireguard tun/netstack) whose packets go through the pair.
// It resolves names via 1.1.1.1 (UDP DNS -> handled by wvpn via the worker) and fetches URLs through the tunnel.
//
//	go run ./tools/wvpnharness -core /tmp/o76core -- -addr 127.0.0.1:8443 -host test.local -uuid U -insecure
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

func main() {
	core := flag.String("core", "/tmp/o76core", "core binary")
	urls := flag.String("urls", "http://www.gstatic.com/generate_204,https://www.google.com/,https://www.wikipedia.org/", "urls")
	wait := flag.Duration("wait", 0, "keep running this long after the fetches (watch health lines)")
	sub := flag.String("cmd", "wvpn", "core sub-command: wvpn | vpn")
	local := flag.String("local", "10.76.0.2", "local IPv4 of the app side (vpn: the WARP ipv4 from config.json)")
	refetch := flag.Duration("refetch", 0, "fetch the first url again every this often during -wait")
	flag.Parse()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		panic(err)
	}
	sock := filepath.Join(os.TempDir(), fmt.Sprintf("wh%d.sock", os.Getpid()))
	args := append([]string{*sub, "-sock", sock}, flag.Args()...)
	cmd := exec.Command(*core, args...)
	cmd.Env = append(os.Environ(), "O76_DEBUG="+os.Getenv("O76_DEBUG"))
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		panic(err)
	}
	defer cmd.Process.Kill()
	ready := make(chan struct{})
	up := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stdout)
		r, u := false, false
		for sc.Scan() {
			l := sc.Text()
			if !strings.HasPrefix(l, "STAT ") {
				fmt.Println("core:", l)
			}
			if l == "READY" && !r {
				r = true
				close(ready)
			}
			if l == "STATE up" && !u {
				u = true
				close(up)
			}
		}
	}()
	<-ready
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		panic(err)
	}
	if _, _, err := c.WriteMsgUnix([]byte{42}, syscall.UnixRights(fds[1]), nil); err != nil {
		panic(err)
	}
	c.Close()
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(*local)}, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, 1280)
	if err != nil {
		panic(err)
	}
	// netstack <-> socketpair
	go func() {
		bufs := [][]byte{make([]byte, 65536)}
		sizes := []int{0}
		for {
			n, err := tdev.Read(bufs, sizes, 0)
			if err != nil {
				return
			}
			for i := 0; i < n; i++ {
				_, _ = syscall.Write(fds[0], bufs[i][:sizes[i]])
			}
		}
	}()
	go func() {
		b := make([]byte, 65536)
		for {
			n, err := syscall.Read(fds[0], b)
			if err != nil {
				return
			}
			p := append([]byte(nil), b[:n]...)
			_, _ = tdev.Write([][]byte{p}, 0)
		}
	}()
	select {
	case <-up:
	case <-time.After(20 * time.Second):
		fmt.Println("HARNESS: no STATE up in 20 s")
	}
	cl := &http.Client{Timeout: 25 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) { return tnet.DialContext(ctx, network, addr) },
	}}
	okN := 0
	for _, u := range strings.Split(*urls, ",") {
		s := time.Now()
		resp, err := cl.Get(u)
		if err != nil {
			fmt.Printf("HARNESS FAIL %s: %v\n", u, err)
			continue
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		okN++
		fmt.Printf("HARNESS OK %s -> %d, %d bytes, %d ms\n", u, resp.StatusCode, n, time.Since(s).Milliseconds())
	}
	// UDP to a non-DNS port must be refused quickly (ICMP unreachable) — just make sure it does not hang the stack
	if uc, err := tnet.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("8.8.8.8:443")); err == nil {
		_, _ = uc.Write([]byte("quic?"))
		uc.Close()
	}
	fmt.Printf("HARNESS DONE %d/%d\n", okN, len(strings.Split(*urls, ",")))
	end := time.Now().Add(*wait)
	for *refetch > 0 && time.Now().Before(end) {
		time.Sleep(*refetch)
		u := strings.Split(*urls, ",")[0]
		s := time.Now()
		if resp, err := cl.Get(u); err == nil {
			n, _ := io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			fmt.Printf("HARNESS REFETCH OK %d %d bytes %d ms\n", resp.StatusCode, n, time.Since(s).Milliseconds())
		} else {
			fmt.Printf("HARNESS REFETCH FAIL %v\n", err)
		}
	}
	time.Sleep(time.Until(end))
}
