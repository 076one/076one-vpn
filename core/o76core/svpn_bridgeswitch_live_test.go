package main

// v1.8.5 live test of the Bridge + Psiphon stall switch, with the real binaries (libchain + o76core svpn). The test
// plays O76VpnService: warm-standby proxy check ("libchain ptest -real 0"), a refusing bridge skipped at connect time
// ("run -upstream … -uptries 1" -> CONFIG_ERR at once), then a stall of the current bridge (SIGSTOP of its proxy, left
// stopped): svpn -chain -nodata 40s reports NODATA, libchain's keep-alive ("KA n") has failed, so the app switches at
// once to the standby bridge: libchain + svpn are restarted on bridge B with the SAME "TUN" (socketpair end kept).
// Skipped unless O76_CHAIN_BIN, O76_SVPN_BIN, O76_BRIDGE_A, O76_BRIDGE_A_PID, O76_BRIDGE_B, O76_BRIDGE_REFUSED are set.

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func TestBridgeSwitchLive(t *testing.T) {
	chainBin, svpnBin := os.Getenv("O76_CHAIN_BIN"), os.Getenv("O76_SVPN_BIN")
	bA, bB, bR, aPid := os.Getenv("O76_BRIDGE_A"), os.Getenv("O76_BRIDGE_B"), os.Getenv("O76_BRIDGE_REFUSED"), os.Getenv("O76_BRIDGE_A_PID")
	if chainBin == "" || svpnBin == "" || bA == "" || bB == "" || bR == "" || aPid == "" {
		t.Skip("set O76_CHAIN_BIN, O76_SVPN_BIN, O76_BRIDGE_A, O76_BRIDGE_A_PID, O76_BRIDGE_B, O76_BRIDGE_REFUSED")
	}
	pidA, _ := strconv.Atoi(aPid)
	dir := os.Getenv("O76_CHAIN_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	lg := &lineLog{t0: time.Now()}
	defer func() {
		syscall.Kill(pidA, syscall.SIGCONT)
		lg.mu.Lock()
		t.Logf("---- timeline ----\n%s", strings.Join(lg.all, "\n"))
		lg.mu.Unlock()
	}()

	// 1. warm standby check: refused + B -> only B answers
	wf := filepath.Join(t.TempDir(), "warm.txt")
	os.WriteFile(wf, []byte(bR+"\n"+bB+"\n"), 0o600)
	out, _ := exec.Command(chainBin, "ptest", "-file", wf, "-real", "0", "-n", "2", "-hs", "6", "-dir", dir).CombinedOutput()
	lg.add("standby", strings.ReplaceAll(strings.TrimSpace(string(out)), "\n", " | "))
	if !strings.Contains(string(out), "PHS 1 ") || strings.Contains(string(out), "PHS 0 ") {
		t.Fatalf("standby check: want only B (index 1) to pass, got %s", out)
	}

	// 2. a refusing bridge fails its check at once (no retries) -> the app skips it
	rf := filepath.Join(t.TempDir(), "r.up")
	os.WriteFile(rf, []byte(bR), 0o600)
	t0 := time.Now()
	out, err := exec.Command(chainBin, "run", "-upstream", "@"+rf, "-uptries", "1", "-dir", dir, "-dns", "1.1.1.1").CombinedOutput()
	el := time.Since(t0)
	lg.add("refused", strings.ReplaceAll(strings.TrimSpace(string(out)), "\n", " | ")+" ("+el.Round(time.Millisecond).String()+")")
	if err == nil || !strings.Contains(string(out), "CONFIG_ERR") || !strings.Contains(string(out), "refused") || el > 5*time.Second {
		t.Fatalf("refused bridge: want CONFIG_ERR …refused within 5 s, got %v after %v: %s", err, el, out)
	}

	// 3. session on bridge A
	type sess struct {
		cc, sc        *exec.Cmd
		cin           io.WriteCloser
		ka            atomic.Int32
		nodata, upCnt atomic.Int32
	}
	var dupTun int
	start := func(name, url string, tunFd int) *sess {
		s := &sess{}
		lf := filepath.Join(t.TempDir(), name+".up")
		os.WriteFile(lf, []byte(url), 0o600)
		s.cc = exec.Command(chainBin, "run", "-upstream", "@"+lf, "-uptries", "1", "-keepalive", "15s", "-dir", dir, "-dns", "1.1.1.1")
		s.cc.Env = append(os.Environ(), "CHAIN_WATCH_STDIN=1")
		s.cin, _ = s.cc.StdinPipe()
		co, _ := s.cc.StdoutPipe()
		s.cc.Stderr = s.cc.Stdout
		if err := s.cc.Start(); err != nil {
			t.Fatal(err)
		}
		ready := make(chan string, 1)
		go func() {
			sc := bufio.NewScanner(co)
			for sc.Scan() {
				l := sc.Text()
				lg.add("chain-"+name, l)
				if strings.HasPrefix(l, "KA ") {
					n, _ := strconv.Atoi(strings.TrimSpace(l[3:]))
					s.ka.Store(int32(n))
				}
				if strings.HasPrefix(l, "READY ") {
					ready <- strings.TrimSpace(l[6:])
				}
			}
			lg.add("chain-"+name, "EXITED")
		}()
		var port string
		select {
		case port = <-ready:
		case <-time.After(4 * time.Minute):
			t.Fatalf("libchain on %s: no READY in 4 min", name)
		}
		sock := filepath.Join(t.TempDir(), name+".sock")
		s.sc = exec.Command(svpnBin, "svpn", "-sock", sock, "-socks", "127.0.0.1:"+port, "-mtu", "1280", "-chain", "-nodata", "40s")
		so, _ := s.sc.StdoutPipe()
		s.sc.Stderr = os.Stderr
		if err := s.sc.Start(); err != nil {
			t.Fatal(err)
		}
		go func() {
			sc := bufio.NewScanner(so)
			for sc.Scan() {
				l := sc.Text()
				if strings.HasPrefix(l, "STAT ") || strings.HasPrefix(l, "RTT ") {
					continue
				}
				lg.add("svpn-"+name, l)
				if strings.HasPrefix(l, "NODATA ") {
					s.nodata.Add(1)
				} else if l == "STATE up" {
					s.upCnt.Add(1)
				}
			}
		}()
		for i := 0; i < 100; i++ {
			if _, err := os.Stat(sock); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		time.Sleep(300 * time.Millisecond)
		uc, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		uc.WriteMsgUnix([]byte{42}, syscall.UnixRights(tunFd), nil)
		uc.Close()
		return s
	}
	stop := func(s *sess) {
		s.sc.Process.Kill()
		s.sc.Wait()
		s.cin.Close()
		s.cc.Process.Kill()
		s.cc.Wait()
	}
	fds, _ := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	dupTun, _ = syscall.Dup(fds[0]) // the app keeps the TUN fd across core restarts
	a := start("A", bA, fds[0])
	syscall.Close(fds[0])
	cs := clientStack(t, fds[1])
	var cur atomic.Pointer[sess]
	cur.Store(a)
	defer func() { stop(cur.Load()) }()

	fetch := func() error {
		dc, err := gonet.DialUDP(cs, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}), Port: 53}, ipv4.ProtocolNumber)
		if err != nil {
			return err
		}
		dc.Write(dnsQuestion("www.gstatic.com", 1, 0x7777))
		dc.SetReadDeadline(time.Now().Add(8 * time.Second))
		ab := make([]byte, 1500)
		n, err := dc.Read(ab)
		dc.Close()
		if err != nil {
			return err
		}
		ip := firstA(ab[:n])
		if ip == nil {
			return io.ErrUnexpectedEOF
		}
		var x [4]byte
		copy(x[:], ip.To4())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := gonet.DialContextTCP(ctx, cs, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(x), Port: 443}, ipv4.ProtocolNumber)
		if err != nil {
			return err
		}
		tc := tls.Client(c, &tls.Config{ServerName: "www.gstatic.com"})
		defer tc.Close()
		tc.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := tc.Write([]byte("GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n")); err != nil {
			return err
		}
		b, _ := io.ReadAll(tc)
		if !strings.Contains(string(b), " 204 ") {
			return io.ErrUnexpectedEOF
		}
		return nil
	}
	waitOK := func(what string, d time.Duration) time.Duration {
		t0 := time.Now()
		for time.Since(t0) < d {
			if fetch() == nil {
				lg.add("test", what+": data flows after "+time.Since(t0).Round(time.Second).String())
				return time.Since(t0)
			}
			time.Sleep(2 * time.Second)
		}
		t.Fatalf("%s: no data within %v", what, d)
		return 0
	}
	waitOK("baseline via A", 60*time.Second)

	// 4. stall A for good; app traffic keeps trying; on NODATA + failed keep-alive -> switch to B at once
	var mu sync.Mutex
	stopApp := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopApp:
				return
			case <-time.After(5 * time.Second):
			}
			mu.Lock()
			err := fetch()
			mu.Unlock()
			if err != nil {
				lg.add("app", "https fail: "+err.Error())
			}
		}
	}()
	lg.add("test", "SIGSTOP bridge A proxy (stays stopped)")
	stallAt := time.Now()
	syscall.Kill(pidA, syscall.SIGSTOP)
	for a.nodata.Load() == 0 {
		if time.Since(stallAt) > 90*time.Second {
			t.Fatal("no NODATA within 90 s of the stall")
		}
		time.Sleep(200 * time.Millisecond)
	}
	ndAfter := time.Since(stallAt)
	kaf := a.ka.Load()
	lg.add("app", "NODATA after "+ndAfter.Round(time.Second).String()+", keep-alive fails="+strconv.Itoa(int(kaf)))
	if kaf < 1 {
		t.Fatalf("keep-alive should have failed by NODATA (%v), KA=%d", ndAfter, kaf)
	}
	lg.add("app", "stall switch -> bridge B (warm standby), TUN kept")
	swAt := time.Now()
	stop(a)
	close(stopApp)
	b := start("B", bB, dupTun)
	cur.Store(b)
	syscall.Close(dupTun)
	readyIn := time.Since(swAt)
	mu.Lock()
	rec := waitOK("after switch to B", 120*time.Second)
	mu.Unlock()
	t.Logf("NODATA %v after the stall (window 40 s + 3 failed probes), keep-alive fails %d; bridge B libchain READY %v after the switch, data via B %v later; total stall->data %v",
		ndAfter.Round(time.Second), kaf, readyIn.Round(100*time.Millisecond), rec.Round(time.Second), time.Since(stallAt).Round(time.Second))
	if ndAfter > 75*time.Second {
		t.Fatalf("switch decision too late: %v", ndAfter)
	}
}
