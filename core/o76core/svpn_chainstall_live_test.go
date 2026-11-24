package main

// v1.8.3 live stall reproduction for Config + Psiphon mode, with the real binaries:
//   libchain run (Xray SOCKS -> local Xray shadowsocks server -> internet, Psiphon over it) + o76core svpn -chain.
// The test plays the app: it feeds svpn a socketpair "TUN", generates app traffic (DNS + HTTPS) through it, and on
// NODATA sends "RECOVER" to libchain's stdin, as O76VpnService does. Stalls are made by SIGSTOP/SIGCONT of the
// local shadowsocks server (the ss leg black-holes, like the Iran log: SOCKS reads time out, then recover).
// Skipped unless O76_CHAIN_BIN (libchain), O76_SVPN_BIN (o76core), O76_SS_LINK and O76_SS_PID are set.
//   O76_STALLS="40,62" stall lengths in seconds (default), O76_CHAIN_PSI=false runs without Psiphon.
// v1.8.4 Bridge + Psiphon: O76_CHAIN_UPSTREAM=<proxy url> (instead of O76_SS_LINK) runs "libchain run -upstream"
// (Psiphon straight through that proxy, no Xray); O76_SS_PID is then the proxy's pid (the stall is SIGSTOP of it).

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
	"syscall"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

type lineLog struct {
	mu  sync.Mutex
	all []string
	t0  time.Time
}

func (l *lineLog) add(who, s string) {
	l.mu.Lock()
	l.all = append(l.all, who+" +"+strconv.FormatFloat(time.Since(l.t0).Seconds(), 'f', 1, 64)+"s "+s)
	l.mu.Unlock()
}

func (l *lineLog) count(sub string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, s := range l.all {
		if strings.Contains(s, sub) {
			n++
		}
	}
	return n
}

func TestChainStallLive(t *testing.T) {
	chainBin, svpnBin, link, ssPid := os.Getenv("O76_CHAIN_BIN"), os.Getenv("O76_SVPN_BIN"), os.Getenv("O76_SS_LINK"), os.Getenv("O76_SS_PID")
	upstream := os.Getenv("O76_CHAIN_UPSTREAM")
	if upstream != "" {
		link = upstream
	}
	if chainBin == "" || svpnBin == "" || link == "" || ssPid == "" {
		t.Skip("set O76_CHAIN_BIN, O76_SVPN_BIN, O76_SS_LINK, O76_SS_PID")
	}
	pid, _ := strconv.Atoi(ssPid)
	stalls := []int{40, 62}
	if s := os.Getenv("O76_STALLS"); s != "" {
		stalls = nil
		for _, f := range strings.Split(s, ",") {
			n, _ := strconv.Atoi(strings.TrimSpace(f))
			stalls = append(stalls, n)
		}
	}
	psi := os.Getenv("O76_CHAIN_PSI") != "false"
	dir := os.Getenv("O76_CHAIN_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	lf := filepath.Join(t.TempDir(), "run.link")
	os.WriteFile(lf, []byte(link), 0o600)
	lg := &lineLog{t0: time.Now()}
	defer func() {
		syscall.Kill(pid, syscall.SIGCONT)
		lg.mu.Lock()
		t.Logf("---- timeline ----\n%s", strings.Join(lg.all, "\n"))
		lg.mu.Unlock()
	}()

	// 1. libchain run
	cc := exec.Command(chainBin, "run", "-link", "@"+lf, "-psiphon="+strconv.FormatBool(psi), "-dir", dir, "-dns", "1.1.1.1")
	if upstream != "" {
		cc = exec.Command(chainBin, "run", "-upstream", "@"+lf, "-dir", dir, "-dns", "1.1.1.1")
	}
	cc.Env = append(os.Environ(), "CHAIN_WATCH_STDIN=1")
	cin, _ := cc.StdinPipe()
	cout, _ := cc.StdoutPipe()
	cc.Stderr = cc.Stdout
	if err := cc.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cin.Close(); cc.Process.Kill(); cc.Wait() }()
	chainLines := make(chan string, 4096)
	go func() {
		sc := bufio.NewScanner(cout)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			l := sc.Text()
			if strings.Contains(l, "[Warning]") {
				continue
			}
			lg.add("chain", l)
			chainLines <- l
		}
		lg.add("chain", "EXITED")
		close(chainLines)
	}()
	port := ""
	to := time.After(4 * time.Minute)
	for port == "" {
		select {
		case l, ok := <-chainLines:
			if !ok {
				t.Fatal("libchain exited before READY")
			}
			if strings.HasPrefix(l, "READY ") {
				port = strings.TrimSpace(l[6:])
			}
		case <-to:
			t.Fatal("libchain: no READY in 4 min")
		}
	}
	var recOK, recFail, chainDead int32
	var recMu sync.Mutex
	go func() {
		for l := range chainLines {
			recMu.Lock()
			if strings.HasPrefix(l, "RECOVER_OK") {
				recOK++
			} else if strings.HasPrefix(l, "RECOVER_FAIL") {
				recFail++
			}
			recMu.Unlock()
		}
		recMu.Lock()
		chainDead = 1
		recMu.Unlock()
	}()

	// 2. svpn -chain on a socketpair TUN
	sock := filepath.Join(t.TempDir(), "tun.sock")
	sc := exec.Command(svpnBin, "svpn", "-sock", sock, "-socks", "127.0.0.1:"+port, "-mtu", "1280", "-chain", "-nodata", "50s")
	sout, _ := sc.StdoutPipe()
	sc.Stderr = os.Stderr
	if err := sc.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { sc.Process.Kill(); sc.Wait() }()
	svpnLines := make(chan string, 4096)
	var nodata, stateUp, stateDown int32
	var stMu sync.Mutex
	go func() {
		s := bufio.NewScanner(sout)
		for s.Scan() {
			l := s.Text()
			if strings.HasPrefix(l, "STAT ") || strings.HasPrefix(l, "RTT ") {
				continue
			}
			lg.add("svpn", l)
			stMu.Lock()
			switch {
			case strings.HasPrefix(l, "NODATA "):
				nodata++
				// what O76VpnService.chainNoData does: partial restart inside libchain
				lg.add("app", "NODATA -> RECOVER (psiphon only; xray + svpn/tun kept)")
				io.WriteString(cin, "RECOVER\n")
			case l == "STATE up":
				stateUp++
			case l == "STATE down":
				stateDown++
			}
			stMu.Unlock()
			select {
			case svpnLines <- l:
			default:
			}
		}
	}()
	for time.Sleep(200 * time.Millisecond); ; time.Sleep(200 * time.Millisecond) {
		if _, err := os.Stat(sock); err == nil {
			break
		}
	}
	time.Sleep(300 * time.Millisecond)
	fds, _ := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	uc, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	uc.WriteMsgUnix([]byte{42}, syscall.UnixRights(fds[0]), nil)
	uc.Close()
	syscall.Close(fds[0])
	cs := clientStack(t, fds[1])
	upBy := time.Now().Add(60 * time.Second)
	for {
		stMu.Lock()
		u := stateUp
		stMu.Unlock()
		if u > 0 {
			break
		}
		if time.Now().After(upBy) {
			t.Fatal("svpn: no STATE up")
		}
		time.Sleep(200 * time.Millisecond)
	}

	// app traffic: one HTTPS request through the TUN every 5 s (resolved through the TUN's DNS too)
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
		var a [4]byte
		copy(a[:], ip.To4())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := gonet.DialContextTCP(ctx, cs, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(a), Port: 443}, ipv4.ProtocolNumber)
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
	var okN, failN int
	stopApp := make(chan struct{})
	appDone := make(chan struct{})
	go func() {
		defer close(appDone)
		for {
			select {
			case <-stopApp:
				return
			case <-time.After(5 * time.Second):
			}
			if err := fetch(); err != nil {
				failN++
				lg.add("app", "https fail: "+err.Error())
			} else {
				okN++
				lg.add("app", "https ok")
			}
		}
	}()
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
	waitOK("baseline", 30*time.Second)
	time.Sleep(10 * time.Second)

	for i, s := range stalls {
		stMu.Lock()
		nd0 := nodata
		stMu.Unlock()
		lg.add("test", "stall "+strconv.Itoa(i+1)+": SIGSTOP ss server for "+strconv.Itoa(s)+"s")
		syscall.Kill(pid, syscall.SIGSTOP)
		time.Sleep(time.Duration(s) * time.Second)
		syscall.Kill(pid, syscall.SIGCONT)
		lg.add("test", "stall "+strconv.Itoa(i+1)+": SIGCONT")
		rec := waitOK("after stall "+strconv.Itoa(i+1), 150*time.Second)
		stMu.Lock()
		nd := nodata - nd0
		stMu.Unlock()
		t.Logf("stall %d (%ds): NODATA %d time(s), data again %v after SIGCONT", i+1, s, nd, rec.Round(time.Second))
		time.Sleep(15 * time.Second)
	}
	close(stopApp)
	<-appDone
	recMu.Lock()
	defer recMu.Unlock()
	t.Logf("summary: app https ok=%d fail=%d, NODATA=%d, RECOVER_OK=%d, RECOVER_FAIL=%d, svpn STATE down=%d, libchain exited=%v (no full restart: the same libchain + svpn processes ran throughout)",
		okN, failN, nodata, recOK, recFail, stateDown, chainDead == 1)
	if chainDead == 1 {
		t.Fatal("libchain exited (a full restart would have been needed)")
	}
	if sc.ProcessState != nil {
		t.Fatal("svpn exited")
	}
}
