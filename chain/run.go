// v1.8.3: "run" with in-process recovery. The app (or libchain itself, when the Psiphon controller exits) can
// restart only the Psiphon layer, keeping Xray (and its SOCKS port) and the local SOCKS port that o76core svpn
// dials, so the VPN TUN never drops. Control lines on stdin (CHAIN_WATCH_STDIN=1):
//
//	RECOVER        check the config (Xray) leg, restart Xray in-process only if it fails, then restart the Psiphon
//	               controller in-process on the same SOCKS port; answers "RECOVER_OK ms" or "RECOVER_FAIL reason"
//	PSI_RESTART    same as RECOVER
//	XRAY_RESTART   restart only the Xray instance on the same port ("RECOVER_OK"/"RECOVER_FAIL")
//	PING           "PONG tunnels"
//
// Extra output lines: PSI_TUNNELS n (Psiphon's own tunnel count; 0 = it lost the tunnel and reconnects by itself),
// WLOG text (recovery steps, keep-alive results).
package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/xtls/xray-core/core"
	"golang.org/x/net/proxy"
)

var ctlCh = make(chan string, 8)

// readControl feeds stdin lines to the run loop; EOF (the app died) ends the process.
func readControl(r io.Reader) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		cmd := strings.ToUpper(strings.TrimSpace(sc.Text()))
		if cmd == "" {
			continue
		}
		select {
		case ctlCh <- cmd:
		default:
			say("WLOG control: busy, dropped %s", cmd)
		}
	}
	os.Exit(0)
}

// addKeepAlive turns on TCP keep-alive (idle 20 s, interval 10 s) on the config's outbound socket(s), so NAT / DPI
// idle timers on the ss/vless leg see traffic; existing sockopt values from the link win. Xray applies these to TCP
// sockets only, so QUIC/xhttp-h3 links are unaffected.
func addKeepAlive(ob map[string]any) {
	ss, _ := ob["streamSettings"].(map[string]any)
	if ss == nil {
		ss = map[string]any{}
		ob["streamSettings"] = ss
	}
	so, _ := ss["sockopt"].(map[string]any)
	if so == nil {
		so = map[string]any{}
		ss["sockopt"] = so
	}
	if _, ok := so["tcpKeepAliveIdle"]; !ok {
		so["tcpKeepAliveIdle"] = 20
	}
	if _, ok := so["tcpKeepAliveInterval"]; !ok {
		so["tcpKeepAliveInterval"] = 10
	}
}

type psiNotice struct {
	Data map[string]any `json:"data"`
	Type string         `json:"noticeType"`
}

// psiRunner owns the Psiphon controller; the config, notice writer and data store are set up once per process,
// controllers can be stopped and started again (same local SOCKS port, same server-affinity data store).
type psiRunner struct {
	config     *psiphon.Config
	dir        string
	cancel     context.CancelFunc
	done       chan struct{}
	upCh       chan struct{}
	failCh     chan error
	exited     chan error
	expectStop atomic.Bool
	tunnels    atomic.Int32
	lastUpErr  atomic.Value
}

func (p *psiRunner) upErr() string {
	s, _ := p.lastUpErr.Load().(string)
	return s
}

func newPsi(dir string, upstreamURL string, socksPort int, region string, timeoutS, pool int, networkID string) (*psiRunner, error) {
	dir, _ = filepath.Abs(filepath.Join(dir, "psiphon"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	timeout := timeoutS
	pause := 1             // seconds between establish rounds (default 2)
	kaMin, kaMax := 20000, 25000 // SSH keep-alive through the whole chain when idle (default 60-120 s)
	kaTimeout := 15000     // a keep-alive unanswered this long = tunnel lost -> Psiphon re-establishes (default 30 s)
	if pool < 1 {
		pool = 1
	}
	config := &psiphon.Config{
		EgressRegion:                            region,
		ListenInterface:                         "",
		LocalSocksProxyPort:                     socksPort,
		UpstreamProxyURL:                        upstreamURL,
		DisableLocalHTTPProxy:                   true,
		PropagationChannelId:                    "FFFFFFFFFFFFFFFF",
		SponsorId:                               "FFFFFFFFFFFFFFFF",
		RemoteServerListDownloadFilename:        "remote_server_list",
		RemoteServerListSignaturePublicKey:      "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=",
		RemoteServerListUrl:                     "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed",
		NetworkID:                               networkID,
		ClientPlatform:                          "Android_076one",
		AllowDefaultDNSResolverWithBindToDevice: true,
		EstablishTunnelTimeoutSeconds:           &timeout,
		EstablishTunnelPausePeriodSeconds:       &pause,
		TunnelPoolSize:                          pool, // warm standby: port forwards keep flowing on the 2nd tunnel
		SSHKeepAlivePeriodMinMilliseconds:       &kaMin,
		SSHKeepAlivePeriodMaxMilliseconds:       &kaMax,
		SSHKeepAlivePeriodicTimeoutMilliseconds: &kaTimeout,
		DataRootDirectory:                       dir, // app files dir (not cache): server affinity survives restarts
	}
	if err := config.Commit(true); err != nil {
		return nil, fmt.Errorf("config: %v", err)
	}
	p := &psiRunner{config: config, dir: dir, upCh: make(chan struct{}, 1), failCh: make(chan error, 1), exited: make(chan error, 1)}
	p.lastUpErr.Store("")
	psiphon.SetNoticeWriter(psiphon.NewNoticeReceiver(func(b []byte) {
		var n psiNotice
		if json.Unmarshal(b, &n) != nil {
			return
		}
		switch n.Type {
		case "Tunnels":
			c, _ := n.Data["count"].(float64)
			old := p.tunnels.Swap(int32(c))
			if int32(c) != old {
				say("PSI_TUNNELS %d", int(c))
				if c == 0 && old > 0 && !p.expectStop.Load() {
					say("WLOG psiphon lost its tunnel(s); psiphon re-establishes by itself")
				}
			}
			if c > 0 {
				select {
				case p.upCh <- struct{}{}:
				default:
				}
			}
		case "EstablishTunnelTimeout":
			select {
			case p.failCh <- errors.New("no Psiphon server reached in time" + suffix(p.upErr())):
			default:
			}
		case "UpstreamProxyError":
			msg, _ := n.Data["message"].(string)
			if msg != p.upErr() {
				p.lastUpErr.Store(msg)
				say("PSI_UPSTREAM_ERR %s", oneLine(msg))
			}
		case "ClientRegion":
			if r, _ := n.Data["region"].(string); r != "" {
				say("PSI_REGION %s", r)
			}
		case "ConnectedServerRegion": // v1.8.4: the exit region (ActiveTunnel is diagnostic-only and has none)
			if r, _ := n.Data["serverRegion"].(string); r != "" {
				say("PSI_ACTIVE %s", r)
			}
		case "ConnectingServer":
			say("PSI_CONNECTING %v", n.Data["region"])
		}
	}))
	if err := psiphon.OpenDataStore(config); err != nil {
		return nil, fmt.Errorf("data store: %v", err)
	}
	if err := psiphon.ImportEmbeddedServerEntries(context.Background(), config, "", ""); err != nil {
		return nil, err
	}
	return p, nil
}

// start runs a new controller and waits until it has a tunnel (or fails / times out).
func (p *psiRunner) start(wait time.Duration) error {
	for _, ch := range []chan struct{}{p.upCh} {
		select {
		case <-ch:
		default:
		}
	}
	select {
	case <-p.failCh:
	default:
	}
	select {
	case <-p.exited:
	default:
	}
	ctl, err := psiphon.NewController(p.config)
	if err != nil {
		return fmt.Errorf("controller: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	p.cancel, p.done = cancel, done
	p.expectStop.Store(false)
	go func() {
		ctl.Run(ctx)
		close(done)
		if !p.expectStop.Load() {
			select {
			case p.exited <- errors.New("Psiphon stopped" + suffix(p.upErr())):
			default:
			}
		}
	}()
	select {
	case <-p.upCh:
		return nil
	case err := <-p.failCh:
		p.stop()
		return err
	case <-done:
		p.expectStop.Store(true)
		select {
		case <-p.exited:
		default:
		}
		return errors.New("Psiphon stopped" + suffix(p.upErr()))
	case <-time.After(wait):
		p.stop()
		return errors.New("Psiphon did not connect in time" + suffix(p.upErr()))
	}
}

// stop ends the running controller (its SOCKS listener closes; the port is free for the next controller).
func (p *psiRunner) stop() {
	p.expectStop.Store(true)
	if p.cancel != nil {
		p.cancel()
		select {
		case <-p.done:
		case <-time.After(15 * time.Second):
			say("WLOG psiphon controller slow to stop (15 s)")
		}
	}
	p.tunnels.Store(0)
}

type chainRun struct {
	link    *Link
	up      *upstream      // v1.8.4 Bridge + Psiphon: the bridge proxy (no Xray)
	adapter *socks4Adapter // v1.8.4: local SOCKS5 -> SOCKS4 adapter for socks4 bridges
	xPort   int
	outPort int
	inst    *core.Instance
	psi     *psiRunner
	nRec    int
	busy    atomic.Bool
}

func (cr *chainRun) restartXray() error {
	if cr.inst != nil {
		cr.inst.Close()
		cr.inst = nil
	}
	var err error
	for try := 0; try < 3; try++ { // the port can take a moment to be free again
		if cr.inst, err = startXray(cr.link, cr.xPort, "error"); err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return err
}

// recover: partial restart. Never touches the outer SOCKS port's owner unless needed, never exits.
func (cr *chainRun) recover(why string, onlyXray bool) bool {
	cr.busy.Store(true)
	defer cr.busy.Store(false)
	cr.nRec++
	n := cr.nRec
	t0 := time.Now()
	tun := int32(-1)
	if cr.psi != nil {
		tun = cr.psi.tunnels.Load()
	}
	var ms int
	var err error
	if cr.up != nil {
		// v1.8.4 Bridge + Psiphon: step 1 checks the bridge proxy (handshake + TLS to a host abroad through it);
		// nothing local to restart there, so a dead bridge fails the recovery at once (the app moves on after 2)
		say("WLOG recover #%d (%s): step 1 check bridge %s, psiphon tunnels=%d", n, why, cr.up.Key(), tun)
		for try := 1; try <= 2; try++ {
			if ms, err = cr.up.check(8 * time.Second); err == nil {
				break
			}
		}
		if err != nil {
			say("RECOVER_FAIL bridge proxy unreachable: %s", oneLine(err.Error()))
			return false
		}
		say("WLOG recover #%d: bridge ok %d ms", n, ms)
		onlyXray = false
	} else {
		say("WLOG recover #%d (%s): step 1 check config leg (xray 127.0.0.1:%d), psiphon tunnels=%d", n, why, cr.xPort, tun)
		ms, err = probe(cr.xPort, 8*time.Second)
	}
	if cr.up == nil && (err != nil || onlyXray) {
		if err != nil {
			say("WLOG recover #%d: config leg check failed: %s -> restarting xray in-process on the same port", n, oneLine(err.Error()))
		} else {
			say("WLOG recover #%d: restarting xray in-process on the same port", n)
		}
		if err := cr.restartXray(); err != nil {
			say("RECOVER_FAIL xray restart: %s", oneLine(err.Error()))
			return false
		}
		for try := 1; try <= 2; try++ {
			if ms, err = probe(cr.xPort, 10*time.Second); err == nil {
				break
			}
		}
		if err != nil {
			say("RECOVER_FAIL config unreachable after xray restart: %s", oneLine(err.Error()))
			return false
		}
		say("WLOG recover #%d: xray restarted, config ok %d ms", n, ms)
	} else if cr.up == nil {
		say("WLOG recover #%d: config leg ok %d ms (xray kept running)", n, ms)
	}
	if cr.psi == nil || onlyXray {
		say("RECOVER_OK %d", time.Since(t0).Milliseconds())
		return true
	}
	say("WLOG recover #%d: step 2 restart psiphon controller in-process (socks 127.0.0.1:%d kept)", n, cr.outPort)
	cr.psi.stop()
	if err := cr.psi.start(75 * time.Second); err != nil {
		say("RECOVER_FAIL psiphon: %s", oneLine(err.Error()))
		return false
	}
	say("WLOG recover #%d: psiphon tunnel up after %d ms; step 3 verify through socks", n, time.Since(t0).Milliseconds())
	if ms, err = probe(cr.outPort, 10*time.Second); err != nil {
		say("RECOVER_FAIL psiphon up but no data: %s", oneLine(err.Error()))
		return false
	}
	say("RECOVER_OK %d psiphon %d ms", time.Since(t0).Milliseconds(), ms)
	return true
}

// dnsViaSocks: one DNS-over-TCP question (www.google.com A) to 1.1.1.1:53 through the SOCKS port. Tiny keep-alive.
func dnsViaSocks(port int, timeout time.Duration) (int, error) {
	t0 := time.Now()
	d, err := proxy.SOCKS5("tcp", "127.0.0.1:"+strconv.Itoa(port), nil, &net.Dialer{Timeout: timeout})
	if err != nil {
		return -1, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err := d.(proxy.ContextDialer).DialContext(ctx, "tcp", "1.1.1.1:53")
	if err != nil {
		return -1, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	q := []byte{0x07, 0x6f, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	m := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(m, uint16(len(q)))
	copy(m[2:], q)
	if _, err := c.Write(m); err != nil {
		return -1, err
	}
	var lb [2]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		return -1, err
	}
	a := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(c, a); err != nil {
		return -1, err
	}
	if len(a) < 12 {
		return -1, errors.New("short dns answer")
	}
	return int(time.Since(t0).Milliseconds()), nil
}

// keepAlive: every `every`, a tiny request through the whole chain so idle NAT/DPI timers on the ss/vless leg do
// not silently drop it. Informational only (the app's svpn health decides about recovery).
func (cr *chainRun) keepAlive(stop <-chan struct{}, every time.Duration) {
	tk := time.NewTicker(every)
	defer tk.Stop()
	fails := 0
	for {
		select {
		case <-stop:
			return
		case <-tk.C:
		}
		if cr.busy.Load() {
			continue
		}
		ms, err := dnsViaSocks(cr.outPort, 6*time.Second)
		if err != nil {
			fails++
			if fails <= 3 || fails%10 == 0 {
				say("WLOG keepalive fail #%d: %s", fails, oneLine(err.Error()))
			}
			continue
		}
		if fails > 0 {
			say("WLOG keepalive ok %d ms after %d fails", ms, fails)
		}
		fails = 0
	}
}

var runMu sync.Mutex

func cmdRun(args []string) int {
	runMu.Lock()
	defer runMu.Unlock()
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	link := fs.String("link", "", "share link (or @file)")
	usePsi := fs.Bool("psiphon", true, "run Psiphon over the config")
	region := fs.String("region", "", "Psiphon egress region (empty = best)")
	socks := fs.Int("socks", 0, "local SOCKS5 port to serve (0 = random)")
	dir := fs.String("dir", ".", "data directory (Psiphon data store)")
	dns := fs.String("dns", "", "DNS servers")
	psiTimeout := fs.Int("psitimeout", 180, "seconds for Psiphon to connect")
	pool := fs.Int("psipool", 2, "Psiphon tunnels kept in parallel (warm standby)")
	ka := fs.Duration("keepalive", 22*time.Second, "keep-alive request through the chain (0 = off)")
	upArg := fs.String("upstream", "", "v1.8.4: bridge proxy URL (or @file) -> Psiphon only, no Xray")
	fs.Parse(args)
	setupDNS(*dns)

	cr := &chainRun{}
	if *upArg != "" {
		// v1.8.4 Bridge + Psiphon: no Xray; the bridge proxy is Psiphon's upstream
		raw := *upArg
		if strings.HasPrefix(raw, "@") {
			b, err := os.ReadFile(raw[1:])
			if err != nil {
				say("ERR %s", err)
				return 1
			}
			raw = strings.TrimSpace(string(b))
		}
		up, err := parseUpstream(raw)
		if err != nil {
			say("CONFIG_ERR %s", oneLine(err.Error()))
			return 3
		}
		cr.up = up
		*usePsi = true
		if cr.outPort = *socks; cr.outPort == 0 {
			if cr.outPort, err = freePort(); err != nil {
				say("ERR %s", err)
				return 1
			}
		}
		say("STAGE config")
		var ms int
		for try := 1; ; try++ {
			ms, err = up.detect(10 * time.Second)
			if err == nil {
				break
			}
			if try >= 3 {
				say("CONFIG_ERR bridge %s: %s", up.Key(), oneLine(err.Error()))
				return 3
			}
			say("WARN bridge test %d failed: %s", try, oneLine(err.Error()))
			time.Sleep(2 * time.Second)
		}
		say("BRIDGE %s", up.Key())
		say("CONFIG_OK %d", ms)
	} else {
		raw := *link
		if strings.HasPrefix(raw, "@") {
			b, err := os.ReadFile(raw[1:])
			if err != nil {
				say("ERR %s", err)
				return 1
			}
			raw = strings.TrimSpace(string(b))
		}
		l, err := ParseLink(raw)
		if err != nil {
			say("CONFIG_ERR %s", oneLine(err.Error()))
			return 3
		}
		for _, w := range l.Warn {
			say("WARN %s", w)
		}
		cr.link = l
		cr.outPort = *socks
		if cr.outPort == 0 {
			if cr.outPort, err = freePort(); err != nil {
				say("ERR %s", err)
				return 1
			}
		}
		cr.xPort = cr.outPort
		if *usePsi {
			if cr.xPort, err = freePort(); err != nil {
				say("ERR %s", err)
				return 1
			}
		}

		say("STAGE config")
		cr.inst, err = startXray(l, cr.xPort, "error")
		if err != nil {
			say("CONFIG_ERR %s", oneLine(err.Error()))
			return 3
		}
		defer func() {
			if cr.inst != nil {
				cr.inst.Close()
			}
		}()
		var ms int
		for try := 1; ; try++ {
			ms, err = probe(cr.xPort, 12*time.Second)
			if err == nil {
				break
			}
			if try >= 3 {
				say("CONFIG_ERR %s", oneLine(err.Error()))
				return 3
			}
			say("WARN config test %d failed: %s", try, oneLine(err.Error()))
			time.Sleep(2 * time.Second)
		}
		say("CONFIG_OK %d", ms)
	}

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	stopKA := make(chan struct{})
	defer close(stopKA)

	var exited chan error
	if *usePsi {
		say("STAGE psiphon")
		var err error
		upURL, netID := fmt.Sprintf("socks5://127.0.0.1:%d", cr.xPort), "076one-chain"
		if cr.up != nil {
			netID = "076one-bridge"
			if upURL = cr.up.psiURL(); upURL == "" {
				if cr.adapter, err = startSocks4Adapter(cr.up); err != nil {
					say("ERR socks4 adapter: %s", err)
					return 1
				}
				defer cr.adapter.close()
				upURL = fmt.Sprintf("socks5://127.0.0.1:%d", cr.adapter.port())
				say("WLOG socks4 bridge: local adapter socks5://127.0.0.1:%d -> %s (names resolved locally)", cr.adapter.port(), cr.up.Key())
			}
		}
		cr.psi, err = newPsi(*dir, upURL, cr.outPort, *region, *psiTimeout, *pool, netID)
		if err == nil {
			say("WLOG psiphon data dir %s (server affinity kept across restarts), pool=%d", cr.psi.dir, max(1, *pool))
			err = cr.psi.start(time.Duration(*psiTimeout+15) * time.Second)
		}
		if err != nil {
			say("ERR psiphon: %s", oneLine(err.Error()))
			return 4
		}
		exited = cr.psi.exited
		defer cr.psi.stop()
	}
	say("READY %d", cr.outPort)
	if *ka > 0 {
		go cr.keepAlive(stopKA, *ka)
	}
	for {
		select {
		case <-sig:
			return 0
		case cmd := <-ctlCh:
			switch {
			case cmd == "PING":
				t := int32(-1)
				if cr.psi != nil {
					t = cr.psi.tunnels.Load()
				}
				say("PONG %d", t)
			case cmd == "RECOVER" || cmd == "PSI_RESTART":
				cr.recover("app: "+strings.ToLower(cmd), false)
			case cmd == "XRAY_RESTART":
				cr.recover("app: xray restart", true)
			default:
				say("WLOG control: unknown command %s", cmd)
			}
		case err := <-exited:
			// the controller gave up on its own (e.g. establish timeout after a long loss): restart it in-process
			say("WLOG psiphon controller exited: %s -> in-process restart", oneLine(err.Error()))
			if !cr.recover("psiphon exited", false) {
				say("ERR psiphon: %s", oneLine(err.Error()))
				return 4
			}
		}
	}
}
