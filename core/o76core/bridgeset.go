// v1.4 bridge failover inside the core (vpn with -bridge primary -bridges standby1,standby2):
//   - standby bridges are kept "warm": every 60 s (and at start) a proxy connect + MASQUE TLS handshake through each
//     one -> "BWARM key ms" | "BWARM key fail <reason>". Only warm ones are used for failover.
//   - on NODATA or 2 consecutive connect failures the core switches to the next warm standby at once (no process
//     restart, the TUN stays): the current connection is closed and the tunnel re-dials through the new bridge
//     -> "BSWITCH oldkey newkey reason". When no warm standby is left the core prints NODATA / FAILS as before and
//     the app re-plans.
//   - the app can replace the standby list while running: a line "BRIDGES url,url" on stdin.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type bset struct {
	mu      sync.Mutex
	list    []*bridge // [0] = current
	warm    map[string]bool
	cur     net.Conn
	ep, sni string
	lastSw  time.Time
	// v1.5 (wvpn, Worker over bridge): warm check and switch hook; nil = MASQUE behaviour above
	check    func(b *bridge) error
	onSwitch func(nb *bridge)
}

var bridges *bset

func newBset(primary *bridge, standby string, ep, sni string) *bset {
	s := &bset{list: []*bridge{primary}, warm: map[string]bool{primary.key(): true}, ep: ep, sni: sni}
	s.setStandby(standby)
	return s
}

func (s *bset) setStandby(list string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.list[0]
	nl := []*bridge{cur}
	for _, u := range strings.Split(list, ",") {
		if strings.TrimSpace(u) == "" {
			continue
		}
		b, err := parseBridge(u, "auto")
		if err != nil || b.addr() == cur.addr() {
			continue
		}
		nl = append(nl, b)
	}
	s.list = nl
}

func (s *bset) current() *bridge {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.list[0]
}

// dial is the HTTP/2 dialer: always through the current bridge; remembers the connection so a switch can close it.
func (s *bset) dial(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
	o := dpi
	o.bridge = s.current()
	c, alpn, err := dialH2TLS(ctx, network, addr, cfg, o)
	if err != nil {
		return nil, err
	}
	if alpn != "h2" {
		c.Close()
		return nil, errALPN
	}
	s.mu.Lock()
	s.cur = c
	s.mu.Unlock()
	return c, nil
}

// switchNext moves to the next warm standby. Returns false when there is none.
func (s *bset) switchNext(reason string) bool {
	s.mu.Lock()
	if time.Since(s.lastSw) < 5*time.Second {
		s.mu.Unlock()
		return true // a switch just happened: give it time
	}
	old := s.list[0]
	idx := -1
	for i := 1; i < len(s.list); i++ {
		if s.warm[s.list[i].key()] {
			idx = i
			break
		}
	}
	if idx < 0 {
		s.mu.Unlock()
		return false
	}
	nb := s.list[idx]
	// new order: chosen, the rest, old one last (marked cold)
	nl := []*bridge{nb}
	for i, b := range s.list {
		if i != idx && i != 0 {
			nl = append(nl, b)
		}
	}
	nl = append(nl, old)
	s.warm[old.key()] = false
	s.list = nl
	s.lastSw = time.Now()
	c := s.cur
	s.cur = nil
	dpi.bridge = nb
	s.mu.Unlock()
	out("BSWITCH %s %s %s", old.key(), nb.key(), reason)
	if s.onSwitch != nil {
		s.onSwitch(nb)
	}
	if c != nil {
		c.Close() // MaintainTunnel notices and re-dials through the new bridge
	}
	return true
}

// warmLoop re-checks the standby bridges every 60 s.
func (s *bset) warmLoop(tc *tlsCache) {
	check := func() {
		s.mu.Lock()
		l := append([]*bridge(nil), s.list[1:]...)
		s.mu.Unlock()
		var wg sync.WaitGroup
		for _, b := range l {
			wg.Add(1)
			go func(b *bridge) {
				defer wg.Done()
				st := time.Now()
				var err error
				alpn := "h2"
				if s.check != nil {
					err = s.check(b)
				} else {
					o := dpi
					o.bridge = b
					ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
					var c net.Conn
					c, alpn, _, err = dialH2TLSBridge(ctx, s.ep, tc.get(s.sni), o)
					cancel()
					if c != nil {
						c.Close()
					}
				}
				ok := err == nil && alpn == "h2"
				s.mu.Lock()
				s.warm[b.key()] = ok
				s.mu.Unlock()
				if ok {
					out("BWARM %s %d", b.key(), max64(time.Since(st).Milliseconds(), 1))
				} else {
					reason := "alpn"
					if err != nil {
						reason = err.Error()
					}
					out("BWARM %s fail %s", b.key(), strings.ReplaceAll(reason, "\n", " "))
				}
			}(b)
		}
		wg.Wait()
	}
	check()
	for range time.Tick(60 * time.Second) {
		check()
	}
}

// onWaddrs (v1.5.1) receives "WADDRS a,b,c" from stdin in wvpn.
var onWaddrs func([]string)

// stdinCommands replaces exitOnStdinClose for vpn: reads command lines, exits on EOF.
func stdinCommands() {
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(line, "WADDRS ") && onWaddrs != nil { // v1.5.1: new clean-IP list for wvpn
				onWaddrs(splitList(strings.TrimPrefix(line, "WADDRS ")))
				continue
			}
			if strings.HasPrefix(line, "BRIDGES ") && bridges != nil {
				bridges.setStandby(strings.TrimPrefix(line, "BRIDGES "))
				out("BSTANDBY %d", len(bridges.list)-1)
			}
		}
		os.Exit(0)
	}()
}
