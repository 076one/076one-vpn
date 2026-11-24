// libchain: 076one "Config + Psiphon" core. One Go binary with Xray-core (MPL-2.0, XTLS/Xray-core v26.3.27) and
// psiphon-tunnel-core (GPL-3.0); the binary as a whole is GPL-3.0.
//
//	libchain run  -link L [-psiphon=true] [-region DE] [-socks PORT] [-dir D] [-dns 1.2.3.4,…]
//	    Xray runs the share link as a SOCKS5 inbound on 127.0.0.1:<random free port> (no auth, loopback only) and the
//	    link is verified with a real request through it. With -psiphon, psiphon-tunnel-core then runs with
//	    UpstreamProxyURL=socks5://127.0.0.1:<xray port> and serves its own SOCKS5 on 127.0.0.1:PORT; without it the
//	    Xray inbound itself listens on PORT. Output lines:
//	      STAGE config | CONFIG_OK ms | CONFIG_ERR reason | STAGE psiphon | PSI_REGION XX | PSI_UPSTREAM_ERR msg
//	      READY port | ERR reason | WARN text | XRAY text
//	libchain run  -upstream URL|@file [-region DE] [-socks PORT] [-dir D] [-dns …]          (v1.8.4 Bridge + Psiphon)
//	    Psiphon only, with UpstreamProxyURL = the bridge proxy (socks5 / http; socks4 via a local adapter). The
//	    proxy is checked first (STAGE config / CONFIG_OK ms / CONFIG_ERR reason, as for a link); no Xray runs.
//	libchain ptest -file F [-par 3] [-real 6] [-keep 3] [-timeout 75] [-dir D]   (v1.8.4) proxy handshake test of
//	    every line, then a real Psiphon connect through the fastest ones (child "run" processes, own data dirs):
//	    "PHS i ms scheme" | "PSTAGE2 n" | "PREAL i ms region" | "PFAIL i stage reason" | "PPROG done ok" | "DONE"
//	libchain test -file F [-par 4] [-timeout 12] [-dns …]   one link per line -> "RES index ms" or "RES index -1 reason"
//	libchain sub  -url U [-dns …]                          subscription -> "LINK l" lines, then "COUNT n" (or "ERR …")
//	libchain parse -link L                                 prints the Xray outbound JSON (debug)
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	"golang.org/x/net/proxy"
)

const XrayVersion = "v26.3.27"

var out = struct {
	sync.Mutex
	w *bufio.Writer
}{w: bufio.NewWriter(os.Stdout)}

func say(format string, a ...any) {
	out.Lock()
	io.WriteString(out.w, redact(fmt.Sprintf(format, a...))+"\n") // v1.8.4: bridge credentials never printed
	out.w.Flush()
	out.Unlock()
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// setupDNS: Android has no /etc/resolv.conf for a static Go binary, so name lookups go to the given servers (the
// phone's own DNS passed by the app first, then public ones), raced, first answer wins.
func setupDNS(list string) {
	var servers []string
	for _, s := range csv(list) {
		if _, _, err := net.SplitHostPort(s); err != nil {
			if ip := net.ParseIP(s); ip != nil {
				s = net.JoinHostPort(s, "53")
			} else {
				continue
			}
		}
		servers = append(servers, s)
	}
	servers = append(servers, "8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53")
	var d net.Dialer
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
			defer cancel()
			type res struct {
				c   net.Conn
				err error
			}
			ch := make(chan res, len(servers))
			for i, s := range servers {
				go func(i int, s string) {
					// small stagger so the phone's own DNS gets the first chance
					select {
					case <-time.After(time.Duration(i) * 150 * time.Millisecond):
					case <-ctx.Done():
						ch <- res{nil, ctx.Err()}
						return
					}
					c, err := d.DialContext(ctx, network, s)
					ch <- res{c, err}
				}(i, s)
			}
			var last error
			for range servers {
				r := <-ch
				if r.err == nil {
					go func() { // close the losers
						for range servers[1:] {
							if x := <-ch; x.c != nil {
								x.c.Close()
							}
						}
					}()
					return r.c, nil
				}
				last = r.err
			}
			return nil, last
		},
	}
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// startXray runs the link as a SOCKS5 inbound on 127.0.0.1:port.
func startXray(l *Link, port int, logLevel string) (*core.Instance, error) {
	ob := map[string]any{}
	for k, v := range l.Outbound {
		ob[k] = v
	}
	ob["tag"] = "proxy"
	addKeepAlive(ob)
	cfg := map[string]any{
		"log": map[string]any{"loglevel": logLevel, "access": "none"},
		"inbounds": []any{map[string]any{
			"tag": "in", "listen": "127.0.0.1", "port": port, "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": true, "ip": "127.0.0.1"},
		}},
		"outbounds": []any{ob},
	}
	if v := os.Getenv("CHAIN_LOGLEVEL"); v != "" {
		cfg["log"] = map[string]any{"loglevel": v}
	}
	b, _ := json.Marshal(cfg)
	jc, err := serial.DecodeJSONConfig(strings.NewReader(string(b)))
	if err != nil {
		return nil, fmt.Errorf("config: %v", err)
	}
	pb, err := jc.Build()
	if err != nil {
		return nil, fmt.Errorf("config: %v", err)
	}
	inst, err := core.New(pb)
	if err != nil {
		return nil, fmt.Errorf("xray: %v", err)
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		return nil, fmt.Errorf("xray start: %v", err)
	}
	return inst, nil
}

// probe makes real HTTP(S) requests through the SOCKS5 port; returns the latency of the 2nd request (the 1st
// includes the proxy handshake), or of the 1st when only one succeeds.
func probe(port int, timeout time.Duration) (int, error) {
	d, err := proxy.SOCKS5("tcp", "127.0.0.1:"+strconv.Itoa(port), nil, &net.Dialer{Timeout: timeout})
	if err != nil {
		return -1, err
	}
	cd := d.(proxy.ContextDialer)
	tr := &http.Transport{DialContext: cd.DialContext, DisableKeepAlives: false, TLSHandshakeTimeout: timeout,
		ResponseHeaderTimeout: timeout, MaxIdleConnsPerHost: 2}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	urls := []string{"https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204", "http://cp.cloudflare.com/generate_204"}
	var lastErr error
	for _, u := range urls {
		first := -1
		for i := 0; i < 2; i++ {
			t0 := time.Now()
			resp, err := cl.Get(u)
			if err != nil {
				lastErr = err
				break
			}
			io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			if resp.StatusCode >= 500 {
				lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
				break
			}
			ms := int(time.Since(t0) / time.Millisecond)
			if i == 0 {
				first = ms
			} else {
				return ms, nil
			}
		}
		if first >= 0 {
			return first, nil
		}
	}
	return -1, shortErr(lastErr)
}

func shortErr(err error) error {
	if err == nil {
		return errors.New("no response")
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "Client.Timeout"), strings.Contains(s, "deadline exceeded"), strings.Contains(s, "i/o timeout"):
		return errors.New("timeout (no answer through the config)")
	case strings.Contains(s, "connection refused"):
		return errors.New("connection refused")
	case strings.Contains(s, "EOF"), strings.Contains(s, "reset by peer"):
		return errors.New("connection closed (wrong id/key/settings, server down, or blocked)")
	}
	return errors.New(oneLine(s))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: libchain run|test|sub|parse|version …")
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	if os.Getenv("CHAIN_WATCH_STDIN") == "1" {
		// the app keeps our stdin open; EOF means the app process died -> do not linger as an orphan.
		// v1.8.3: lines on stdin are control commands for "run" (RECOVER, PSI_RESTART, XRAY_RESTART, PING).
		go readControl(os.Stdin)
	}
	switch cmd {
	case "version":
		fmt.Println("libchain xray-core", XrayVersion, "psiphon-tunnel-core 6f412a9e0c31")
	case "parse":
		fs := flag.NewFlagSet("parse", flag.ExitOnError)
		link := fs.String("link", "", "share link")
		fs.Parse(args)
		l, err := ParseLink(*link)
		if err != nil {
			say("ERR %s", err)
			os.Exit(1)
		}
		b, _ := json.MarshalIndent(l.Outbound, "", "  ")
		say("NAME %s", l.Name)
		for _, w := range l.Warn {
			say("WARN %s", w)
		}
		say("%s", b)
	case "sub":
		os.Exit(cmdSub(args))
	case "test":
		os.Exit(cmdTest(args))
	case "run":
		os.Exit(cmdRun(args))
	case "ptest":
		os.Exit(cmdPTest(args))
	default:
		fmt.Fprintln(os.Stderr, "unknown command", cmd)
		os.Exit(2)
	}
}

func cmdSub(args []string) int {
	fs := flag.NewFlagSet("sub", flag.ExitOnError)
	u := fs.String("url", "", "subscription URL")
	dns := fs.String("dns", "", "DNS servers")
	fs.Parse(args)
	setupDNS(*dns)
	req, err := http.NewRequest("GET", strings.TrimSpace(*u), nil)
	if err != nil {
		say("ERR bad URL")
		return 1
	}
	req.Header.Set("User-Agent", "v2rayNG/1.10.0")
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		say("ERR %s", shortErr(err))
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		say("ERR HTTP %d", resp.StatusCode)
		return 1
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	links := ParseSubscription(body)
	for _, l := range links {
		say("LINK %s", l)
	}
	say("COUNT %d", len(links))
	return 0
}

func cmdTest(args []string) int {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	file := fs.String("file", "", "file with one link per line")
	par := fs.Int("par", 4, "parallel tests")
	to := fs.Int("timeout", 12, "seconds per request")
	dns := fs.String("dns", "", "DNS servers")
	fs.Parse(args)
	setupDNS(*dns)
	b, err := os.ReadFile(*file)
	if err != nil {
		say("ERR %s", err)
		return 1
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r", ""), "\n")
	sem := make(chan struct{}, max(1, *par))
	var wg sync.WaitGroup
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		wg.Add(1)
		go func(i int, line string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			l, err := ParseLink(line)
			if err != nil {
				say("RES %d -1 %s", i, oneLine(err.Error()))
				return
			}
			port, err := freePort()
			if err != nil {
				say("RES %d -1 %s", i, err)
				return
			}
			inst, err := startXray(l, port, "none")
			if err != nil {
				say("RES %d -1 %s", i, oneLine(err.Error()))
				return
			}
			defer inst.Close()
			ms, err := probe(port, time.Duration(*to)*time.Second)
			if err != nil {
				say("RES %d -1 %s", i, oneLine(err.Error()))
				return
			}
			say("RES %d %d", i, ms)
		}(i, line)
	}
	wg.Wait()
	say("DONE")
	return 0
}

func suffix(s string) string {
	if s == "" {
		return ""
	}
	return " (" + oneLine(s) + ")"
}
