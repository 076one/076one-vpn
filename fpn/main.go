// SPDX-License-Identifier: GPL-3.0-or-later
//
// libfpn: 076one "Firefox" mode (v1.7). A small command-line front for the Predator VPN core
// (erfan-tahvilian/PredatorVPN v2.0.7, GPL-3.0-or-later, vendored unmodified in third_party/predator-core).
// It signs in to the user's OWN Firefox account and runs the authenticated HTTP/2 / HTTP/3 CONNECT tunnel as a local
// SOCKS5 server; the app carries the Android TUN into it with `o76core svpn -dnsudp`.
//
// It never creates accounts. The password is read once from stdin, hashed by the core (onepw) and never stored;
// only the OAuth tokens are kept, in <dir>/vault.json (app-private storage, mode 0600).
//
//	libfpn login  -dir D [-dns IP] [-recovery]   stdin: email, password, then the e-mail code / CAPTCHA answer when asked
//	libfpn status -dir D                         one JSON line: signedIn, email, quota, servers
//	libfpn servers -dir D [-dns IP]
//	libfpn logout -dir D
//	libfpn run    -dir D -port P [-transport auto|h2|h3] [-server REC|id] [-dns IP] [-recovery]
//
// Output lines: "LOG level msg", "NEEDCODE method", "CAPTCHA path", "OK …", "UP proto|location|exit",
// "STAT up down", "QUOTA limit remaining reset", "DOWN reason", "ERR reason".
package main

import (
	"bufio"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"foxvpn/android/core/mobile"
)

//go:embed cacert.pem
var cacert string

//go:embed bootstrap-nodes.txt
var bootstrapNodes string

var (
	outMu sync.Mutex
	stdin = bufio.NewReader(os.Stdin)
	lines = make(chan string, 4)
)

func out(f string, a ...any) {
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Fprintln(os.Stdout, strings.ReplaceAll(fmt.Sprintf(f, a...), "\n", " "))
}

func readLine(timeout time.Duration) (string, error) {
	select {
	case l, ok := <-lines:
		if !ok {
			return "", errors.New("input closed")
		}
		return strings.TrimRight(l, "\r\n"), nil
	case <-time.After(timeout):
		return "", errors.New("timed out waiting for input")
	}
}

type host struct {
	dir      string
	dns      string
	mu       sync.Mutex
	logsSeen int
	last     map[string]any
	onState  func(map[string]any)
}

func (h *host) Save(vault string) error {
	tmp := filepath.Join(h.dir, "vault.json.tmp")
	if err := os.WriteFile(tmp, []byte(vault), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(h.dir, "vault.json"))
}

func (h *host) Changed(state string) {
	var s map[string]any
	if json.Unmarshal([]byte(state), &s) != nil {
		return
	}
	h.mu.Lock()
	logs, _ := s["logs"].([]any)
	if len(logs) < h.logsSeen {
		h.logsSeen = 0
	}
	fresh := logs[h.logsSeen:]
	h.logsSeen = len(logs)
	h.last = s
	cb := h.onState
	h.mu.Unlock()
	for _, l := range fresh {
		m, _ := l.(map[string]any)
		out("LOG %v %v", m["level"], m["message"])
	}
	if cb != nil {
		cb(s)
	}
}

func (h *host) Protect(int32) bool { return true } // the app itself is excluded from its VPN

func (h *host) DNSAddress() string {
	if net.ParseIP(h.dns) != nil {
		return h.dns
	}
	return "8.8.8.8"
}

func (h *host) Certificates() string   { return cacert }
func (h *host) BootstrapNodes() string { return bootstrapNodes }

// SolveCaptcha: the provider's image goes to a file the app shows; the human types the answer (stdin).
func (h *host) SolveCaptcha(image string) (string, error) {
	i := strings.Index(image, ",")
	if i < 0 {
		return "", errors.New("bad captcha image")
	}
	raw, err := base64.StdEncoding.DecodeString(image[i+1:])
	if err != nil {
		return "", err
	}
	p := filepath.Join(h.dir, "captcha.img")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		return "", err
	}
	out("CAPTCHA %s", p)
	return readLine(170 * time.Second)
}

type envelope struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data"`
	Error string          `json:"error"`
}

func call(b *mobile.Backend, ch string, args ...any) (json.RawMessage, error) {
	a, _ := json.Marshal(args)
	if args == nil {
		a = []byte("[]")
	}
	var e envelope
	if err := json.Unmarshal([]byte(b.Call(ch, string(a))), &e); err != nil {
		return nil, err
	}
	if !e.OK {
		if e.Error == "" {
			e.Error = "failed"
		}
		return nil, errors.New(e.Error)
	}
	return e.Data, nil
}

func open(dir, dns string) (*mobile.Backend, *host) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		out("ERR %v", err)
		os.Exit(1)
	}
	h := &host{dir: dir, dns: dns}
	vault, _ := os.ReadFile(filepath.Join(dir, "vault.json"))
	b := mobile.NewBackend(h, string(vault))
	return b, h
}

func state(b *mobile.Backend) map[string]any {
	var s map[string]any
	_ = json.Unmarshal([]byte(b.Snapshot()), &s)
	return s
}

// settings keeps the core's own defaults and changes only what 076one needs: a local SOCKS port, no Android
// VPN engine of its own (svpn carries the TUN), protocol, location and the optional account-route recovery.
func applySettings(b *mobile.Backend, port int, transport, server string, recovery bool) error {
	s, _ := state(b)["settings"].(map[string]any)
	if s == nil {
		return errors.New("no settings")
	}
	s["proxyOnly"] = true
	s["bind"] = "127.0.0.1"
	if port > 0 {
		s["socksPort"] = port
	}
	if transport != "" {
		s["transport"] = transport
	}
	s["subscriptionsEnabled"] = recovery
	s["accountRecoveryEnabled"] = recovery
	if _, err := call(b, "settings", s); err != nil {
		return err
	}
	if server != "" {
		if _, err := call(b, "select", server); err != nil && server != "REC" {
			out("LOG warn location %s: %v (using recommended)", server, err)
			_, _ = call(b, "select", "REC")
		}
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		out("ERR usage: libfpn login|status|servers|logout|run -dir D")
		os.Exit(2)
	}
	go func() {
		for {
			l, err := stdin.ReadString('\n')
			if l != "" {
				lines <- l
			}
			if err != nil {
				close(lines)
				return
			}
		}
	}()
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dir := fs.String("dir", "", "state directory (app-private)")
	dns := fs.String("dns", "", "network DNS server IP")
	port := fs.Int("port", 0, "local SOCKS5 port")
	transport := fs.String("transport", "auto", "auto|h2|h3")
	server := fs.String("server", "REC", "location id, REC = recommended")
	recovery := fs.Bool("recovery", false, "reach Firefox Accounts through public relays when it is blocked (opt-in)")
	_ = fs.Parse(os.Args[2:])
	if *dir == "" {
		out("ERR -dir required")
		os.Exit(2)
	}
	b, h := open(*dir, *dns)
	switch cmd {
	case "status":
		s := state(b)
		servers, _ := s["servers"].([]any)
		j, _ := json.Marshal(map[string]any{"signedIn": s["signedIn"], "email": s["email"], "quota": s["quota"], "servers": len(servers)})
		out("%s", j)
	case "logout":
		if _, err := call(b, "logout"); err != nil {
			out("ERR %v", err)
			os.Exit(1)
		}
		out("OK")
	case "servers":
		if err := applySettings(b, 0, "", "", *recovery); err != nil {
			out("ERR %v", err)
			os.Exit(1)
		}
		data, err := call(b, "servers")
		if err != nil {
			out("ERR %v", err)
			os.Exit(1)
		}
		var list []map[string]any
		_ = json.Unmarshal(data, &list)
		for _, s := range list {
			out("SERVER %v|%v|%v|%v", s["id"], s["code"], s["country"], s["city"])
		}
		out("OK %d", len(list))
	case "login":
		login(b, *recovery)
	case "run":
		run(b, h, *port, *transport, *server, *recovery)
	default:
		out("ERR unknown command %s", cmd)
		os.Exit(2)
	}
}

func login(b *mobile.Backend, recovery bool) {
	if err := applySettings(b, 0, "", "", recovery); err != nil {
		out("ERR %v", err)
		os.Exit(1)
	}
	email, err := readLine(60 * time.Second)
	if err != nil {
		out("ERR %v", err)
		os.Exit(1)
	}
	password, err := readLine(60 * time.Second)
	if err != nil {
		out("ERR %v", err)
		os.Exit(1)
	}
	data, err := call(b, "login", map[string]any{"email": strings.TrimSpace(email), "password": password})
	password = ""
	if err != nil {
		out("ERR %v", err)
		os.Exit(1)
	}
	var r struct {
		NeedsCode bool   `json:"needsCode"`
		Method    string `json:"verificationMethod"`
	}
	_ = json.Unmarshal(data, &r)
	for tries := 0; r.NeedsCode && tries < 3; tries++ {
		out("NEEDCODE %s", r.Method)
		code, err := readLine(15 * time.Minute)
		if err != nil {
			_, _ = call(b, "cancelAccountLogin")
			out("ERR %v", err)
			os.Exit(1)
		}
		if _, err = call(b, "verify", strings.TrimSpace(code)); err != nil {
			out("LOG error %v", err)
			continue
		}
		r.NeedsCode = false
	}
	if r.NeedsCode {
		out("ERR verification failed")
		os.Exit(1)
	}
	s := state(b)
	if _, err := call(b, "servers"); err != nil {
		out("LOG warn servers: %v", err)
	}
	out("OK %v", s["email"])
}

func run(b *mobile.Backend, h *host, port int, transport, server string, recovery bool) {
	if port <= 0 {
		out("ERR -port required")
		os.Exit(2)
	}
	if signed, _ := state(b)["signedIn"].(bool); !signed {
		out("ERR not signed in")
		os.Exit(3)
	}
	if err := applySettings(b, port, transport, server, recovery); err != nil {
		out("ERR %v", err)
		os.Exit(1)
	}
	done := make(chan string, 1)
	var upOnce sync.Once
	connected := false
	var lastStat time.Time
	h.mu.Lock()
	h.onState = func(s map[string]any) {
		conn, _ := s["connection"].(string)
		switch conn {
		case "connected":
			upOnce.Do(func() {
				connected = true
				loc := ""
				if as, ok := s["activeServer"].(map[string]any); ok {
					loc = fmt.Sprintf("%v %v", as["country"], as["city"])
				}
				exit := ""
				if e, ok := s["exit"].(map[string]any); ok {
					exit = fmt.Sprintf("%v %v", e["ip"], e["country"])
				}
				out("UP %v|%s|%s", s["protocol"], strings.TrimSpace(loc), strings.TrimSpace(exit))
				if q, ok := s["quota"].(map[string]any); ok {
					out("QUOTA %v %v %v", q["limit"], q["remaining"], q["reset"])
				}
			})
			if time.Since(lastStat) > time.Second {
				lastStat = time.Now()
				out("STAT %v %v", s["up"], s["down"])
			}
		case "disconnected":
			if connected {
				reason, _ := s["lastError"].(string)
				if reason == "" {
					reason = "disconnected"
				}
				select {
				case done <- reason:
				default:
				}
			}
		}
	}
	h.mu.Unlock()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		b.Disconnect()
		out("DOWN stopped")
		os.Exit(0)
	}()
	go func() {
		if _, err := call(b, "connect"); err != nil {
			select {
			case done <- err.Error():
			default:
			}
		}
	}()
	go func() { // keep the traffic counter moving even when nothing else changes
		for range time.Tick(2 * time.Second) {
			b.Call("state", "[]")
			h.Changed(b.Snapshot())
		}
	}()
	reason := <-done
	b.Disconnect()
	out("DOWN %s", reason)
	os.Exit(1)
}
