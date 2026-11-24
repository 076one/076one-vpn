package main

// v1.5.1 multi-route WARP registration.
//
// api.cloudflareclient.com is often blocked or throttled in Iran (field log 2026-11-22: "TLS handshake timeout"
// three times on Irancell). Registration now tries, in order, until one route works:
//   1. direct: TCP (MSS clamp) + fragmented ClientHello + uTLS Chrome, i.e. the same anti-DPI options as the tunnel,
//      to every address of the API host (system DNS + -apiips fallbacks);
//   2. each bridge from -bridges (HTTP / SOCKS proxies, best first; the app passes working intl=1 ones).
// (v1.8.2: the Worker route was removed together with Worker mode.)
// Both API calls (POST /reg, PATCH /reg/<id>) use the same route; when the PATCH fails on that route, it is retried
// on the remaining routes with the account already created. Nothing is written unless everything succeeded; the
// app writes to a temp file and only renames it over config.json on "OK", so an existing account is never lost.

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/Diniboy1123/usque/models"
)

const apiHost = "api.cloudflareclient.com"

var reqEcho = regexp.MustCompile(`(Post|Patch|Get|Put) "[^"]*": `)

// fallback addresses of api.cloudflareclient.com (Cloudflare anycast; used when DNS is poisoned / fails)
var defaultAPIIPs = []string{"162.159.143.174", "172.66.3.170", "162.159.137.105", "162.159.138.105"}

type regRoute struct {
	kind  string // direct | bridge
	label string // short Persian label for the log
	dial  func(ctx context.Context, addr string) (net.Conn, error)
}

// regClient: an HTTP/1.1 client whose every connection is dialed by r and wrapped in our TLS (fragmented
// ClientHello + Chrome fingerprint, certificate verified for the API host).
func regClient(r regRoute, o dpiOpts, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy:             nil,
		ForceAttemptHTTP2: false,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := r.dial(ctx, addr)
			if err != nil {
				return nil, err
			}
			host, _, _ := net.SplitHostPort(addr)
			c, err := clientTLS(ctx, raw, host, []string{"http/1.1"}, false, o)
			if err != nil {
				raw.Close()
				return nil, fmt.Errorf("tls: %w", err)
			}
			return c, nil
		},
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConnsPerHost:   1,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: timeout + 5*time.Second}
}

// directDialer tries every address of the API host (resolved first, then the fallbacks), each with a share of the
// context budget.
func directDialer(o dpiOpts, ips []string, useDNS bool) func(ctx context.Context, addr string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		var cands []string
		if net.ParseIP(host) != nil {
			cands = []string{host}
		} else if useDNS {
			rctx, cancel := context.WithTimeout(ctx, 4*time.Second)
			if as, err := net.DefaultResolver.LookupHost(rctx, host); err == nil {
				for _, a := range as {
					// v4 only (v6 is often absent on mobile); skip private / blackhole answers (Iranian DNS
					// answers blocked names with 10.10.34.x)
					if ip := net.ParseIP(a); ip != nil && ip.To4() != nil && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsUnspecified() {
						cands = append(cands, a)
					}
				}
			}
			cancel()
		}
		if net.ParseIP(host) == nil {
			for _, a := range ips {
				if !containsStr(cands, a) {
					cands = append(cands, a)
				}
			}
		}
		if len(cands) > 3 {
			cands = cands[:3]
		}
		var lastErr error
		for i, ip := range cands {
			left := time.Until(deadlineOr(ctx, 10*time.Second))
			per := left / time.Duration(len(cands)-i)
			if per < 2*time.Second {
				per = left
			}
			dctx, cancel := context.WithTimeout(ctx, per)
			c, err := dialTCP(dctx, "tcp", net.JoinHostPort(ip, port), o)
			cancel()
			if err == nil {
				return c, nil
			}
			lastErr = err
			if ctx.Err() != nil {
				break
			}
		}
		if lastErr == nil {
			lastErr = errors.New("no address for " + host)
		}
		return nil, lastErr
	}
}

func deadlineOr(ctx context.Context, d time.Duration) time.Time {
	if dl, ok := ctx.Deadline(); ok {
		return dl
	}
	return time.Now().Add(d)
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// buildRegRoutes: direct first (unless disabled), then bridges in the given order.
func buildRegRoutes(o dpiOpts, direct, useDNS bool, apiIPs []string, bridgeList []*bridge) []regRoute {
	var rs []regRoute
	if direct {
		rs = append(rs, regRoute{kind: "direct", label: "مستقیم (TLS تکه‌تکه + Chrome)", dial: directDialer(o, apiIPs, useDNS)})
	}
	for _, b := range bridgeList {
		b := b
		rs = append(rs, regRoute{kind: "bridge", label: "پل " + b.key(), dial: func(ctx context.Context, addr string) (net.Conn, error) {
			c, _, err := dialBridge(ctx, b, addr, o)
			return c, err
		}})
	}
	return rs
}

// tryRoutes runs attempt on each route in order until one succeeds; returns the index of the winner.
// logf gets one concise line per attempt.
func tryRoutes(rs []regRoute, logf func(string, ...interface{}), attempt func(regRoute) error) (int, error) {
	var errs []string
	for i, r := range rs {
		logf("ثبت‌نام: مسیر %d/%d — %s …", i+1, len(rs), r.label)
		t0 := time.Now()
		err := attempt(r)
		if err == nil {
			logf("ثبت‌نام: ✓ از طریق %s (%.1f ثانیه)", r.label, time.Since(t0).Seconds())
			return i, nil
		}
		var apiErr *models.APIError
		if errors.As(err, &apiErr) {
			// the API answered but refused (e.g. too many registrations from this source IP): another route has
			// another source IP, so keep going
			logf("ثبت‌نام: ✗ %s — پاسخ API: %s", r.label, shortErr(err))
			errs = append(errs, r.kind+": api "+shortErr(err))
			continue
		}
		logf("ثبت‌نام: ✗ %s — %s (%.1f ثانیه)", r.label, shortErr(err), time.Since(t0).Seconds())
		errs = append(errs, r.kind+": "+shortErr(err))
	}
	if len(rs) == 0 {
		return -1, errors.New("no route")
	}
	return -1, fmt.Errorf("all %d routes failed (%s)", len(rs), strings.Join(errs, "; "))
}

func shortErr(err error) string {
	s := strings.ReplaceAll(err.Error(), "\n", " ")
	s = strings.ReplaceAll(s, "failed to send request: ", "")
	// drop the request echo: `Post "https://api.cloudflareclient.com/v0a4471/reg": `
	s = reqEcho.ReplaceAllString(s, "")
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

func cmdRegister(args []string) {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	cfgPath := fs.String("c", "config.json", "config path (written only after a complete success)")
	dns := fs.String("dns", "", "comma separated DNS servers")
	direct := fs.Bool("direct", true, "try the direct route first")
	apiIPs := fs.String("apiips", strings.Join(defaultAPIIPs, ","), "fallback IPs of "+apiHost+" for the direct route")
	bridgesF := fs.String("bridges", "", "bridges (proxies) to try after direct, best first, comma separated")
	useDNS := fs.Bool("apidns", true, "direct route: resolve the API host with DNS (false = only -apiips)")
	timeout := fs.Duration("t", 20*time.Second, "timeout per route and request")
	addDPIFlags(fs)
	_ = fs.Parse(args)
	runPostParse()
	setupResolver(strings.Split(*dns, ","))

	var bl []*bridge
	if dpi.bridge != nil { // -bridge (single) is accepted too and goes first
		bl = append(bl, dpi.bridge)
	}
	for _, s := range splitList(*bridgesF) {
		b, err := parseBridge(s, "socks5")
		if err != nil {
			out("ثبت‌نام: پل نامعتبر رد شد: %v", err)
			continue
		}
		bl = append(bl, b)
	}
	o := dpi
	o.bridge = nil
	rs := buildRegRoutes(o, *direct, *useDNS, splitList(*apiIPs), bl)
	logf := func(f string, a ...interface{}) { out(f, a...) }

	var acc *models.AccountData
	var client *http.Client
	win, err := tryRoutes(rs, logf, func(r regRoute) error {
		api.HTTPClient = regClient(r, o, *timeout)
		a, err := api.Register(internal.DefaultModel, internal.DefaultLocale, "", true)
		if err != nil {
			return err
		}
		acc, client = a, api.HTTPClient
		return nil
	})
	if err != nil {
		fail("register: %v", err)
	}
	priv, pub, err := internal.GenerateEcKeyPair()
	if err != nil {
		fail("keygen: %v", err)
	}
	// enroll the MASQUE key on the winning route; if that fails, on the routes after it
	var upd *models.AccountData
	api.HTTPClient = client
	upd, err = api.EnrollKey(acc.ID, acc.Token, pub, "076one")
	if err != nil && win+1 < len(rs) {
		out("ثبت‌نام: ثبت کلید روی همان مسیر نشد (%s)؛ مسیرهای بعدی …", shortErr(err))
		_, err = tryRoutes(rs[win+1:], logf, func(r regRoute) error {
			api.HTTPClient = regClient(r, o, *timeout)
			u, e := api.EnrollKey(acc.ID, acc.Token, pub, "076one")
			if e == nil {
				upd = u
			}
			return e
		})
	}
	if err != nil {
		fail("enroll: %v", err)
	}
	peer := upd.Config.Peers[0]
	v4 := peer.Endpoint.V4
	if i := strings.LastIndex(v4, ":"); i > 0 {
		v4 = v4[:i]
	}
	v6 := strings.TrimPrefix(peer.Endpoint.V6, "[")
	if i := strings.LastIndex(v6, "]"); i > 0 {
		v6 = v6[:i]
	}
	config.AppConfig = config.Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(priv),
		EndpointV4:     v4,
		EndpointV6:     v6,
		EndpointH2V4:   config.DefaultEndpointH2V4,
		EndpointH2V6:   config.DefaultEndpointH2V6,
		EndpointPubKey: peer.PublicKey,
		ID:             upd.ID,
		AccessToken:    acc.Token,
		IPv4:           upd.Config.Interface.Addresses.V4,
		IPv6:           upd.Config.Interface.Addresses.V6,
	}
	if err := config.AppConfig.SaveConfig(*cfgPath); err != nil {
		fail("save: %v", err)
	}
	out("ROUTE %s", rs[win].kind)
	out("OK")
}
