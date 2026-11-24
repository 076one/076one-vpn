// v1.8.4 "Bridge + Psiphon": phone -> public SOCKS5 / SOCKS4 / HTTP-CONNECT proxy (the user's bridge list) -> Psiphon.
//
// psiphon-tunnel-core's UpstreamProxyURL (psiphon/upstreamproxy) supports these schemes:
//   socks5 / socks5h  golang.org/x/net/proxy, optional user:password (RFC 1929)
//   http              HTTP CONNECT, optional Basic / Digest / NTLM proxy auth
//   socks4a           its own SOCKS4a dialer; a domain destination is sent as SOCKS4a (0.0.0.1 + name)
// A plain SOCKS4 proxy rejects SOCKS4a names, and Psiphon resolves nothing itself before dialing through the upstream
// (the remote server list download goes to a host name), so socks4 bridges run through a small local adapter here:
// SOCKS5 (no auth) on 127.0.0.1:<random> that resolves names locally (IPv4) and speaks plain SOCKS4 upstream.
// Credentials are URL-encoded for Psiphon (url.UserPassword) and never printed: say() redacts them.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// upstream is one bridge proxy.
type upstream struct {
	Scheme     string // socks5 | socks4 | http | auto
	Host       string // host:port
	User, Pass string
}

var redactMu sync.Mutex
var redactList []string

// addSecret: every later output line has s replaced with "***" (only values of 3+ chars, so short ones cannot
// blank out ordinary text).
func addSecret(s string) {
	if len(s) < 3 {
		return
	}
	redactMu.Lock()
	redactList = append(redactList, s)
	if e := url.QueryEscape(s); e != s {
		redactList = append(redactList, e)
	}
	if e := url.PathEscape(s); e != s {
		redactList = append(redactList, e)
	}
	// longest first, so a short secret never cuts into a longer one before that is replaced
	sort.Slice(redactList, func(i, j int) bool { return len(redactList[i]) > len(redactList[j]) })
	redactMu.Unlock()
}

func redact(s string) string {
	redactMu.Lock()
	defer redactMu.Unlock()
	for _, r := range redactList {
		s = strings.ReplaceAll(s, r, "***")
	}
	return s
}

// parseUpstream accepts scheme://[user:pass@]host:port (socks5, socks5h, socks, socks4, socks4a, http, https, auto)
// and bare host:port / user:pass@host:port (= auto). Already %-encoded credentials are decoded once.
func parseUpstream(raw string) (*upstream, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errors.New("empty proxy")
	}
	u := &upstream{Scheme: "auto"}
	if i := strings.Index(s, "://"); i >= 0 {
		u.Scheme = strings.ToLower(s[:i])
		s = s[i+3:]
	}
	switch u.Scheme {
	case "socks5", "socks5h", "socks":
		u.Scheme = "socks5"
	case "socks4", "socks4a":
		u.Scheme = "socks4"
	case "http", "https":
		u.Scheme = "http"
	case "auto":
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
	}
	s = strings.TrimSuffix(s, "/")
	if at := strings.LastIndex(s, "@"); at >= 0 {
		cred := s[:at]
		s = s[at+1:]
		user, pass := cred, ""
		if c := strings.Index(cred, ":"); c >= 0 {
			user, pass = cred[:c], cred[c+1:]
		}
		if d, err := url.PathUnescape(user); err == nil {
			user = d
		}
		if d, err := url.PathUnescape(pass); err == nil {
			pass = d
		}
		u.User, u.Pass = user, pass
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil || h == "" {
		return nil, errors.New("bad proxy address (want host:port)")
	}
	if n, err := strconv.Atoi(p); err != nil || n <= 0 || n > 65535 {
		return nil, errors.New("bad proxy port")
	}
	u.Host = net.JoinHostPort(h, p)
	addSecret(u.User)
	addSecret(u.Pass)
	return u, nil
}

// Key is scheme://host:port without credentials (safe to print).
func (u *upstream) Key() string { return u.Scheme + "://" + u.Host }

// psiURL is the UpstreamProxyURL for Psiphon ("" for socks4: use the local adapter).
func (u *upstream) psiURL() string {
	if u.Scheme == "socks4" || u.Scheme == "auto" {
		return ""
	}
	x := &url.URL{Scheme: u.Scheme, Host: u.Host}
	if u.User != "" || u.Pass != "" {
		x.User = url.UserPassword(u.User, u.Pass)
	}
	return x.String()
}

// dial opens a TCP stream to target (host:port) through the proxy.
func (u *upstream) dial(ctx context.Context, target string) (net.Conn, error) {
	var d net.Dialer
	switch u.Scheme {
	case "socks5":
		var auth *proxy.Auth
		if u.User != "" || u.Pass != "" {
			auth = &proxy.Auth{User: u.User, Password: u.Pass}
		}
		pd, err := proxy.SOCKS5("tcp", u.Host, auth, &d)
		if err != nil {
			return nil, err
		}
		return pd.(proxy.ContextDialer).DialContext(ctx, "tcp", target)
	case "http":
		c, err := d.DialContext(ctx, "tcp", u.Host)
		if err != nil {
			return nil, err
		}
		if dl, ok := ctx.Deadline(); ok {
			c.SetDeadline(dl)
		}
		req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
		if u.User != "" || u.Pass != "" {
			req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(u.User+":"+u.Pass)) + "\r\n"
		}
		req += "\r\n"
		if _, err := io.WriteString(c, req); err != nil {
			c.Close()
			return nil, err
		}
		br := bufio.NewReader(c)
		resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
		if err != nil {
			c.Close()
			return nil, err
		}
		if resp.StatusCode != 200 {
			c.Close()
			return nil, fmt.Errorf("proxy answered HTTP %d", resp.StatusCode)
		}
		c.SetDeadline(time.Time{})
		if br.Buffered() > 0 { // data after the 200 (unusual) must not be lost
			return &bufConn{Conn: c, r: br}, nil
		}
		return c, nil
	case "socks4":
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			return nil, err
		}
		pn, _ := strconv.Atoi(port)
		ip := net.ParseIP(host)
		if ip == nil {
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("resolve %s: %v", host, err)
			}
			ip = ips[0]
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, errors.New("socks4: IPv6 destination")
		}
		c, err := d.DialContext(ctx, "tcp", u.Host)
		if err != nil {
			return nil, err
		}
		if dl, ok := ctx.Deadline(); ok {
			c.SetDeadline(dl)
		}
		req := []byte{4, 1, byte(pn >> 8), byte(pn)}
		req = append(req, ip4...)
		req = append(req, []byte(u.User)...)
		req = append(req, 0)
		if _, err := c.Write(req); err != nil {
			c.Close()
			return nil, err
		}
		var rep [8]byte
		if _, err := io.ReadFull(c, rep[:]); err != nil {
			c.Close()
			return nil, err
		}
		if rep[1] != 0x5a {
			c.Close()
			return nil, fmt.Errorf("socks4 rejected (0x%02x)", rep[1])
		}
		c.SetDeadline(time.Time{})
		return c, nil
	}
	return nil, errors.New("proxy type unknown (auto): detect first")
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// checkTargets: a TLS handshake to a host abroad proves the proxy relays to the internet (not just answers).
var checkTargets = [][2]string{{"1.1.1.1:443", "one.one.one.one"}, {"8.8.8.8:443", "dns.google"}, {"www.google.com:443", "www.google.com"}}

// check: proxy handshake + TLS handshake through it; returns the handshake time.
func (u *upstream) check(timeout time.Duration) (int, error) {
	var last error
	for _, t := range checkTargets {
		ms, err := u.checkOne(t[0], t[1], timeout)
		if err == nil {
			return ms, nil
		}
		last = err
	}
	return -1, shortErr(last)
}

func (u *upstream) checkOne(target, sni string, timeout time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	t0 := time.Now()
	c, err := u.dial(ctx, target)
	if err != nil {
		return -1, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	tc := tls.Client(c, &tls.Config{ServerName: sni, NextProtos: []string{"http/1.1"}})
	if err := tc.HandshakeContext(ctx); err != nil {
		return -1, err
	}
	return int(time.Since(t0).Milliseconds()), nil
}

// detect finds the type of an "auto" proxy: SOCKS5, then HTTP, then SOCKS4 (as the app's bridge test does).
func (u *upstream) detect(timeout time.Duration) (int, error) {
	if u.Scheme != "auto" {
		return u.check(timeout)
	}
	var last error
	for _, s := range []string{"socks5", "http", "socks4"} {
		x := *u
		x.Scheme = s
		ms, err := x.checkOne(checkTargets[0][0], checkTargets[0][1], timeout)
		if err == nil {
			u.Scheme = s
			return ms, nil
		}
		last = err
	}
	return -1, shortErr(last)
}

// socks4Adapter serves SOCKS5 (no auth, CONNECT only) on 127.0.0.1 and forwards through a plain SOCKS4 proxy,
// resolving names locally. Used for Psiphon only (its own socks4a dialer would send names to the proxy).
type socks4Adapter struct {
	ln net.Listener
	up *upstream
}

func startSocks4Adapter(up *upstream) (*socks4Adapter, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	a := &socks4Adapter{ln: ln, up: up}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go a.serve(c)
		}
	}()
	return a, nil
}

func (a *socks4Adapter) port() int { return a.ln.Addr().(*net.TCPAddr).Port }
func (a *socks4Adapter) close()    { a.ln.Close() }

func (a *socks4Adapter) serve(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 5 {
		return
	}
	m := make([]byte, h[1])
	if _, err := io.ReadFull(c, m); err != nil {
		return
	}
	c.Write([]byte{5, 0})
	var r [4]byte
	if _, err := io.ReadFull(c, r[:]); err != nil || r[1] != 1 {
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch r[3] {
	case 1:
		var b [4]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return
		}
		host = net.IP(b[:]).String()
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	default: // IPv6: plain SOCKS4 cannot carry it
		c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(pb[0])<<8|int(pb[1])))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	uc, err := a.up.dial(ctx, target)
	cancel()
	if err != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer uc.Close()
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	c.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(uc, c)
		if cw, ok := uc.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(c, uc)
		if cw, ok := c.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}
