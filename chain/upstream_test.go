package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// v1.8.4: bridge proxy lines -> Psiphon UpstreamProxyURL (credentials URL-encoded) and safe keys.
func TestParseUpstream(t *testing.T) {
	cases := []struct{ in, scheme, host, user, pass, psi, key string }{
		{"socks5://1.2.3.4:1080", "socks5", "1.2.3.4:1080", "", "", "socks5://1.2.3.4:1080", "socks5://1.2.3.4:1080"},
		{"socks5h://u:p@x.example:1080/", "socks5", "x.example:1080", "u", "p", "socks5://u:p@x.example:1080", "socks5://x.example:1080"},
		{"http://us%40r:p%3Ass@5.6.7.8:8080", "http", "5.6.7.8:8080", "us@r", "p:ss", "http://us%40r:p%3Ass@5.6.7.8:8080", "http://5.6.7.8:8080"},
		{"https://a:b c@5.6.7.8:3128", "http", "5.6.7.8:3128", "a", "b c", "http://a:b%20c@5.6.7.8:3128", "http://5.6.7.8:3128"},
		{"socks4://9.9.9.9:4145", "socks4", "9.9.9.9:4145", "", "", "", "socks4://9.9.9.9:4145"},
		{"user:pa@ss@1.1.1.1:99", "auto", "1.1.1.1:99", "user", "pa@ss", "", "auto://1.1.1.1:99"},
	}
	for _, c := range cases {
		u, err := parseUpstream(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if u.Scheme != c.scheme || u.Host != c.host || u.User != c.user || u.Pass != c.pass {
			t.Fatalf("%s: got %+v", c.in, u)
		}
		if got := u.psiURL(); got != c.psi {
			t.Fatalf("%s: psiURL %q want %q", c.in, got, c.psi)
		}
		if u.Key() != c.key {
			t.Fatalf("%s: key %q", c.in, u.Key())
		}
		if c.psi != "" { // Psiphon parses it back to the same credentials
			pu, err := url.Parse(c.psi)
			if err != nil {
				t.Fatal(err)
			}
			if p, _ := pu.User.Password(); pu.User != nil && (pu.User.Username() != c.user || p != c.pass) {
				t.Fatalf("%s: round trip %q %q", c.in, pu.User.Username(), p)
			}
		}
	}
	for _, bad := range []string{"", "ftp://1.2.3.4:21", "1.2.3.4", "socks5://1.2.3.4:0", "socks5://1.2.3.4:99999"} {
		if _, err := parseUpstream(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	// credentials never printed
	parseUpstream("socks5://secretuser:secretpass@1.2.3.4:1080")
	if s := redact("dial socks5://secretuser:secretpass@1.2.3.4:1080 failed"); strings.Contains(s, "secret") {
		t.Fatalf("not redacted: %s", s)
	}
}

func echoServer(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

// fake plain SOCKS4 proxy (rejects SOCKS4a names like real socks4-only servers)
func socks4Server(t *testing.T) string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var h [8]byte
				if _, err := io.ReadFull(c, h[:]); err != nil {
					return
				}
				br := bufio.NewReader(c)
				br.ReadBytes(0)
				if h[4] == 0 && h[5] == 0 && h[6] == 0 && h[7] != 0 { // SOCKS4a name: not supported
					c.Write([]byte{0, 0x5b, 0, 0, 0, 0, 0, 0})
					return
				}
				dst := net.JoinHostPort(net.IP(h[4:8]).String(), strconv.Itoa(int(binary.BigEndian.Uint16(h[2:4]))))
				u, err := net.Dial("tcp", dst)
				if err != nil {
					c.Write([]byte{0, 0x5b, 0, 0, 0, 0, 0, 0})
					return
				}
				defer u.Close()
				c.Write([]byte{0, 0x5a, 0, 0, 0, 0, 0, 0})
				go io.Copy(u, br)
				io.Copy(c, u)
			}()
		}
	}()
	return ln.Addr().String()
}

// fake HTTP CONNECT proxy with Basic auth
func httpProxy(t *testing.T, user, pass string) string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			w.WriteHeader(405)
			return
		}
		if u, p, ok := parseBasic(r.Header.Get("Proxy-Authorization")); !ok || u != user || p != pass {
			w.WriteHeader(407)
			return
		}
		up, err := net.Dial("tcp", r.Host)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		hj, _ := w.(http.Hijacker)
		c, buf, _ := hj.Hijack()
		c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go io.Copy(up, buf)
		io.Copy(c, up)
		c.Close()
		up.Close()
	})}
	go srv.Serve(ln)
	return ln.Addr().String()
}

func parseBasic(h string) (string, string, bool) {
	r := &http.Request{Header: http.Header{"Authorization": {h}}}
	return r.BasicAuth()
}

func roundTrip(t *testing.T, c net.Conn) {
	t.Helper()
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("ping-076"))
	b := make([]byte, 8)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "ping-076" {
		t.Fatalf("echo: %q %v", b, err)
	}
}

func TestUpstreamDialers(t *testing.T) {
	echo := echoServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hp := httpProxy(t, "us@r", "p:ss w")
	u, _ := parseUpstream("http://us%40r:p%3Ass%20w@" + hp)
	c, err := u.dial(ctx, echo)
	if err != nil {
		t.Fatalf("http connect: %v", err)
	}
	roundTrip(t, c)
	bad, _ := parseUpstream("http://us%40r:wrong@" + hp)
	if _, err := bad.dial(ctx, echo); err == nil || !strings.Contains(err.Error(), "407") {
		t.Fatalf("wrong password accepted: %v", err)
	}

	s4 := socks4Server(t)
	u4, _ := parseUpstream("socks4://" + s4)
	c, err = u4.dial(ctx, echo)
	if err != nil {
		t.Fatalf("socks4: %v", err)
	}
	roundTrip(t, c)

	// the adapter: SOCKS5 with a host name in, plain SOCKS4 out (name resolved locally)
	a, err := startSocks4Adapter(u4)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	_, port, _ := net.SplitHostPort(echo)
	d, _ := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(a.port())), nil, proxy.Direct)
	c, err = d.Dial("tcp", "localhost:"+port)
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	roundTrip(t, c)
}

// v1.8.5: a refusing bridge proxy is not retried (the app skips to the next healthy bridge)
func TestIsRefusedBridge(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens there now -> connection refused
	u, err := parseUpstream("socks5://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	_, err = u.check(3 * time.Second)
	if !isRefused(err) {
		t.Fatalf("want refused, got %v", err)
	}
	if isRefused(errors.New("timeout (no answer through the config)")) || isRefused(nil) {
		t.Fatal("timeout / nil must not count as refused")
	}
}
