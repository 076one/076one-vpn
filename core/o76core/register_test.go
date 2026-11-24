package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Diniboy1123/usque/models"
)

// fallback order: direct -> bridges (given order); stops at the first success
func TestRegRoutesOrderAndFallback(t *testing.T) {
	b1, _ := parseBridge("http://10.0.0.1:8080", "socks5")
	b2, _ := parseBridge("socks5://10.0.0.2:1080", "socks5")
	rs := buildRegRoutes(dpi, true, true, nil, []*bridge{b1, b2})
	var kinds []string
	for _, r := range rs {
		kinds = append(kinds, r.kind)
	}
	if fmt.Sprint(kinds) != "[direct bridge bridge]" {
		t.Fatalf("order %v", kinds)
	}
	var tried []string
	win, err := tryRoutes(rs, t.Logf, func(r regRoute) error {
		tried = append(tried, r.label)
		if r.label == "پل "+b2.key() {
			return nil
		}
		return errors.New("net/http: TLS handshake timeout")
	})
	if err != nil || win != 2 || len(tried) != 3 {
		t.Fatalf("win=%d err=%v tried=%v", win, err, tried)
	}
	// last bridge reached when everything before fails
	win, err = tryRoutes(rs, t.Logf, func(r regRoute) error {
		if r.label == "پل "+b2.key() {
			return nil
		}
		return errors.New("timeout")
	})
	if err != nil || win != len(rs)-1 {
		t.Fatalf("last-route fallback: win=%d err=%v", win, err)
	}
	// all fail -> error naming every route
	_, err = tryRoutes(rs, t.Logf, func(r regRoute) error { return errors.New("x") })
	if err == nil {
		t.Fatal("expected error")
	}
	// direct disabled -> bridges first
	rs2 := buildRegRoutes(dpi, false, true, nil, []*bridge{b1})
	if len(rs2) != 1 || rs2[0].kind != "bridge" {
		t.Fatalf("no-direct: %+v", rs2)
	}
}

// an API refusal (e.g. rate limit for this source IP) moves on to the next route (other source IP)
func TestRegRoutesAPIErrorMovesOn(t *testing.T) {
	b1, _ := parseBridge("socks5://10.0.0.2:1080", "socks5")
	rs := buildRegRoutes(dpi, true, true, nil, []*bridge{b1})
	n := 0
	_, err := tryRoutes(rs, t.Logf, func(r regRoute) error {
		n++
		return &models.APIError{}
	})
	if err == nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

// direct route: an unroutable / blackholed address must not stop the next candidate address
func TestDirectDialerSkipsDeadAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	o := dpi
	o.mss = 0
	d := directDialer(o, []string{"10.255.255.1", "127.0.0.1"}, false)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	t0 := time.Now()
	c, err := d(ctx, net.JoinHostPort("api.example.invalid", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()
	t.Logf("fell through the dead address in %v", time.Since(t0))
}

func TestShortErr(t *testing.T) {
	e := errors.New(`failed to send request: Post "https://api.cloudflareclient.com/v0a4471/reg": net/http: TLS handshake timeout`)
	if s := shortErr(e); s != "net/http: TLS handshake timeout" {
		t.Fatalf("%q", s)
	}
}
